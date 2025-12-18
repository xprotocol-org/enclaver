use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use anyhow::Result;
use ignore_result::Ignore;
use log::{debug, error, info};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::{Configuration, ListenerConfig};
use enclaver::manifest::IngressHealthcheck;
use enclaver::proxy::ingress::EnclaveProxy;

pub struct IngressService {
    proxies: Vec<JoinHandle<()>>,
    healthchecks: Vec<JoinHandle<()>>,
    shutdown: watch::Sender<()>,
}

impl IngressService {
    pub fn start(config: &Configuration) -> Result<Self> {
        let mut proxy_tasks = Vec::new();
        let mut healthcheck_tasks = Vec::new();

        let (tx, rx) = tokio::sync::watch::channel(());

        if let Some(ingress_list) = &config.manifest.ingress {
            for ingress in ingress_list {
                let port = ingress.listen_port;
                let listener_cfg = config.listener_configs.get(&port);

                match listener_cfg {
                    Some(ListenerConfig::TCP) => {
                        info!("Starting TCP ingress on port {}", port);
                        let proxy = EnclaveProxy::bind(port)?;
                        proxy_tasks.push(tokio::spawn(proxy.serve(rx.clone())));
                    }
                    Some(ListenerConfig::TLS(tls_cfg)) => {
                        info!("Starting TLS ingress on port {}", port);
                        let proxy = EnclaveProxy::bind_tls(port, tls_cfg.clone())?;
                        proxy_tasks.push(tokio::spawn(proxy.serve(rx.clone())));
                    }
                    None => {
                        info!("Starting TCP ingress on port {}", port);
                        let proxy = EnclaveProxy::bind(port)?;
                        proxy_tasks.push(tokio::spawn(proxy.serve(rx.clone())));
                    }
                }

                if let Some(healthcheck_cfg) = &ingress.healthcheck {
                    info!(
                        "Starting healthcheck for localhost:{} (interval={}s, timeout={}s, initial_delay={}s, threshold={})",
                        port,
                        healthcheck_cfg.interval_seconds,
                        healthcheck_cfg.timeout_seconds,
                        healthcheck_cfg.initial_delay_seconds,
                        healthcheck_cfg.failure_threshold
                    );
                    let shutdown_rx = rx.clone();
                    let hc_cfg = healthcheck_cfg.clone();
                    healthcheck_tasks.push(tokio::spawn(async move {
                        run_healthcheck(port, hc_cfg, shutdown_rx).await;
                    }));
                }
            }
        }

        Ok(Self {
            proxies: proxy_tasks,
            healthchecks: healthcheck_tasks,
            shutdown: tx,
        })
    }

    pub async fn stop(self) {
        self.shutdown.send(()).ignore();

        for p in self.proxies {
            p.await.ignore();
        }

        for h in self.healthchecks {
            h.abort();
            h.await.ignore();
        }
    }
}

async fn run_healthcheck(port: u16, config: IngressHealthcheck, mut shutdown: watch::Receiver<()>) {
    if config.initial_delay_seconds > 0 {
        info!(
            "Healthcheck for port {}: waiting {} seconds before first check",
            port, config.initial_delay_seconds
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.initial_delay_seconds)) => {}
            _ = shutdown.changed() => {
                debug!("Healthcheck for port {}: shutdown during initial delay", port);
                return;
            }
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    interval.tick().await;

    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                match perform_healthcheck(port, config.timeout_seconds).await {
                    Ok(()) => {
                        if consecutive_failures > 0 {
                            info!(
                                "Healthcheck for port {} recovered after {} consecutive failure(s)",
                                port, consecutive_failures
                            );
                        }
                        consecutive_failures = 0;
                        debug!("Healthcheck for port {} passed", port);
                    }
                    Err(err) => {
                        consecutive_failures += 1;
                        error!(
                            "Healthcheck for port {} failed ({}/{}): {}",
                            port, consecutive_failures, config.failure_threshold, err
                        );

                        if consecutive_failures >= config.failure_threshold {
                            error!(
                                "Healthcheck for port {}: {} consecutive failures reached threshold, crashing enclave",
                                port, consecutive_failures
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
            _ = shutdown.changed() => {
                debug!("Healthcheck for port {}: received shutdown signal", port);
                return;
            }
        }
    }
}

async fn perform_healthcheck(port: u16, timeout_seconds: u64) -> Result<()> {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let timeout_duration = Duration::from_secs(timeout_seconds);

    timeout(timeout_duration, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("timeout after {} seconds", timeout_seconds))?
        .map_err(|e| anyhow::anyhow!("failed to connect to localhost:{}: {}", port, e))?;

    Ok(())
}
