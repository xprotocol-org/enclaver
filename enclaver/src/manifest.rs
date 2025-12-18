use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::pin::Pin;
use tokio::fs::File;
use tokio::io::AsyncRead;

use tokio::io::AsyncReadExt;

use crate::utils::expand_env_vars;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    pub name: String,
    pub target: String,
    pub sources: Sources,
    pub signature: Option<Signature>,
    pub ingress: Option<Vec<Ingress>>,
    pub egress: Option<Egress>,
    pub defaults: Option<Defaults>,
    pub kms_proxy: Option<KmsProxy>,
    pub api: Option<Api>,
    pub spire: Option<Spire>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub app: String,
    pub odyn: Option<String>,
    pub sleeve: Option<String>,
    pub nitro_cli: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ingress {
    pub listen_port: u16,
    pub tls: Option<ServerTls>,
    pub healthcheck: Option<IngressHealthcheck>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub key_file: String,
    pub cert_file: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressHealthcheck {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub initial_delay_seconds: u64,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

fn default_failure_threshold() -> u32 {
    3
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub proxy_port: Option<u16>,
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub cpu_count: Option<i32>,
    pub memory_mb: Option<i32>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsProxy {
    pub listen_port: u16,
    pub endpoints: Option<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    pub listen_port: u16,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spire {
    pub server_addr: String,
    pub ca_cert: PathBuf,
    pub trust_domain: String,
    pub svid_dir: PathBuf,
}

fn parse_manifest(buf: &[u8]) -> Result<Manifest> {
    let manifest: Manifest = serde_yaml::from_slice(buf)?;

    Ok(manifest)
}

pub async fn load_manifest_raw<P: AsRef<Path>>(path: P) -> Result<(Vec<u8>, Manifest)> {
    let mut file: Pin<Box<dyn AsyncRead>> = if path.as_ref() == Path::new("-") {
        Box::pin(tokio::io::stdin())
    } else {
        match File::open(&path).await {
            Ok(file) => Box::pin(file),
            Err(err) => anyhow::bail!("failed to open {}: {err}", path.as_ref().display()),
        }
    };

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;

    let manifest = parse_manifest(&buf)
        .map_err(|e| anyhow!("invalid configuration in {}: {e}", path.as_ref().display()))?;

    Ok((buf, manifest))
}

/// Expand environment variables in manifest fields.
/// This recursively walks the manifest structure and expands environment variables
/// in string fields that contain ${VAR}, ${VAR:-default}, or $VAR syntax.
fn expand_env_vars_in_manifest(manifest: &mut Manifest) {
    // Expand in target field
    manifest.target = expand_env_vars(&manifest.target);

    // Expand in sources fields
    manifest.sources.app = expand_env_vars(&manifest.sources.app);
    if let Some(ref mut odyn) = manifest.sources.odyn {
        *odyn = expand_env_vars(odyn);
    }
    if let Some(ref mut sleeve) = manifest.sources.sleeve {
        *sleeve = expand_env_vars(sleeve);
    }
    if let Some(ref mut nitro_cli) = manifest.sources.nitro_cli {
        *nitro_cli = expand_env_vars(nitro_cli);
    }

    // Expand in name field
    manifest.name = expand_env_vars(&manifest.name);

    // Expand in signature paths if present
    if let Some(ref mut signature) = manifest.signature {
        signature.certificate = PathBuf::from(expand_env_vars(&signature.certificate.to_string_lossy()));
        signature.key = PathBuf::from(expand_env_vars(&signature.key.to_string_lossy()));
    }

    // Expand in ingress configurations
    if let Some(ref mut ingress_list) = manifest.ingress {
        for ingress in ingress_list.iter_mut() {
            if let Some(ref mut tls) = ingress.tls {
                tls.cert_file = expand_env_vars(&tls.cert_file);
                tls.key_file = expand_env_vars(&tls.key_file);
            }
            // IngressHealthcheck doesn't have string fields to expand
        }
    }

    // Expand in egress configurations
    if let Some(ref mut egress) = manifest.egress {
        if let Some(ref mut allow_list) = egress.allow {
            *allow_list = allow_list.iter().map(|s| expand_env_vars(s)).collect();
        }
        if let Some(ref mut deny_list) = egress.deny {
            *deny_list = deny_list.iter().map(|s| expand_env_vars(s)).collect();
        }
    }
}

pub async fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest> {
    let (_, mut manifest) = load_manifest_raw(path).await?;

    // Expand environment variables in the manifest
    expand_env_vars_in_manifest(&mut manifest);

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use crate::manifest::parse_manifest;

    #[test]
    fn test_parse_manifest_with_unknown_fields() {
        assert!(parse_manifest(br#"foo: "bar""#).is_err());
    }

    #[test]
    fn test_parse_minimal_manifest() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.version, "v1");
        assert_eq!(manifest.name, "test");
        assert_eq!(manifest.target, "target-image:latest");
        assert_eq!(manifest.sources.app, "app-image:latest");
    }

    #[test]
    fn test_parse_ingress_with_healthcheck() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
ingress:
  - listen_port: 8000
    healthcheck:
      interval_seconds: 30
      timeout_seconds: 5
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.ingress.as_ref().unwrap().len(), 1);
        let ingress = &manifest.ingress.as_ref().unwrap()[0];
        assert_eq!(ingress.listen_port, 8000);
        assert!(ingress.healthcheck.is_some());
        let healthcheck = ingress.healthcheck.as_ref().unwrap();
        assert_eq!(healthcheck.interval_seconds, 30);
        assert_eq!(healthcheck.timeout_seconds, 5);
    }

    #[test]
    fn test_parse_ingress_without_healthcheck() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
ingress:
  - listen_port: 8000
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.ingress.as_ref().unwrap().len(), 1);
        let ingress = &manifest.ingress.as_ref().unwrap()[0];
        assert_eq!(ingress.listen_port, 8000);
        assert!(ingress.healthcheck.is_none());
    }

    #[test]
    fn test_parse_ingress_healthcheck_invalid_field() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
ingress:
  - listen_port: 8000
    healthcheck:
      interval_seconds: 30
      timeout_seconds: 5
      invalid_field: "should_fail"
#r"#;

        let result = parse_manifest(raw_manifest);
        assert!(result.is_err(), "Should fail with unknown field in healthcheck");
    }

    #[test]
    fn test_parse_sources_with_nitro_cli() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
  nitro_cli: "my-custom-nitro-cli:latest"
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.sources.app, "app-image:latest");
        assert_eq!(manifest.sources.nitro_cli, Some("my-custom-nitro-cli:latest".to_string()));
    }

    #[test]
    fn test_parse_sources_without_nitro_cli() {
        let raw_manifest = br#"
version: v1
name: "test"
target: "target-image:latest"
sources:
  app: "app-image:latest"
#r"#;

        let manifest = parse_manifest(raw_manifest).unwrap();

        assert_eq!(manifest.sources.app, "app-image:latest");
        assert!(manifest.sources.nitro_cli.is_none());
    }
}
