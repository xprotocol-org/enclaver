use crate::constants::{
    EIF_FILE_NAME, ENCLAVE_CONFIG_DIR, ENCLAVE_ODYN_PATH, MANIFEST_FILE_NAME, RELEASE_BUNDLE_DIR,
};
use crate::images::{FileBuilder, FileSource, ImageManager, ImageRef, LayerBuilder};
use crate::manifest::{Manifest, Signature, load_manifest};
use crate::nitro_cli::{EIFInfo, KnownIssue};
pub use crate::nitro_cli_container::SigningInfo;
use anyhow::{Result, anyhow, bail};
use bollard::Docker;
use bollard::models::ImageConfig;
use bollard::query_parameters::RemoveImageOptions;
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::{canonicalize, rename};
use uuid::Uuid;
const ENCLAVE_OVERLAY_CHOWN: &str = "0:0";
const RELEASE_OVERLAY_CHOWN: &str = "0:0";

// TODO: Update to your multi-arch nitro-cli image
const NITRO_CLI_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest";
// For multi-arch support, replace with: "your-registry.com/multi-arch-nitro-cli:latest"
const ODYN_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/odyn:latest";
const ODYN_IMAGE_BINARY_PATH: &str = "/usr/local/bin/odyn";
const SLEEVE_IMAGE: &str = "public.ecr.aws/s2t1d4c6/enclaver-io/enclaver-wrapper-base:latest";

async fn is_docker_build_native(target_platform: &str) -> bool {
    let host_arch = match tokio::process::Command::new("uname")
        .arg("-m")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => {
            warn!("Failed to detect host architecture via uname, assuming x86_64");
            "x86_64".to_string()
        }
    };

    let host_docker_platform = match host_arch.as_str() {
        "x86_64" | "amd64" => "linux/amd64",
        "aarch64" | "arm64" => "linux/arm64",
        "armv7l" | "armhf" => "linux/arm/v7",
        other => {
            warn!("Unknown host architecture '{}', assuming linux/amd64", other);
            "linux/amd64"
        }
    };

    let is_native = host_docker_platform == target_platform;
    debug!(
        "Host arch: {} ({}), Target platform: {}, Native build: {}",
        host_arch, host_docker_platform, target_platform, is_native
    );
    is_native
}

pub struct EnclaveArtifactBuilder {
    docker: Arc<Docker>,
    image_manager: ImageManager,
    pull_tags: bool,
}

impl EnclaveArtifactBuilder {
    pub fn new(pull_tags: bool) -> Result<Self> {
        let docker_client = Arc::new(
            Docker::connect_with_local_defaults()
                .map_err(|e| anyhow!("connecting to docker: {}", e))?,
        );

        Ok(Self {
            pull_tags,
            docker: docker_client.clone(),
            image_manager: ImageManager::new_with_docker(docker_client)?,
        })
    }

    /// Build a release image based on the referenced manifest.
    pub async fn build_release(
        &self,
        manifest_path: &str,
        custom_nitro_cli: Option<&str>,
    ) -> Result<(EIFInfo, ResolvedSources, ImageRef)> {
        let ibr = self.common_build(manifest_path, custom_nitro_cli).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        let mut release_img = self
            .package_eif(eif_path, manifest_path, &ibr.resolved_sources)
            .await?;

        let release_tag = &ibr.manifest.target;
        release_img.name = Some(release_tag.to_string());

        self.image_manager
            .tag_image(&release_img, release_tag)
            .await?;

        Ok((ibr.eif_info, ibr.resolved_sources, release_img))
    }

    /// Build a multi-architecture release image for both AMD64 and ARM64.
    ///
    /// Uses Docker's multi-platform capabilities and binfmt/QEMU to run
    /// nitro-cli containers on different architectures, producing enclave
    /// images for each target platform.
    ///
    /// Process:
    /// 1. Use docker buildx with --platform to run nitro-cli on target architectures
    /// 2. Each nitro-cli builds EIF for its native architecture
    /// 3. Collect EIFs and build multi-arch Docker images
    /// 4. Create multi-arch manifest (and optionally push to registry)
    ///
    /// Requires: multi-arch nitro-cli + binfmt/QEMU setup
    pub async fn build_release_multi_arch(
        &self,
        manifest_path: &str,
        push: bool,
        custom_nitro_cli: Option<&str>,
    ) -> Result<(EIFInfo, ResolvedSources, ImageRef)> {
        info!("🔄 Building multi-architecture enclave images (AMD64 + ARM64)");
        info!("🐳 Using Docker multi-platform with binfmt/QEMU emulation");

        info!("🔍 Checking binfmt/QEMU setup for cross-platform execution...");
        self.verify_binfmt_setup().await?;

        let manifest = load_manifest(manifest_path).await?;
        self.analyze_manifest(&manifest);
        let resolved_sources = self.resolve_sources(&manifest, custom_nitro_cli).await?;

        info!("🔍 Validating multi-arch compatibility of all images...");
        self.validate_multi_arch_images(&manifest, &resolved_sources).await?;

        info!("🏗️  Building enclave images for both architectures...");

        let platforms = ["linux/amd64", "linux/arm64"];
        let mut intermediate_images = Vec::new();

        info!("📋 Building intermediate images for each platform");
        for &platform in &platforms {
            let amended_img = self
                .amend_source_image_platform(&manifest, &resolved_sources, manifest_path, platform)
                .await?;

            let local_tag = amended_img.name.clone().unwrap_or(amended_img.id.clone());
            info!("✅ Built intermediate image: {} ({})", local_tag, platform);

            intermediate_images.push((platform, ImageRef {
                id: amended_img.id,
                name: Some(local_tag),
                repo_digest: amended_img.repo_digest,
            }));
        }

        let eif_results = self
            .build_eifs_multi_arch(
                &intermediate_images,
                &resolved_sources.nitro_cli,
                manifest.signature.as_ref(),
                manifest_path,
            )
            .await?;

        for (platform, img) in &intermediate_images {
            if let Some(tag) = &img.name {
                debug!("🧹 Cleaning up intermediate image for {}: {}", platform, tag);
                let _ = self.docker.remove_image(tag, None::<RemoveImageOptions>, None).await;
            }
        }

        let amd64_eif_info = eif_results.amd64_eif_info.clone();

        // Package into multi-arch Docker images
        let release_tag = &manifest.target;

        let mode = if push { "production (registry)" } else { "development (local)" };
        info!("📦 Packaging mode: {}", mode);

        let multi_arch_img = self
            .package_eifs_multi_arch(
                eif_results,
                manifest_path,
                &resolved_sources,
                release_tag,
                push,
            )
            .await?;

        info!("✅ Multi-arch enclave images built successfully");
        if push {
            info!("📦 Pushed multi-arch image to registry: {}", release_tag);
        } else {
            info!("🏠 Created local multi-arch images with manifest: {}", release_tag);
        }
        info!("🎯 Supports: linux/amd64, linux/arm64");

        // Return info for the primary (AMD64) architecture
        Ok((amd64_eif_info, resolved_sources, multi_arch_img))
    }

    /// Build EIFs for multiple architectures using cross-platform nitro-cli containers.
    async fn build_eifs_multi_arch(
        &self,
        intermediate_images: &[( &str, ImageRef)],
        nitro_cli_img: &ImageRef,
        signature: Option<&Signature>,
        manifest_path: &str,
    ) -> Result<MultiArchEIFResults> {
        info!("🔨 Building EIFs for AMD64 and ARM64 architectures...");

        let sign: Option<SigningInfo> = if let Some(signature) = signature {
            if let Some(parent_path) = PathBuf::from(manifest_path).parent() {
                Some(SigningInfo {
                    certificate: canonicalize(parent_path.join(&signature.certificate)).await?,
                    key: canonicalize(parent_path.join(&signature.key)).await?,
                })
            } else {
                bail!("Failed to get parent path of manifest");
            }
        } else {
            None
        };

        // Build AMD64 EIF using AMD64 intermediate image
        info!("🏗️  Building AMD64 EIF...");
        let amd64_build_dir = TempDir::new()?;
        let amd64_img = intermediate_images.iter().find(|(platform, _)| *platform == "linux/amd64").unwrap().1.clone();
        let amd64_eif_info = self
            .image_to_eif_host(&amd64_img, nitro_cli_img, &amd64_build_dir, "enclave-amd64.eif", &sign, "linux/amd64")
            .await?;
        let amd64_eif_path = amd64_build_dir.path().join("enclave-amd64.eif");

        // Build ARM64 EIF using ARM64 intermediate image
        info!("🏗️  Building ARM64 EIF...");
        let arm64_build_dir = TempDir::new()?;
        let arm64_img = intermediate_images.iter().find(|(platform, _)| *platform == "linux/arm64").unwrap().1.clone();

        // For ARM64, we need to use the ARM64 variant of nitro-cli
        // Create a new image reference that will resolve to ARM64
        let arm64_nitro_cli_img = if let Some(name) = &nitro_cli_img.name {
            // Use the name so Docker can resolve the correct platform variant
            ImageRef {
                id: name.clone(),
                name: Some(name.clone()),
                repo_digest: nitro_cli_img.repo_digest.clone(),
            }
        } else {
            // Fallback to original if no name available
            nitro_cli_img.clone()
        };

        let arm64_eif_result = self
            .image_to_eif_host(&arm64_img, &arm64_nitro_cli_img, &arm64_build_dir, "enclave-arm64.eif", &sign, "linux/arm64")
            .await;

        let (arm64_eif_info, arm64_eif_path) = match arm64_eif_result {
            Ok(info) => {
                info!("✅ ARM64 EIF built successfully");
                let path = arm64_build_dir.path().join("enclave-arm64.eif");
                (info, path)
            },
            Err(e) => {
                error!("❌ ARM64 EIF build failed: {}", e);
                error!("💥 Multi-arch build requires both AMD64 and ARM64 to succeed");
                return Err(e);
            }
        };

        Ok(MultiArchEIFResults {
            amd64_eif_info,
            amd64_eif_path,
            _arm64_eif_info: arm64_eif_info,
            arm64_eif_path,
            _amd64_build_dir: amd64_build_dir,
            _arm64_build_dir: arm64_build_dir,
        })
    }

    /// Build EIF using nitro-cli directly with Docker socket access (single arch, no platform specification).

    /// Build EIF by running nitro-cli directly on host (using binfmt for cross-platform)
    async fn image_to_eif_host(
        &self,
        source_img: &ImageRef,
        nitro_cli_img: &ImageRef,
        build_dir: &TempDir,
        eif_name: &str,
        sign: &Option<SigningInfo>,
        platform: &str,
    ) -> Result<EIFInfo> {
        if !is_docker_build_native(platform).await {
            info!("🔧 Verifying binfmt setup for cross-platform build (platform: {})", platform);
            self.verify_binfmt_setup().await?;
        }

        let build_dir_path = build_dir.path();

        // Use DinD: run nitro-cli in a container with access to host Docker and output directory
        let img_tag = source_img.name.as_ref().unwrap_or(&source_img.id).clone();
        let nitro_cli_image_name = nitro_cli_img.name.as_ref()
            .unwrap_or(&nitro_cli_img.id);

        let mut docker_cmd = vec![
            "docker".to_string(),
            "run".to_string(),
            "--rm".to_string(),
            "--platform".to_string(),
            platform.to_string(),
            "-v".to_string(),
            format!("{}/.docker/config.json:/root/.docker/config.json", std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())),
            "-v".to_string(),
            "/var/run/docker.sock:/var/run/docker.sock".to_string(),
            "-v".to_string(),
            format!("{}:/build", build_dir_path.to_str().unwrap()),
        ];

        if let Some(sign) = sign {
            let cert_path = sign.certificate.to_string_lossy();
            let key_path = sign.key.to_string_lossy();
            docker_cmd.push("-v".to_string());
            docker_cmd.push(format!("{}:{}", cert_path, cert_path));
            docker_cmd.push("-v".to_string());
            docker_cmd.push(format!("{}:{}", key_path, key_path));
        }

        docker_cmd.push(nitro_cli_image_name.clone());
        docker_cmd.push("build-enclave".to_string());
        docker_cmd.push("--docker-uri".to_string());
        docker_cmd.push(img_tag);
        docker_cmd.push("--output-file".to_string());
        docker_cmd.push(format!("/build/{}", eif_name));

        if let Some(sign) = sign {
            docker_cmd.push("--signing-certificate".to_string());
            docker_cmd.push(sign.certificate.to_string_lossy().to_string());
            docker_cmd.push("--private-key".to_string());
            docker_cmd.push(sign.key.to_string_lossy().to_string());
        }

        info!("🚀 Running nitro-cli in container for {}: {:?}", platform, docker_cmd);

        let output = tokio::process::Command::new(&docker_cmd[0])
            .args(&docker_cmd[1..])
            .output()
            .await?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            let detected_nitro_cli_issue = KnownIssue::detect(&stderr);
            if let Some(issue) = detected_nitro_cli_issue {
                warn!(
                    "detected known nitro-cli issue:\n{}",
                    issue.helpful_message()
                );
            }

            for line in stderr.lines() {
                info!(target: "nitro-cli::build-eif", "{}", line);
            }
        }

        if !output.status.success() {
            bail!("non-zero exit code from nitro-cli container: {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.is_empty() {
            bail!("No JSON output from nitro-cli container");
        }

        Ok(serde_json::from_slice(stdout.as_bytes())?)
    }


    async fn is_multi_arch_image(&self, image_name: &str) -> bool {
        debug!("🔍 Inspecting image '{}' for multi-arch support using docker buildx", image_name);

        match tokio::process::Command::new("docker")
            .args(["buildx", "imagetools", "inspect", image_name])
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    debug!("📋 buildx imagetools inspect output:\n{}", stdout);

                    let has_amd64 = stdout.contains("linux/amd64");
                    let has_arm64 = stdout.contains("linux/arm64");
                    let is_multi_arch = has_amd64 && has_arm64;

                    if is_multi_arch {
                        debug!("✅ Image '{}' supports both linux/amd64 and linux/arm64", image_name);
                    } else {
                        debug!("❌ Image '{}' missing platforms - amd64: {}, arm64: {}", image_name, has_amd64, has_arm64);
                    }

                    is_multi_arch
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    debug!("❌ buildx imagetools inspect failed for '{}': {}", image_name, stderr);

                    if stderr.contains("unauthorized") || stderr.contains("not found") || stderr.contains("network") {
                        warn!("⚠️  Unable to inspect image '{}' - may be due to registry access: {}", image_name, stderr);
                    }

                    false
                }
            }
            Err(e) => {
                debug!("❌ buildx imagetools inspect command failed for '{}': {}", image_name, e);
                warn!("⚠️  Docker buildx may not be available or properly configured");
                false
            }
        }
    }

    async fn validate_multi_arch_images(&self, manifest: &Manifest, _sources: &ResolvedSources) -> Result<()> {
        info!("🔍 Validating multi-arch compatibility of all prerequisite images using docker buildx...");

        let mut validation_errors = Vec::new();

        // Check odyn image using the original name from manifest
        if let Some(odyn_name) = &manifest.sources.odyn {
            info!("🔍 Inspecting odyn image: {}", odyn_name);
            if !self.is_multi_arch_image(odyn_name).await {
                validation_errors.push(format!("❌ Odyn image '{}' does not support both linux/amd64 and linux/arm64 platforms", odyn_name));
            } else {
                info!("✅ Odyn image '{}' supports multi-arch (linux/amd64 + linux/arm64)", odyn_name);
            }
        } else {
            // If odyn is not specified in manifest, it should use default - but let's skip validation for now
            info!("ℹ️  Odyn image not specified in manifest, skipping validation");
        }

        // Check sleeve/enclave_wrapper_base image using the original name from manifest
        if let Some(sleeve_name) = &manifest.sources.sleeve {
            info!("🔍 Inspecting enclave wrapper base image: {}", sleeve_name);
            if !self.is_multi_arch_image(sleeve_name).await {
                validation_errors.push(format!("❌ Enclave wrapper base image '{}' does not support both linux/amd64 and linux/arm64 platforms", sleeve_name));
            } else {
                info!("✅ Enclave wrapper base image '{}' supports multi-arch (linux/amd64 + linux/arm64)", sleeve_name);
            }
        } else {
            // If sleeve is not specified in manifest, it should use default - but let's skip validation for now
            info!("ℹ️  Enclave wrapper base image not specified in manifest, skipping validation");
        }

        // Check nitro-cli image using the original name from manifest
        let nitro_cli_name = manifest.sources.nitro_cli.as_ref().unwrap_or(&NITRO_CLI_IMAGE.to_string()).clone();
        info!("🔍 Inspecting nitro-cli image: {}", nitro_cli_name);
        if !self.is_multi_arch_image(&nitro_cli_name).await {
            validation_errors.push(format!("❌ Nitro-CLI image '{}' does not support both linux/amd64 and linux/arm64 platforms", nitro_cli_name));
        } else {
            info!("✅ Nitro-CLI image '{}' supports multi-arch (linux/amd64 + linux/arm64)", nitro_cli_name);
        }

        // Check app image for multi-arch support (affects intermediate image building strategy)
        let app_name = &manifest.sources.app;
        info!("🔍 Inspecting app image: {}", app_name);
        let app_is_multi_arch = self.is_multi_arch_image(app_name).await;
        if app_is_multi_arch {
            info!("✅ App image '{}' supports multi-arch - will use optimized buildx intermediate image building", app_name);
        } else {
            info!("ℹ️  App image '{}' is single-arch - will build separate intermediate images per platform", app_name);
        }

        // If there are any validation errors, report them all and fail
        if !validation_errors.is_empty() {
            error!("🚫 Multi-arch build validation failed:");
            for error in &validation_errors {
                error!("{}", error);
            }
            error!("💡 To fix this, ensure all images support both linux/amd64 and linux/arm64 platforms");
            error!("💡 Check with: docker buildx imagetools inspect <image-name>");
            error!("💡 Build multi-arch images with: docker buildx build --platform linux/amd64,linux/arm64 --push -t <image> .");
            bail!("Multi-arch build requires all prerequisite images to support both AMD64 and ARM64 platforms. See errors above.");
        }

        info!("🎉 All prerequisite images validated for multi-arch support using docker buildx!");
        Ok(())
    }

    async fn verify_binfmt_setup(&self) -> Result<()> {
        info!("🔧 Verifying binfmt/QEMU setup for cross-platform builds...");

        match tokio::fs::read_dir("/proc/sys/fs/binfmt_misc").await {
            Ok(_) => debug!("✅ binfmt_misc filesystem is available"),
            Err(e) => {
                warn!("❌ binfmt_misc filesystem not available: {}", e);
                warn!("💡 This may indicate binfmt is not properly set up");
                bail!("binfmt/QEMU not available for cross-platform execution. Please run: docker run --privileged --rm tonistiigi/binfmt --install all");
            }
        }

        let qemu_aarch64_path = "/proc/sys/fs/binfmt_misc/qemu-aarch64";
        match tokio::fs::metadata(qemu_aarch64_path).await {
            Ok(_) => {
                match tokio::fs::read_to_string(qemu_aarch64_path).await {
                    Ok(content) if content.contains("enabled") => {
                        info!("✅ ARM64 (qemu-aarch64) emulation is enabled");
                    }
                    Ok(_) => {
                        warn!("⚠️  ARM64 binfmt entry exists but may not be enabled");
                    }
                    Err(e) => warn!("⚠️  Could not read ARM64 binfmt status: {}", e),
                }
            }
            Err(_) => {
                warn!("❌ ARM64 (qemu-aarch64) binfmt entry not found");
                warn!("💡 This is needed for ARM64 cross-platform builds");
            }
        }

        info!("🧪 Testing binfmt functionality...");
        match tokio::process::Command::new("docker")
            .args(["run", "--rm", "--platform", "linux/arm64", "alpine:latest", "echo", "binfmt test"])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("binfmt test") {
                    info!("✅ binfmt/QEMU test passed - cross-platform execution works");
                } else {
                    warn!("⚠️  binfmt test output unexpected: {}", stdout.trim());
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("❌ binfmt test failed with exit code {}: {}", output.status, stderr);
                warn!("💡 Cross-platform builds may not work properly");
            }
            Err(e) => {
                warn!("❌ Could not test binfmt setup: {}", e);
                warn!("💡 Please ensure Docker and binfmt are properly configured");
            }
        }

        info!("🎉 binfmt/QEMU verification completed");
        Ok(())
    }


    /// Package EIFs into multi-arch Docker images.
    ///
    /// For development: builds each arch separately and loads locally,
    /// then creates a local multi-arch manifest.
    /// For production: pushes multi-arch to registry.
    async fn package_eifs_multi_arch(
        &self,
        eif_results: MultiArchEIFResults,
        manifest_path: &str,
        sources: &ResolvedSources,
        release_tag: &str,
        push: bool,
    ) -> Result<ImageRef> {
        info!("📦 Creating multi-arch Docker images...");

        if push {
            // Production mode: push multi-arch to registry
            self.package_eifs_multi_arch_production(
                eif_results, manifest_path, sources, release_tag
            ).await
        } else {
            // Development mode: build locally for each arch, then create manifest
            self.package_eifs_multi_arch_development(
                eif_results, manifest_path, sources, release_tag
            ).await
        }
    }

    /// Production mode: push multi-arch image to registry using buildx
    async fn package_eifs_multi_arch_production(
        &self,
        eif_results: MultiArchEIFResults,
        manifest_path: &str,
        sources: &ResolvedSources,
        release_tag: &str,
    ) -> Result<ImageRef> {
        info!("🏭 Production mode: pushing multi-arch image to registry");
        debug!("📋 Release tag: {}", release_tag);
        debug!("📄 Manifest path: {}", manifest_path);

        let build_dir = TempDir::new()?;
        let build_dir_path = build_dir.path();
        debug!("📁 Created build directory: {}", build_dir_path.display());

        let amd64_eif_dest = build_dir_path.join("application-amd64.eif");
        let arm64_eif_dest = build_dir_path.join("application-arm64.eif");

        debug!("📋 Copying AMD64 EIF from {} to {}", eif_results.amd64_eif_path.display(), amd64_eif_dest.display());
        tokio::fs::copy(&eif_results.amd64_eif_path, &amd64_eif_dest).await?;
        debug!("📋 Copying ARM64 EIF from {} to {}", eif_results.arm64_eif_path.display(), arm64_eif_dest.display());
        tokio::fs::copy(&eif_results.arm64_eif_path, &arm64_eif_dest).await?;

        if !amd64_eif_dest.exists() {
            bail!("AMD64 EIF file was not copied to build directory");
        }
        if !arm64_eif_dest.exists() {
            bail!("ARM64 EIF file was not copied to build directory");
        }
        debug!("✅ Both EIF files copied successfully");

        let sleeve_image = sources.sleeve.name.as_ref()
            .ok_or_else(|| anyhow!("Sleeve image has no name"))?;

        let dockerfile_content = format!(r#"
FROM --platform=$TARGETPLATFORM {sleeve} AS base
ARG TARGETARCH
COPY application-${{TARGETARCH}}.eif {bundle_dir}/{eif_name}
COPY manifest.yaml {bundle_dir}/{manifest_name}
"#,
            sleeve = sleeve_image,
            bundle_dir = RELEASE_BUNDLE_DIR,
            eif_name = EIF_FILE_NAME,
            manifest_name = MANIFEST_FILE_NAME,
        );

        let dockerfile_path = build_dir_path.join("Dockerfile");
        tokio::fs::write(&dockerfile_path, &dockerfile_content).await?;
        debug!("📝 Created Dockerfile:\n{}", dockerfile_content);

        let manifest_dest = build_dir_path.join("manifest.yaml");
        tokio::fs::copy(manifest_path, &manifest_dest).await?;
        debug!("📋 Copied manifest from {} to {}", manifest_path, manifest_dest.display());

        // Build multi-arch image using docker buildx with --push
        let build_context = build_dir_path.to_str().unwrap();
        let platforms = "linux/amd64,linux/arm64";

        debug!("🔧 Build context: {}", build_context);
        debug!("🏗️  Platforms: {}", platforms);
        debug!("🏷️  Release tag: {}", release_tag);

        let buildx_cmd = format!(
            "docker buildx build --platform {} -f {}/Dockerfile -t {} --push {}",
            platforms, build_context, release_tag, build_context
        );

        info!("🚀 Pushing multi-arch image: {}", buildx_cmd);

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&buildx_cmd)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            error!("❌ Docker buildx command failed with exit code: {}", output.status);
            if !stdout.is_empty() {
                info!("📄 Build stdout: {}", stdout);
            }
            if !stderr.is_empty() {
                error!("📄 Build stderr: {}", stderr);
            }

            // Provide more specific error analysis
            if stderr.contains("invalid reference format") {
                error!("🔍 'Invalid reference format' error detected");
                error!("🔍 This usually means the image tag '{}' is malformed", release_tag);
                error!("🔍 Image tags should be in format: registry.com/namespace/image:tag");
                if !release_tag.contains('/') {
                    error!("🔍 Tag '{}' is missing a registry separator ('/')", release_tag);
                }
            }

            bail!("docker buildx push failed: {}", stderr);
        }

        if !stdout.is_empty() {
            debug!("📄 Build stdout: {}", stdout);
        }

        info!("✅ Multi-arch image pushed to registry: {}", release_tag);

        Ok(ImageRef {
            id: format!("multi-arch-registry:{}", release_tag),
            name: Some(release_tag.to_string()),
            repo_digest: None,
        })
    }

    async fn package_eifs_multi_arch_development(
        &self,
        eif_results: MultiArchEIFResults,
        manifest_path: &str,
        _sources: &ResolvedSources,
        release_tag: &str,
    ) -> Result<ImageRef> {
        info!("🏠 Development mode: building images for each architecture separately");
        info!("⚠️  Note: Docker buildx --load doesn't support multi-platform. Building host architecture only.");

        let build_dir = TempDir::new()?;
        let build_dir_path = build_dir.path();

        let host_arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        };

        let (eif_path, platform) = if host_arch == "amd64" {
            (&eif_results.amd64_eif_path, "linux/amd64")
        } else {
            (&eif_results.arm64_eif_path, "linux/arm64")
        };

        let eif_dest = build_dir_path.join("enclave.eif");
        std::fs::copy(eif_path, &eif_dest)?;

        let dockerfile_content = format!(r#"
FROM alpine:latest

COPY enclave.eif {bundle_dir}/enclave.eif
COPY manifest.yaml {bundle_dir}/{manifest_name}

ENTRYPOINT ["/bin/sh", "-c", "echo 'Enclave image contents:' && ls -la {bundle_dir}/ && echo 'Ready for nitro-cli deployment' && tail -f /dev/null"]
"#,
            bundle_dir = RELEASE_BUNDLE_DIR,
            manifest_name = MANIFEST_FILE_NAME,
        );

        let dockerfile_path = build_dir_path.join("Dockerfile");
        std::fs::write(&dockerfile_path, dockerfile_content)?;

        let manifest_dest = build_dir_path.join("manifest.yaml");
        std::fs::copy(manifest_path, &manifest_dest)?;

        let build_output = tokio::process::Command::new("docker")
            .args([
                "buildx", "build",
                "--platform", platform,
                "-f", dockerfile_path.to_str().unwrap(),
                "-t", release_tag,
                "--load",
                build_dir_path.to_str().unwrap(),
            ])
            .output()
            .await?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            error!("❌ buildx local build failed: {}", stderr);
            bail!("buildx build failed: {}", stderr);
        }

        info!("✅ Local image built for {}: {}", platform, release_tag);
        info!("💡 For multi-arch distribution, use --push to push to a registry");

        Ok(ImageRef {
            id: format!("local:{}", release_tag),
            name: Some(release_tag.to_string()),
            repo_digest: None,
        })
    }



    /// Build an EIF, as would be included in a release image, based on the referenced manifest.
    pub async fn build_eif_only(
        &self,
        manifest_path: &str,
        dst_path: &str,
    ) -> Result<(EIFInfo, PathBuf)> {
        let ibr = self.common_build(manifest_path, None).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        rename(&eif_path, dst_path).await?;

        Ok((ibr.eif_info, canonicalize(dst_path).await?))
    }

    /// Load the referenced manifest, amend the image it references to match what we expect in
    /// an enclave, then convert the resulting image to an EIF.
    async fn common_build(&self, manifest_path: &str, custom_nitro_cli: Option<&str>) -> Result<IntermediateBuildResult> {
        let manifest = load_manifest(manifest_path).await?;

        self.analyze_manifest(&manifest);

        let resolved_sources = self.resolve_sources(&manifest, custom_nitro_cli).await?;

        let amended_img = self
            .amend_source_image(&resolved_sources, manifest_path)
            .await?;

        info!("built intermediate image: {}", amended_img);

        let build_dir = TempDir::new()?;

        let sign: Option<SigningInfo> = if let Some(signature) = &manifest.signature {
            if let Some(parent_path) = PathBuf::from(manifest_path).parent() {
                Some(SigningInfo {
                    certificate: canonicalize(parent_path.join(&signature.certificate)).await?,
                    key: canonicalize(parent_path.join(&signature.key)).await?,
                })
            } else {
                bail!("Failed to get parent path of manifest");
            }
        } else {
            None
        };

        let eif_info = self
            .image_to_eif(
                &amended_img,
                resolved_sources.nitro_cli.clone(),
                &build_dir,
                EIF_FILE_NAME,
                sign,
            )
            .await?;

        Ok(IntermediateBuildResult {
            manifest,
            resolved_sources,
            build_dir,
            eif_info,
        })
    }

    async fn amend_source_image_platform(
        &self,
        manifest: &Manifest,
        sources: &ResolvedSources,
        manifest_path: &str,
        platform: &str,
    ) -> Result<ImageRef> {
        info!("🏗️  Creating platform-specific intermediate image for {}", platform);

        let build_dir = TempDir::new()?;
        let build_dir_path = build_dir.path();

        let etc_enclaver_dir = build_dir_path.join("etc").join("enclaver");
        tokio::fs::create_dir_all(&etc_enclaver_dir).await?;
        
        let manifest_dest = etc_enclaver_dir.join("enclaver.yaml");
        tokio::fs::copy(manifest_path, &manifest_dest).await?;

        let app_image_name = &manifest.sources.app;
        let odyn_default = sources.odyn.name.as_ref().unwrap_or(&sources.odyn.id).to_string();
        let odyn_image_name = manifest.sources.odyn.as_ref().unwrap_or(&odyn_default);

        let img_config = self
            .docker
            .inspect_image(sources.app.to_str())
            .await?
            .config;

        let mut cmd: Vec<String> = match img_config {
            Some(bollard::models::ImageConfig { cmd: Some(ref c), .. }) => c.clone(),
            _ => vec![],
        };

        let mut entrypoint: Vec<String> = match img_config {
            Some(bollard::models::ImageConfig { entrypoint: Some(ref e), .. }) => e.clone(),
            _ => vec![],
        };

        let mut odyn_command = vec![
            String::from(ENCLAVE_ODYN_PATH),
            String::from("--config-dir"),
            String::from("/etc/enclaver"),
            String::from("--"),
        ];
        odyn_command.append(&mut entrypoint);
        odyn_command.append(&mut cmd);

        let entrypoint_json = serde_json::to_string(&odyn_command)?;

        let dockerfile_content = format!(
            r#"FROM --platform={platform} {app} AS app
FROM --platform={platform} {odyn} AS odyn

FROM app
COPY --from=odyn {odyn_src_path} {odyn_dst_path}
COPY etc/enclaver/enclaver.yaml {config_dir}/{manifest_name}
ENTRYPOINT {entrypoint}
"#,
            platform = platform,
            app = app_image_name,
            odyn = odyn_image_name,
            odyn_src_path = ODYN_IMAGE_BINARY_PATH,
            odyn_dst_path = ENCLAVE_ODYN_PATH,
            config_dir = ENCLAVE_CONFIG_DIR,
            manifest_name = MANIFEST_FILE_NAME,
            entrypoint = entrypoint_json,
        );

        let dockerfile_path = build_dir_path.join("Dockerfile");
        tokio::fs::write(&dockerfile_path, &dockerfile_content).await?;
        debug!("📝 Created Dockerfile:\n{}", dockerfile_content);

        let intermediate_tag = format!("enclaver-intermediate-{}-{}",
            platform.replace("/", "-"),
            uuid::Uuid::new_v4().simple()
        );

        let build_output = tokio::process::Command::new("docker")
            .args([
                "buildx", "build",
                "--platform", platform,
                "-f", dockerfile_path.to_str().unwrap(),
                "-t", &intermediate_tag,
                "--load",
                build_dir_path.to_str().unwrap(),
            ])
            .output()
            .await?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            let stdout = String::from_utf8_lossy(&build_output.stdout);
            error!("❌ buildx build failed for {}:\nstderr: {}\nstdout: {}", platform, stderr, stdout);
            bail!("Failed to build intermediate image for {}: {}", platform, stderr);
        }

        info!("✅ Built platform-specific intermediate image: {} ({})", intermediate_tag, platform);

        let inspect = self.docker.inspect_image(&intermediate_tag).await?;
        Ok(ImageRef {
            id: inspect.id.unwrap_or_default(),
            name: Some(intermediate_tag),
            repo_digest: None,
        })
    }


    async fn amend_source_image(
        &self,
        sources: &ResolvedSources,
        manifest_path: &str,
    ) -> Result<ImageRef> {
        let img_config = self
            .docker
            .inspect_image(sources.app.to_str())
            .await?
            .config;

        // Find the CMD and ENTRYPOINT from the source image. If either was specified in "shell form"
        // Docker seems to convert it to "exec form" as an actual shell invocation, so we can simply
        // ignore that possibility.
        //
        // Since the enclave image cannot take any arguments (which would normally override a CMD),
        // we can simply take everything from CMD and append it to the ENTRYPOINT, then append that
        // whole thing to the odyn invocation.
        // TODO(russell_h): Figure out what happens when a source image specifies env variables.
        let mut cmd = match img_config {
            Some(ImageConfig {
                cmd: Some(ref cmd), ..
            }) => cmd.clone(),
            _ => vec![],
        };

        let mut entrypoint = match img_config {
            Some(ImageConfig {
                entrypoint: Some(ref entrypoint),
                ..
            }) => entrypoint.clone(),
            _ => vec![],
        };

        let mut odyn_command = vec![
            String::from(ENCLAVE_ODYN_PATH),
            String::from("--config-dir"),
            String::from("/etc/enclaver"),
            String::from("--"),
        ];

        odyn_command.append(&mut entrypoint);
        odyn_command.append(&mut cmd);

        debug!("appending layer to source image");
        let amended_image = self
            .image_manager
            .append_layer(
                &sources.app,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_CONFIG_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_ODYN_PATH),
                        source: FileSource::Image {
                            name: sources.odyn.to_string(),
                            path: ODYN_IMAGE_BINARY_PATH.into(),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .set_entrypoint(odyn_command),
            )
            .await?;

        Ok(amended_image)
    }

    /// Convert an EIF file into a release OCI image.
    ///
    /// TODO: this currently is incomplete; file permissions are wrong, the base image
    /// doesn't match our current requirements, and the exact intended format is still
    /// TBD.
    async fn package_eif(
        &self,
        eif_path: PathBuf,
        manifest_path: &str,
        sources: &ResolvedSources,
    ) -> Result<ImageRef> {
        info!("packaging EIF into release image");
        debug!("EIF file: {}", eif_path.to_string_lossy());

        let packaged_img = self
            .image_manager
            .append_layer(
                &sources.sleeve,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(EIF_FILE_NAME),
                        source: FileSource::Local { path: eif_path },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    }),
            )
            .await?;

        Ok(packaged_img)
    }

    /// Convert the referenced image to an EIF file, which will be deposited into `build_dir`
    /// using the file name `eif_name`.
    ///
    /// This operates by running nitro-cli directly with Docker socket access, allowing it to
    /// access host Docker images directly.
    async fn image_to_eif(
        &self,
        source_img: &ImageRef,
        nitro_cli_img: ImageRef,
        build_dir: &TempDir,
        eif_name: &str,
        sign: Option<SigningInfo>,
    ) -> Result<EIFInfo> {
        let build_dir_path = build_dir.path().to_str().unwrap();

        // There is currently no way to point nitro-cli to a local image ID; it insists
        // on attempting to pull the image (this may be a bug;. As a workaround, give our image a random
        // tag, and pass that.
        let img_tag = Uuid::new_v4().to_string();
        self.image_manager.tag_image(source_img, &img_tag).await?;

        debug!("tagged intermediate image: {}", img_tag);

        // Get the nitro-cli image name
        let nitro_cli_image_name = nitro_cli_img.name.as_ref()
            .unwrap_or(&nitro_cli_img.id);

        let mut docker_cmd = vec![
            "docker".to_string(),
            "run".to_string(),
            "--rm".to_string(),
            "-v".to_string(),
            format!("{}/.docker/config.json:/root/.docker/config.json", std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())),
            "-v".to_string(),
            "/var/run/docker.sock:/var/run/docker.sock".to_string(),
            "-v".to_string(),
            format!("{}:{}", build_dir_path, build_dir_path),
        ];

        if let Some(ref sign) = sign {
            let cert_path = sign.certificate.to_string_lossy();
            let key_path = sign.key.to_string_lossy();
            docker_cmd.push("-v".to_string());
            docker_cmd.push(format!("{}:{}", cert_path, cert_path));
            docker_cmd.push("-v".to_string());
            docker_cmd.push(format!("{}:{}", key_path, key_path));
        }

        docker_cmd.push(nitro_cli_image_name.clone());
        docker_cmd.push("build-enclave".to_string());
        docker_cmd.push("--docker-uri".to_string());
        docker_cmd.push(img_tag.clone());
        docker_cmd.push("--output-file".to_string());
        docker_cmd.push(format!("{}/{}", build_dir_path, eif_name));

        if let Some(sign) = sign {
            docker_cmd.push("--signing-certificate".to_string());
            docker_cmd.push(sign.certificate.to_string_lossy().to_string());
            docker_cmd.push("--private-key".to_string());
            docker_cmd.push(sign.key.to_string_lossy().to_string());
        }

        info!("🚀 Running nitro-cli directly with DinD access: {:?}", docker_cmd);

        let output = tokio::process::Command::new(&docker_cmd[0])
            .args(&docker_cmd[1..])
            .output()
            .await?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            let detected_nitro_cli_issue = KnownIssue::detect(&stderr);
            if let Some(issue) = detected_nitro_cli_issue {
                warn!(
                    "detected known nitro-cli issue:\n{}",
                    issue.helpful_message()
                );
            }

            for line in stderr.lines() {
                info!(target: "nitro-cli::build-eif", "{}", line);
            }
        }

        if !output.status.success() {
            bail!("non-zero exit code from nitro-cli: {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.is_empty() {
            bail!("No JSON output from nitro-cli");
        }

        let _ = self
            .docker
            .remove_image(&img_tag, None::<RemoveImageOptions>, None)
            .await?;

        Ok(serde_json::from_slice(stdout.as_bytes())?)
    }

    fn analyze_manifest(&self, manifest: &Manifest) {
        if manifest.ingress.is_none() {
            info!(
                "no ingress specified in manifest; there will be no way to connect to this enclave"
            );
        }

        if manifest.egress.is_none() {
            info!(
                "no egress specified in manifest; this enclave will have no outbound network access"
            );
        }
    }

    // External images are images whose tags we do not normally manage. In other words,
    // a user tags an image, then gives us that tag - and unless specifically instructed
    // otherwise we should not overwrite that tag.
    async fn resolve_external_source_image(&self, image_name: &str) -> Result<ImageRef> {
        if self.pull_tags {
            self.image_manager.pull_image(image_name).await
        } else {
            self.image_manager.find_or_pull(image_name).await
        }
    }

    async fn resolve_internal_source_image(
        &self,
        name_override: Option<&str>,
        default: &str,
    ) -> Result<ImageRef> {
        match name_override {
            Some(image_name) => {
                let mut img = self.image_manager.find_or_pull(image_name).await?;
                img.name = Some(image_name.to_string());
                Ok(img)
            }
            None => {
                let mut img = self.image_manager.pull_image(default).await?;
                img.name = Some(default.to_string());
                Ok(img)
            }
        }
    }

    async fn resolve_sources(&self, manifest: &Manifest, custom_nitro_cli: Option<&str>) -> Result<ResolvedSources> {
        let app = self
            .resolve_external_source_image(&manifest.sources.app)
            .await?;
        info!("using app image: {app}");

        let odyn = self
            .resolve_internal_source_image(manifest.sources.odyn.as_deref(), ODYN_IMAGE)
            .await?;
        if manifest.sources.odyn.is_none() {
            debug!("no supervisor image specified in manifest; using default: {odyn}");
        } else {
            info!("using supervisor image: {odyn}");
        }

        let release_base = self
            .resolve_internal_source_image(manifest.sources.sleeve.as_deref(), SLEEVE_IMAGE)
            .await?;
        if manifest.sources.sleeve.is_none() {
            debug!("no sleeve base image specified in manifest; using default: {release_base}");
        } else {
            info!("using sleeve base image: {release_base}");
        }

        let nitro_cli_default = custom_nitro_cli.unwrap_or(NITRO_CLI_IMAGE);
        let nitro_cli = self
            .resolve_internal_source_image(manifest.sources.nitro_cli.as_deref(), nitro_cli_default)
            .await?;
        info!("using nitro-cli image: {nitro_cli}");
        if custom_nitro_cli.is_some() {
            info!("⚠️  Using custom nitro-cli image: {}", custom_nitro_cli.unwrap());
        } else if manifest.sources.nitro_cli.is_some() {
            info!("📄 Using nitro-cli from manifest: {}", manifest.sources.nitro_cli.as_ref().unwrap());
        } else {
            info!("🏠 Using default nitro-cli image: {}", nitro_cli_default);
        }

        let sources = ResolvedSources {
            app,
            odyn,
            nitro_cli,
            sleeve: release_base,
        };

        Ok(sources)
    }
}

struct IntermediateBuildResult {
    manifest: Manifest,
    resolved_sources: ResolvedSources,
    build_dir: TempDir,
    eif_info: EIFInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSources {
    #[serde(rename = "App")]
    app: ImageRef,

    #[serde(rename = "Odyn")]
    odyn: ImageRef,

    #[serde(rename = "NitroCLI")]
    nitro_cli: ImageRef,

    #[serde(rename = "Sleeve")]
    sleeve: ImageRef,
}

/// Results from building EIFs for multiple architectures.
struct MultiArchEIFResults {
    amd64_eif_info: EIFInfo,
    amd64_eif_path: PathBuf,
    _arm64_eif_info: EIFInfo,
    arm64_eif_path: PathBuf,
    _amd64_build_dir: TempDir,
    _arm64_build_dir: TempDir,
}

impl EnclaveArtifactBuilder {
    pub async fn push_image(&self, image: &ImageRef) -> Result<()> {
        let image_name = image.name.as_ref()
            .ok_or_else(|| anyhow!("Image has no name tag to push"))?;

        info!("🚀 Pushing image: {}", image_name);

        let output = tokio::process::Command::new("docker")
            .args(["push", image_name])
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            info!("📤 {}", stdout.trim());
            info!("✅ Successfully pushed image: {}", image_name);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("❌ Push error: {}", stderr);
            Err(anyhow!("Failed to push image: {}", stderr))
        }
    }
}
