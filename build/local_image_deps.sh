#!/bin/bash

set -eu

# Parse command line arguments
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build multi-architecture Docker images for Enclaver development"
    echo ""
    echo "Options:"
    echo "  -r, --registry HOSTNAME    Docker registry hostname (default: none)"
    echo "  -p, --push                 Push images to registry (requires --registry)"
    echo "  -n, --nitro-cli-image IMG  Nitro CLI base Docker image (default: public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest)"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                          # Build locally without pushing"
    echo "  $0 --registry localhost:5000 --push    # Build and push to local registry"
    echo "  $0 -r myregistry.com -p                # Build and push to custom registry"
    echo "  $0 -n myregistry.com/nitro-cli:v1.0    # Use custom nitro-cli image"
}

REGISTRY=""
PUSH_FLAG=""
NITRO_CLI_IMAGE="public.ecr.aws/s2t1d4c6/enclaver-io/nitro-cli:latest"

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_FLAG="--push"
            shift
            ;;
        -n|--nitro-cli-image)
            NITRO_CLI_IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate arguments
if [ -n "$PUSH_FLAG" ] && [ -z "$REGISTRY" ]; then
    echo "Error: --push requires --registry to be specified"
    echo ""
    usage
    exit 1
fi

# Define target architectures for multi-arch build
declare -a docker_platforms=("linux/amd64" "linux/arm64")

echo "Checking prerequisites..."

if ! docker buildx version >/dev/null 2>&1; then
    echo "Error: docker buildx is not available. Please install Docker 19.03+ with buildx support."
    exit 1
fi

# Validate current active builder supports multi-platform builds
echo "Validating current buildx builder..."

current_builder=$(docker buildx ls 2>&1 | awk '/\*/ {gsub(/\*/, "", $1); print $1; exit}')
if [ -z "$current_builder" ]; then
    echo "Error: No active buildx builder found"
    echo ""
    echo "Available builders:"
    docker buildx ls 2>&1
    exit 1
fi

echo "Active builder: $current_builder"

builder_info=$(docker buildx inspect "$current_builder" --bootstrap 2>&1)
if [ $? -ne 0 ]; then
    echo "Error: Failed to inspect builder '$current_builder'"
    echo "$builder_info"
    exit 1
fi

supported_platforms=$(echo "$builder_info" | grep "Platforms:" | sed 's/Platforms://' | tr -d ' ')
if [ -z "$supported_platforms" ]; then
    echo "Error: Unable to determine supported platforms for builder '$current_builder'"
    echo "Builder info:"
    echo "$builder_info"
    exit 1
fi

echo "Supported platforms: $supported_platforms"

if [[ ! "$supported_platforms" =~ "linux/amd64" ]] || [[ ! "$supported_platforms" =~ "linux/arm64" ]]; then
    echo ""
    echo "Error: Active builder '$current_builder' does not support both linux/amd64 and linux/arm64"
    echo "Required platforms: linux/amd64, linux/arm64"
    echo "Supported platforms: $supported_platforms"
    echo ""
    echo "To fix this, create a multi-platform builder:"
    echo "  docker buildx create --name multiarch-builder --driver docker-container --bootstrap --use"
    echo ""
    echo "Or switch to an existing multi-platform builder:"
    echo "  docker buildx use <builder-name>"
    echo ""
    echo "Available builders:"
    docker buildx ls 2>&1
    exit 1
fi

echo "✓ Builder '$current_builder' supports required platforms"

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
enclaver_dir="$project_root/enclaver"

# Configure image tags and build arguments
if [ -n "$REGISTRY" ]; then
    odyn_tag="${REGISTRY}/odyn-dev:latest"
    wrapper_base_tag="${REGISTRY}/enclaver-wrapper-base:latest"
else
    odyn_tag="odyn-dev:latest"
    wrapper_base_tag="enclaver-wrapper-base:latest"
fi

# Prepare platform arguments
platforms_arg=$(IFS=,; echo "${docker_platforms[*]}")

# Determine output strategy
if [ -n "$PUSH_FLAG" ]; then
    output_flag="$PUSH_FLAG"
    build_platforms="$platforms_arg"
else
    echo ""
    echo "Note: Multi-arch images cannot be loaded directly to local Docker"
    echo "Building for current platform only to enable local loading"
    
    current_arch=$(uname -m)
    case "$current_arch" in
        x86_64) build_platforms="linux/amd64" ;;
        aarch64|arm64) build_platforms="linux/arm64" ;;
        *)
            echo "Error: Unsupported architecture: $current_arch"
            exit 1
            ;;
    esac
    
    output_flag="--load"
    echo "Building for: $build_platforms"
fi

# Build images
echo ""
echo "Building odyn-dev image for platforms: $build_platforms"
docker buildx build \
    --platform "$build_platforms" \
    -f "$project_root/build/dockerfiles/odyn-dev.dockerfile" \
    -t ${odyn_tag} \
    ${output_flag} \
    "$enclaver_dir"

echo ""
echo "Building enclaver-wrapper-base image for platforms: $build_platforms"
docker buildx build \
    --platform "$build_platforms" \
    --build-arg NITRO_CLI_IMAGE="${NITRO_CLI_IMAGE}" \
    -f "$project_root/build/dockerfiles/runtimebase-dev.dockerfile" \
    -t ${wrapper_base_tag} \
    ${output_flag} \
    "$enclaver_dir"

echo ""
if [ -n "$PUSH_FLAG" ]; then
    echo "✓ Multi-arch images built and pushed:"
else
    echo "✓ Images built locally:"
fi
echo "  - ${odyn_tag} ($build_platforms)"
echo "  - ${wrapper_base_tag} ($build_platforms)"
echo ""
echo "To use dev images, merge the following into enclaver.yaml:"
echo ""
echo "sources:"
echo "   supervisor: \"${odyn_tag}\""
echo "   wrapper: \"${wrapper_base_tag}\""
