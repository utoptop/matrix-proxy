#!/usr/bin/env bash
set -euo pipefail

# Native multi-architecture Docker build & publish (zero QEMU emulation):
#   - linux/arm64 built natively on this Apple Silicon Mac (throttled via CARGO_BUILD_JOBS=4)
#   - linux/amd64 built natively on the x86_64 `utop` node
#   - Merged into a unified OCI multi-arch manifest index on Docker Hub
#     (and optionally GHCR when GHCR_TOKEN is supplied).

APP_VERSION="${APP_VERSION:-1.4.3}"
DOCKERHUB_REPO="${DOCKERHUB_REPO:-utoptop/matrix-proxy}"
PUBLISH_TAGS="${PUBLISH_TAGS:-1.0 latest ${APP_VERSION}}"
LOCAL_CARGO_JOBS="${LOCAL_CARGO_JOBS:-4}"
REMOTE_HOST="${REMOTE_HOST:-utop}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/matrix-proxy-build}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARM_TAG="${DOCKERHUB_REPO}:${APP_VERSION}-arm64"
AMD_TAG="${DOCKERHUB_REPO}:${APP_VERSION}-amd64"

echo "==> [1/4] Building native linux/arm64 image locally (${ARM_TAG}, CARGO_BUILD_JOBS=${LOCAL_CARGO_JOBS})"
(
  cd "${PROJECT_DIR}"
  DOCKER_BUILDKIT=1 docker build \
    --platform linux/arm64 \
    --build-arg "CARGO_BUILD_JOBS=${LOCAL_CARGO_JOBS}" \
    -t "${ARM_TAG}" \
    .
  docker push "${ARM_TAG}"
)

echo "==> [2/4] Syncing source tree & building native linux/amd64 image on ${REMOTE_HOST} (${AMD_TAG})"
ssh "${REMOTE_HOST}" "rm -rf '${REMOTE_DIR}' && mkdir -p '${REMOTE_DIR}'"
COPYFILE_DISABLE=1 tar --no-xattrs -C "${PROJECT_DIR}" \
    --exclude='./target' \
    --exclude='./.git' \
    --exclude='./.DS_Store' \
    --exclude='./.env' \
    --exclude='./config.toml' \
    -czf - . | ssh "${REMOTE_HOST}" "tar -C '${REMOTE_DIR}' -xzf -"

ssh "${REMOTE_HOST}" "bash -euo pipefail -c '
cd \"${REMOTE_DIR}\"
PROXY_URL=\"${REMOTE_PROXY:-}\"
if [[ -z \"\${PROXY_URL}\" ]] && ss -tln | grep -q \"127.0.0.1:10809\"; then
  PROXY_URL=\"http://127.0.0.1:10809\"
fi
BUILD_PROXY_ARGS=()
if [[ -n \"\${PROXY_URL}\" ]]; then
  export HTTP_PROXY=\"\${PROXY_URL}\" HTTPS_PROXY=\"\${PROXY_URL}\" http_proxy=\"\${PROXY_URL}\" https_proxy=\"\${PROXY_URL}\"
  export NO_PROXY=\"localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12\"
  BUILD_PROXY_ARGS=(--network=host --build-arg \"HTTP_PROXY=\${PROXY_URL}\" --build-arg \"HTTPS_PROXY=\${PROXY_URL}\" --build-arg \"NO_PROXY=\${NO_PROXY}\")
fi
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \"\${BUILD_PROXY_ARGS[@]}\" -t \"${AMD_TAG}\" .
docker push \"${AMD_TAG}\"
rm -rf \"${REMOTE_DIR}\"
'"

echo "==> [3/4] Creating unified multi-arch manifest index (linux/amd64 + linux/arm64)"
TAG_ARGS=()
for t in ${PUBLISH_TAGS}; do
  TAG_ARGS+=(-t "${DOCKERHUB_REPO}:${t}")
done
docker buildx imagetools create "${TAG_ARGS[@]}" "${AMD_TAG}" "${ARM_TAG}"

echo "==> [4/4] Verifying multi-arch manifest on Docker Hub"
docker buildx imagetools inspect "${DOCKERHUB_REPO}:1.0"
echo "==> Done: ${DOCKERHUB_REPO} (${PUBLISH_TAGS}) [linux/amd64 + linux/arm64]"
