#!/usr/bin/env bash
set -euo pipefail

# Build linux/amd64 image natively on the utop x86_64 node and push to Docker Hub.
IMAGE="${IMAGE:-utoptop/matrix-proxy:1.0}"
REMOTE_HOST="${REMOTE_HOST:-utop}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/matrix-proxy-build}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Syncing source tree to ${REMOTE_HOST}:${REMOTE_DIR}"
ssh "${REMOTE_HOST}" "rm -rf '${REMOTE_DIR}' && mkdir -p '${REMOTE_DIR}'"
COPYFILE_DISABLE=1 tar --no-xattrs -C "${PROJECT_DIR}" \
    --exclude='./target' \
    --exclude='./.git' \
    --exclude='./.DS_Store' \
    --exclude='./.env' \
    --exclude='./config.toml' \
    -czf - . | ssh "${REMOTE_HOST}" "tar -C '${REMOTE_DIR}' -xzf -"

echo "==> Building linux/amd64 image ${IMAGE} on ${REMOTE_HOST}"
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
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \"\${BUILD_PROXY_ARGS[@]}\" -t \"${IMAGE}\" .
'"

echo "==> Pushing ${IMAGE}"
ssh "${REMOTE_HOST}" "bash -euo pipefail -c '
if ss -tln | grep -q \"127.0.0.1:10809\"; then
  export HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809
fi
docker push \"${IMAGE}\"
echo \"==> Verifying pushed manifest\"
docker buildx imagetools inspect \"${IMAGE}\"
'"

echo "==> Cleaning up remote build directory ${REMOTE_DIR}"
ssh "${REMOTE_HOST}" "rm -rf '${REMOTE_DIR}'"

echo "==> Done: ${IMAGE}"
