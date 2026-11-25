#!/usr/bin/env bash
set -euo pipefail

# Build linux/amd64 image natively on the utop x86_64 node and push to Docker Hub
# (plus GitHub Container Registry `ghcr.io` when GHCR_PUSH=1 or GHCR_TOKEN/existing login is configured).
APP_VERSION="${APP_VERSION:-1.4.2}"
DOCKERHUB_REPO="${DOCKERHUB_REPO:-utoptop/matrix-proxy}"
IMAGE="${IMAGE:-${DOCKERHUB_REPO}:1.0}"
EXTRA_TAGS="${EXTRA_TAGS:-${DOCKERHUB_REPO}:latest ${DOCKERHUB_REPO}:${APP_VERSION}}"
GHCR_REPO="${GHCR_REPO:-ghcr.io/utoptop/matrix-proxy}"
GHCR_USER="${GHCR_USER:-utoptop}"
GHCR_TOKEN="${GHCR_TOKEN:-}"
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
for tag in ${EXTRA_TAGS}; do
  docker tag \"${IMAGE}\" \"\${tag}\"
done
'"

echo "==> Pushing Docker Hub tags (${IMAGE} ${EXTRA_TAGS})"
ssh "${REMOTE_HOST}" "bash -euo pipefail -c '
if ss -tln | grep -q \"127.0.0.1:10809\"; then
  export HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809
fi
for tag in ${IMAGE} ${EXTRA_TAGS}; do
  docker push \"\${tag}\"
done
echo \"==> Verifying pushed Docker Hub manifest\"
docker buildx imagetools inspect \"${IMAGE}\"
'"

if [[ -n "${GHCR_TOKEN}" ]]; then
  echo "==> Pushing GHCR tags (${GHCR_REPO}:1.0, :latest, :${APP_VERSION})"
  printf '%s' "${GHCR_TOKEN}" | ssh "${REMOTE_HOST}" "bash -euo pipefail -c '
    if ss -tln | grep -q \"127.0.0.1:10809\"; then
      export HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809
    fi
    docker login ghcr.io -u \"${GHCR_USER}\" --password-stdin
    trap \"docker logout ghcr.io >/dev/null 2>&1 || true\" EXIT
    for suffix in 1.0 latest ${APP_VERSION}; do
      docker tag \"${IMAGE}\" \"${GHCR_REPO}:\${suffix}\"
      docker push \"${GHCR_REPO}:\${suffix}\"
    done
    docker buildx imagetools inspect \"${GHCR_REPO}:latest\"
  '"
fi

echo "==> Cleaning up remote build directory ${REMOTE_DIR}"
ssh "${REMOTE_HOST}" "rm -rf '${REMOTE_DIR}'"

echo "==> Done: ${IMAGE}"
