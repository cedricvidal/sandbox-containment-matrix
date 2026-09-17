#!/usr/bin/env bash
# Shared helpers for the reproduction scripts.
set -euo pipefail

IMAGE="${IMAGE:-sandbox-mxc-sdk-typescript:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The security options MXC's bubblewrap backend needs (docs/findings.md §13).
MXC_OPTS=(--security-opt label=disable --security-opt unmask=ALL)

# npmjs.org is unreachable from some corporate build networks; inherit whatever
# registry npm is configured with so the build works either way.
npm_registry() {
  npm config get registry 2>/dev/null | grep -E '^https?://' || echo 'https://registry.npmjs.org/'
}

require_docker() {
  command -v docker >/dev/null 2>&1 || { echo "docker not found — these scripts need a Linux container runtime"; exit 2; }
  docker info >/dev/null 2>&1 || { echo "docker daemon not reachable"; exit 2; }
}

build_image() {
  require_docker
  echo "==> building $IMAGE (registry: $(npm_registry))"
  docker build --quiet \
    --build-arg "NPM_REGISTRY=$(npm_registry)" \
    -t "$IMAGE" "$HERE" >/dev/null
  echo "==> built"
}

# Run a command in the image with the MXC security options applied.
# Usage: mxc_run [extra docker args...] -- <command...>
mxc_run() {
  local docker_args=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do docker_args+=("$1"); shift; done
  shift || true
  docker run --rm "${MXC_OPTS[@]}" "${docker_args[@]}" "$IMAGE" "$@"
}

hr() { printf '%s\n' "------------------------------------------------------------"; }
