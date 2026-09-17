#!/usr/bin/env bash
# Reproduces docs/findings.md §14 — the SDK ships a prebuilt glibc runner, so
# Alpine/musl fails even with a compatibility shim.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_docker

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf '{"name":"t","version":"1.0.0","dependencies":{"@microsoft/mxc-sdk":"^0.8.0"}}' > "$WORK/package.json"
cat > "$WORK/probe.mjs" <<'JS'
import { getPlatformSupport } from '@microsoft/mxc-sdk';
console.log('getPlatformSupport():', JSON.stringify(getPlatformSupport()));
JS

for shim in libc6-compat gcompat; do
  echo
  echo "==> node:22-alpine with $shim"
  cat > "$WORK/Dockerfile" <<DOCKER
FROM node:22-alpine
RUN apk add --no-cache bubblewrap $shim
WORKDIR /app
COPY package.json ./
RUN npm config set registry $(npm_registry) && npm install --omit=dev
COPY probe.mjs ./
DOCKER
  docker build --quiet -t "mxc-alpine-$shim" "$WORK" >/dev/null
  echo "-- SDK probe (note it still claims support):"
  docker run --rm "${MXC_OPTS[@]}" "mxc-alpine-$shim" node probe.mjs 2>&1 | tail -2
  echo "-- dynamic linker check on the shipped runner:"
  docker run --rm "mxc-alpine-$shim" \
    sh -c 'ldd node_modules/@microsoft/mxc-sdk/bin/*/lxc-exec 2>&1 | grep -i "symbol not found" || echo "(relocated cleanly)"' | tail -2
  docker rmi -f "mxc-alpine-$shim" >/dev/null 2>&1 || true
done

echo
hr
echo "Conclusion: use a glibc base image (this experiment uses bookworm-slim)."
