#!/usr/bin/env bash
# Runs every reproduction script, plus both test suites, in order.
# Takes several minutes: it builds images and runs many timed measurements.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

build_image

run_step() {
  echo
  echo "############################################################"
  echo "# $1"
  echo "############################################################"
  shift
  "$@"
}

run_step "Policy conformance suite (docs/README.md)" \
  mxc_run -- pnpm dev
run_step "Adversarial escape probes (docs/threat-model.md)" \
  mxc_run -- pnpm probes
run_step "Container hardening bisect (findings §13)" \
  "$(dirname "${BASH_SOURCE[0]}")/repro-container-bisect.sh"
run_step "CPU/memory limits (findings §12)" \
  "$(dirname "${BASH_SOURCE[0]}")/repro-cpu-limits.sh"
run_step "Trusted-side CPU protection (findings §16)" \
  "$(dirname "${BASH_SOURCE[0]}")/repro-trusted-side.sh"

echo
echo "############################################################"
echo "# Done. glibc/Alpine check is separate (builds extra images):"
echo "#   ./scripts/repro-glibc.sh"
echo "############################################################"
