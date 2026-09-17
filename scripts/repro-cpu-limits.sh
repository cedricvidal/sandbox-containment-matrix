#!/usr/bin/env bash
# Reproduces docs/findings.md §12 — MXC has no CPU/memory limit, and the
# resource-limits probe correctly reports a cgroup cap across the whole range.
#
# Expected: uncapped -> ESCAPED; every --cpus value -> CONTAINED, with the
# reported allowance tracking the configured quota.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# Probe runs legitimately exit non-zero; do not let that abort the comparison.
set +e

build_image

probe_line() { grep -A2 'resource-limits' | tail -1 | sed 's/^ *//'; }

echo
echo "MXC resource containment vs cgroup caps"
hr
echo "== no cgroup limits =="
mxc_run -- pnpm probes 2>&1 | probe_line

for c in 0.5 1 2 4; do
  echo "== --cpus $c =="
  mxc_run --cpus "$c" -- pnpm probes 2>&1 | probe_line
done

echo "== --memory 256m (memory cap alone) =="
mxc_run --memory 256m --memory-swap 256m -- pnpm probes 2>&1 | probe_line
hr
echo "Conclusion: MXC expresses no CPU/memory limit; the cgroup does the work."
