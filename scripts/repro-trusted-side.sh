#!/usr/bin/env bash
# Reproduces docs/findings.md §16 — the trusted side must keep breathing while
# the untrusted side saturates the CPU.
#
# Compares three ways of bounding CPU:
#   1. no bound            — trusted fine, but untrusted is unbounded
#   2. cpus quota (shared) — untrusted bounded, trusted SUFFOCATES
#   3. cpuset + reserved   — untrusted bounded AND trusted unaffected  <-- goal
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# Probe runs legitimately exit non-zero; do not let that abort the comparison.
set +e

build_image

# Pull the summary table plus the slowdown line out of `pnpm latency`.
summary() { sed -n '/=== Summary/,/slowdown/p' | sed '1d;$d' | sed 's/^/  /'; }

echo
echo "Trusted-side responsiveness while a sandboxed hog saturates every core"
echo "The 'hog + affinity' row is the one that matters: it is the configuration"
echo "where the sandbox is confined and a CPU is reserved for the orchestrator."
hr

echo
echo "### 1. No CPU bound — untrusted unbounded"
mxc_run -- pnpm latency 2>&1 | summary

echo
echo "### 2. --cpus 1 — a quota SHARED by both sides (the wrong shape)"
mxc_run --cpus 1 -- pnpm latency 2>&1 | summary

echo
echo "### 3. --cpuset-cpus 0-3 + reserved CPU 0 (the working shape)"
mxc_run --cpuset-cpus 0-3 -- pnpm latency 2>&1 | summary

hr
cat <<'NOTE'
Reading the tables:
  'served'  — percentage of the trusted side's 20ms service ticks that ran.
  'stretch' — how much longer a fixed 5ms slice of trusted work took.

Expected shape of the result:
  Case 2 collapses the trusted side (roughly 40% of ticks served) because a
  cgroup cpu quota throttles the whole container once spent — nice and CPU
  affinity cannot rescue it.
  Case 3 keeps the trusted side at its idle speed on the 'hog + affinity' row
  while the sandbox still saturates only CPUs 1-3.
NOTE
