#!/usr/bin/env bash
# Reproduces docs/findings.md §13 — which container restrictions block
# bubblewrap, and which privileges do NOT help.
#
# Expected: only `label=disable` + `unmask=ALL` (or --privileged) succeed.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

build_image

SMOKE='bwrap --unshare-user --unshare-pid --dev /dev --proc /proc --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /bin /bin /bin/echo ok'

echo
echo "Bisecting container options against a minimal bwrap smoke test"
hr
printf '%-62s %s\n' "DOCKER OPTIONS" "RESULT"
hr

# A failing bwrap is the expected result for most rows, so failures must not
# abort the script under `set -e`.
try() {
  local label="$1"; shift
  local out
  out="$(docker run --rm "$@" "$IMAGE" sh -c "$SMOKE" 2>&1 | tail -1 || true)"
  printf '%-62s %s\n' "$label" "${out:-<no output>}"
}

try "(none — stock hardening)"
try "--cap-add SYS_ADMIN"                       --cap-add SYS_ADMIN
try "--cap-add ALL"                             --cap-add ALL
try "--security-opt seccomp=unconfined"         --security-opt seccomp=unconfined
try "--security-opt apparmor=unconfined"        --security-opt apparmor=unconfined
try "--user 1000"                               --user 1000
try "--security-opt label=disable"              --security-opt label=disable
try "--security-opt unmask=ALL"                 --security-opt unmask=ALL
try "label=disable + unmask=ALL  <-- minimum"   --security-opt label=disable --security-opt unmask=ALL
try "label=disable + unmask=ALL + --user 1000"  --security-opt label=disable --security-opt unmask=ALL --user 1000
try "--privileged"                              --privileged
hr
echo "Conclusion: it is a mount-visibility problem, not a capability or"
echo "syscall-filter one — and it works fine as a non-root user."
