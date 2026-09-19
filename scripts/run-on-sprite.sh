#!/usr/bin/env bash
# Evaluate Fly.io Sprites *as a sandbox* — provision one sprite, probe what it
# contains, tear it down. This is the Sprites row of the containment matrix
# (docs/sprites.md); it does NOT run MXC inside the sprite.
#
# Each probe prints its command and the raw output under an hr() banner so the
# result can be pasted verbatim into docs/findings.md. Probes may legitimately
# exit non-zero (a blocked connection is a *pass*), so enforcement is judged on
# observed output, never on a child exit code — the same rule the MXC suites use.
#
# Auth: uses the already-configured `sprite` CLI if it is logged in. Otherwise it
# reads a token from $SPRITE_TOKEN, or from 1Password
# ("op://Personal/Fly.io Sprites API Credentials/token"), writes it to a mode-600
# file under a scratch dir, feeds it to `sprite auth setup --token`, and deletes
# that file on exit.
#
# Usage: bash scripts/run-on-sprite.sh
set -uo pipefail

SPRITE_BIN="${SPRITE_BIN:-sprite}"
SPRITE_NAME="${SPRITE_NAME:-mxc-eval-$(date +%s)}"
ALLOW_DOMAIN="${ALLOW_DOMAIN:-example.com}"    # the one domain the allowlist permits
DENY_DOMAIN="${DENY_DOMAIN:-github.com}"       # a domain that must be refused
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sprite-eval.XXXXXX")"
TOKEN_FILE=""

hr() { printf '%s\n' "------------------------------------------------------------"; }
banner() { echo; hr; echo "## $*"; hr; }
have() { command -v "$1" >/dev/null 2>&1; }

# Run a command inside the sprite, non-interactively, merging stderr.
sx() { "$SPRITE_BIN" exec -s "$SPRITE_NAME" --no-stdin -- "$@" 2>&1; }
# Run a shell snippet inside the sprite.
sxsh() { sx sh -c "$1"; }
# Raw authenticated API call: sapi <path> [curl args...]
sapi() { "$SPRITE_BIN" api "$1" -- -s "${@:2}" 2>/dev/null; }

cleanup() {
  banner "TEARDOWN"
  "$SPRITE_BIN" destroy "$SPRITE_NAME" --force 2>&1 | tail -3 || true
  [[ -n "$TOKEN_FILE" && -f "$TOKEN_FILE" ]] && rm -f "$TOKEN_FILE"
  rm -rf "$SCRATCH"
  echo "cleaned up scratch dir and token file"
}

authenticate() {
  if "$SPRITE_BIN" org list >/dev/null 2>&1; then
    echo "==> sprite CLI already authenticated"
    return
  fi
  local token="${SPRITE_TOKEN:-}"
  if [[ -z "$token" ]] && have op; then
    echo "==> reading token from 1Password"
    umask 077
    TOKEN_FILE="$SCRATCH/sprite-token"
    op read "op://Personal/Fly.io Sprites API Credentials/token" > "$TOKEN_FILE" 2>/dev/null \
      && token="$(cat "$TOKEN_FILE")"
  fi
  [[ -z "$token" ]] && { echo "no auth: set \$SPRITE_TOKEN or configure 1Password / 'sprite login'"; exit 2; }
  "$SPRITE_BIN" auth setup --token "$token" >/dev/null
}

main() {
  have "$SPRITE_BIN" || { echo "sprite CLI not found (see https://sprites.dev)"; exit 2; }
  authenticate
  trap cleanup EXIT

  banner "PROVISION  ($SPRITE_NAME)"
  "$SPRITE_BIN" create --skip-console "$SPRITE_NAME" 2>&1 | grep -iE 'created|error' | head -3

  banner "BASELINE / IDENTITY"
  echo "\$ uname -a";                 sx uname -a
  echo "\$ whoami; id";               sxsh 'whoami; id'
  echo "\$ head -1 /etc/os-release";  sxsh 'grep PRETTY_NAME /etc/os-release'
  echo "\$ readlink /proc/1/exe; cat /proc/1/comm"; sxsh 'cat /proc/1/comm'
  echo "\$ nproc; MemTotal";          sxsh 'echo "nproc=$(nproc)"; grep MemTotal /proc/meminfo'
  echo "\$ cgroup cpu.max/memory.max/pids.max"; \
    sxsh 'for f in cpu.max memory.max pids.max; do printf "%s: " "$f"; cat /sys/fs/cgroup/$f; done'
  echo "\$ /proc/self/status caps + seccomp"; \
    sxsh 'grep -E "^Cap(Eff|Bnd)|Seccomp" /proc/self/status'

  banner "PRIVILEGE  (default user vs sudo)"
  echo "\$ sudo -n whoami";           sxsh 'sudo -n whoami 2>&1 || echo "(sudo unavailable rc=$?)"'

  banner "VM ISOLATION  (PID namespace + host/metadata reachability)"
  echo "\$ ps -e | wc -l ; ps -e (top)"; sxsh 'ps -e -o pid,comm | head -8; echo "total: $(ps -e | wc -l)"'
  echo "\$ curl 169.254.169.254 (cloud metadata)"; \
    sxsh 'curl -sS -o /dev/null -w "metadata HTTP %{http_code}\n" --max-time 8 http://169.254.169.254/ 2>&1 || echo "blocked rc=$?"'
  echo "\$ curl 10.0.0.1 (RFC1918)"; \
    sxsh 'curl -sS -o /dev/null -w "10.0.0.1 HTTP %{http_code}\n" --max-time 6 http://10.0.0.1/ 2>&1 || echo "blocked rc=$?"'

  banner "NETWORK EGRESS — DEFAULT (no policy)"
  echo "\$ curl https://$ALLOW_DOMAIN"; \
    sxsh "curl -sS -o /dev/null -w '$ALLOW_DOMAIN HTTP %{http_code}\n' --max-time 15 https://$ALLOW_DOMAIN 2>&1 || echo rc=\$?"
  echo "\$ curl https://$DENY_DOMAIN"; \
    sxsh "curl -sS -o /dev/null -w '$DENY_DOMAIN HTTP %{http_code}\n' --max-time 15 https://$DENY_DOMAIN 2>&1 || echo rc=\$?"
  echo "\$ curl https://1.1.1.1 (raw public IP)"; \
    sxsh 'curl -sS -o /dev/null -w "1.1.1.1 HTTP %{http_code}\n" --max-time 10 https://1.1.1.1 2>&1 || echo rc=$?'

  banner "NETWORK EGRESS — ALLOWLIST (allow $ALLOW_DOMAIN, deny *)"
  echo "\$ POST /v1/sprites/$SPRITE_NAME/policy/network"
  sapi "/v1/sprites/$SPRITE_NAME/policy/network" -X POST -H 'Content-Type: application/json' \
    -d "{\"rules\":[{\"domain\":\"$ALLOW_DOMAIN\",\"action\":\"allow\"},{\"domain\":\"*\",\"action\":\"deny\"}]}" \
    -w 'set-policy HTTP=%{http_code}\n' | tail -1
  echo "\$ GET active policy"; sapi "/v1/sprites/$SPRITE_NAME/policy/network"; echo
  sleep 2
  echo "\$ dig $ALLOW_DOMAIN (allowed) vs $DENY_DOMAIN (denied) — DNS status"; \
    sxsh "echo '[$ALLOW_DOMAIN]'; dig $ALLOW_DOMAIN | grep -i 'status:'; echo '[$DENY_DOMAIN]'; dig $DENY_DOMAIN | grep -i 'status:'"
  echo "\$ curl https://$ALLOW_DOMAIN (allowed)"; \
    sxsh "curl -sS -o /dev/null -w '$ALLOW_DOMAIN HTTP %{http_code}\n' --max-time 12 https://$ALLOW_DOMAIN 2>&1 || echo blocked rc=\$?"
  echo "\$ curl https://$DENY_DOMAIN (denied)"; \
    sxsh "curl -sS -o /dev/null -w '$DENY_DOMAIN HTTP %{http_code}\n' --max-time 12 https://$DENY_DOMAIN 2>&1 || echo blocked rc=\$?"
  echo "\$ curl https://1.1.1.1 (raw IP, now unresolved-from-allowed)"; \
    sxsh 'curl -sS -o /dev/null -w "1.1.1.1 HTTP %{http_code}\n" --max-time 8 https://1.1.1.1 2>&1 || echo blocked rc=$?'
  echo "\$ reset policy to unrestricted"
  sapi "/v1/sprites/$SPRITE_NAME/policy/network" -X POST -H 'Content-Type: application/json' \
    -d '{"rules":[]}' -w 'reset HTTP=%{http_code}\n' | tail -1

  banner "CHECKPOINT / ROLLBACK"
  echo "\$ write canary, checkpoint, mutate, restore, re-read"
  sxsh 'echo ORIGINAL-CONTENT > /home/sprite/canary.txt; cat /home/sprite/canary.txt'
  "$SPRITE_BIN" checkpoint create -s "$SPRITE_NAME" 2>&1 | grep -iE 'created|restore with' | head -2
  local cp; cp="$("$SPRITE_BIN" checkpoint list -s "$SPRITE_NAME" 2>&1 | awk '/^v[0-9]/{print $1; exit}')"
  echo "restoring checkpoint: ${cp:-v1}"
  sxsh 'echo MUTATED > /home/sprite/canary.txt; echo x > /home/sprite/new-file.txt'
  "$SPRITE_BIN" restore "${cp:-v1}" -s "$SPRITE_NAME" 2>&1 | grep -iE 'restored' | head -1
  echo "\$ after restore:"; \
    sxsh 'echo "canary.txt: $(cat /home/sprite/canary.txt 2>&1)"; echo "new-file.txt: $(cat /home/sprite/new-file.txt 2>&1)"'

  banner "RESOURCE LIMITS  (bounded CPU grab)"
  echo "\$ spin one busy loop per visible core for ~3s"
  sxsh 'N=$(nproc); END=$(( $(date +%s) + 3 ));
        for i in $(seq 1 $N); do ( while [ $(date +%s) -lt $END ]; do :; done ) & done; wait 2>/dev/null;
        echo "ran $N busy loops; cgroup cpu.max=$(cat /sys/fs/cgroup/cpu.max) (\"max\" = uncapped within the VM)"'

  echo
  echo "=== done — see docs/sprites.md for the interpreted matrix row ==="
}

main "$@"
