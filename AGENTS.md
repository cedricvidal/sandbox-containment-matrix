# AGENTS.md — working in this repo

This repo is a **sandbox containment matrix**: it empirically measures what real
sandbox systems for untrusted code actually contain, on real hosts, with
verbatim evidence. Each system is a row. See [README.md](./README.md) for the
cross-system comparison and [docs/](./docs) for the detail.

## What lives where

| Path | What it is |
|------|-----------|
| `src/` | the MXC TypeScript suites (see below) |
| `scripts/` | bash reproduction drivers; `lib.sh` is shared Docker helpers |
| `scripts/run-on-sprite.sh` | the **Fly.io Sprites** driver (provision → probe → destroy) |
| `k8s/` | AKS manifests — applied via **GitOps**, not `kubectl apply` (see below) |
| `docs/` | findings log, threat model, and one write-up per system |
| `docs/findings.md` | the running, numbered evidence log — the source of truth |
| `docker-compose.yml` | five profiles for the Bubblewrap row (minimal → privileged) |

## Running the suites

**MXC (Seatbelt on macOS / Bubblewrap in a container)** — needs Node ≥ 18 + pnpm:

```bash
pnpm install
pnpm probe    # what backends/paths does this host expose?
pnpm dev      # policy conformance: does the sandbox do what the policy says?
pnpm probes   # adversarial: does the boundary hold when code attacks it?
pnpm latency  # is the trusted side starved under sandboxed CPU load?
pnpm typecheck
```

In a Linux container (Bubblewrap): `docker compose run --rm mxc pnpm dev`. The
security options bwrap needs (`label=disable`, `unmask=ALL`) live in `lib.sh` and
the compose file — don't drop them.

**Fly.io Sprites** — needs the `sprite` CLI (https://sprites.dev), authenticated:

```bash
bash scripts/run-on-sprite.sh   # creates one sprite, probes it, always destroys it
```

Auth order: an already-logged-in CLI → `$SPRITE_TOKEN` → 1Password
(`op://Personal/Fly.io Sprites API Credentials/token`). The script tears the
sprite down on exit (`trap`), so a failed run never leaves one billing. Sprites
bill per CPU/GB-hour — keep runs short and don't leave sprites alive.

**AKS** — the cluster is FluxCD-reconciled with `prune: true`; `kubectl apply` is
drift and gets reverted. Go through the GitOps repo. See
[docs/kubernetes.md](./docs/kubernetes.md) and [docs/aks-enablement.md](./docs/aks-enablement.md).

## Conventions that keep the log trustworthy

Findings are written down **as they are discovered**, in `docs/findings.md`, each
as `## N. claim` → **What happened / Evidence / Takeaway**. The rules
(from [docs/README.md](./docs/README.md)):

1. **Paste real output.** No paraphrased or reconstructed console text.
2. **Say which system and host.** Backends disagree; an unqualified claim is
   usually wrong somewhere.
3. **Record negative results too.** "X does not work" saves the next person time.
4. **Distinguish _unsupported_ from _contained_.** A control the sandbox cannot
   express is not a control that held — tally them separately.
5. **Correct in place, and say so.** The correction is part of the record.

Assert on **host-side effects and disclosure**, never on a child's exit code:
backends deny differently (Seatbelt `EPERM`; Bubblewrap omits the path and can
exit 0). A sandbox that never launched must be an `ERROR`, never a `PASS` — else
every "denied" expectation passes for the wrong reason.

## Adding a new sandbox system (a new row)

1. Write a driver that provisions the environment, runs comparable probes, and
   tears it down (model it on `scripts/run-on-sprite.sh`).
2. Add `docs/<system>.md` shaped like [docs/kubernetes.md](./docs/kubernetes.md)
   or [docs/sprites.md](./docs/sprites.md): an environment table, the isolation
   model, a probe-results table, and a "how it compares" summary.
3. Append verbatim findings to `docs/findings.md`, continuing the numbering.
4. Add the row to the comparison tables in [README.md](./README.md) and the
   matrix note in [docs/threat-model.md](./docs/threat-model.md), and index the
   new doc in `README.md` + `docs/README.md`.

## Gotchas

- **macOS ships bash 3.2**: guard empty-array expansion under `set -u`
  (`${arr[@]+"${arr[@]}"}`) — see the note in `scripts/lib.sh`.
- **The MXC sandbox does not inherit `process.env`**: use absolute interpreter
  paths in `commandLine` (findings §2).
- **`timeoutMs` is silently ignored on Bubblewrap** (findings §9) — enforce your
  own deadline.
- **Never commit secrets.** Sprite tokens come from 1Password/env at run time and
  are deleted after use; nothing token-shaped belongs in the repo or the logs.

## Git

Commit incrementally with explicit `git add <paths>` (never `git add .`). Match
the repo's plain sentence-case commit style — no conventional-commit prefixes.
Don't push or open PRs unless asked.
