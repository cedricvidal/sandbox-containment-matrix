# Threat model — what is actually demonstrated

> ⚠️ Upstream states that MXC profiles are **not security boundaries** today and
> that generated policies are knowingly overly permissive. Everything below is a
> behavioural baseline to re-run as MXC matures — evidence about current
> defaults, not a security guarantee.

## Conformance is not containment

The two suites measure different things, and conflating them is the easiest way
to overstate what MXC does:

| Suite | Question it answers | Adversary assumed |
|-------|--------------------|-------------------|
| `pnpm dev` (`src/index.ts`) | Does the sandbox do what the policy says? | None — the code cooperates |
| `pnpm probes` (`src/escape-probes.ts`) | Does the boundary hold when code attacks it? | Code actively trying to get out |

Every program in the scenario suite asks for a denied resource and accepts the
error. That demonstrates the policy is *applied*; it says nothing about whether
the policy *holds* against code that is trying to break it.

## Why the positive controls matter

`extra-path-granted` and `net-allowed` must **succeed**. Without them a totally
broken sandbox — where every operation fails for unrelated reasons — would
produce a perfect score.

This is not hypothetical. The first container run reported 5/9 "passing" purely
because `bwrap` never launched and every deny-expectation was satisfied by the
failure. Launch failures are now reported as `ERROR`, never `PASS`, and a failed
baseline aborts the run (see [findings.md](./findings.md) §7).

## Probe results

| Probe | Threat | Seatbelt | Bubblewrap |
|-------|--------|----------|------------|
| `symlink-read-escape` | symlink in a writable dir pointing at a secret | contained | contained |
| `symlink-write-escape` | write out through a symlink | contained | contained |
| `env-leak` | inherit host env (tokens, keys) | contained | contained |
| `loopback-egress` | reach a host service on 127.0.0.1 under `allowOutbound: false` | contained | contained |
| `signal-host-process` | signal/inspect a process outside the sandbox | contained | contained |
| `home-dir-read` | read an ungranted file in `$HOME` | contained | contained |
| `network-allowlist` | allow one site, deny the rest — then reach another | **unsupported** | contained |
| `timeout-enforced` | ignore `timeoutMs` and run forever | contained | **ESCAPED** |
| `resource-limits` | exhaust CPU and memory | **ESCAPED** | **ESCAPED**¹ |

¹ Contained only when the *container* supplies a cgroup cap — see the
`mxc-limits` compose profile. MXC itself has no CPU/memory field on any
cross-platform backend ([findings.md](./findings.md) §12).

Totals: Seatbelt `7/9 contained, 1 escaped, 1 unsupported`; Bubblewrap
`7/9 contained, 2 escaped, 0 unsupported` — or `8/9 contained, 1 escaped`
when run under `mxc-limits`.

`unsupported` is tallied separately from `contained` on purpose — "this backend
cannot express the control you asked for" is not "the control held".

## Explicitly not covered

- **The kernel.** Both backends share the host kernel and, measured rather than
  assumed, add **no syscall filter**: `Seccomp: 0`, `Seccomp_filters: 0` inside
  the sandbox once the container's own profile is removed
  ([findings.md](./findings.md) §10). The entire syscall ABI is reachable, so a
  kernel LPE walks straight out.
- **Resource exhaustion — by MXC.** Wall-clock `timeoutMs` is the only limit
  the schema expresses, and it is not enforced on Bubblewrap
  ([findings.md](./findings.md) §9). There is no CPU, memory or process-count
  field at all ([findings.md](./findings.md) §12): a sandboxed workload
  committed 512 MB and obtained ~10 of 12 cores on macOS and ~5.6 of 6 in a
  container. This is delegable —
  a container cgroup (`mem_limit`, `cpus`, `pids_limit`) enforces it, and the
  `mxc-limits` profile demonstrates the OOM kill landing. On a bare macOS host
  there is no equivalent. Note that *how* the CPU limit is expressed matters:
  a container-wide `cpus:` quota starves the trusted orchestrator alongside the
  workload ([findings.md](./findings.md) §16); use `cpuset` plus
  `reserveHostCpu` to bound the sandbox while reserving a core.
- **Whatever you grant.** `readwritePaths` is a hole by construction, and
  `getAvailableToolsPolicy()` grants *every* `PATH` entry read-only — about 30
  directories on this Mac, including `~/.cargo/bin`, `~/.local/bin` and `~/bin`.
  Untrusted code can read all of it, and any entry that is user-writable is a
  plausible persistence point. Narrow this for real workloads.
- **TOCTOU** on granted paths, and side channels of every kind.
- **Windows `processcontainer`** — not tested here at all.
- **Proxy-mediated egress.** MXC confines egress *to* the proxy endpoint, but a
  workload actually speaking HTTP to it is cooperative, not enforced.

## Residual risk worth restating

Two findings matter more than the rest when deciding whether to rely on this:

1. **`getPlatformSupport()` can report a backend as available on a host where
   nothing can run** ([findings.md](./findings.md) §7). Always smoke-test.
2. **Bubblewrap denies by omission**, so an ungranted write can return exit 0
   while landing in a throwaway namespace ([findings.md](./findings.md) §8).
   Assert on disclosure and on host-side effects, never on the child's exit
   code alone.
3. **Nothing in MXC stops a workload burning the machine's CPU and RAM**
   ([findings.md](./findings.md) §12). If the workload is genuinely untrusted,
   run it under a cgroup — but bound CPU with `cpuset` and a reserved core, not
   a shared quota, or the orchestrator starves with it
   ([findings.md](./findings.md) §16).
