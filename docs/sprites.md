# Fly.io Sprites as a sandbox

Where the other rows in this matrix measure MXC confining a *child process* on a
host (seatbelt, bubblewrap, bubblewrap-on-AKS), this row measures a different
*kind* of sandbox: **[Fly.io Sprites](https://sprites.dev)** — a per-tenant
**KVM micro-VM** (the same substrate as Fly Machines) in which your code runs
inside an inner container. There is no MXC here. The question is what a Sprite
contains on its own.

> **Status: run on org `cedric-925`.** Everything below is from a sprite that was
> created, probed, and destroyed by [`../scripts/run-on-sprite.sh`](../scripts/run-on-sprite.sh),
> not from documentation. Sprite platform version `0.0.1-rc48`, image
> `Ubuntu 26.04.1 LTS`, kernel `6.12.105-fly`.

## Environment

| | Local Docker (bubblewrap row) | Fly Sprite |
|---|---|---|
| Boundary | userspace namespaces on the host kernel | **KVM micro-VM**, one per sprite |
| Node OS | Debian bookworm container | Ubuntu 26.04.1 LTS |
| Kernel | host VM kernel | `6.12.105-fly` (custom), shared with no other tenant |
| Architecture | arm64 | amd64 (`x86_64`) |
| Default user | root in container | `sprite` (uid 1001), **passwordless `sudo` → root** |
| pid 1 | node/pnpm | `tini` |
| Confined thing | one MXC child process | the whole VM |

## The headline: the boundary is a VM, and egress is a real enforced control

The two things that make Sprites categorically different from the userspace rows:

1. **The isolation boundary is a KVM guest**, not a set of namespaces sharing the
   host kernel. A kernel LPE inside a sprite lands you in a `6.12-fly` guest
   kernel, not on a shared host — the exact escape route the threat model calls
   out for seatbelt/bubblewrap ("both share the host kernel … a kernel LPE walks
   straight out") does not apply the same way.
2. **Egress is filtered by a DNS allowlist that the sprite cannot edit.** The
   policy is set from *outside* over the API; inside, it is read-only. This is a
   containment control that bubblewrap could only fake (it needed `/dev/net/tun`)
   and seatbelt could not express at all (`network-allowlist` is *unsupported*
   there — see [threat-model.md](./threat-model.md)).

### Egress allowlist — the mechanism

Documented at `/.sprite/docs/agent-context.md` inside every sprite. The policy is
a JSON rule list, evaluated by specificity, applied over the API:

```bash
# from OUTSIDE the sprite (the container cannot modify its own policy):
curl -X POST https://api.sprites.dev/v1/sprites/<name>/policy/network \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"domain":"example.com","action":"allow"},{"domain":"*","action":"deny"}]}'
```

Measured behaviour under that policy, from inside the sprite:

```
[example.com]  ;; ->>HEADER<<- opcode: QUERY, status: NOERROR   # allowed: resolves
[github.com]   ;; ->>HEADER<<- opcode: QUERY, status: REFUSED   # denied: DNS refused
example.com HTTP 200                                            # allowed: reachable
github.com  curl: (6) Could not resolve host: github.com        # denied: blocked
1.1.1.1     curl: (7) Failed to connect ... Could not connect    # raw IP now blocked
```

The same raw IP (`https://1.1.1.1`) returns `HTTP 301` with **no** policy set, so
the block is the allowlist doing its job, not a routing accident: raw-IP
connections are refused unless the IP was resolved from an allowed domain.
`{"rules": []}` restores unrestricted egress. `REFUSED` is a fast-fail, so denied
lookups do not hang.

## Probe results

Reusing the vocabulary from [threat-model.md](./threat-model.md)
(`contained` / `ESCAPED` / `unsupported`):

| Probe | Threat | Verdict | Evidence |
|-------|--------|---------|----------|
| host-process-visibility | see processes outside the sandbox | **contained** | `ps -e` shows 7 procs, pid 1 = `tini`; no host/node processes in the PID namespace |
| cloud-metadata | reach `169.254.169.254` | **contained** | `curl` times out (rc 28) |
| private-range | reach RFC1918 (`10.0.0.1`) | **contained** | connect fails instantly (rc 7); private IPs always blocked |
| egress-default | outbound with no policy | **open by design** | `example.com`/`github.com`/raw `1.1.1.1` all reachable (`200`/`200`/`301`) |
| egress-allowlist | allow one domain, deny the rest | **contained** | denied domain → DNS `REFUSED`; raw IP blocked; allowed domain `200` |
| checkpoint-rollback | undo a filesystem change | **contained** | after `restore v1`, canary reverts to `ORIGINAL-CONTENT` and a post-checkpoint file is gone |
| resource-limits (in-VM) | exhaust CPU/memory | **VM-bounded** | no cgroup cap inside (`cpu.max: max`, `memory.max: max`, `pids.max: max`); the ceiling is the VM's own ~8 vCPU allocation |

### What the sprite grants by default (the flip side)

Inside the inner container the shell is not fully unprivileged:

```
CapEff: 00000000a82435fb  -> chown, dac_override, fowner, kill, setuid/gid,
                             setpcap, net_bind_service, net_admin, net_raw,
                             sys_chroot, sys_admin, mknod, audit_write, setfcap
Seccomp: 0                # no syscall filter — same as every other row here
sudo -n whoami -> root    # passwordless root is one command away
```

So *within* the guest a workload is effectively root with `CAP_SYS_ADMIN` and no
seccomp filter — this is not a locked-down process jail. What makes it safe to
hand untrusted code is not in-guest confinement but the **VM boundary around the
whole thing**: that root, and any kernel bug it reaches, is confined to a
disposable single-tenant micro-VM whose egress you control and whose disk you can
roll back.

## Resource exhaustion is bounded by the VM, not by a cgroup

[findings.md](./findings.md) §12 showed MXC has no CPU/memory field, so on a bare
host a runaway workload took ~10 of 12 cores; only a *container* cgroup contained
it. A sprite has no in-VM cgroup cap either (`cpu.max: max`, `memory.max: max`),
but the containment is structural: the workload can burn the sprite's own
~8 vCPU and nothing more, it cannot touch the host or another tenant, and Fly
meters it per CPU/GB-hour so the cost is bounded and attributable. Observed RAM
varied between sprites (`~8 GB` on one, `~16 GB` on another), so treat the
allocation as elastic rather than a fixed guarantee.

## How Sprites compares to the other rows

| Question | seatbelt / bubblewrap | Fly Sprite |
|---|---|---|
| Boundary | userspace, shared host kernel | dedicated KVM micro-VM |
| Kernel LPE escapes to… | the host | a disposable guest kernel |
| Syscall filter | none (`Seccomp: 0`) | none (`Seccomp: 0`) — same |
| Egress allowlist | bubblewrap: yes w/ `/dev/net/tun`; seatbelt: unsupported | **enforced from outside, DNS-based** |
| Resource cap | none in MXC; needs a container cgroup | none in-VM; bounded by the VM allocation + billing |
| Undo state | — | checkpoint / restore rolls back the whole overlay |
| In-sandbox privilege | varies | root via `sudo`, `CAP_SYS_ADMIN` present |

The trade is clear: a sprite is a **heavier, stronger** boundary. It does not try
to make the process unprivileged — it gives you root — and instead isolates the
whole machine, controls what it can talk to, and lets you throw it away or rewind
it. For running genuinely untrusted agent code that is a better shape than a
userspace jail on a shared kernel; the cost is a whole VM per workload.

## Reproducing

```bash
bash scripts/run-on-sprite.sh          # provisions, probes, and destroys one sprite
```

Auth: the script uses the already-configured `sprite` CLI if logged in; otherwise
it reads a token from `$SPRITE_TOKEN` or 1Password
(`op://Personal/Fly.io Sprites API Credentials/token`), uses it via
`sprite auth setup --token`, and deletes the copy on exit. It always destroys the
sprite it created (`trap ... EXIT`), so a failed run does not leave one billing.

## Summary

| Question | Answer |
|---|---|
| What is the boundary? | a per-tenant KVM micro-VM, not a userspace jail |
| Is egress controllable? | **yes** — a DNS allowlist set over the API, read-only inside, `REFUSED` for denied domains, raw/private IPs blocked |
| Can state be rolled back? | yes — filesystem checkpoints; `restore` reverts the whole overlay |
| Is the in-guest process locked down? | no — default user gains root via `sudo`, `CAP_SYS_ADMIN`, `Seccomp: 0` |
| Is resource exhaustion contained? | at the VM boundary (no in-VM cgroup cap), plus per-hour billing |
| Biggest difference from the MXC rows | the sandbox is the *machine*, so a kernel escape stays inside a disposable VM instead of reaching a shared host |
