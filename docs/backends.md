# Backend comparison — Seatbelt vs Bubblewrap

Measured on macOS 15 arm64 (Seatbelt) and Debian bookworm arm64 in a container
(Bubblewrap, bwrap 0.8.0). Windows `processcontainer` was not tested.

## Capability matrix

| Capability | Seatbelt (macOS) | Bubblewrap (Linux) |
|---|---|---|
| Minimum schema | `0.7.0-alpha` | `0.6.0-alpha` |
| `readonlyPaths` / `readwritePaths` | enforced | enforced |
| Block all outbound | enforced | enforced (`--unshare-net`) |
| Allow all outbound | enforced | enforced |
| Per-CIDR / port egress rules | **rejected at config time** | enforced (slirp4netns + iptables) |
| Hostname allowlisting | no primitive | no — rules are IP/CIDR only |
| `timeoutMs` | enforced | **silently ignored** |
| Syscall filtering | none | none |
| Host env inheritance | never | never |

## How they deny — the difference that bites

This is the single most important behavioural divergence, and it is easy to
write a test that cannot see it.

| | Seatbelt | Bubblewrap |
|---|---|---|
| Model | deny the syscall on the real path | omit the path from the namespace |
| Ungranted read | `EPERM` | `ENOENT` |
| Ungranted write | `EPERM`, exit 1 | **exit 0**, into a throwaway namespace |
| Write to a `readonlyPaths` grant | `EPERM` | `EROFS` |

Consequence: an assertion of the form "the sandboxed process exits non-zero" is
correct on Seatbelt and wrong on Bubblewrap, even though both contained the
write. Assert on **host-side effect** ("the file does not exist afterwards") and
on **disclosure** ("the secret is not in stdout") instead. See
[findings.md](./findings.md) §8.

## Failure modes

Both backends fail closed, which is the reassuring part:

| Situation | Behaviour |
|---|---|
| Seatbelt asked for per-CIDR egress rules | rejected at config time with a clear message, nothing runs |
| Bubblewrap missing `/dev/net/tun` for a firewall policy | everything blocked, including the allowlisted host — never falls back to an open network |
| Container blocks bwrap's mounts | spawn fails loudly on stderr; no silent degradation to "unsandboxed" |

The last one is only safe *because* the suite now treats a launch failure as
`ERROR` rather than counting the resulting denials as passes.

## Practical implications

- **Write backend-agnostic assertions.** Test outcomes, not error codes.
- **Do not rely on `timeoutMs` on Linux.** Enforce your own deadline.
- **Per-site network policy is a Linux-only feature today.** On macOS the
  choice is all-or-nothing outbound plus a loopback exception; anything finer
  needs a proxy, and using the proxy is cooperative rather than enforced.
- **Smoke-test at startup on every platform.** `getPlatformSupport()` returning
  `isSupported: true` has been wrong in two distinct environments
  ([findings.md](./findings.md) §7).
