# Docs — MXC TypeScript SDK experiment

Working notes for the `sandbox-mxc-sdk-typescript` experiment. The root
[`README.md`](../README.md) is the short overview; the detail lives here.

| Document | Contents |
|----------|----------|
| [findings.md](./findings.md) | Running log of everything learned, numbered and dated |
| [threat-model.md](./threat-model.md) | What the tests actually demonstrate, and what they do not |
| [backends.md](./backends.md) | Seatbelt vs Bubblewrap capability comparison |
| [docker.md](./docker.md) | Running the experiment in a container, with architecture diagrams |
| [kubernetes.md](./kubernetes.md) | How sandboxing differs between docker compose and AKS |
| [aks-enablement.md](./aks-enablement.md) | Can AKS be configured to run MXC in pods? (research) |

## Convention

**Findings get written down as they are discovered, not at the end.** Every
entry in [findings.md](./findings.md) follows the same shape:

```markdown
## N. Short claim in the title

**What happened** — the observation.
**Evidence** — the command and its actual output, pasted verbatim.
**Takeaway** — what to do about it.
```

Rules that keep this log trustworthy:

1. **Paste real output.** No paraphrased or reconstructed console text.
2. **Say which backend and host.** Seatbelt and Bubblewrap disagree often
   enough that an unqualified claim is usually wrong somewhere.
3. **Record negative results too.** "Alpine does not work" and "`--cap-add ALL`
   did not help" saved more time than most positive results.
4. **Distinguish *unsupported* from *contained*.** A control the backend cannot
   express is not a control that held.
5. **Correct in place, and say so.** Finding 8 exists because an earlier
   scenario was measuring the wrong property; the correction is part of the
   record rather than a silent edit.

MXC is an early preview and upstream states its profiles are not security
boundaries yet, so these are observations about a moving target. Re-run the
suites (`pnpm dev`, `pnpm probes`) against a new SDK version before trusting
anything here.
