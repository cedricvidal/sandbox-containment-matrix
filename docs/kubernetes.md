# Docker Compose vs AKS — how the sandboxing differs

Comparison of running this experiment locally under `docker compose` against
running it on **`aks-scope-v2-int`** (Project Scope integration cluster).

> **Status: run on `aks-scope-v2-int`.** Results below are from pods that
> actually executed, not from dry-runs.

## Environments

| | Local | AKS |
|---|---|---|
| Runtime | Podman (Linux VM on macOS) | containerd 2.3.3 |
| Node OS | Debian bookworm container | Ubuntu 24.04 LTS |
| Kernel | VM kernel | 6.8.0-1064-azure |
| Architecture | arm64 | **amd64** — the image needs a cross-build |
| Kubernetes | — | v1.35.7 |
| MXC backend | bubblewrap | bubblewrap (same) |

## The headline: AKS needs `privileged`, Docker does not

This is the opposite of what the API server suggested, and the gap between the
two is the most useful thing this comparison produced.

Kubernetes refuses `procMount: Unmasked` unless the pod runs in its own user
namespace:

```
The Pod "mxc-probe" is invalid: spec.containers[0].securityContext.procMount:
  Invalid value: "Unmasked": `hostUsers` must be false to use `Unmasked`
```

Adding `hostUsers: false` makes the pod **admissible** — `kubectl apply
--dry-run=server` accepts it with `privileged: false` and every capability
dropped. That looks like a strictly stronger posture than the local setup.

**It does not work.** Admission accepting a `securityContext` says nothing
about whether the workload functions. Measured on the cluster:

| Variant | `hostUsers` | securityContext | Result |
|---|---|---|---|
| A | `false` | `procMount: Unmasked`, drop `ALL` | `bwrap: setting up uid map: Operation not permitted` |
| B | `false` | as A + `SETUID`,`SETGID` | **identical failure** — capabilities do not help |
| C | `false` | `procMount: Unmasked`, defaults | `bwrap: Failed to make / slave: Permission denied` |
| D | (host) | `privileged: true` | **OK** |
| E | `false` | `privileged: true` | **OK** |

Bubblewrap builds its sandbox by unsharing a *user* namespace and writing a
uid map. It cannot, and granting `SETUID`/`SETGID` changes nothing.

The reason is not Kubernetes: the nodes run **Ubuntu 24.04**, where
`kernel.apparmor_restrict_unprivileged_userns = 1` blocks unprivileged user
namespace creation. Our local container is Debian bookworm, which has no such
restriction. See [aks-enablement.md](./aks-enablement.md) for the evidence and
for the node-pool options that remove the need for `privileged` entirely.

So the safe configuration that the API server happily admits is precisely the
one in which MXC cannot run.

### The least-bad configuration is E

`privileged: true` **with** `hostUsers: false` works, and is meaningfully
better than plain `privileged: true`: the privilege is scoped to the pod's user
namespace, so pod-root maps to an unprivileged uid on the node. Variant D
(privileged, host user namespace) grants real node-level root.

```yaml
spec:
  hostUsers: false          # privilege is scoped to this namespace
  containers:
    - securityContext:
        privileged: true    # unavoidable: bwrap needs it
```

Compared with local Docker, which needs no privilege at all — only
`label=disable` and `systempaths=unconfined` — **AKS is the weaker posture for
this workload**, and the user namespace is what claws most of it back.

## Behaviour is otherwise identical to Docker

Both suites were run in the namespace under variant E:

```
=== 8 passed, 0 failed, 0 errored, 1 skipped ===        # pnpm dev
=== 8/9 probes contained, 1 escaped, 0 unsupported ===  # pnpm probes
```

Same verdicts as the container, including `timeout-enforced` escaping
([findings.md](./findings.md) §9). Two differences worth noting:

- `network-allowlist` **passed without any extra configuration**. Locally it
  needed `/dev/net/tun` added explicitly ([findings.md](./findings.md) §11);
  a privileged pod already has the device.
- `resource-limits` reported `throttled to ~1.98 of 4 cores demanded` under
  `limits.cpu: "2"`, confirming the probe reads a Kubernetes CFS quota exactly
  as it reads a Docker one.

## CPU reservation maps cleanly onto Kubernetes

[findings.md](./findings.md) §16 showed a shared CFS quota (`cpus:`) starves
the trusted orchestrator, and that `cpuset` plus a reserved core fixes it.
Kubernetes expresses the same distinction natively:

| Intent | Docker Compose | Kubernetes |
|---|---|---|
| Shared quota (starves trusted side) | `cpus: 1` | `limits.cpu: "1"` with Burstable QoS — same CFS quota, same problem |
| Exclusive cores (trusted side protected) | `cpuset` + `taskset` | **Guaranteed QoS** (integer `requests == limits`) with the kubelet `static` CPU manager policy |

Guaranteed QoS plus the static CPU manager policy pins the pod to *exclusive*
cores rather than giving it a slice of a shared quota — the Kubernetes-native
equivalent of the `mxc-reserved` profile. The manifests in
[`../k8s/`](../k8s) request integer CPU to land in that class.

> Whether the `static` policy is actually enabled is a kubelet setting on the
> node pool; it must be confirmed before the CPU comparison is meaningful, and
> it cannot be read from the API alone.

## Policy and deployment differences

| | Local | AKS |
|---|---|---|
| Admission control | none | Pod Security Admission labels; Gatekeeper installed (no constraint templates at time of writing) |
| Deployment | imperative `docker run` / `docker compose` | **FluxCD GitOps**, four kustomizations with `prune: true` |
| Source of truth | this repo | `growth-ecosystems/scope-core-infra` |

That last row is the operationally important one: the cluster continuously
reconciles against Git, so anything created with `kubectl apply` is drift and
will be reverted. The manifests in [`../k8s/`](../k8s) are written to be
applied through the GitOps repo, not by hand.

## Reproducing

The image must be built for **amd64** — AKS node pools here are x86_64 while
the dev machine is Apple Silicon:

```bash
docker build --platform linux/amd64 \
  --build-arg NPM_REGISTRY="$(npm config get registry)" \
  -t acrscopev2int.azurecr.io/sandbox-mxc-sdk-typescript:latest .
az acr login --name acrscopev2int
docker push acrscopev2int.azurecr.io/sandbox-mxc-sdk-typescript:latest

kubectl --context aks-scope-v2-int apply -f k8s/
```

> The cluster is FluxCD-reconciled with `prune: true` from
> `growth-ecosystems/scope-core-infra`. The `mxc-sandbox-eval` namespace is not
> referenced by any kustomization, so it is not pruned — but for anything
> longer-lived than an experiment, go through the GitOps repo, which already
> has a `pr-envs` kustomization (`./deploy/pr-envs`) for ephemeral
> environments. Delete the namespace when finished.

## Manifests

| File | Purpose |
|---|---|
| [`../k8s/namespace.yaml`](../k8s/namespace.yaml) | `mxc-sandbox-eval`, PSA `privileged`, scoped to this experiment |
| [`../k8s/mxc-probe-job.yaml`](../k8s/mxc-probe-job.yaml) | adversarial probes (`pnpm probes`) |
| [`../k8s/mxc-conformance-job.yaml`](../k8s/mxc-conformance-job.yaml) | policy conformance suite (`pnpm dev`) |

## Summary

| Question | Answer |
|---|---|
| Does MXC work on AKS? | Yes — but only with `privileged: true` |
| Can it run unprivileged like it does in Docker? | **No.** bwrap cannot write a uid map inside Kubernetes' user namespace |
| Best available configuration | `privileged: true` **+** `hostUsers: false`, which scopes the privilege to the pod's user namespace |
| Do the sandbox guarantees differ? | No — identical suite and probe verdicts |
| Biggest trap | `--dry-run=server` accepting a securityContext proves nothing about whether the workload runs |
