# Docker Compose vs AKS — how the sandboxing differs

Comparison of running this experiment locally under `docker compose` against
running it on **`aks-scope-v2-int`** (Project Scope integration cluster).

> **Status: analysis complete, runtime comparison pending.** Everything below
> was established read-only or with `kubectl apply --dry-run=server`, which
> passes through admission control without persisting anything. The pods have
> **not** been run — see [Blockers](#blockers).

## Environments

| | Local | AKS |
|---|---|---|
| Runtime | Podman (Linux VM on macOS) | containerd 2.3.3 |
| Node OS | Debian bookworm container | Ubuntu 24.04 LTS |
| Kernel | VM kernel | 6.8.0-1064-azure |
| Kubernetes | — | v1.35.7 |
| MXC backend | bubblewrap | bubblewrap (same) |

## The security posture is genuinely different — and AKS wins

MXC's bubblewrap backend needs an unmasked `/proc` and no SELinux relabelling
([findings.md](./findings.md) §13). The two platforms grant that very
differently:

| Requirement | Local Docker | AKS / Kubernetes |
|---|---|---|
| Unmasked `/proc` | `--security-opt unmask=ALL` — container-wide, coarse | `procMount: Unmasked`, **only valid with `hostUsers: false`** |
| SELinux | `--security-opt label=disable` required | not needed (Ubuntu uses AppArmor) |
| User namespace | none — container root is host root | `hostUsers: false` maps pod root to an unprivileged node uid |
| Capabilities | container defaults retained | `capabilities: drop: ["ALL"]` accepted |
| Privilege escalation | not restricted | `allowPrivilegeEscalation: false` accepted |

The key result, from the API server itself:

```
$ kubectl apply --dry-run=server -f pod-with-procmount-unmasked.yaml
The Pod "mxc-probe" is invalid: spec.containers[0].securityContext.procMount:
  Invalid value: "Unmasked": `hostUsers` must be false to use `Unmasked`
```

Kubernetes **refuses** to hand out an unmasked `/proc` unless the pod is in its
own user namespace. Adding `hostUsers: false` makes the same pod admissible
with `privileged: false` and every capability dropped:

```
$ kubectl apply --dry-run=server -f pod-with-hostusers-false.yaml
pod/mxc-probe created (server dry run)
```

**So the AKS posture is strictly stronger than the local one.** Locally the
experiment disables SELinux labelling and unmasks `/proc` for the whole
container, with container-root equal to host-root. On AKS the same MXC
capability is obtained inside a user namespace, unprivileged, with no
capabilities — a containment boundary the docker compose setup never had.

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

## Blockers

Two things stand between this analysis and an actual runtime comparison, both
of which mutate shared infrastructure:

1. **The image is local-only.** `sandbox-mxc-sdk-typescript:latest` exists on
   the dev machine. AKS would need it in `acrscopev2int.azurecr.io`, which
   means pushing to a shared registry.
2. **The cluster is GitOps-managed.** Creating the namespace and Jobs directly
   would drift against `scope-core-infra` and be pruned. The sanctioned path is
   a PR to that repo — note it already has a `pr-envs` kustomization
   (`./deploy/pr-envs`) that looks purpose-built for ephemeral environments.

## Manifests

| File | Purpose |
|---|---|
| [`../k8s/namespace.yaml`](../k8s/namespace.yaml) | `mxc-sandbox-eval`, PSA set to `privileged`, scoped to this experiment |
| [`../k8s/mxc-probe-job.yaml`](../k8s/mxc-probe-job.yaml) | adversarial probes (`pnpm probes`) |
| [`../k8s/mxc-conformance-job.yaml`](../k8s/mxc-conformance-job.yaml) | policy conformance suite (`pnpm dev`) |

All three pass `kubectl apply --dry-run=server` against `aks-scope-v2-int`.

## What the runtime comparison should answer

Once the pods can run, the open questions are:

1. Does bubblewrap actually work under **containerd + user namespace**, or does
   nesting a user namespace inside one break `bwrap --unshare-user`? This is
   the single biggest unknown — and it is exactly the kind of thing
   `getPlatformSupport()` will claim works when it does not
   ([findings.md](./findings.md) §7).
2. Do the escape probes give the same verdicts as under Docker, particularly
   `network-allowlist` (needs `/dev/net/tun`, which a stock pod does not get).
3. Does Guaranteed QoS protect the trusted side as well as `cpuset` did (§16)?
