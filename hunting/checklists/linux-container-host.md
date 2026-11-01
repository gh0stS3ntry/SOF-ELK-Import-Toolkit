# Checklist: Linux container host

Docker and Podman hosts and Kubernetes nodes (containerd, CRI-O). Run the [Linux baseline](linux-baseline-all-hosts.md) first. A container host runs many workloads on one kernel, so the questions are whether a container or the container API was used to reach the host, what ran on the host afterwards, and whether the cluster's credentials were taken. The toolkit loads the host, not the containers: their file systems and logs are only seen where they are on the host's disk. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Runtimes, orchestration and their versions | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/) | 1.2.1, 1.2.3 | Docker, containerd, runc, kubelet versions against container-escape CVEs; tools installed next to them. |
| 1.2 | Who can control the runtime | [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 1.3.2, 2.4.20 | Members of the `docker` group (root-equivalent), sudo rules for `docker`, `kubectl` or `crictl`. |
| 1.3 | Whether the API is reachable from the network | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 1.3.1 | `dockerd` listening on TCP (2375 without TLS), `-H tcp://` in units; ask the client about the Kubernetes API and kubelet ports. |

## 2. Container abuse and escape

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Privileged and host-mounted containers, escapes | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.1.1 | `--privileged`, `-v /:/host`, the Docker socket mounted, `nsenter -t 1`, `release_agent` tricks, escape tools. |
| 2.2 | Exec into containers and pods | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.13 | `docker exec`, `kubectl exec`/`cp`/`debug` by unexpected users or at odd times. |
| 2.3 | Programs run from writable and hidden places | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LDE-04](../queries/linux/TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) | 2.1.1, 2.1.4 | Binaries in `/tmp`, `/dev/shm` or container overlay folders running on the host, names masquerading as kernel threads. |
| 2.4 | Miners | [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | The most common outcome of an exposed Docker API or Kubernetes dashboard. |

## 3. Persistence and credentials

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Units, cron jobs and keys on the host | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.14, 2.4.25 | Units that start containers with `--privileged` or from unknown images, cron jobs that pull images, keys added to root. |
| 3.2 | Kubernetes and registry credentials | [LCA-02](../queries/linux/TA0006-credential-access/LCA-02-credential-files-and-cracking-tools/), [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.22 | `admin.conf`, `.kube/config`, `.docker/config.json` changed or copied; `kubectl` reading secrets or creating tokens and bindings. |
| 3.3 | Static pods and runtime configuration | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.14 | New files in `/etc/kubernetes/manifests`, changes to `daemon.json` or the containerd config. |

## 4. Spread and impact

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Scans and connections from the host | [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.4, 2.4.7 | Scans of the cluster or internal network, rare outbound destinations. |
| 4.2 | Tunnels and downloads | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LC2-03](../queries/linux/TA0011-command-and-control/LC2-03-tool-and-payload-downloads/) | 2.4.7 | Reverse shells and tunnels, tools pulled into `/tmp`. |
| 4.3 | Containers, volumes and data destroyed | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/) | 2.4.9 | `docker rm -f`, volume prunes, `kubectl delete` outside deployments. |

## Not covered by these queries

- Container logs (`docker logs`, `/var/log/containers`, `/var/log/pods`), image contents and the writable layers in `/var/lib/docker` or `/var/lib/containerd`: read them from the collection or export them from the runtime.
- Kubernetes API server audit logs and cloud-managed cluster logs (EKS, AKS, GKE).
