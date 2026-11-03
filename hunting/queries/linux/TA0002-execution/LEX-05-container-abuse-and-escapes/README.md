# LEX-05 Container abuse: privileged and host-mounted containers, exposed Docker APIs, exec into containers and escape commands

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1609 Container Administration Command, T1610 Deploy Container, T1611 Escape to Host, T1613 Container and Resource Discovery |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*` |
| Needs | commands in logstash-*, auditd-* or linuxconfig-*; dockerd lines in logstash-*; bodyfile-* for Docker and Kubernetes config files |
| Applies to | every Linux host (web, database and other servers often run containers); Docker and Podman hosts first; its Kubernetes signals stay in the query for the future Kubernetes checklist |

**What it finds.** Container runtimes used to run code with the host's privileges, or to reach other containers: `docker`/`podman`/`nerdctl` runs with `--privileged`, added capabilities, host PID, network or user namespaces, or with `/`, `/etc`, `/root`, `/proc` or the Docker socket mounted; `nsenter -t 1`, `chroot /host`, cgroup `release_agent` and `core_pattern` tricks and escape tools (`cdk`, `deepce`); `exec` into containers and pods; `kubectl` commands that create bindings or tokens or read secrets; the Docker API used over TCP (`-H tcp://`, `DOCKER_HOST`) and `dockerd` listening on a TCP port; and Docker, containerd and Kubernetes configuration files changed after `since`. Commands come from sudo, pkexec, cron and audit records and from cron entries, units and startup files.

**Reading the output.** Set `since` first, then read highest score first. On a container host the commands people type are mostly `docker`; the leads are runs that give a container the host (`--privileged` with `-v /:/host`, the Docker socket mounted) and anything run as root right after. `dockerd` listening on 2375 without TLS is the most exploited container misconfiguration: from the internet it gives root on the host to anyone, and is usually followed by miners ([LIM-03](../../TA0040-impact/LIM-03-cryptominers/)). Membership of the `docker` group is root-equivalent: see [LPR-03](../../TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/). Processes inside containers are not in the host's audit log unless auditd watched them; container logs are not loaded.

**If it errors or looks empty.** `Unknown column [linuxconfig.line]`: no `linuxconfig-*`; replace it with `null`. `Unknown column [file.ctime]` or `[file.type]`: no `bodyfile-*`; remove `bodyfile-*` and the `f_cfg` line. No rows on a host without auditd can simply mean the commands ran without sudo (members of the `docker` group need none).

**Next.** [LIM-03](../../TA0040-impact/LIM-03-cryptominers/) for miners, [LPR-03](../../TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) for who is in the `docker` group, [LC2-01](../../TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/) for tunnels started from containers.
