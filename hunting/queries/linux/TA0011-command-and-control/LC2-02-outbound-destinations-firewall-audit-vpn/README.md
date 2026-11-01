# LC2-02 Outbound destinations from firewall logs, audited connections and VPN logs, rarest first

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071 Application Layer Protocol, T1571 Non-Standard Port, T1572 Protocol Tunneling |
| Indexes | `logstash-*`, `auditd-*` |
| Needs | firewall or VPN logs in logstash-*, or auditd-* connect records |
| Applies to | every Linux host with firewall logging, network auditing or a VPN client |

**What it finds.** Every public address the host connected to, as far as the logs show it: firewall log lines (iptables `LOG`, UFW, firewalld) with a destination, audited `connect` calls (program and user), and the remote endpoints OpenVPN clients logged (`[AF_INET]a.b.c.d:port`). Per destination: how many records, over how many distinct hours, which ports, programs and users, and when first and last seen. Rare destinations come first.

**Reading the output.** Rare destinations reached by an unexpected program (a shell, an interpreter, a binary in `/tmp`) are the first leads. A destination seen in many distinct hours across a long span with few records each hour is beacon-like; sort by `active_hours` to find those. Non-standard ports (`uncommon_port`) on an outbound connection from a server matter more than on a workstation. Most hosts log neither outbound connections nor `connect` calls, so an empty result usually means no data, not no traffic; then rely on [LC2-01](../LC2-01-reverse-shells-tunnels-and-proxies/) and the network evidence outside the host.

**If it errors or looks empty.** `Unknown column [process.name]` does not occur while `logstash-*` exists. If ES|QL reports the `REPLACE` pattern, check that the backslashes survived copy and paste (each literal bracket is written `\\[` in the query).

**Next.** [LC2-01](../LC2-01-reverse-shells-tunnels-and-proxies/) for the tools that made the connections.
