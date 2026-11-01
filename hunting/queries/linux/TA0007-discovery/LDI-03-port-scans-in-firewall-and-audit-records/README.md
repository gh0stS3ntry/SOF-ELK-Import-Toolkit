# LDI-03 Port and host scans in firewall logs and audited connections: one source reaching many ports or hosts

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery |
| Indexes | `logstash-*`, `auditd-*` |
| Needs | iptables/UFW/firewalld logs in logstash-*, or auditd-* connect records |
| Applies to | every Linux host with firewall logging or network auditing |

**What it finds.** Ten-minute windows in which one actor reached 15 or more ports or 15 or more hosts: for firewall log lines (iptables `LOG`, UFW `[UFW BLOCK]`/`[UFW ALLOW]`, firewalld) the actor is the source address, and for audited `connect` calls it is the program and user that connected. Inbound rows are scans of this host; outbound rows are scans from it.

**Reading the output.** Inbound scans from the internet are background noise; from an internal address they point at another compromised host. Any outbound scan (this host as the source, or an audited program connecting to many addresses) means it was used as a pivot: the `actor` program and `window` lead to the commands in [LDI-02](../LDI-02-network-scanning-tools/) and [LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/). Firewalls usually log only blocked or new connections, so counts are a lower bound.

**If it errors or looks empty.** No rows: no firewall logging and no audit rules on `connect`, which is the default on most hosts; this query then has nothing to read. `destination.port` is an integer in the system logs and a long in the audit log, so the query converts it with `TO_INTEGER`.

**Next.** [LC2-02](../../TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) for outbound destinations, [LLM-02](../../TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/) for remote access from this host.
