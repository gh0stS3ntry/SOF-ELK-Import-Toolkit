# APE-03 Possible web shells: script files on the load balancer reached by very few clients

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell |
| Indexes | `aws-alb-*` |
| Needs | ALB or Classic ELB access logs |
| Applies to | internet-facing applications behind an ALB or ELB |

**What it finds.** Script pages (`.php`, `.jsp`, `.aspx` and similar) that answered 2xx to at most three distinct clients. Scored: POST requests +2, a single client +1, ten or more requests +1, the script sits in an upload, image, cache or static folder +2.

**Reading the output.** A web shell is a page nobody but the attacker uses, usually POSTed to repeatedly, often in a folder where uploads land. Legitimate rarely used pages (health checks, admin consoles reached from one office address) score too; check `client_ips` against the client's ranges. Take a suspect path's `first_seen` to the file system of the targets: its creation time dates the compromise.

**Next.** [AIA-04](../../TA0001-initial-access/AIA-04-alb-exploitation-attempts/) for how it got there.
