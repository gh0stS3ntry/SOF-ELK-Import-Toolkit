# AEXF-03 Clients that pulled the most data through the load balancer

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service |
| Indexes | `aws-alb-*` |
| Needs | ALB or Classic ELB access logs |
| Applies to | internet-facing applications behind an ALB or ELB |

**What it finds.** Per client: megabytes the load balancer sent back, how many responses were 10 MB or larger and for which paths, compared with the median client of the same load balancer.

**Reading the output.** Look for clients far above `median_mb` that pulled export, backup, report or API list endpoints, especially the same clients [AIA-04](../../TA0001-initial-access/AIA-04-alb-exploitation-attempts/) flagged. A single large download of `/backup.zip` or `/.git/` content is a misconfiguration that was found; many medium responses walking an API with incrementing IDs is scraping (an IDOR).
