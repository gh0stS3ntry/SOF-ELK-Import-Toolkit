# AIA-05 WAF: blocked clients, and what the same clients got through

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1190 Exploit Public-Facing Application, T1595 Active Scanning |
| Indexes | `aws-waf-*` |
| Needs | AWS WAF web ACL logs (full logs, not only blocked requests) |
| Applies to | internet-facing applications behind AWS WAF |

**What it finds.** Every client the WAF blocked at least once, with the rules that blocked it, and the requests from the same client that the WAF allowed. `allowed_with_rule_match` counts allowed requests that matched a rule in Count mode.

**Reading the output.** A client that was blocked for SQL injection and then allowed on other paths may have found a variant the rules miss: compare `allowed_paths` with the blocked requests (drop the `STATS` and filter on the `source.ip`). Rules in Count mode do not protect anything; see [AIA-06](../AIA-06-waf-count-mode-matches/). Blocks by rate-based rules alone are usually scanners or bots.

**If it errors or looks empty.** If only blocked requests were logged (a WAF logging filter), `allowed_requests` is always 0.

**Next.** [AIA-04](../AIA-04-web-exploitation-attempts/) to see the same clients in the load balancer log, with the application's status codes.
