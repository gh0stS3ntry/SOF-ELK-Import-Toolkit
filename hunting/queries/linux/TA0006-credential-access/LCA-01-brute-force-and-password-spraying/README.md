# LCA-01 Brute force and password spraying per source address, and whether a login then succeeded

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.001 Password Guessing, T1110.003 Password Spraying |
| Indexes | `logstash-*`, `wtmp-*`, `auditd-*` |
| Needs | sshd/PAM/FTP logs in logstash-*, or wtmp-* (btmp), or auditd-* |
| Applies to | every Linux host reachable over the network |

**What it finds.** Every source address with failed logins, per host: failed SSH passwords and keys, invalid users, too many authentication attempts, PAM authentication failures, `btmp` records, failed audit `USER_LOGIN`/`USER_AUTH` and failed FTP logins; how many accounts it tried, whether it looks like spraying (many accounts, few tries each) or brute force, over how many hours, and whether the same address then logged in.

**Reading the output.** Score 4 and above is a source that failed and then succeeded: confirm the account in `accounts_ok`, then follow `first_success` in [LLM-01](../../TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) and the commands in [LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/). An internal source spraying is a compromised host on the network (`internal`, +1). `sample_accounts` shows which names were tried: real account names mean the attacker knew them (from `/etc/passwd` on another host, or OSINT). Failures in `wtmp` (btmp) and in sshd messages describe the same attempts, so `failures` counts records rather than unique attempts. A distributed attack spreads across many addresses with few failures each; sort by `last_failure` to see it as a wave.

**If it errors or looks empty.** `Unknown column [wtmp.*]` does not apply (no wtmp-only field is used). No rows: no failed logins with a source address were logged; `btmp` is often empty or root-only and is not always collected.

**Next.** [LIA-01](../../TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) for successful logins from public addresses, [LTRI-03](../../00-triage/LTRI-03-accounts-and-their-activity/) for the accounts.
