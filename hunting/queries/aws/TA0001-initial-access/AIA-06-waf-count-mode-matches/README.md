# AIA-06 WAF rules that matched but did not block (Count mode and labels on allowed requests)

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1190 Exploit Public-Facing Application |
| Indexes | `aws-waf-*` |
| Needs | AWS WAF web ACL logs with allowed requests |
| Applies to | internet-facing applications behind AWS WAF |

**What it finds.** Rules that matched allowed requests without blocking them: rules (or whole managed rule groups) left in Count mode, and rule-group rules overridden to Count. The managed-rule labels on those requests show what the rule recognised (`awswaf:managed:aws:sql-database:...`, `...:bot-control:...`).

**Reading the output.** A Count-mode SQL injection, Log4j (`AWSManagedRulesKnownBadInputsRuleSet`) or PHP/LFI rule with matches during the incident means the attack reached the application unfiltered. Check when the rule was switched to Count with [ADE-01](../../TA0112-defense-impairment/ADE-01-logging-and-security-tool-tampering/) (`UpdateWebACL`).
