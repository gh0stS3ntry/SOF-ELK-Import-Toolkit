# APR-01 IAM privilege escalation: admin policies, policy versions and permission boundaries

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1098.003 Additional Cloud Roles, T1484 Domain or Tenant Policy Modification |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail IAM management events |
| Applies to | every AWS account |

**What it finds.** Successful IAM policy changes that raise privileges: managed policies attached to users, roles or groups, inline policies, new policy versions set as default (the `iam:CreatePolicyVersion` escalation), users added to groups, and permission boundaries removed. Scored: an admin-level AWS managed policy +3, a principal changing its own permissions +3, a new default policy version +2, a boundary removed +2, an inline policy that looks like it grants `*` +1.

**Reading the output.** Self-grants (`f_self`) are rare in legitimate work, because pipelines change other principals' permissions, not their own. A new default policy version on a policy attached to the caller is the textbook escalation path. Read `request` for inline and versioned policy documents: `"Action":"*"` with `"Resource":"*"` is full admin.

**If it errors or looks empty.** `f_wildcard` is a loose text match on the escaped policy JSON; treat it as a hint.

**Next.** [APE-02](../../TA0003-persistence/APE-02-role-trust-and-federation-backdoors/) for trust-policy changes.
