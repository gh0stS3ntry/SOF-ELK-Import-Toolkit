# APE-02 Role trust policies and identity providers that let an outside principal in

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1098.003 Additional Cloud Roles, T1484.002 Trust Modification |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail IAM and IAM Identity Center management events |
| Applies to | every AWS account |

**What it finds.** New roles and trust-policy changes, new or changed SAML and OIDC identity providers, IAM Identity Center assignments and permission-set policies, and instance profiles. Scored: the trust policy names another AWS account +3, it trusts any principal (`"AWS": "*"`) +3, an identity provider was added or changed +2, an existing role's trust was rewritten +1.

**Reading the output.** A role that trusts an account the client does not own is a durable backdoor: the attacker assumes it from their own account and leaves no IAM user behind. `trusted_account` is the first account ID in the request; read `request` (the policy is JSON inside JSON, so quotes appear escaped) for the full list. A new OIDC provider for GitHub or another CI system plus a role trusting it is a modern variant. Compare with the client's own cross-account roles (security tooling, backup and audit accounts usually explain the external IDs).

**If it errors or looks empty.** `f_any_principal` is a text match on the request JSON, which CloudTrail sometimes logs with the policy as an escaped string and sometimes as an object; both forms are matched, but whitespace inside the policy can defeat it. When in doubt, read `request`.

**Next.** [ALM-01](../../TA0008-lateral-movement/ALM-01-role-assumption-and-cross-account/) to see who assumed the role afterwards.
