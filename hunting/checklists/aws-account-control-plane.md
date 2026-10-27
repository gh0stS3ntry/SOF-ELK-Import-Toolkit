# Checklist: AWS account (CloudTrail)

Every AWS account in scope, from its CloudTrail logs (`aws-cloudtrail-*`). Load each account (or each trail) with its own `--source`, so every row shows which account it came from in `_index`. The usual questions: how did the attacker get credentials or a session, what did those principals do, did they keep access, and did they take, destroy or hide anything.

## 1. Account profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which accounts, regions and time range the loaded CloudTrail covers | [ATRI-01](../queries/aws/00-triage/ATRI-01-aws-data-coverage/) | 1.2.3, 2.4 | Gaps in the time range (trail stopped, regions not logged); whether S3 data events exist (`event_category` Data) for rows 5.1 and 7.3. |
| 1.2 | Principals that call the APIs, and from where | [ATRI-02](../queries/aws/00-triage/ATRI-02-cloudtrail-principal-inventory/) | 1.2.4, 1.3.2 | Expected automation (CI roles, AWS services) versus people; principals with many failures; the known-good source ranges for later rows. |
| 1.3 | Privileged identities, break-glass accounts and the organisation's known-good IP ranges |  | 1.3.2 to 1.3.5 | Ask the client: who should hold AdministratorAccess, which roles are assumed from which accounts, which corporate egress addresses and VPN ranges are normal. |
| 1.4 | Regions the account normally uses | [ADE-02](../queries/aws/TA0112-defense-impairment/ADE-02-rare-regions/) | 1.2.3 | API calls in regions nobody uses are a common sign of crypto-mining or hidden resources. |

## 2. Initial access

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Console sign-ins: root, no MFA, failures, new sources | [AIA-01](../queries/aws/TA0001-initial-access/AIA-01-console-logins/) | 2.4.3, 2.4.4 | Root sign-ins; sign-ins without MFA; successful sign-ins from addresses outside the known-good ranges, especially right after failures. |
| 2.2 | Brute force and password spraying against the console | [AIA-02](../queries/aws/TA0001-initial-access/AIA-02-console-brute-force/) | 2.4.1, 2.4.2 | One source failing for many users, or one user failing from many sources, followed by a success. |
| 2.3 | Long-term access keys used from new places or with new tooling | [AIA-03](../queries/aws/TA0001-initial-access/AIA-03-access-key-sources/) | 2.4.4 | An `AKIA...` key suddenly used from a VPS or Tor address, or with a user agent such as Kali, Pacu, ScoutSuite or an odd SDK version. |
| 2.4 | Instance role credentials used outside the instance | [ACA-02](../queries/aws/TA0006-credential-access/ACA-02-instance-credentials-from-many-sources/) | 2.4.22 | The same EC2 role session used from several addresses, one of them public: credentials stolen through SSRF or from the metadata service. |

## 3. Discovery and probing

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Enumeration bursts | [ADI-01](../queries/aws/TA0007-discovery/ADI-01-enumeration-bursts/) | 2.4.6 | Dozens of List/Describe/Get calls across services within minutes: someone mapping what the key can see. |
| 3.2 | Permission probing | [ADI-02](../queries/aws/TA0007-discovery/ADI-02-access-denied-probing/) | 2.4.6 | AccessDenied and UnauthorizedOperation errors across many services from one principal. |

## 4. Privilege escalation, persistence and lateral movement

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | IAM policy escalation | [APR-01](../queries/aws/TA0004-privilege-escalation/APR-01-iam-policy-escalation/) | 2.4.18 to 2.4.20 | Admin policies attached, new default policy versions, permission boundaries removed, inline policies with `*:*`. |
| 4.2 | New IAM users, access keys, passwords and MFA changes | [APE-01](../queries/aws/TA0003-persistence/APE-01-iam-user-and-key-persistence/) | 2.4.18 to 2.4.20 | Users and keys created by a suspicious principal; login profiles added to service users; MFA devices removed. |
| 4.3 | Role trust and federation backdoors | [APE-02](../queries/aws/TA0003-persistence/APE-02-role-trust-and-federation-backdoors/) | 2.4.18 to 2.4.20 | Trust policies that let an outside account or `*` assume a role; new SAML/OIDC providers; IAM Identity Center changes. |
| 4.4 | Role assumption and cross-account access | [ALM-01](../queries/aws/TA0008-lateral-movement/ALM-01-role-assumption-and-cross-account/) | 2.4.13 | Chains of AssumeRole from the compromised principal; roles assumed from accounts outside the organisation. |
| 4.5 | Code run on workloads through AWS APIs | [AEX-01](../queries/aws/TA0002-execution/AEX-01-remote-execution-on-workloads/) | 2.4.5, 2.4.13 | SSM SendCommand/StartSession, user data changes, EC2 Instance Connect keys, new Lambda code, ECS task definitions and CloudFormation stacks from the suspicious principal. |

## 5. Credential access and collection

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 5.1 | Secrets, parameters and EC2 passwords retrieved | [ACA-01](../queries/aws/TA0006-credential-access/ACA-01-secrets-and-parameter-retrieval/) | 2.4.22 | GetSecretValue, GetParameter(s) with decryption and GetPasswordData by principals that do not normally read them. |
| 5.2 | S3 reads and listings per principal and bucket | [ACO-01](../queries/aws/TA0009-collection/ACO-01-s3-data-access-volume/) | 2.1.4 | Large GetObject counts or byte totals from one principal or source; needs S3 data events. |

## 6. Defense impairment

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 6.1 | Logging and security services stopped or weakened | [ADE-01](../queries/aws/TA0112-defense-impairment/ADE-01-logging-and-security-tool-tampering/) | 2.4.21 | StopLogging, DeleteTrail, event selectors reduced, GuardDuty detectors or Security Hub disabled, Config recorders stopped, flow logs deleted. |
| 6.2 | Network exposure changes | [ADE-03](../queries/aws/TA0112-defense-impairment/ADE-03-network-exposure-changes/) | 2.4.26, 2.4.27 | Security groups or network ACLs opened to `0.0.0.0/0`, new internet gateways and routes, public RDS instances. |

## 7. Exfiltration and impact

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 7.1 | Snapshots, images, buckets and keys shared or made public | [AEXF-01](../queries/aws/TA0010-exfiltration/AEXF-01-resource-sharing-and-public-exposure/) | 2.4.7 | ModifySnapshotAttribute/ModifyImageAttribute with another account, bucket policies or ACLs that grant public or foreign access, KMS grants to outside accounts. |
| 7.2 | Destructive actions, ransom-style encryption and resource hijacking | [AIM-01](../queries/aws/TA0040-impact/AIM-01-destructive-and-resource-hijacking-actions/) | 2.1.10 | Mass deletion of buckets, snapshots and backups; S3 objects re-encrypted with an outside KMS key; many large instances started (mining). |

## Not covered by these queries

- CloudTrail S3 data events and Lambda invoke events are only there if the trail logged them; without them rows 5.2 and parts of 7.2 have no data.
- GuardDuty findings, Security Hub, IAM credential reports and Access Advisor data: export them separately, they help confirm rows 2.3, 2.4 and 4.1.
- Activity inside instances (process, logon and file artifacts): collect the hosts and use the Windows checklists, or Linux triage outside this toolkit.
- S3 server access logs and CloudFront logs are not loaded by this toolkit.
