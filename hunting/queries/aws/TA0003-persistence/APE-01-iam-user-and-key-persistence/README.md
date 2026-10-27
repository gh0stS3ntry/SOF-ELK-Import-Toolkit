# APE-01 IAM users, access keys, passwords and MFA changes, scored

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1098.001 Additional Cloud Credentials, T1136.003 Create Cloud Account, T1556.006 Multi-Factor Authentication |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail IAM management events (logged in us-east-1) |
| Applies to | every AWS account |

**What it finds.** IAM changes that give someone a lasting way back in: new users, access keys, console passwords, SSH keys and service credentials, admin policies or admin groups for users, inline user policies, and MFA devices removed. Scored: credentials created for another user +3, admin policy or group +3, MFA removed +2, done as root +2, inline policy +1, new user +1.

**Reading the output.** The classic sequence after a key leak is `CreateUser` then `AttachUserPolicy AdministratorAccess` then `CreateAccessKey` for the new user, minutes apart and from the same source: sort by `@timestamp` and read the rows around a high score. `CreateAccessKey` for an existing user (`f_for_other`) gives the attacker a second key that survives the first one being rotated. `new_key` is the key that was created: search for it in [AIA-03](../../TA0001-initial-access/AIA-03-access-key-sources/) to see where it was used.

**Next.** [APE-02](../APE-02-role-trust-and-federation-backdoors/) for role and federation backdoors.
