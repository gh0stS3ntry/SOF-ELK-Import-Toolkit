# CA-03 Registry settings that enable or hide credential theft, and tool traces

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1003.001 LSASS Memory, T1112 Modify Registry, T1547.005 Security Support Provider, T1550.002 Pass the Hash |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV that dumps `Control\SecurityProviders\WDigest`, `Control\Lsa`, `Control\CrashControl`, `Software\Sysinternals` (NTUSER.DAT) and the Services key |
| Roles | all |

**What it finds.** `UseLogonCredential = 1` (WDigest keeps cleartext passwords in LSASS), `RunAsPPL = 0`, `LsaCfgFlags = 0`, `DisableRestrictedAdmin = 0` (pass-the-hash over RDP), LSA packages with Mimikatz SSP names or non-default entries, NMI crash dumps, Sysinternals EULA keys (proof that ProcDump or PsExec ran under that user, with the key write time as the first run) and service keys of known dump or vulnerable drivers.

**Reading the output.** `registry.last_write` is when the key last changed: for WDigest it is usually the attacker's change, followed by a wait for an admin to log on and a dump ([CA-01](../CA-01-credential-dumping-events/)). `user.name` is set for the Sysinternals rows (NTUSER.DAT owner).
