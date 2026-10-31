# PE-05 Service installation events (System 7045, Security 4697), scored

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1543.003 Windows Service, T1569.002 Service Execution, T1021.002 SMB/Windows Admin Shares |
| Indexes | `evtxlogs-*` |
| Needs | System 7045 and/or Security 4697 (policy "Audit Security System Extension") |
| Roles | all; servers and domain controllers especially |

**What it finds.** Every service installation, scored for PsExec-style and RMM tool services, interpreters or encoded/piped commands in the service command (`%COMSPEC% /c echo ... \| powershell` is a classic Cobalt Strike / Impacket pattern), user-writable or UNC paths, random executables in `\Windows`, and random-looking service names (8 letters, or 16+ letters and digits, as PsExec clones and Metasploit use). Defender's per-update `MpKsl*` driver installs score negative.

**Reading the output.** `svc_cmd` is the service command line. 4697 also gives `SubjectUserName`, the account that installed it; for a remote install, look for a type 3 logon from the same account moments before ([LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/)).

**If it errors.** `Unknown column` on `winlog.payload.event_data.ImagePath` means no System 7045 events were loaded (RD01 had none); on `ServiceFileName`, no 4697. Delete that line from the `COALESCE`.
