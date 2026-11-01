# IA-01 Logons and failed logons from public IP addresses

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1133 External Remote Services, T1078 Valid Accounts, T1110 Brute Force |
| Indexes | `evtxlogs-*` |
| Needs | Security 4624/4625 (checklist 2.4.4 Attempts from external IP addresses) |
| Roles | all; most important for internet-facing servers, jump hosts and VPN/RDP gateways |

**What it finds.** One row per host and source address that is not private, loopback, link-local or CGNAT: successful and failed logon counts, the accounts that got in, how many accounts were tried, logon types and failure status codes.

**Reading the output.** Rows with `successes > 0` from an address you cannot explain are the first leads. `f_success_after_failures` means the same address failed and then succeeded, the classic brute-force pattern; compare `first_success` with `first_seen`. `f_rdp` marks type 10 (RDP) logons. Status `0xc000006a` is a bad password for a real account, `0xc0000064` a user name that does not exist (spraying with a list).

**Tuning.** If the client's own public ranges (VPN concentrators, NAT egress) appear, add them to `CIDR_MATCH`. NTLM logons through a reverse proxy often show the proxy's address; use [LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) for session durations of the accounts found here.
