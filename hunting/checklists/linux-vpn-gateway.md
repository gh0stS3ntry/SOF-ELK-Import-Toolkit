# Checklist: Linux VPN and remote-access gateway

OpenVPN, WireGuard, strongSwan/IPsec and SSH gateways on Linux that let users into the internal network. Run the [Linux baseline](linux-baseline-all-hosts.md) first. A VPN gateway is where stolen credentials are used to get in, so the questions are which sessions came from outside, whether any account logged in from somewhere it never does, and whether the gateway itself was changed to keep access. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | VPN software, versions and profiles | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LC2-04](../queries/linux/TA0011-command-and-control/LC2-04-hosts-resolver-and-proxy-settings/) | 1.2.1, 1.2.3 | Product and version against known exploited CVEs; server configurations and client profiles on disk. |
| 1.2 | How users authenticate | | 1.3.2 | Ask the client: certificates, passwords, RADIUS/LDAP, MFA. Decides how much a stolen password is worth. |

## 2. Who came in

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Remote logins and VPN sessions from public addresses | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.3, 2.4.4 | Accounts connecting from new countries or hosting providers; OpenVPN peers and their addresses. |
| 2.2 | Password guessing | [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1, 2.4.2 | Spraying and brute force against SSH and PAM-backed VPN logins, success after failures. |
| 2.3 | Session lengths and overlaps | [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) | 2.4.13 | One account connected from two places at once, sessions at hours the user never works. |

## 3. Gateway changed or used to pivot

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | New VPN profiles, keys and certificates | [LC2-04](../queries/linux/TA0011-command-and-control/LC2-04-hosts-resolver-and-proxy-settings/), [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.18 | New client configurations or peers (WireGuard `[Peer]` entries), keys added to admin accounts. |
| 3.2 | Firewall and forwarding changed | [LDE-02](../queries/linux/TA0112-defense-impairment/LDE-02-security-tools-and-logging-disabled/) | 2.4.26 | Firewall rules flushed or disabled, NAT and forwarding opened. |
| 3.3 | Tunnels and scans from the gateway | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/), [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/) | 2.4.4, 2.4.13 | `chisel`, `socat` and SSH tunnels, internal scans, SSH to internal hosts. |
| 3.4 | Exploitation of the gateway | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) | 2.1.1 | Programs in `/tmp` run as root, units added after the exploit. |

## Not covered by these queries

- VPN server logs written to their own files (`openvpn-status.log`, strongSwan `charon.log`) and RADIUS or identity-provider logs: read them from the collection.
- Appliance VPNs (Fortinet, Palo Alto, Ivanti, Cisco): use the vendor's logs and integrity tools.
