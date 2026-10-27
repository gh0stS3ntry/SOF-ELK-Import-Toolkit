# ES|QL hunting query pack

A first-cut set of ES|QL queries for Windows incident response on SOF-ELK, for data loaded with this toolkit. The queries are grouped by MITRE ATT&CK tactic, each in its own folder with a `query.esql` and a short `README.md` (what it finds, what it needs, how to read the output). The role checklists in [`checklists/`](checklists/) say which queries to run for which kind of host.

The AWS queries under [`queries/aws/`](queries/aws/) do the same for CloudTrail, VPC Flow Logs, ALB/ELB access logs and AWS WAF logs loaded with the importers in [`AWS/`](../AWS/); see [AWS logs](#aws-logs) below.

The Windows pack is built from the queries used in an earlier engagement (RD01) and the IR checklist used to track it, rewritten for the toolkit's field names. It also covers sources RD01 did not have, such as Security 4688 and Sysmon process creation, network and WMI events. Every query passes the static checker below. None has been run against a live cluster as part of this change, so expect to adjust a few field names to what your data actually has.

## Running a query

1. In Kibana, open **Discover**, switch to **ES|QL**, and paste the contents of `query.esql`. Lines starting with `//` are comments and can stay.
2. Set the time picker wide enough to cover the incident (ES|QL in Discover honours it), or add your own `| WHERE @timestamp >= "..."`.
3. Lines marked `// EDIT:` hold a list you are expected to change, such as account names to pivot on or the client's admin accounts.
4. Scored queries sort the strongest rows first. A high score is a lead, not a verdict; each README says what usually explains a false positive.

The queries need Elasticsearch 9.x, because several use `INLINE STATS` and `STATS ... WHERE`. They were written for the 9.4 SOF-ELK VM.

## Conventions

- `FROM <family>-* METADATA _index`, with `_index` in every output, so each row shows which host it came from. Indexes are named `<family>-<hostname>`, for example `evtxlogs-rd01`.
- `KEEP` lists explicit fields, never wildcards.
- `winlog.event_id` is a number: it is compared as `TO_STRING(winlog.event_id)`.
- Paths are compared lower case. In `RLIKE` (Lucene regex), patterns are always anchored, `\d` and `\w` do not exist, and `& @ ~ # < >` must be bracketed. In `LIKE`, a literal backslash is written `\\\\`.
- Query IDs are stable: `TRI` triage, `IA` initial access, `EX` execution, `PE` persistence, `PR` privilege escalation, `CA` credential access, `DI` discovery, `LM` lateral movement, `CO` collection, `EXF` exfiltration, `C2` command and control, `IM` impact, `DE` defense impairment (Defense Evasion in older ATT&CK versions).

## When a query errors

- **`Unknown column [...]`.** ES|QL refuses a field that no index in `FROM` has. A query that reads several event sources (for example 4688, Sysmon 1 and 4104) fails if one of them was never loaded. The README's "If it errors" note says which term to replace with `null` or `""`. Removing an index family you did not load from `FROM` also works.
- **Field with conflicting types.** If the same field is a keyword in one index and a date or number in another (for example after loading an old index made by the original importers), wrap it in `TO_STRING()` or reload the old index with the current importer. `file.update_timestamp` is one such field, and the pack avoids it.
- **No rows.** Check [TRI-01](queries/00-triage/TRI-01-data-coverage/) and [TRI-02](queries/00-triage/TRI-02-event-log-coverage/) first: they list which artifact families, channels and event IDs each host actually has.

## Notes on the data

- `message` on event-log documents holds only `KAPE map used: <map description>`. Queries match the event's own fields (`kape.executable_info`, `winlog.payload.event_data.*`, `winlog.payload.user_data.*`) instead.
- For 4688 and Sysmon 1, `kape.executable_info` is the image followed by the command line. RD01's 254 process-creation events had no command line (the "include command line" policy was off), so command-line queries only see the image there.
- PowerShell 4104 text is in `winlog.payload.event_data.ScriptBlockText`. WMI-Activity 5857-5861 keep their data under `winlog.payload.user_data.Operation_*`.
- WFP 5156/5157: `Direction` `%%14593` is outbound and `%%14592` inbound; `Source*` is always the local host and `Dest*` the remote side. The earlier engagement's port-scan query read `RemoteAddress`/`RemotePorts`, which do not exist in these events (see [DI-01](queries/TA0007-discovery/DI-01-outbound-port-and-host-scan/)).
- `winlog.payload.event_data.string` (unnamed event data, as in System and Application events) only exists when such events were loaded. RD01's collection had none.
- `sum-*` (SumECmd) has no template, so its field names follow the raw CSV columns and are not verified; see [LM-06](queries/TA0008-lateral-movement/LM-06-sum-ual-client-access/).
- Registry plugin output is in `registry.plugin.<snake_case_column>`, batch output in `registry.data.strings` (see `docs/schemas/registry.md`). A query can only see keys your RECmd batch file dumps.

## AWS logs

- Indexes are `aws-cloudtrail-<source>`, `aws-vpcflow-<source>`, `aws-alb-<source>` and `aws-waf-<source>`, where `<source>` is the `--source` label given to the importer (usually the account ID or an evidence label). `_index` in each row says which evidence source it came from.
- Each query names its index family explicitly (`FROM aws-cloudtrail-*`), never `aws-*`: SOF-ELK's own pipeline writes CloudTrail to `aws-YYYY.MM` indexes with a different mapping, and a bare `aws-*` would mix the two.
- Field names follow SOF-ELK's AWS parsing (`aws.cloudtrail.event_name`, `source.ip`, `user.name`, `aws.vpcflow.action`, `aws.elb.*`) plus the toolkit's additions; the field reference is in [`docs/schemas/aws-*.md`](../docs/schemas/). WAF has no SOF-ELK parser, so `aws.waf.*` is the toolkit's own schema.
- CloudTrail request parameters are searchable two ways: a curated set as keywords (`aws.cloudtrail.request_parameters.bucket_name`, `.policy_arn`, ...) and the whole object as JSON text in `aws.cloudtrail.flattened.request_parameters`, which the queries match with `LIKE`/`RLIKE` when a key is not curated.
- VPC Flow records count one direction: `source.bytes` is what the source sent, and `destination.bytes` is always 0, as in SOF-ELK. Queries that need both directions pair the two records.
- Query IDs start with `A`: `ATRI` triage, `AIA` initial access, `AEX` execution, `APE` persistence, `APR` privilege escalation, `ACA` credential access, `ADI` discovery, `ALM` lateral movement, `ACO` collection, `AEXF` exfiltration, `AC2` command and control, `AIM` impact, `ADE` defense impairment.
- Times loaded from a CSV that Excel re-saved lose their seconds (and their time zone, read as UTC). Beaconing and burst queries (AC2-01, ADI-01, AIA-02) are the ones that suffer; reload from the original export when it matters.

## Checking the pack

```
python3 hunting/tools/check_queries.py        # add -v to list each query
```

The checker needs only the Python standard library. It reads the toolkit's index templates and `docs/sofelk-native-fields.csv` and reports unknown field names, raw parser column names, broken conventions, RLIKE and LIKE patterns that Lucene reads differently than intended, missing READMEs, catalog entries and checklist references. Run it after editing any query.

Optionally, the queries can also be checked with Elastic's own ES|QL grammar, which catches syntax errors (bad escapes, reserved words used as names) that the static checker does not:

```
npm install --prefix /tmp/esql @elastic/esql
node hunting/tools/parse_queries.mjs /tmp/esql      # every query.esql under hunting/queries
```

## Checklists

| Checklist | Use for |
|---|---|
| [Baseline: all Windows hosts](checklists/00-baseline-all-windows-hosts.md) | every host, before the role checklist |
| [End-user workstation](checklists/end-user-workstation.md) | laptops, desktops, VDI, jump hosts |
| [Web server](checklists/web-server.md) | IIS, Exchange front end, other internet-facing applications |
| [Database server](checklists/database-server.md) | SQL Server and other database hosts |
| [Domain controller](checklists/domain-controller.md) | AD DS, DNS, and other tier-0 servers |
| [File server](checklists/file-server.md) | file shares, DFS, backup targets |
| [AWS account (CloudTrail)](checklists/aws-account-control-plane.md) | every AWS account in scope |
| [AWS web application (ALB and WAF)](checklists/aws-web-application.md) | applications behind an ALB/ELB and AWS WAF |
| [AWS network (VPC Flow Logs)](checklists/aws-vpc-network.md) | VPCs, subnets and interfaces with flow logs |

`checklists/IR_CHECKLIST_ROLES.xlsx` has the same content with one sheet per role and the tracking columns of the IR checklist (Tasked to, Status, Findings, Handover). Rebuild it after editing a checklist with `python3 hunting/tools/build_checklist_xlsx.py` (needs `openpyxl`).

## Catalog

### Triage (run first)

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [TRI-01](queries/00-triage/TRI-01-data-coverage/) | Data coverage per index | every toolkit index family | all |
| [TRI-02](queries/00-triage/TRI-02-event-log-coverage/) | Event log sources per host | `evtxlogs-*` | all |
| [TRI-03](queries/00-triage/TRI-03-defender-events/) | Microsoft Defender detections, failures and tampering | `evtxlogs-*` | all |
| [TRI-04](queries/00-triage/TRI-04-defender-detections-and-history-purge/) | Defender detections per host per day, with history purges | `evtxlogs-*` | all |
| [TRI-05](queries/00-triage/TRI-05-installed-software/) | Installed software, newest first, with rarity across hosts | `amcache-*` | all |

### TA0001 Initial Access

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [IA-01](queries/TA0001-initial-access/IA-01-logons-from-public-ip/) | Logons and failed logons from public IP addresses | `evtxlogs-*` | all; most important for internet-facing servers, jump hosts and VPN/RDP gateways |
| [IA-02](queries/TA0001-initial-access/IA-02-suspicious-urls/) | Suspicious URLs in browsing history | `browsinghistory-*` | end-user workstation, jump host; servers where admins browse |
| [IA-03](queries/TA0001-initial-access/IA-03-lnk-email-archive-removable/) | Files opened from email attachments, archives, mounted images, removable or network drives | `lnkfiles-*` | end-user workstation, jump host |
| [IA-04](queries/TA0001-initial-access/IA-04-web-app-exploitation-events/) | Web application exploitation signs in the Application and IIS logs | `evtxlogs-*` | web server, Exchange, any server running IIS or a Java/PHP app server |

### TA0002 Execution

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [EX-01](queries/TA0002-execution/EX-01-process-creation-4688/) | Suspicious process creation (Security 4688) | `evtxlogs-*` | all |
| [EX-02](queries/TA0002-execution/EX-02-process-creation-sysmon/) | Suspicious process creation (Sysmon 1) | `evtxlogs-*` | all |
| [EX-03](queries/TA0002-execution/EX-03-rare-parent-child-4688/) | Rare parent and child process pairs (Security 4688) | `evtxlogs-*` | all; most useful with several hosts of the same role |
| [EX-04](queries/TA0002-execution/EX-04-rare-binaries-sysmon/) | Rare binaries by hash (Sysmon 1) | `evtxlogs-*` | all |
| [EX-05](queries/TA0002-execution/EX-05-powershell-unique-commands/) | Unique PowerShell host applications across hosts (long tail) | `evtxlogs-*` | all |
| [EX-06](queries/TA0002-execution/EX-06-powershell-command-timeline/) | PowerShell commands in time order, with user and host application | `evtxlogs-*` | all |
| [EX-07](queries/TA0002-execution/EX-07-powershell-script-blocks/) | Suspicious PowerShell script blocks (4104) | `evtxlogs-*` | all |
| [EX-08](queries/TA0002-execution/EX-08-scripting-interpreters/) | Script interpreter execution across event sources | `evtxlogs-*` | all |
| [EX-09](queries/TA0002-execution/EX-09-wmi-execution/) | Suspicious WMI execution | `evtxlogs-*` | all |
| [EX-10](queries/TA0002-execution/EX-10-amcache-long-tail/) | Amcache executables by rarity (long tail by SHA-1) | `amcache-*` | all |
| [EX-11](queries/TA0002-execution/EX-11-shimcache-long-tail/) | ShimCache executables by rarity (long tail by path) | `shimcache-*` | all |
| [EX-12](queries/TA0002-execution/EX-12-srum-long-tail/) | SRUM applications by rarity, with resource use | `srum-*` | all (SRUM exists on Windows 8+ clients and on servers with the Diagnostic Policy Service running) |
| [EX-13](queries/TA0002-execution/EX-13-prefetch-rare-executables/) | Prefetch: rare executables, low run counts and loads from user-writable paths | `prefetch-*` | end-user workstation; servers only if Prefetch was enabled |
| [EX-14](queries/TA0002-execution/EX-14-clr-usage-unusual-hosts/) | .NET CLR loaded by unusual processes (CLR usage logs) | `clrusagelogs-*` | all |
| [EX-15](queries/TA0002-execution/EX-15-execution-evidence-pivot/) | Execution evidence for named files across Amcache, ShimCache and SRUM (pivot) | `amcache-*`, `shimcache-*`, `srum-*` | all (pivot, not first cut) |
| [EX-16](queries/TA0002-execution/EX-16-userassist-bam/) | Program execution recorded in UserAssist and BAM/DAM | `registry-*` | all; UserAssist matters most on workstations and RDP/jump hosts |
| [EX-17](queries/TA0002-execution/EX-17-runmru-commands/) | Commands typed in the Run dialog (RunMRU) | `registry-*` | end-user workstation, RDP/jump host, any server where admins log on interactively |

### TA0003 Persistence

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [PE-01](queries/TA0003-persistence/PE-01-asep-registry-scoring/) | Autostart (ASEP) registry values, scored | `registry-*` | all |
| [PE-02](queries/TA0003-persistence/PE-02-asep-rarity/) | Autostart (ASEP) registry values by rarity across hosts | `registry-*` | all; most useful across a fleet of similar workstations or servers |
| [PE-03](queries/TA0003-persistence/PE-03-services-registry-scoring/) | Services in the SYSTEM hive, scored (RECmd Services plugin) | `registry-*` | all; servers and domain controllers especially |
| [PE-04](queries/TA0003-persistence/PE-04-services-rarity/) | Services by rarity across hosts (RECmd Services plugin) | `registry-*` | all |
| [PE-05](queries/TA0003-persistence/PE-05-service-install-events/) | Service installation events (System 7045, Security 4697), scored | `evtxlogs-*` | all; servers and domain controllers especially |
| [PE-06](queries/TA0003-persistence/PE-06-scheduled-task-commands/) | Scheduled task creation and changes from the command line or PowerShell | `evtxlogs-*` | all |
| [PE-07](queries/TA0003-persistence/PE-07-task-scheduler-per-task/) | Task Scheduler Operational log summarised per host and task | `evtxlogs-*` | all |
| [PE-08](queries/TA0003-persistence/PE-08-scheduled-task-created-4698/) | Scheduled tasks created, updated or deleted (Security 4698-4702) | `evtxlogs-*` | all |
| [PE-09](queries/TA0003-persistence/PE-09-taskcache-registry/) | Scheduled tasks in the TaskCache registry key, scored by their actions | `registry-*` | all |
| [PE-10](queries/TA0003-persistence/PE-10-hidden-scheduled-tasks/) | Hidden scheduled tasks: TaskCache\Tree entries with no security descriptor | `registry-*` | all |
| [PE-11](queries/TA0003-persistence/PE-11-task-xml-files-mft/) | Scheduled task XML files on disk ($MFT), outside the \Microsoft\ tree | `filesystem-*` | all |
| [PE-12](queries/TA0003-persistence/PE-12-startup-folder/) | Files in Startup folders ($MFT and $J), scored | `filesystem-*` | end-user workstation, RDP/jump host; all hosts for the all-users folder |
| [PE-13](queries/TA0003-persistence/PE-13-winlogon-userinit/) | Extra entries in Winlogon Userinit | `registry-*` | all |
| [PE-14](queries/TA0003-persistence/PE-14-knowndlls/) | KnownDLLs tampering | `registry-*` | all |
| [PE-15](queries/TA0003-persistence/PE-15-wmi-event-subscriptions/) | Permanent WMI event subscriptions | `evtxlogs-*` | all |
| [PE-16](queries/TA0003-persistence/PE-16-account-and-group-changes/) | Local and domain account creation and privileged group changes | `evtxlogs-*` | all; domain controllers for domain accounts and groups |
| [PE-17](queries/TA0003-persistence/PE-17-web-shell-files/) | Script files in web roots: possible web shells | `filesystem-*` | web server, Exchange, SharePoint, any host running IIS, Tomcat, Apache or PHP |
| [PE-18](queries/TA0003-persistence/PE-18-server-process-spawns-shell-4688/) | Web, database or mail server process starting shells and tools (Security 4688) | `evtxlogs-*` | web server, database server, Exchange, any application server |
| [PE-19](queries/TA0003-persistence/PE-19-server-process-spawns-shell-sysmon/) | Web, database or mail server process starting shells and tools (Sysmon 1) | `evtxlogs-*` | web server, database server, Exchange, any application server |
| [PE-20](queries/TA0003-persistence/PE-20-sql-server-config-and-xp-cmdshell/) | SQL Server configuration changes, xp_cmdshell and CLR use | `evtxlogs-*` | database server; any host with a SQL Server Express instance |
| [PE-21](queries/TA0003-persistence/PE-21-gpo-sysvol-scripts-and-tasks/) | Group Policy scripts, scheduled tasks and preferences in SYSVOL | `filesystem-*` | domain controller |

### TA0004 Privilege Escalation

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [PR-01](queries/TA0004-privilege-escalation/PR-01-special-privileges-rare-accounts/) | Accounts given sensitive privileges at logon (Security 4672), by rarity | `evtxlogs-*` | all; domain controllers and servers especially |
| [PR-02](queries/TA0004-privilege-escalation/PR-02-ad-sensitive-changes/) | Sensitive Active Directory and account-control changes | `evtxlogs-*` | domain controller (member servers and workstations log the local-account part) |

### TA0006 Credential Access

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [CA-01](queries/TA0006-credential-access/CA-01-credential-dumping-events/) | OS credential dumping signs in the event logs | `evtxlogs-*` | all; domain controllers for DCSync and NTDS |
| [CA-02](queries/TA0006-credential-access/CA-02-dump-files-mft/) | Credential dump files and dump tools on disk ($MFT) | `filesystem-*` | all; domain controllers for `ntds.dit` copies |
| [CA-03](queries/TA0006-credential-access/CA-03-credential-registry-settings/) | Registry settings that enable or hide credential theft, and tool traces | `registry-*` | all |
| [CA-04](queries/TA0006-credential-access/CA-04-dump-tools-execution-evidence/) | Credential dumping and memory dump tools in Amcache, ShimCache and SRUM | `amcache-*`, `shimcache-*`, `srum-*` | all |
| [CA-05](queries/TA0006-credential-access/CA-05-password-spraying/) | Password spraying: one source failing against many accounts | `evtxlogs-*` | all internet-facing or RDP-exposed hosts, domain controllers |
| [CA-06](queries/TA0006-credential-access/CA-06-brute-force-then-success/) | Brute force against an account followed by a successful logon, and account lockouts | `evtxlogs-*` | all internet-facing or RDP-exposed hosts, domain controllers |
| [CA-07](queries/TA0006-credential-access/CA-07-kerberoasting-and-asrep-roasting/) | Kerberoasting and AS-REP roasting | `evtxlogs-*` | domain controller |
| [CA-08](queries/TA0006-credential-access/CA-08-kerberos-and-ntlm-failures/) | Kerberos and NTLM authentication failures by source and reason | `evtxlogs-*` | domain controller; all hosts for local-account NTLM |
| [CA-09](queries/TA0006-credential-access/CA-09-sql-server-failed-logins/) | SQL Server failed logins (Application 18456), by client and login | `evtxlogs-*` | database server; any host with SQL Server Express exposed to the network |

### TA0007 Discovery

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [DI-01](queries/TA0007-discovery/DI-01-outbound-port-and-host-scan/) | Outbound scanning from a host: many ports or many internal hosts | `evtxlogs-*` | all |
| [DI-02](queries/TA0007-discovery/DI-02-inbound-scan-probes/) | Inbound scan probes: one remote address hitting many local ports | `evtxlogs-*` | all; most useful on servers and domain controllers, which see every internal scanner |
| [DI-03](queries/TA0007-discovery/DI-03-powershell-port-scan/) | Port scanning and network probing with PowerShell or command-line tools | `evtxlogs-*` | all |
| [DI-04](queries/TA0007-discovery/DI-04-user-group-enumeration-4798-4799/) | Local user and group membership enumeration (Security 4798/4799) | `evtxlogs-*` | all |
| [DI-05](queries/TA0007-discovery/DI-05-powershell-user-group-discovery/) | User, group, domain and trust discovery in PowerShell and command lines | `evtxlogs-*` | all |
| [DI-06](queries/TA0007-discovery/DI-06-discovery-command-bursts/) | Bursts of discovery commands from one account | `evtxlogs-*` | all |

### TA0008 Lateral Movement

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [LM-01](queries/TA0008-lateral-movement/LM-01-lateral-movement-methods/) | Lateral movement via RDP, SMB, PsExec-style services, WinRM and WMI | `evtxlogs-*` | all |
| [LM-02](queries/TA0008-lateral-movement/LM-02-portproxy-and-remote-access-settings/) | netsh portproxy rules, RDP enablement and remote-admin settings | `registry-*` | all; jump hosts and internet-facing servers especially |
| [LM-03](queries/TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) | Logon sessions with start, end, duration and admin rights | `evtxlogs-*` | all |
| [LM-04](queries/TA0008-lateral-movement/LM-04-executables-dropped-in-admin-share-paths/) | Executables and scripts created in admin-share reachable folders | `filesystem-*` | all; servers and domain controllers especially |
| [LM-05](queries/TA0008-lateral-movement/LM-05-share-access/) | Network share access by source, account and share, with named pipes | `evtxlogs-*` | file server, domain controller, all servers |
| [LM-06](queries/TA0008-lateral-movement/LM-06-sum-ual-client-access/) | Server client access from User Access Logging (SUM database) | `sum-*` | file server, domain controller, web server, any Windows Server |

### TA0009 Collection

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [CO-01](queries/TA0009-collection/CO-01-archives-and-staged-files/) | Archives and large staged files in user-writable and staging folders | `filesystem-*` | all; file servers and database servers for large staging |
| [CO-02](queries/TA0009-collection/CO-02-mass-copy-bursts/) | Mass copying of documents into one folder (staging bursts) | `filesystem-*` | all; file servers especially |
| [CO-03](queries/TA0009-collection/CO-03-archiver-tools-execution/) | Archiver tools in Amcache, ShimCache and SRUM, with bytes written | `amcache-*`, `shimcache-*`, `srum-*` | all |
| [CO-04](queries/TA0009-collection/CO-04-shellbags-network-removable-and-other-profiles/) | Folders browsed on network shares, removable drives, other profiles and sensitive paths | `shellbag-*` | end-user workstation, RDP/jump host, file server (for admins browsing locally) |
| [CO-05](queries/TA0009-collection/CO-05-jumplist-files-opened/) | Files and folders opened, per application (jump lists) | `jumplist-*` | end-user workstation, RDP/jump host |
| [CO-06](queries/TA0009-collection/CO-06-office-mru-and-recent-docs/) | Recently opened documents (OfficeMRU and RecentDocs) | `registry-*` | end-user workstation, RDP/jump host |

### TA0010 Exfiltration

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [EXF-01](queries/TA0010-exfiltration/EXF-01-usb-devices-registry/) | USB and removable storage devices in the SYSTEM hive, scored | `registry-*` | end-user workstation; servers where console access is in scope |
| [EXF-02](queries/TA0010-exfiltration/EXF-02-usb-devices-amcache/) | Plug and Play devices recorded in Amcache | `amcache-*` | end-user workstation |
| [EXF-03](queries/TA0010-exfiltration/EXF-03-srum-network-usage/) | Network bytes sent and received per application and user (SRUM) | `srum-*` | all with SRUM (clients by default; servers when the Diagnostic Policy Service runs) |
| [EXF-04](queries/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/) | Exfiltration and cloud-transfer tools in execution artifacts | `amcache-*`, `shimcache-*`, `srum-*` | all; file servers and database servers especially |
| [EXF-05](queries/TA0010-exfiltration/EXF-05-file-sharing-site-visits/) | Visits to file-sharing, paste and personal cloud storage sites | `browsinghistory-*` | end-user workstation, RDP/jump host, any server where someone browsed |

### TA0011 Command and Control

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [C2-01](queries/TA0011-command-and-control/C2-01-suspicious-destinations-event-logs/) | Suspicious destinations and beacon-style code in event logs | `evtxlogs-*` | all |
| [C2-02](queries/TA0011-command-and-control/C2-02-motw-zone-identifier/) | Files downloaded from the internet: Zone.Identifier streams (Mark of the Web) | `filesystem-*` | all |
| [C2-03](queries/TA0011-command-and-control/C2-03-browser-downloads/) | Files downloaded through the browser | `browsinghistory-*` | end-user workstation; any server where someone browsed |
| [C2-04](queries/TA0011-command-and-control/C2-04-opensave-mru-files/) | Files chosen in Open/Save dialogs (OpenSaveMRU / OpenSavePidlMRU) | `registry-*` | end-user workstation, RDP/jump host |
| [C2-05](queries/TA0011-command-and-control/C2-05-remote-access-and-tunnel-tools/) | Remote access (RMM) and tunnelling tools in execution artifacts | `amcache-*`, `shimcache-*`, `srum-*` | all |
| [C2-06](queries/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/) | Outbound connections to public addresses, per application (WFP 5156) | `evtxlogs-*` | all |
| [C2-07](queries/TA0011-command-and-control/C2-07-sysmon-network-connections/) | Network connections by process (Sysmon 3), scored | `evtxlogs-*` | all with Sysmon |
| [C2-08](queries/TA0011-command-and-control/C2-08-unique-urls/) | Unique URLs visited | `browsinghistory-*` | all where browsing history was collected |
| [C2-09](queries/TA0011-command-and-control/C2-09-browsing-pivot-named-accounts/) | Browsing history of named accounts (pivot) | `browsinghistory-*` | all (pivot, not first cut) |

### TA0040 Impact

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [IM-01](queries/TA0040-impact/IM-01-inhibit-system-recovery/) | Shadow copy, backup and recovery tampering | `evtxlogs-*` | all; file servers, database servers and backup servers first |
| [IM-02](queries/TA0040-impact/IM-02-mass-file-renames/) | Mass renames to a new extension (encryption bursts) | `filesystem-*` | all; file servers first |
| [IM-03](queries/TA0040-impact/IM-03-ransom-notes/) | Ransom notes: the same file name in many folders | `filesystem-*` | all; file servers first |

### TA0112 Defense Impairment

| ID | Query | Indexes | Roles |
|---|---|---|---|
| [DE-01](queries/TA0112-defense-impairment/DE-01-timestomping/) | Timestomping: `$SI` earlier than `$FN`, zeroed sub-seconds | `filesystem-*` | all |
| [DE-02](queries/TA0112-defense-impairment/DE-02-event-log-clearing/) | Event logs cleared, event log service stopped or disabled | `evtxlogs-*` | all |
| [DE-03](queries/TA0112-defense-impairment/DE-03-defender-exclusions-and-preference-changes/) | Defender exclusions and protection settings changed | `evtxlogs-*` | all |
| [DE-04](queries/TA0112-defense-impairment/DE-04-security-tool-tampering-registry/) | Defender, firewall, logging and security-tool settings in the registry | `registry-*` | all |
| [DE-05](queries/TA0112-defense-impairment/DE-05-firewall-rule-changes-events/) | Windows Firewall rules and settings changed (events) | `evtxlogs-*` | all |
| [DE-06](queries/TA0112-defense-impairment/DE-06-firewall-rules-registry/) | Inbound allow rules and odd programs in the firewall rule list (registry) | `registry-*` | all; servers first |
| [DE-07](queries/TA0112-defense-impairment/DE-07-deleted-executables-usn/) | Executables and scripts deleted (USN `$J`) | `filesystem-*` | all |
| [DE-08](queries/TA0112-defense-impairment/DE-08-recycle-bin-deletions/) | Files sent to the Recycle Bin | `recyclebin-*` | end-user workstation; any host with interactive logons |
| [DE-09](queries/TA0112-defense-impairment/DE-09-masquerading-system-binaries/) | Masquerading: Windows binary names in the wrong folder, and look-alike names | `amcache-*`, `shimcache-*`, `prefetch-*` | all |
| [DE-10](queries/TA0112-defense-impairment/DE-10-audit-policy-and-time-changes/) | Audit policy reduced, system time changed | `evtxlogs-*` | all; domain controllers for policy changes pushed by GPO |

### AWS

The AWS queries, by tactic. Run ATRI-01 first: it shows which AWS log types, accounts and regions were loaded.

#### AWS: Triage (run first)

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ATRI-01](queries/aws/00-triage/ATRI-01-aws-data-coverage/) | AWS data coverage per index: log types, accounts, regions, time range | `aws-cloudtrail-*`, `aws-vpcflow-*`, `aws-alb-*`, `aws-waf-*` | every AWS evidence source |
| [ATRI-02](queries/aws/00-triage/ATRI-02-cloudtrail-principal-inventory/) | CloudTrail principals: who called what, from where, and how often it failed | `aws-cloudtrail-*` | every AWS account |

#### AWS: TA0001 Initial Access

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [AIA-01](queries/aws/TA0001-initial-access/AIA-01-console-logins/) | Console sign-ins: root use, missing MFA and failures, per user and source | `aws-cloudtrail-*` | every AWS account |
| [AIA-02](queries/aws/TA0001-initial-access/AIA-02-console-brute-force/) | Console brute force and password spraying, per source and hour | `aws-cloudtrail-*` | every AWS account with IAM users |
| [AIA-03](queries/aws/TA0001-initial-access/AIA-03-access-key-sources/) | Long-term access keys: source addresses, user agents and tooling per key | `aws-cloudtrail-*` | every AWS account with IAM user access keys |
| [AIA-04](queries/aws/TA0001-initial-access/AIA-04-alb-exploitation-attempts/) | Web exploitation attempts in load balancer logs, scored per client | `aws-alb-*` | internet-facing applications behind an ALB or ELB |
| [AIA-05](queries/aws/TA0001-initial-access/AIA-05-waf-blocked-and-allowed-sources/) | WAF: blocked clients, and what the same clients got through | `aws-waf-*` | internet-facing applications behind AWS WAF |
| [AIA-06](queries/aws/TA0001-initial-access/AIA-06-waf-count-mode-matches/) | WAF rules that matched but did not block (Count mode and labels on allowed requests) | `aws-waf-*` | internet-facing applications behind AWS WAF |

#### AWS: TA0002 Execution

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [AEX-01](queries/aws/TA0002-execution/AEX-01-remote-execution-on-workloads/) | Code run on workloads through AWS APIs: SSM, EC2 user data, Instance Connect, Lambda, ECS, CloudFormation | `aws-cloudtrail-*` | every AWS account with EC2, Lambda or ECS workloads |

#### AWS: TA0003 Persistence

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [APE-01](queries/aws/TA0003-persistence/APE-01-iam-user-and-key-persistence/) | IAM users, access keys, passwords and MFA changes, scored | `aws-cloudtrail-*` | every AWS account |
| [APE-02](queries/aws/TA0003-persistence/APE-02-role-trust-and-federation-backdoors/) | Role trust policies and identity providers that let an outside principal in | `aws-cloudtrail-*` | every AWS account |
| [APE-03](queries/aws/TA0003-persistence/APE-03-alb-web-shell-requests/) | Possible web shells: script files on the load balancer reached by very few clients | `aws-alb-*` | internet-facing applications behind an ALB or ELB |

#### AWS: TA0004 Privilege Escalation

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [APR-01](queries/aws/TA0004-privilege-escalation/APR-01-iam-policy-escalation/) | IAM privilege escalation: admin policies, policy versions and permission boundaries | `aws-cloudtrail-*` | every AWS account |

#### AWS: TA0006 Credential Access

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ACA-01](queries/aws/TA0006-credential-access/ACA-01-secrets-and-parameter-retrieval/) | Secrets Manager, Parameter Store and EC2 password retrieval, per principal | `aws-cloudtrail-*` | every AWS account |
| [ACA-02](queries/aws/TA0006-credential-access/ACA-02-instance-credentials-from-many-sources/) | EC2 instance role credentials used from several source addresses | `aws-cloudtrail-*` | every AWS account with EC2 instances |

#### AWS: TA0007 Discovery

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ADI-01](queries/aws/TA0007-discovery/ADI-01-enumeration-bursts/) | Enumeration bursts: many List, Describe and Get calls across services in a few minutes | `aws-cloudtrail-*` | every AWS account |
| [ADI-02](queries/aws/TA0007-discovery/ADI-02-access-denied-probing/) | Permission probing: AccessDenied and UnauthorizedOperation errors per principal | `aws-cloudtrail-*` | every AWS account |
| [ADI-03](queries/aws/TA0007-discovery/ADI-03-vpc-internal-scanning/) | Internal scanning inside the VPC: one source reaching many hosts or ports | `aws-vpcflow-*` | every VPC with flow logs |
| [ADI-04](queries/aws/TA0007-discovery/ADI-04-vpc-inbound-scans-and-exposure/) | Inbound traffic from the internet: scanners, and what they reached | `aws-vpcflow-*` | every VPC with internet-facing instances or load balancers |

#### AWS: TA0008 Lateral Movement

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ALM-01](queries/aws/TA0008-lateral-movement/ALM-01-role-assumption-and-cross-account/) | Role assumption: who assumed which role, cross-account access and failures | `aws-cloudtrail-*` | every AWS account, and organizations with several accounts |
| [ALM-02](queries/aws/TA0008-lateral-movement/ALM-02-vpc-east-west-admin-protocols/) | East-west administrative connections inside the VPC (SSH, RDP, SMB, WinRM, databases) | `aws-vpcflow-*` | every VPC with flow logs |

#### AWS: TA0009 Collection

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ACO-01](queries/aws/TA0009-collection/ACO-01-s3-data-access-volume/) | S3 object reads and listings per principal, bucket and hour | `aws-cloudtrail-*` | every AWS account holding data in S3 |

#### AWS: TA0010 Exfiltration

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [AEXF-01](queries/aws/TA0010-exfiltration/AEXF-01-resource-sharing-and-public-exposure/) | Snapshots, images, buckets and keys shared with other accounts or made public | `aws-cloudtrail-*` | every AWS account |
| [AEXF-02](queries/aws/TA0010-exfiltration/AEXF-02-vpc-large-outbound-transfers/) | Large outbound transfers from the VPC to public addresses | `aws-vpcflow-*` | every VPC with flow logs |
| [AEXF-03](queries/aws/TA0010-exfiltration/AEXF-03-alb-large-responses/) | Clients that pulled the most data through the load balancer | `aws-alb-*` | internet-facing applications behind an ALB or ELB |

#### AWS: TA0011 Command and Control

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [AC2-01](queries/aws/TA0011-command-and-control/AC2-01-vpc-beaconing/) | Beacon-like outbound connections: one instance, one rare destination, every hour | `aws-vpcflow-*` | every VPC with flow logs |
| [AC2-02](queries/aws/TA0011-command-and-control/AC2-02-vpc-uncommon-outbound-ports/) | Outbound connections on uncommon and known-bad ports (Tor, mining pools, reverse shells) | `aws-vpcflow-*` | every VPC with flow logs |

#### AWS: TA0040 Impact

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [AIM-01](queries/aws/TA0040-impact/AIM-01-destructive-and-resource-hijacking-actions/) | Destructive actions, ransom-style encryption and resource hijacking, per principal and hour | `aws-cloudtrail-*` | every AWS account |

#### AWS: TA0112 Defense Impairment

| ID | Query | Indexes | Applies to |
|---|---|---|---|
| [ADE-01](queries/aws/TA0112-defense-impairment/ADE-01-logging-and-security-tool-tampering/) | Logging and security services stopped, deleted or weakened | `aws-cloudtrail-*` | every AWS account |
| [ADE-02](queries/aws/TA0112-defense-impairment/ADE-02-rare-regions/) | Activity in regions the account rarely uses | `aws-cloudtrail-*` | every AWS account |
| [ADE-03](queries/aws/TA0112-defense-impairment/ADE-03-network-exposure-changes/) | Security groups, network ACLs and routes opened to the internet | `aws-cloudtrail-*` | every AWS account with VPCs |
