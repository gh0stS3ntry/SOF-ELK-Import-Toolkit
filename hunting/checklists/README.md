# Role checklists

A first cut for each kind of host: what to establish about the host, and which queries to run, in order, to scope the investigation and point it in the right direction. They are derived from the IR checklist (`IR_CHECKLIST_ED.xlsx`, sections 1.x, 2.1, 2.3 and 2.4) and from the queries in this pack. The `IR ref` column gives the IR checklist item each row covers.

1. Run the [baseline](00-baseline-all-windows-hosts.md) on every host.
2. Add the checklist for each host's role. A host with several roles (a DC that is also a file server, an RDP server used as a workstation) gets each checklist that applies.
3. Record who did each row, its status and the findings in [`IR_CHECKLIST_ROLES.xlsx`](IR_CHECKLIST_ROLES.xlsx) (one sheet per checklist, same columns as the IR checklist), or in the engagement's own tracker.

| Checklist | Use for |
|---|---|
| [Baseline: all Windows hosts](00-baseline-all-windows-hosts.md) | every host |
| [End-user workstation](end-user-workstation.md) | laptops, desktops, VDI, RDP/jump hosts used interactively |
| [Web server](web-server.md) | IIS, Exchange front end, Tomcat/Apache/PHP, other internet-facing applications |
| [Database server](database-server.md) | SQL Server and other database hosts |
| [Domain controller](domain-controller.md) | AD DS, plus DNS/ADCS/ADFS on tier-0 servers |
| [File server](file-server.md) | file shares, DFS, backup targets, NAS front ends |

**Format.** Each checklist is Markdown with numbered sections (`## 1. ...`) holding one table each, with the columns `#`, `Check`, `Queries`, `IR ref` and `What to look for`. [`build_checklist_xlsx.py`](../tools/build_checklist_xlsx.py) reads that layout, so keep it when editing, then rebuild the workbook:

```
pip install openpyxl
python3 hunting/tools/build_checklist_xlsx.py
```

**Not covered by the pack.** Memory analysis (IR 2.2), live-response output (IR 2.3: `netstat`, `net session`, `ipconfig /displaydns`), IIS/Apache access logs, SQL Server `ERRORLOG` and audit files, firewall/proxy/VPN logs, and email gateway logs are outside what this toolkit loads. The checklists list them where they matter so they are not forgotten.
