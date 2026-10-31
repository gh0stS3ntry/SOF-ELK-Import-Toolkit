# PE-17 Script files in web roots: possible web shells

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell, T1190 Exploit Public-Facing Application |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` and/or `$J` for the web server |
| Roles | web server, Exchange, SharePoint, any host running IIS, Tomcat, Apache or PHP |

**What it finds.** Server-side script files (`.aspx`, `.ashx`, `.asmx`, `.jsp`, `.war`, `.php`, `.cfm` and others, plus `web.config`) under IIS, Exchange OWA/ECP, Java application servers, Apache/nginx/XAMPP, SharePoint and other web roots, from the `$MFT` and from `$J` creations and renames. Scored for web-shell-like names (including 8 hex characters, as dropped by several Exchange exploits), Exchange `auth` and `aspnet_client` folders, `$SI` earlier than `$FN`, names on one host only, small files and recent creation.

**Reading the output.** Sort by `event_time` around the suspected exploitation time instead of score once you have one. Web applications deploy many legitimate pages at install time: a burst of hundreds of files with the same `file.filename.created` second is a deployment, a single new file weeks later is not. Then read the IIS logs for requests to that page (IIS W3C logs are not in this pack; load them with SOF-ELK's native HTTP log pipeline). [PE-18](../PE-18-server-process-spawns-shell-4688/) shows what a web shell ran.
