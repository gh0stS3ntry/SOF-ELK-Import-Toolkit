# TRI-05 Installed software, newest first, with rarity across hosts

| | |
|---|---|
| Group | Triage (checklist 2.1.3 Installed software) |
| ATT&CK | T1219 Remote Access Software, T1072 Software Deployment Tools |
| Indexes | `amcache-*` |
| Needs | AmcacheParser `ProgramEntries` |
| Roles | all |

**What it finds.** Every program Amcache recorded as installed, newest first, with how many hosts have the same program (`host_count`) and flags for remote-access tools, dual-use admin tools, installs under user-writable paths, and programs with no publisher.

**Reading the output.** Look at what was installed during the incident window, then at `f_remote_tool` / `f_admin_tool` rows and programs that only one host has. `installed` falls back from `InstallDate` to the MSI date, the ARP key time and finally the Amcache key last write, so treat it as approximate.

**Tuning.** The keyword lists are first-cut lists; add your client's standard tools to exclude them, or new tools to include. Registry `UnInstall` plugin output (`event.dataset: registry.uninstall`) carries the same kind of information per user hive.
