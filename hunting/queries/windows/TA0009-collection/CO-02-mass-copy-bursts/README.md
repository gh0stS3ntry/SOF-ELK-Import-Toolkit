# CO-02 Mass copying of documents into one folder (staging bursts)

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1074.001 Local Data Staging, T1005 Data from Local System, T1039 Data from Network Shared Drive |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all; file servers especially |

**What it finds.** Ten-minute windows in which 25 or more documents or sensitive files (Office, PDF, mail, key stores, certificates, `.kdbx`, database backups, VPN configs), or 200 or more files of any kind, were created in one user-writable or staging folder. `copied_files` counts files whose `$SI` modified time is older than their creation time, which is what a copy looks like.

**Reading the output.** A high `copy_ratio` in a folder that is not a sync client (OneDrive, Dropbox) or a backup target is staging. `first_file`/`last_file` give a feel for what was copied; list the folder with `| WHERE file.directory == "<dir>"` on `filesystem-*` for the full set.
