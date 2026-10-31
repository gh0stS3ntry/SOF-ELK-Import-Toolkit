# DE-08 Files sent to the Recycle Bin

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1070.004 File Deletion |
| Indexes | `recyclebin-*` |
| Needs | RBCmd output (`$I` files, or `INFO2` on old systems) |
| Roles | end-user workstation; any host with interactive logons |

**What it finds.** Every file and folder sent to the Recycle Bin, with the deletion time, the deleting user's SID (`user.id`, from the `$Recycle.Bin\<SID>` folder), original name, folder and size. Flags executables and disk images, archives, known attacker tools and folders.

**Reading the output.** The earlier engagement's query on the template field names (`recyclebin.*`, `file.size`, `user.id`). Map `user.id` to an account with the `ProfileList` key or 4624 events. If the matching `$R` file is still in the collection, it holds the original content. Deletions with Shift+Delete or from the command line bypass the Recycle Bin; see [DE-07](../DE-07-deleted-executables-usn/).
