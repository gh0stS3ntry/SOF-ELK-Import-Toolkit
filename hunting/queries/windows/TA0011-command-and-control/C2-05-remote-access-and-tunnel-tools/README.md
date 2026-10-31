# C2-05 Remote access (RMM) and tunnelling tools in execution artifacts

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1219 Remote Access Software, T1572 Protocol Tunneling, T1090 Proxy |
| Indexes | `amcache-*`, `shimcache-*`, `srum-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all |

**What it finds.** About 25 remote-management products that ransomware operators install for persistent access (AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, RustDesk, NetSupport, MeshCentral, Tactical RMM, Action1, SimpleHelp, Radmin, LogMeIn, GoTo, Zoho Assist, DWService, Chrome Remote Desktop) and tunnelling tools (ngrok, cloudflared, chisel, frp, ligolo, gost, plink, Tor), matched by file name and, in Amcache, by PE product name so renamed copies are caught. Tunnels, copies in user-writable folders and tools on one host score higher.

**Reading the output.** Ask the client which RMM product they use; any other one is suspect. Service installs for these tools are in [PE-05](../../TA0003-persistence/PE-05-service-install-events/) and [PE-03](../../TA0003-persistence/PE-03-services-registry-scoring/). AnyDesk and TeamViewer also keep their own connection logs (`ad.trace`, `connections_incoming.txt`) in the collection.
