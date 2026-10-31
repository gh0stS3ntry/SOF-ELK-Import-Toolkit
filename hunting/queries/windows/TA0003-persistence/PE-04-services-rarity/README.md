# PE-04 Services by rarity across hosts (RECmd Services plugin)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1543.003 Windows Service |
| Indexes | `registry-*` |
| Needs | RECmd `Services` plugin CSV for two or more hosts |
| Roles | all |

**What it finds.** Service binaries (ImagePath + ServiceDll) present on three hosts or fewer, with [PE-03](../PE-03-services-registry-scoring/)'s highest score and reasons, the service names used and the first and last key write.

**Reading the output.** Lateral movement tools often install a service with a different random name on each host but the same binary path, so look for one `img_l` with many `service_names`. Raise or remove `host_count <= 3` for a large fleet.
