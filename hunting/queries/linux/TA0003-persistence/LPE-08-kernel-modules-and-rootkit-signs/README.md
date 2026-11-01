# LPE-08 Kernel modules: out-of-tree and unsigned modules loaded, module commands, and module files outside the module tree

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.006 Kernel Modules and Extensions, T1014 Rootkit |
| Indexes | `logstash-*`, `auditd-*`, `bodyfile-*` |
| Needs | kernel messages in logstash-*, or auditd-*, or bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Kernel modules from every source: kernel messages about out-of-tree, unsigned or proprietary modules tainting the kernel (VirtualBox, VMware and NVIDIA drivers do this too, and so does nearly every kernel rootkit: Diamorphine, Reptile, Suterusu); audit records of module loads and unloads (`KERN_MODULE`, `init_module`, `finit_module`, `delete_module`); `insmod`, `modprobe` and `rmmod` commands; `.ko` files outside `/lib/modules`, `/usr/src` and DKMS; and the files that load modules at boot (`/etc/modules`, `modules-load.d`, `modprobe.d`).

**Reading the output.** Score 3 rows first. A taint message names the module (`<name>: loading out-of-tree module taints kernel`): look it up, and look for the `.ko` file by that name. A module file in `/tmp`, a home folder or `/dev/shm`, a `modules-load.d` file changed in the incident window, or `insmod` of a file from a work folder is a rootkit until shown otherwise. A loaded rootkit hides itself from live tools, but its taint message is written before it can hide, and the bodyfile of an image still lists its file. The `module load configuration` rows (score 0) are context: compare their `ts` with the window.

**If it errors or looks empty.** `Unknown column [file.owner]`: no `bodyfile-*` index exists; remove it and the bodyfile terms. Kernel messages need the journal export or `kern.log` in `logstash-*`.

**Next.** [LPE-06](../LPE-06-ld-preload-and-dynamic-linker-hijacking/) for userland rootkits, [LDE-02](../../TA0112-defense-impairment/LDE-02-security-tools-and-logging-disabled/) for security tooling turned off.
