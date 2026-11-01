# IM-03 Ransom notes: the same file name in many folders

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1486 Data Encrypted for Impact, T1491.001 Internal Defacement |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all; file servers first |

**What it finds.** Text, HTML, HTA and image files with the same name and (nearly) the same size in 20 or more folders, kept when the name looks like a ransom note or the copies were created in a short burst across 100 or more folders. Wallpaper-style notes (`.bmp`, `.jpg`) are included.

**Reading the output.** `first_created` is when the encryptor reached this volume; compare with [IM-02](../IM-02-mass-file-renames/). Read one note from the collection for the group name, the victim ID and any contact address, which the client's legal and insurance teams will need. `README.txt`-style names that ship with software are usually filtered out by the size and burst checks, but not always.
