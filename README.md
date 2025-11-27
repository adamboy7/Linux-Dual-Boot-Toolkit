# Linux Dual-Boot Toolkit

This toolkit helps dual-boot users share Bluetooth pairings and Steam libraries between Windows and Linux. It includes cross-platform Bluetooth key managers and a Steam symlink helper so you can avoid re-pairing devices or re-downloading games when switching operating systems.

## Why transfer Bluetooth keys?
Windows and Linux store Bluetooth link keys separately. Without transferring the keys, every reboot into the other OS requires re-pairing headphones, controllers, and other devices. The Linux (`Linux-Bluetooth-GUI.py`) and Windows (`Windows-Bluetooth-GUI.py`) managers export a paired device's link key to JSON on one platform and import it on the other, letting both systems recognize the device immediately.

### Permission model on Windows
Bluetooth link keys live under the system-wide registry path `HKLM\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters` and are only writable by the LocalSystem account. The Windows GUI enforces SYSTEM-level execution and, when launched from an administrator session, re-invokes itself via PsExec so it can access and modify the required registry values (`Keys` and `Devices`). Keep a copy of `PsExec.exe`/`PsExec64.exe` in `PATH` or alongside the script to allow this elevation flow.

### Double-layered backups for Bluetooth keys
The toolkit takes two safety nets before modifying stored keys:

* **JSON export backup** – Every import writes a timestamped `bt_key_backup_<adapter>_<device>_<timestamp>.json` containing the pre-existing key to the current working directory. This mirrors the data used for cross-OS transfers and lets you roll back even if system files are overwritten.
* **System-level snapshot** – The platform-specific storage is also preserved before changes:
  * On Linux, the BlueZ `info` file being edited is copied to `info.<timestamp>.bak` in the same directory.
  * On Windows, the relevant Bluetooth registry hives (`Keys` and `Devices`) are exported to `.reg` files in the working directory alongside the JSON backup.

If an import fails, the tooling attempts to restore from these backups automatically, reducing the risk of losing pairing data.

## Steam Symlink Helper
`Steam-Symlink-Helper.py` links your Windows Steam library (typically on an NTFS partition) into Linux. It scans Windows `steamapps` manifests, then creates symlinks in your Linux `steamapps` folder pointing to the Windows game directories and manifest files. This approach avoids duplicating installs while letting the Linux Steam client see and launch the existing games. A managed-links file tracks what the tool created so you can clean up stale links later. The script offers both a Tkinter GUI and headless flags for automation.

## Repository layout
- `Linux-Bluetooth-GUI.py`: GTK tool for exporting/importing BlueZ link keys on Linux.
- `Windows-Bluetooth-GUI.py`: Tkinter tool for exporting/importing Bluetooth link keys on Windows with SYSTEM and PsExec support.
- `Steam-Symlink-Helper.py`: GUI/CLI helper to mirror a Windows Steam library into Linux via symlinks.
- `libraries/`: Shared logic for Bluetooth parsing, permissions, backup handling, and GUI helpers.

## Usage tips
- Always run the Windows Bluetooth manager with PsExec-enabled SYSTEM rights so registry writes succeed.
- Keep the JSON backups from imports— they are portable between OSes and act as a quick restore point.
- For Steam, point the Windows path to the NTFS-mounted `steamapps` folder; rerun the tool after adding or moving games to refresh the symlinks.
