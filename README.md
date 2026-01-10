# Linux Dual-Boot Toolkit

## Repository layout
- `Bluetooth-GUI.py`: Cross-platform entry point that launches the Linux or Windows Bluetooth GUI for exporting/importing link keys. Windows version uses Tkinter.
- `Steam-Symlink-Helper.py`: GUI/CLI helper to mirror a Windows Steam library into Linux via symlinks.
- `Media-Sync-Windows.py`: Windows-only Media Sync utility for smart multi-PC media control (tray-based).
- `Media-Sync-Windows-Single.py`: Windows-only Media Sync utility that runs in a single thread (console-based).
- `Media-Sync-Linux.py`: Linux-only Media Sync utility for smart multi-PC media control.
- `libraries/`: Shared logic for Bluetooth parsing, permissions, backup handling, and GUI helpers.


This toolkit helps dual-boot users share Bluetooth pairings and Steam libraries between Windows and Linux. It includes cross-platform Bluetooth key managers and a Steam symlink helper so you can avoid re-pairing devices or re-downloading games when switching operating systems.

## Why transfer Bluetooth keys?
Windows and Linux store Bluetooth link keys separately. Without transferring the keys, every reboot into the other OS requires re-pairing headphones, controllers, and other devices. The cross-platform launcher (`Bluetooth-GUI.py`) dispatches to the Linux (`libraries/gui/linux.py`) or Windows (`libraries/gui/windows.py`) GUI to export a paired device's link key to JSON on one platform and import it on the other, letting both systems recognize the device immediately.

### Double-layered backups for Bluetooth keys
The toolkit takes two safety nets before modifying stored keys:

* **JSON export backup** – Every import writes a timestamped `bt_key_backup_<adapter>_<device>_<timestamp>.json` containing the pre-existing key to the current working directory. This mirrors the data used for cross-OS transfers and lets you roll back even if system files are overwritten.
* **System-level snapshot** – The platform-specific storage is also preserved before changes:
  * On Linux, the BlueZ `info` file being edited is copied to `info.<timestamp>.bak` in the same directory.
  * On Windows, the relevant Bluetooth registry hives (`Keys` and `Devices`) are exported to `.reg` files in the working directory alongside the JSON backup.

If an import fails, the tooling attempts to restore from these backups automatically, reducing the risk of losing pairing data.

### Permission model on Windows
Bluetooth link keys live under the system-wide registry path `HKLM\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters` and are only visible and writable to the LocalSystem account. A standard Administrator account cannot even enumerate those keys, so the Windows GUI enforces SYSTEM-level execution and, when launched from an administrator session, re-invokes itself via PsExec to gain visibility into the `Keys` and `Devices` subkeys before editing. Keep a copy of `PsExec.exe`/`PsExec64.exe` in `PATH` or alongside the script to allow this elevation flow. Download it from [here](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools).

## Steam Symlink Helper
`Steam-Symlink-Helper.py` links your Windows Steam library (typically on an NTFS partition) into Linux. It scans Windows `steamapps` manifests, then creates symlinks in your Linux `steamapps` folder pointing to the Windows game directories and manifest files. Steam on Linux can see an NTFS library with the default driver but often cannot launch games because of permission, metadata, and compatibility differences between Windows and Linux; symlinking allows Steam to read the files natively and rebuild metadata so Proton/Steam Runtime can execute them properly. A managed-links file tracks what the tool created so you can clean up stale links later. The script offers both a GUI and headless flags for automation. For reliability, mount your NTFS partition to a consistent location by adding an entry to `/etc/fstab` and point the helper at that stable mount point.

### Launch options
Headless mode is useful for automation and repeat runs after adding games. The CLI accepts:
- `--linux-steam`: Linux `steamapps` path where symlinks should live (optional; auto-detected if omitted).
- `--win-steam`: Windows NTFS `steamapps` path mounted on Linux (required in headless mode if a path is not already saved).
- `--cleanup`: After syncing, remove stale symlinks in the Linux library.
- `--headless`: Force headless execution even when no other flags are provided; combines with saved defaults.

If you pass any CLI path flags or `--cleanup`, headless mode is implied. Without those flags the GTK GUI launches. Headless runs reuse the last saved GUI defaults when flags are omitted, auto-detect the Linux `steamapps` path if no default exists, and still require either `--win-steam` or a previously saved Windows path.

Example headless sync with cleanup using a stable NTFS mount from `/etc/fstab`:

```bash
python3 Steam-Symlink-Helper.py \
  --linux-steam "$HOME/.local/share/Steam/steamapps" \
  --win-steam /mnt/windows/SteamLibrary/steamapps \
  --cleanup
```

## Media Playback Sync Tool
`Media-Sync-Windows.py` and `Media-Sync-Linux.py` are system tray tools that control playback for two PC's at once, KVM style. One PC is host, the other client. If media is playing on one or more PC's, it automatically pauses. If either PC has paused media it plays. If both PC's have paused media, the tool can be configured to resume host only or both. Remembers the last connected host and auto re-connects unless manually disconnected. On Windows, use `pythonw.exe` to run without the console window, or rename to .pyw.

`Media-Sync-Windows-Single.py` provides a single-threaded, console-based variant for Windows that reuses the same networking and arbitration logic without spawning background threads.


## Usage tips
- Keep `PsExec.exe`/`PsExec64.exe` in your `PATH` on Windows so the GUI can elevate to SYSTEM when needed for registry writes.
- Keep the JSON backups from imports— they are portable between OSes and act as a quick restore point.
- Store your exported Bluetooth key JSONs on a network share or synced storage so updated keys are easy to import on both OSes.
- Mount your Windows partition in `/etc/fstab` so the NTFS library path is stable across boots; add `nofail` if the drive might not always be connected.
- To properly sync your Bluetooth device, first pair your device to either Windows or Linux. Reboot to the other OS, re-sync and pair your device again, then export your device's Bluetooth key. Reboot one last time to the OS you started in, import your recently exported key, and never re-pair your headphones again. Be sure to only export your key after the second pairing; connecting to a new device changes your headphone's internal keys. Going out of order will "break" things.
- It's absolutely possible to use the Bluetooth GUI tool to sync devices between two instances of Windows, two instances of Linux, or even two different computers altogether. Just make sure if multiple devices are involved, they're not in range of one another.
- If you overwrite a key to a device that's actively in use (for some reason), Windows stores the active key in memory even after refreshing. Linux should update immediately after a reload, but Windows will require a reboot.
- Remember to mark the scripts as executable on Linux, that lets you just double click and run my scripts. Scripts will automatically attempt to escalate privileges from any level when necisary.
- To automate Steam syncs at login, run a headless command such as:

  ```bash
  python3 Steam-Symlink-Helper.py --win-steam /mnt/windows/SteamLibrary/steamapps --cleanup
  ```
- Media-Sync works with Keyboard HID style media playback control. Bluetooth based playback usually works on a different driver level and therefore can't be easily intercepted. It causes the wireless playback control to be single system only. Maybe bug, maybe feature ¯\_(ツ)_/¯
