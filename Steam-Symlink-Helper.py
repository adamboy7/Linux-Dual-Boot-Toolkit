#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import argparse
import json

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ---------- Config ----------

CONFIG_PATH = Path.home() / ".steam_symlink_manager.json"
LINKS_PATH = Path.home() / ".steam_symlink_manager.links.json"


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(linux_steamapps, windows_steamapps):
    # Preserve any existing keys (like managed_links if we add more later)
    cfg = load_config()
    cfg["linux_steamapps"] = str(linux_steamapps) if linux_steamapps else cfg.get("linux_steamapps", "")
    cfg["windows_steamapps"] = str(windows_steamapps) if windows_steamapps else cfg.get("windows_steamapps", "")
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception as e:
        print(f"[WARN] Failed to save config: {e}")
        return False


# ---------- Managed symlink tracking ----------

def load_managed_links():
    try:
        with open(LINKS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        links = data.get("links", [])
        # Normalize to strings
        return set(str(Path(p)) for p in links)
    except Exception:
        return set()


def save_managed_links(links):
    try:
        data = {"links": sorted(str(Path(p)) for p in links)}
        with open(LINKS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save managed links: {e}")


# ---------- Helpers ----------

def guess_steamapps_candidates():
    home = Path.home()
    candidates = []

    # Common Linux Steam locations
    candidates.append(home / ".steam/steam/steamapps")
    candidates.append(home / ".local/share/Steam/steamapps")

    # Some people use custom library paths under home
    candidates.append(home / "SteamLibrary/steamapps")
    candidates.append(home / "Games/SteamLibrary/steamapps")

    existing = [str(p) for p in candidates if p.is_dir()]
    return existing


def read_installdir_from_acf(acf_path, logger=print):
    """
    Very simple parser: look for a line containing "installdir"
    and grab the next quoted string on that line or the next.
    """
    try:
        with open(acf_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        logger(f"  [WARN] Could not read {acf_path}: {e}")
        return None

    for i, line in enumerate(lines):
        if '"installdir"' in line:
            # example: "\t\t\"installdir\"\t\t\"Game Name\""
            parts = line.split('"')
            # parts: ['', '\t\t', 'installdir', '\t\t', 'Game Name', '"\n']
            if len(parts) >= 6 and parts[5].strip():
                return parts[5].strip()
            if len(parts) >= 4 and parts[3].strip():
                return parts[3].strip()
            # fallback: check next line
            if i + 1 < len(lines):
                nxt = lines[i+1].split('"')
                if len(nxt) >= 4 and nxt[3].strip():
                    return nxt[3].strip()
    return None


def safe_symlink(target, link_path, logger=print):
    """
    Create or maintain a symlink.

    Returns:
        True  -> link is now a symlink pointing at the desired target (either newly created or already correct)
        False -> link was skipped or failed (not managed by this tool)
    """
    link = Path(link_path)
    target = Path(target)

    if link.exists() or link.is_symlink():
        # If it's already a symlink to the right place, mark as managed
        if link.is_symlink():
            try:
                current_target = Path(os.readlink(link))
                if not current_target.is_absolute():
                    current_target = (link.parent / current_target).resolve()
                if current_target == target.resolve():
                    logger(f"  [OK] Symlink already correct: {link}")
                    return True
            except OSError:
                # broken symlink or unreadable target; fall through to creation attempt
                pass
        logger(f"  [SKIP] {link} already exists and is not the expected symlink.")
        return False

    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(str(target.resolve()), str(link))
        logger(f"  [NEW] {link} -> {target}")
        return True
    except Exception as e:
        logger(f"  [ERROR] Failed to create symlink {link} -> {target}: {e}")
        return False


def within_root(path, root):
    """
    Return True if `path` is inside `root` (after resolving symlinks).
    """
    try:
        path = Path(path).resolve()
        root = Path(root).resolve()
        return str(path).startswith(str(root))
    except Exception:
        return False


# ---------- Core actions ----------

def sync_symlinks(linux_steamapps, windows_steamapps, logger=print):
    linux_steamapps = Path(linux_steamapps)
    windows_steamapps = Path(windows_steamapps)

    linux_common = linux_steamapps / "common"
    windows_common = windows_steamapps / "common"

    if not windows_steamapps.is_dir():
        logger(f"[ERROR] Windows steamapps path does not exist: {windows_steamapps}")
        return 1

    if not windows_common.is_dir():
        logger(f"[WARN] Windows 'common' directory not found at {windows_common}")
        logger("       Are you sure you pointed at the steamapps folder?")
        return 1

    linux_common.mkdir(parents=True, exist_ok=True)
    linux_steamapps.mkdir(parents=True, exist_ok=True)

    manifests = sorted(windows_steamapps.glob("appmanifest_*.acf"))
    if not manifests:
        logger(f"[WARN] No appmanifest_*.acf files found in {windows_steamapps}")
        return 1

    managed_links = load_managed_links()

    logger(f"[INFO] Found {len(manifests)} manifest(s) in {windows_steamapps}")
    for manifest in manifests:
        installdir = read_installdir_from_acf(manifest, logger=logger)
        if not installdir:
            logger(f"  [WARN] Could not determine installdir for {manifest.name}, skipping game folder symlink.")
        else:
            win_game_dir = windows_common / installdir
            if not win_game_dir.is_dir():
                logger(f"  [WARN] Game dir doesn't exist for {manifest.name}: {win_game_dir}")
            else:
                linux_game_link = linux_common / installdir
                if safe_symlink(win_game_dir, linux_game_link, logger=logger):
                    managed_links.add(str(linux_game_link))

        linux_manifest_link = linux_steamapps / manifest.name
        if safe_symlink(manifest, linux_manifest_link, logger=logger):
            managed_links.add(str(linux_manifest_link))

    save_managed_links(managed_links)
    logger("[INFO] Sync complete. Restart Steam if it's running.")
    # also keep config's paths up to date
    save_config(linux_steamapps, windows_steamapps)
    return 0


def remove_stale_symlinks(linux_steamapps, windows_steamapps, logger=print):
    linux_steamapps = Path(linux_steamapps)
    windows_steamapps = Path(windows_steamapps)

    if not linux_steamapps.is_dir():
        logger(f"[ERROR] Linux steamapps path does not exist: {linux_steamapps}")
        return 1

    managed_links = load_managed_links()
    if not managed_links:
        logger("[INFO] No managed symlinks recorded; nothing to clean.")
        return 0

    removed = 0
    checked = 0
    kept_links = set()

    for link_str in sorted(managed_links):
        link_path = Path(link_str)
        # Only touch links under the current linux_steamapps root
        if not within_root(link_path, linux_steamapps):
            logger(f"  [SKIP] Managed link outside current linux steamapps root: {link_path}")
            kept_links.add(link_str)
            continue

        checked += 1

        if not (link_path.exists() or link_path.is_symlink()):
            logger(f"  [STALE] Managed link no longer exists: {link_path}")
            # don't keep it
            continue

        if not link_path.is_symlink():
            logger(f"  [SKIP] Managed path is no longer a symlink: {link_path}")
            # stop managing it
            continue

        # Resolve the target
        try:
            target = Path(os.readlink(link_path))
            if not target.is_absolute():
                target = (link_path.parent / target).resolve()
        except OSError:
            logger(f"  [STALE] Managed symlink unreadable: {link_path}")
            try:
                link_path.unlink(missing_ok=True)
            except Exception as e:
                logger(f"  [WARN] Failed to remove broken symlink {link_path}: {e}")
            removed += 1
            continue

        # If the target doesn't exist or is no longer under windows_steamapps, it's stale
        if (not target.exists()) or (not within_root(target, windows_steamapps)):
            logger(f"  [STALE] Target invalid or outside Windows library: {link_path} -> {target}")
            try:
                link_path.unlink(missing_ok=True)
            except Exception as e:
                logger(f"  [WARN] Failed to remove stale symlink {link_path}: {e}")
            removed += 1
        else:
            # Still valid and under the right windows library, keep tracking it
            kept_links.add(str(link_path))

    save_managed_links(kept_links)
    logger(f"[INFO] Checked {checked} managed symlink(s), removed {removed} stale symlink(s).")
    # keep paths current as well
    save_config(linux_steamapps, windows_steamapps)
    return 0


# ---------- Tkinter GUI ----------

class SteamSymlinkGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steam Symlink Manager")

        # Try to load config
        cfg = load_config()
        candidates = guess_steamapps_candidates()
        default_linux = cfg.get("linux_steamapps") or (candidates[0] if candidates else "")

        self.linux_var = tk.StringVar(value=default_linux)
        self.win_var = tk.StringVar(value=cfg.get("windows_steamapps", ""))

        self._build_widgets()

    # Logger that writes to both GUI log and stdout
    def make_logger(self):
        def logger(msg):
            # Print to console as well
            print(msg)
            try:
                self.log_text.configure(state="normal")
                self.log_text.insert("end", msg + "\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            except Exception:
                pass
        return logger

    def _build_widgets(self):
        # Top frame for path entries
        path_frame = tk.Frame(self)
        path_frame.pack(side="top", fill="x", padx=8, pady=8)

        # Linux steamapps
        tk.Label(path_frame, text="Linux steamapps:").grid(row=0, column=0, sticky="w")
        linux_entry = tk.Entry(path_frame, textvariable=self.linux_var, width=60)
        linux_entry.grid(row=0, column=1, sticky="we", padx=4)
        linux_btn = tk.Button(path_frame, text="Browse…", command=self.browse_linux)
        linux_btn.grid(row=0, column=2, sticky="e")

        # Windows steamapps
        tk.Label(path_frame, text="Windows steamapps:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        win_entry = tk.Entry(path_frame, textvariable=self.win_var, width=60)
        win_entry.grid(row=1, column=1, sticky="we", padx=4, pady=(4, 0))
        win_btn = tk.Button(path_frame, text="Browse…", command=self.browse_win)
        win_btn.grid(row=1, column=2, sticky="e", pady=(4, 0))

        path_frame.columnconfigure(1, weight=1)

        # Toolbar frame
        toolbar = tk.Frame(self)
        toolbar.pack(side="top", fill="x", padx=8, pady=(0, 4))

        sync_btn = tk.Button(toolbar, text="Sync Symlinks", command=self.on_sync)
        sync_btn.pack(side="left", padx=(0, 4))

        cleanup_btn = tk.Button(toolbar, text="Cleanup Stale", command=self.on_cleanup)
        cleanup_btn.pack(side="left", padx=(0, 4))

        save_btn = tk.Button(toolbar, text="Save Paths", command=self.on_save)
        save_btn.pack(side="left", padx=(0, 4))

        quit_btn = tk.Button(toolbar, text="Quit", command=self.destroy)
        quit_btn.pack(side="right")

        # Log area
        log_frame = tk.Frame(self)
        log_frame.pack(side="top", fill="both", expand=True, padx=8, pady=(0, 8))

        self.log_text = ScrolledText(log_frame, wrap="word", height=18)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

        # Initial message
        logger = self.make_logger()
        logger("[INFO] GUI ready. Set paths and click 'Sync Symlinks' or 'Cleanup Stale'.")

    def browse_linux(self):
        path = filedialog.askdirectory(title="Select Linux steamapps directory")
        if path:
            self.linux_var.set(path)

    def browse_win(self):
        path = filedialog.askdirectory(title="Select Windows (NTFS) steamapps directory")
        if path:
            self.win_var.set(path)

    def validate_paths(self):
        linux = self.linux_var.get().strip()
        win = self.win_var.get().strip()
        if not linux or not win:
            messagebox.showerror("Error", "Both Linux and Windows steamapps paths are required.")
            return None, None
        return linux, win

    def on_sync(self):
        linux, win = self.validate_paths()
        if not linux:
            return
        logger = self.make_logger()
        logger("[INFO] Running sync…")
        rc = sync_symlinks(linux, win, logger=logger)
        if rc == 0:
            logger("[INFO] Sync finished successfully.")
        else:
            logger("[INFO] Sync completed with warnings or errors (see above).")

    def on_cleanup(self):
        linux, win = self.validate_paths()
        if not linux:
            return
        logger = self.make_logger()
        logger("[INFO] Running cleanup…")
        rc = remove_stale_symlinks(linux, win, logger=logger)
        if rc == 0:
            logger("[INFO] Cleanup finished.")
        else:
            logger("[INFO] Cleanup completed with warnings or errors (see above).")

    def on_save(self):
        linux = self.linux_var.get().strip()
        win = self.win_var.get().strip()
        if not linux or not win:
            messagebox.showerror("Error", "Both paths must be set to save.")
            return
        ok = save_config(linux, win)
        if ok:
            messagebox.showinfo("Saved", f"Paths saved to {CONFIG_PATH}")
        else:
            messagebox.showerror("Error", "Failed to save configuration.")


def run_gui():
    app = SteamSymlinkGUI()
    app.mainloop()


# ---------- CLI entrypoint ----------

def main():
    parser = argparse.ArgumentParser(
        description="Sync Steam libraries via symlinks between Windows (NTFS) and Linux.",
    )
    parser.add_argument(
        "--linux-steam",
        dest="linux_steam",
        help="Path to Linux steamapps directory (where symlinks should live).",
    )
    parser.add_argument(
        "--win-steam",
        dest="win_steam",
        help="Path to Windows (NTFS) steamapps directory (mounted under Linux).",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="After syncing, also remove stale symlinks in the Linux library.",
    )

    args = parser.parse_args()

    # Headless mode: any of these flags mean "do not show GUI, just run"
    headless = bool(args.linux_steam or args.win_steam or args.cleanup)

    if not headless:
        # No useful flags -> launch GUI
        run_gui()
        return

    # Headless mode logic
    # Linux steamapps: use flag if provided, else auto-detect
    linux_steamapps = args.linux_steam
    if not linux_steamapps:
        candidates = guess_steamapps_candidates()
        if candidates:
            linux_steamapps = candidates[0]
            print(f"[INFO] Using detected Linux steamapps: {linux_steamapps}")
        else:
            print("[ERROR] --linux-steam not provided and no steamapps candidates detected.")
            sys.exit(1)

    # Windows steamapps must be explicitly provided
    if not args.win_steam:
        print("[ERROR] --win-steam is required in headless mode.")
        sys.exit(1)

    windows_steamapps = args.win_steam

    print("[INFO] Headless mode:")
    print(f"  Linux steamapps : {linux_steamapps}")
    print(f"  Windows steamapps: {windows_steamapps}")
    print(f"  Cleanup stale symlinks: {'yes' if args.cleanup else 'no'}")

    rc = sync_symlinks(linux_steamapps, windows_steamapps)
    if rc != 0:
        sys.exit(rc)

    if args.cleanup:
        rc2 = remove_stale_symlinks(linux_steamapps, windows_steamapps)
        if rc2 != 0:
            sys.exit(rc2)


if __name__ == "__main__":
    main()
