#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import argparse
import json

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
        path_resolved = Path(path).resolve()
        root_resolved = Path(root).resolve()

        if hasattr(path_resolved, "is_relative_to"):
            return path_resolved.is_relative_to(root_resolved)

        try:
            path_resolved.relative_to(root_resolved)
            return True
        except ValueError:
            return False
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

def run_gui():
    try:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
    except Exception as e:
        print(f"[ERROR] GTK not available: {e}")
        sys.exit(1)

    class SteamSymlinkGTK(Gtk.Window):
        def __init__(self):
            super().__init__(title="Steam Symlink Manager")
            self.set_default_size(720, 480)
            self.set_border_width(10)

            cfg = load_config()
            candidates = guess_steamapps_candidates()
            default_linux = cfg.get("linux_steamapps") or (candidates[0] if candidates else "")

            self.linux_entry = Gtk.Entry(text=default_linux)
            self.win_entry = Gtk.Entry(text=cfg.get("windows_steamapps", ""))

            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.add(outer)

            self._build_path_row(outer)
            self._build_toolbar(outer)
            self._build_log_area(outer)

            self.connect("destroy", Gtk.main_quit)
            self.show_all()

            logger = self.make_logger()
            logger("[INFO] GUI ready. Set paths and click 'Sync Symlinks' or 'Cleanup Stale'.")

        def _build_path_row(self, outer: Gtk.Box):
            grid = Gtk.Grid(column_spacing=8, row_spacing=6)
            outer.pack_start(grid, False, False, 0)

            linux_label = Gtk.Label(label="Linux steamapps:")
            linux_label.set_xalign(0.0)
            grid.attach(linux_label, 0, 0, 1, 1)

            grid.attach(self.linux_entry, 1, 0, 1, 1)
            self.linux_entry.set_hexpand(True)

            linux_btn = Gtk.Button(label="Browse…")
            linux_btn.connect("clicked", self.browse_linux)
            grid.attach(linux_btn, 2, 0, 1, 1)

            win_label = Gtk.Label(label="Windows steamapps:")
            win_label.set_xalign(0.0)
            grid.attach(win_label, 0, 1, 1, 1)

            grid.attach(self.win_entry, 1, 1, 1, 1)
            self.win_entry.set_hexpand(True)

            win_btn = Gtk.Button(label="Browse…")
            win_btn.connect("clicked", self.browse_win)
            grid.attach(win_btn, 2, 1, 1, 1)

        def _build_toolbar(self, outer: Gtk.Box):
            toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            outer.pack_start(toolbar, False, False, 0)

            sync_btn = Gtk.Button(label="Sync Symlinks")
            sync_btn.connect("clicked", self.on_sync)
            toolbar.pack_start(sync_btn, False, False, 0)

            cleanup_btn = Gtk.Button(label="Cleanup Stale")
            cleanup_btn.connect("clicked", self.on_cleanup)
            toolbar.pack_start(cleanup_btn, False, False, 0)

            save_btn = Gtk.Button(label="Save Paths")
            save_btn.connect("clicked", self.on_save)
            toolbar.pack_start(save_btn, False, False, 0)

            toolbar.set_child_packing(save_btn, False, False, 0, Gtk.PackType.START)

            quit_btn = Gtk.Button(label="Quit")
            quit_btn.connect("clicked", self.on_quit)
            toolbar.pack_end(quit_btn, False, False, 0)

        def _build_log_area(self, outer: Gtk.Box):
            frame = Gtk.Frame()
            outer.pack_start(frame, True, True, 0)

            scroller = Gtk.ScrolledWindow()
            scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            frame.add(scroller)

            self.log_view = Gtk.TextView(editable=False, wrap_mode=Gtk.WrapMode.WORD)
            self.log_buffer = self.log_view.get_buffer()
            scroller.add(self.log_view)

        def make_logger(self):
            def logger(msg: str):
                print(msg)
                try:
                    end_iter = self.log_buffer.get_end_iter()
                    self.log_buffer.insert(end_iter, msg + "\n")
                    mark = self.log_buffer.create_mark(None, self.log_buffer.get_end_iter(), False)
                    self.log_view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
                except Exception:
                    pass

            return logger

        def browse_linux(self, _button=None):
            path = self._choose_directory("Select Linux steamapps directory")
            if path:
                self.linux_entry.set_text(path)

        def browse_win(self, _button=None):
            path = self._choose_directory("Select Windows (NTFS) steamapps directory")
            if path:
                self.win_entry.set_text(path)

        def _choose_directory(self, title: str) -> str | None:
            dialog = Gtk.FileChooserDialog(
                title=title,
                parent=self,
                action=Gtk.FileChooserAction.SELECT_FOLDER,
            )
            dialog.add_buttons(
                Gtk.STOCK_CANCEL,
                Gtk.ResponseType.CANCEL,
                Gtk.STOCK_OPEN,
                Gtk.ResponseType.OK,
            )

            response = dialog.run()
            filename = dialog.get_filename() if response == Gtk.ResponseType.OK else None
            dialog.destroy()
            return filename

        def _error_dialog(self, message: str):
            dialog = Gtk.MessageDialog(
                transient_for=self,
                flags=0,
                message_type=Gtk.MessageType.ERROR,
                buttons=Gtk.ButtonsType.OK,
                text="Error",
            )
            dialog.format_secondary_text(message)
            dialog.run()
            dialog.destroy()

        def _info_dialog(self, message: str, title: str = "Info"):
            dialog = Gtk.MessageDialog(
                transient_for=self,
                flags=0,
                message_type=Gtk.MessageType.INFO,
                buttons=Gtk.ButtonsType.OK,
                text=title,
            )
            dialog.format_secondary_text(message)
            dialog.run()
            dialog.destroy()

        def validate_paths(self):
            linux = self.linux_entry.get_text().strip()
            win = self.win_entry.get_text().strip()
            if not linux or not win:
                self._error_dialog("Both Linux and Windows steamapps paths are required.")
                return None, None
            return linux, win

        def on_sync(self, _button=None):
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

        def on_cleanup(self, _button=None):
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

        def on_save(self, _button=None):
            linux = self.linux_entry.get_text().strip()
            win = self.win_entry.get_text().strip()
            if not linux or not win:
                self._error_dialog("Both paths must be set to save.")
                return
            ok = save_config(linux, win)
            if ok:
                self._info_dialog(f"Paths saved to {CONFIG_PATH}", title="Saved")
            else:
                self._error_dialog("Failed to save configuration.")

        def on_quit(self, _button=None):
            # Explicit handler to ensure the application closes cleanly
            self.destroy()
            Gtk.main_quit()

    app = SteamSymlinkGTK()
    Gtk.main()


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
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without GUI using saved defaults when paths are omitted.",
    )

    args = parser.parse_args()

    # Headless mode: command-line paths, cleanup flag, or explicit --headless
    headless = bool(args.headless or args.linux_steam or args.win_steam or args.cleanup)

    if not headless:
        # No useful flags -> launch GUI
        run_gui()
        return

    cfg = load_config()

    # Headless mode logic
    # Linux steamapps: prefer flag, then saved config, then auto-detect
    linux_steamapps = args.linux_steam or cfg.get("linux_steamapps")
    if not linux_steamapps:
        candidates = guess_steamapps_candidates()
        if candidates:
            linux_steamapps = candidates[0]
            print(f"[INFO] Using detected Linux steamapps: {linux_steamapps}")
        else:
            print("[ERROR] --linux-steam not provided and no steamapps candidates detected.")
            sys.exit(1)
    elif args.linux_steam:
        # explicit CLI flag overrides saved defaults
        pass
    else:
        print(f"[INFO] Using saved Linux steamapps: {linux_steamapps}")

    # Windows steamapps: prefer flag, then saved config
    windows_steamapps = args.win_steam or cfg.get("windows_steamapps")
    if not windows_steamapps:
        print("[ERROR] --win-steam not provided and no saved default available.")
        sys.exit(1)
    elif args.win_steam:
        # explicit CLI flag overrides saved defaults
        pass
    else:
        print(f"[INFO] Using saved Windows steamapps: {windows_steamapps}")

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
