#!/usr/bin/env python3
"""Symlink maker.

Drop files/folders on the window, or use the buttons. One item lets you name
the link; several items reuse their own names and just ask for a destination
folder. Targets can also be passed as command-line arguments, which is what
Explorer does when you drop onto a shortcut.

Optional: pip install tkinterdnd2   (enables the drop zone)
"""

import errno
import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from urllib.parse import unquote, urlparse

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

IS_WINDOWS = sys.platform == "win32"


# --- pure path helpers -------------------------------------------------------

def normalize_dropped(path):
    """Drop payloads arrive as plain paths or as file:// URIs, depending on the
    source application and platform. Reduce both to an absolute local path."""
    path = path.strip()
    if path.startswith("file://"):
        parsed = urlparse(path)
        path = unquote(parsed.path)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            path = f"//{parsed.netloc}{path}"      # UNC share
        elif IS_WINDOWS and len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]                        # /C:/x -> C:/x
    return os.path.abspath(path)


def relative_target(target, link):
    """Path to target as seen from the link's own directory, or None if the two
    are on different Windows drives."""
    try:
        return os.path.relpath(target, os.path.dirname(link))
    except ValueError:
        return None


def relative_is_useful(target, link):
    """Only worth offering when the pair is reasonably close together."""
    rel = relative_target(target, link)
    return rel is not None and rel.count(".." + os.sep) <= 2


# --- linking -----------------------------------------------------------------

class LinkRunner:
    """Creates one batch of links, remembering the user's fallback decision so a
    twenty-file drop doesn't produce twenty identical prompts."""

    def __init__(self):
        self.fallback_choice = None

    def run(self, targets, link_paths, use_relative):
        made, skipped, failed = [], [], []
        for target, link in zip(targets, link_paths):
            if os.path.lexists(link):
                skipped.append(os.path.basename(link))
                continue
            ok, err = self.create_one(target, link, use_relative)
            (made if ok else failed).append(
                os.path.basename(link) if ok else f"{os.path.basename(link)}: {err}"
            )
        return made, skipped, failed

    def create_one(self, target, link, use_relative):
        is_dir = os.path.isdir(target)
        stored = target
        if use_relative:
            stored = relative_target(target, link) or target

        try:
            os.symlink(stored, link, target_is_directory=is_dir)
            return True, None
        except OSError as e:
            return self.fallback(target, link, is_dir, e)

    def fallback(self, target, link, is_dir, exc):
        kind = "junction" if is_dir else "hard link"

        if IS_WINDOWS and getattr(exc, "winerror", None) == 1314:
            reason = "Symlink creation needs Developer Mode or elevation."
        elif not IS_WINDOWS and exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            if is_dir:
                return False, f"{exc.strerror} (no unprivileged directory link on Linux)"
            reason = exc.strerror
        else:
            return False, str(exc)

        if self.fallback_choice is None:
            note = "" if is_dir else "\n\n(Hard links only work within one filesystem.)"
            self.fallback_choice = messagebox.askyesno(
                "Cannot create symlink",
                f"{reason}\n\nUse a {kind} instead for this batch?{note}",
            )
        if not self.fallback_choice:
            return False, "symlink not permitted"

        try:
            if is_dir:
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", link, target],
                    check=True, capture_output=True, text=True,
                )
            else:
                os.link(target, link)
            return True, None
        except (OSError, subprocess.CalledProcessError) as e:
            return False, (getattr(e, "stderr", None) or str(e)).strip()


# --- gui ---------------------------------------------------------------------

class App:
    def __init__(self):
        self.root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        self.root.title("Symlink Maker")
        self.root.geometry("420x220")
        self.root.minsize(360, 200)

        zone_text = (
            "Drop files or folders here"
            if HAS_DND
            else "Drag and drop unavailable\n(pip install tkinterdnd2)"
        )
        self.zone = tk.Label(
            self.root, text=zone_text, relief="ridge", borderwidth=2,
            justify="center", padx=20, pady=20,
        )
        self.zone.pack(fill="both", expand=True, padx=12, pady=(12, 6))

        row = tk.Frame(self.root)
        row.pack(fill="x", padx=12)
        tk.Button(row, text="Pick file\u2026", command=self.pick_file).pack(
            side="left", expand=True, fill="x", padx=(0, 4))
        tk.Button(row, text="Pick folder\u2026", command=self.pick_folder).pack(
            side="left", expand=True, fill="x", padx=(4, 0))

        self.status = tk.Label(self.root, text="", anchor="w", fg="gray30")
        self.status.pack(fill="x", padx=12, pady=(6, 10))

        if HAS_DND:
            self.zone.drop_target_register(DND_FILES)
            self.zone.dnd_bind("<<Drop>>", self.on_drop)

    def on_drop(self, event):
        # Tcl hands back a list string; braces protect paths containing spaces,
        # so let Tcl split it rather than doing it by hand.
        raw = self.root.tk.splitlist(event.data)
        self.handle([normalize_dropped(p) for p in raw])

    def pick_file(self):
        paths = filedialog.askopenfilenames(title="Select file(s) to link to")
        if paths:
            self.handle([os.path.abspath(p) for p in paths])

    def pick_folder(self):
        path = filedialog.askdirectory(title="Select folder to link to", mustexist=True)
        if path:
            self.handle([os.path.abspath(path)])

    def handle(self, targets):
        targets = [t for t in targets if os.path.exists(t)]
        if not targets:
            self.status.config(text="Nothing usable in that drop.")
            return

        if len(targets) == 1:
            link = self.ask_single_destination(targets[0])
            if not link:
                return
            links = [link]
        else:
            folder = filedialog.askdirectory(
                title=f"Destination folder for {len(targets)} links", mustexist=True)
            if not folder:
                return
            links = [os.path.join(folder, os.path.basename(t.rstrip("\\/")))
                     for t in targets]

        use_relative = False
        if relative_is_useful(targets[0], links[0]):
            use_relative = messagebox.askyesno(
                "Relative links?",
                "Store targets as relative paths?\n\n"
                "Relative links survive the whole tree being moved; absolute "
                "ones survive the link alone being moved.",
            )

        made, skipped, failed = LinkRunner().run(targets, links, use_relative)
        self.report(made, skipped, failed)

    def ask_single_destination(self, target):
        base = os.path.basename(target.rstrip("\\/"))
        link = filedialog.asksaveasfilename(
            title="Save link as",
            initialfile=base,
            initialdir=os.path.dirname(target),
            confirmoverwrite=False,
        )
        return os.path.abspath(link) if link else None

    def report(self, made, skipped, failed):
        self.status.config(
            text=f"{len(made)} created, {len(skipped)} skipped, {len(failed)} failed")
        lines = []
        if made:
            lines.append(f"Created {len(made)}:\n  " + "\n  ".join(made[:12]))
            if len(made) > 12:
                lines.append(f"  \u2026and {len(made) - 12} more")
        if skipped:
            lines.append("Skipped (already exists):\n  " + "\n  ".join(skipped[:8]))
        if failed:
            lines.append("Failed:\n  " + "\n  ".join(failed[:8]))
        body = "\n\n".join(lines) or "Nothing to do."
        (messagebox.showerror if failed else messagebox.showinfo)("Result", body)

    def run(self, initial=None):
        if initial:
            self.status.config(text=f"Received {len(initial)} item(s) on launch\u2026")
            # Force the window to actually exist before a modal dialog opens on
            # top of it, otherwise the dialog can appear behind or off-screen.
            self.root.update_idletasks()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after(50, lambda: self.root.attributes("-topmost", False))
            self.root.after(120, lambda: self.handle(initial))
        self.root.mainloop()


def collect_argv(args):
    """Shell drops arrive as absolute paths in arbitrary order, sometimes with
    duplicates if the selection overlapped. Preserve order, drop repeats."""
    seen, out = set(), []
    for a in args:
        p = os.path.abspath(a)
        key = os.path.normcase(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def install_launcher():
    """Create a drop target you can drag onto: a .lnk on Windows, a .desktop
    entry on Linux. Dropping onto either appends the paths to argv."""
    script = os.path.abspath(__file__)

    if IS_WINDOWS:
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        desktop = os.path.join(os.path.expanduser("~"), "Desktop", "Symlink Maker.lnk")
        ps = (
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}'); "
            "$s.TargetPath = '{exe}'; "
            "$s.Arguments = '\"{script}\"'; "
            "$s.WorkingDirectory = '{cwd}'; "
            "$s.Save()"
        ).format(lnk=desktop, exe=pythonw, script=script,
                 cwd=os.path.dirname(script))
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)
        print(f"Created {desktop}\nDrag files or folders onto it.")
        return

    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Symlink Maker\n"
        f"Exec={sys.executable} \"{script}\" %F\n"
        "Icon=folder-symbolic\n"
        "Terminal=false\n"
        "Categories=Utility;\n"
        "MimeType=inode/directory;application/octet-stream;\n"
    )
    apps = os.path.join(os.path.expanduser("~"), ".local", "share", "applications")
    os.makedirs(apps, exist_ok=True)
    path = os.path.join(apps, "symlink-maker.desktop")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(entry)
    os.chmod(path, 0o755)
    print(f"Created {path}\nCopy it to ~/Desktop and mark it trusted to drop onto it.")


if __name__ == "__main__":
    if "--install-launcher" in sys.argv[1:]:
        install_launcher()
    else:
        App().run(initial=collect_argv(sys.argv[1:]))
