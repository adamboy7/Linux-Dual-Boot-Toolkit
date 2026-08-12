#!/usr/bin/env python3
"""Batch archive extractor.

Drop .zip / .7z / .rar files on the window, pick a destination, extract.

  Create sub-folder : each archive gets its own folder named after it.
                      Off, everything merges into the destination directly.
                      Internal folder structure is preserved either way.
  Overwrite         : replace existing files silently. Off, you get a
                      yes / no / yes-to-all / no-to-all prompt per conflict.

Optional backends:  pip install py7zr rarfile
Or install 7-Zip and put 7z on PATH, which covers both formats.
"""

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import zipfile
from tkinter import filedialog, messagebox, ttk
from urllib.parse import unquote, urlparse

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False

try:
    from send2trash import send2trash
    HAS_TRASH = True
except ImportError:
    HAS_TRASH = False

IS_WINDOWS = sys.platform == "win32"
ARCHIVE_EXTS = {".zip", ".7z", ".rar"}

# Conflict resolutions
YES, NO, YES_ALL, NO_ALL, CANCEL = "yes", "no", "yes_all", "no_all", "cancel"


# --- pure helpers ------------------------------------------------------------

def normalize_dropped(path):
    """Drop payloads arrive as plain paths or file:// URIs depending on source."""
    path = path.strip()
    if path.startswith("file://"):
        parsed = urlparse(path)
        path = unquote(parsed.path)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            path = f"//{parsed.netloc}{path}"
        elif IS_WINDOWS and len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
    return os.path.abspath(path)


def archive_stem(path):
    """Folder name for an archive: strip the extension, and the .tar of
    .tar.gz-style names since 7-Zip happily opens those too."""
    base = os.path.basename(path.rstrip("\\/"))
    stem, ext = os.path.splitext(base)
    if ext.lower() in (".gz", ".bz2", ".xz", ".zst") and stem.lower().endswith(".tar"):
        stem = stem[:-4]
    return stem or base


def is_safe_member(name):
    """Reject Zip Slip: absolute paths, drive letters, and parent traversal.

    A malicious archive can carry a member called ../../.ssh/authorized_keys.
    extractall() sanitizes this but we extract member-by-member, so the check
    is ours to make."""
    if not name or name in (".", ".."):
        return False
    norm = name.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        return False
    return ".." not in norm.split("/")


def destination_for(root, member):
    """Absolute path a member will land at, with separators localized."""
    return os.path.normpath(os.path.join(root, member.replace("\\", "/")))


def plan_root(archive, dest, subfolder):
    return os.path.join(dest, archive_stem(archive)) if subfolder else dest


# --- archive backends --------------------------------------------------------

class Member:
    __slots__ = ("name", "is_dir")

    def __init__(self, name, is_dir):
        self.name = name
        self.is_dir = is_dir


class Backend:
    """Two jobs: list members, and extract a chosen subset into a root dir.

    Only a subset is ever needed because conflict decisions are made up front,
    and the internal folder structure is preserved by every backend natively --
    so no per-member path rewriting is required, only per-member selection."""

    def list_members(self):
        raise NotImplementedError

    def extract(self, names, root):
        raise NotImplementedError

    def close(self):
        pass


class ZipBackend(Backend):
    def __init__(self, path):
        self.zf = zipfile.ZipFile(path)

    def list_members(self):
        return [Member(i.filename, i.is_dir()) for i in self.zf.infolist()]

    def extract(self, names, root):
        for name in names:
            info = self.zf.getinfo(name)
            target = destination_for(root, name)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with self.zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

    def close(self):
        self.zf.close()


class RarBackend(Backend):
    def __init__(self, path):
        self.rf = rarfile.RarFile(path)

    def list_members(self):
        return [Member(i.filename, i.isdir()) for i in self.rf.infolist()]

    def extract(self, names, root):
        self.rf.extractall(path=root, members=names)

    def close(self):
        self.rf.close()


class Py7zrBackend(Backend):
    def __init__(self, path):
        self.path = path

    def list_members(self):
        with py7zr.SevenZipFile(self.path) as z:
            return [Member(i.filename, i.is_directory) for i in z.list()]

    def extract(self, names, root):
        # py7zr cannot resume a partially-read handle, so reopen per pass.
        with py7zr.SevenZipFile(self.path) as z:
            z.extract(path=root, targets=list(names))


class SevenZipCliBackend(Backend):
    """Fallback for .7z/.rar via the 7-Zip executable."""

    EXES = ("7z", "7za", "7zz", "7z.exe")

    def __init__(self, path):
        self.path = path
        self.exe = self.find_exe()
        if not self.exe:
            raise RuntimeError("7-Zip not found on PATH")

    @classmethod
    def find_exe(cls):
        for name in cls.EXES:
            found = shutil.which(name)
            if found:
                return found
        if IS_WINDOWS:
            for guess in (r"C:\Program Files\7-Zip\7z.exe",
                          r"C:\Program Files (x86)\7-Zip\7z.exe"):
                if os.path.isfile(guess):
                    return guess
        return None

    def list_members(self):
        out = subprocess.run(
            [self.exe, "l", "-ba", "-slt", self.path],
            capture_output=True, text=True, errors="replace", check=True,
        ).stdout
        members, name, attrs = [], None, ""
        for line in out.splitlines():
            if line.startswith("Path = "):
                if name is not None:
                    members.append(Member(name, "D" in attrs.split()))
                name, attrs = line[7:], ""
            elif line.startswith("Attributes = "):
                attrs = line[13:]
        if name is not None:
            members.append(Member(name, "D" in attrs.split()))
        return members

    def extract(self, names, root):
        os.makedirs(root, exist_ok=True)
        cmd = [self.exe, "x", self.path, f"-o{root}", "-aoa", "-y"]
        listfile = None
        try:
            # Explicit member list, via a response file to dodge command-line
            # length limits on big archives.
            fd, listfile = tempfile.mkstemp(suffix=".txt", text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(names))
            cmd.append(f"@{listfile}")
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            if r.returncode != 0:
                raise RuntimeError((r.stderr or r.stdout).strip()[:300])
        finally:
            if listfile and os.path.exists(listfile):
                os.unlink(listfile)


def open_archive(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".zip":
        return ZipBackend(path)
    if ext == ".rar":
        if HAS_RARFILE:
            try:
                return RarBackend(path)
            except Exception:
                pass  # rarfile present but unrar binary missing
        return SevenZipCliBackend(path)
    if ext == ".7z":
        if HAS_PY7ZR:
            return Py7zrBackend(path)
        return SevenZipCliBackend(path)
    raise RuntimeError(f"unsupported type: {ext}")


# --- extraction job ----------------------------------------------------------

class ExtractJob:
    """Runs the batch. `ask` is a callback returning one of YES/NO/YES_ALL/
    NO_ALL/CANCEL; it is supplied by the GUI and blocks on the main thread."""

    def __init__(self, ask, log, cancel_event=None):
        self.ask = ask
        self.log = log
        self.cancel = cancel_event or threading.Event()
        self.blanket = None  # set once the user picks a *_ALL option

    def run(self, archives, dest, subfolder, overwrite):
        stats = {"extracted": 0, "skipped": 0, "unsafe": 0}
        errors, done = [], []
        for archive in archives:
            if self.cancel.is_set():
                break
            try:
                result = self.do_one(archive, dest, subfolder, overwrite, stats)
                if result["complete"]:
                    done.append(archive)
            except Exception as e:
                errors.append(f"{os.path.basename(archive)}: {e}")
        return stats, errors, done

    def do_one(self, archive, dest, subfolder, overwrite, stats):
        """Returns a per-archive result. `complete` means every file member was
        either written or already present at the destination -- the test for
        whether the archive is redundant and therefore safe to offer to delete."""
        result = {"extracted": 0, "skipped": 0, "unsafe": 0, "complete": False}
        backend = open_archive(archive)
        try:
            root = plan_root(archive, dest, subfolder)
            members = backend.list_members()

            selected, dirs, present = [], [], 0
            for m in members:
                if self.cancel.is_set():
                    return result
                if not is_safe_member(m.name):
                    stats["unsafe"] += 1
                    result["unsafe"] += 1
                    self.log(f"unsafe path rejected: {m.name}")
                    continue
                if m.is_dir:
                    dirs.append(m.name)
                    continue
                target = destination_for(root, m.name)
                if os.path.exists(target) and not overwrite:
                    if not self.allow_overwrite(target):
                        stats["skipped"] += 1
                        result["skipped"] += 1
                        # Declining an overwrite still leaves the content on
                        # disk, so it does not by itself make the archive
                        # non-redundant.
                        present += 1
                        continue
                selected.append(m.name)

            if self.cancel.is_set():
                return result

            # Directory entries are cheap and harmless; keeping them means
            # empty folders in the archive still appear in the output.
            todo = dirs + selected
            if todo:
                os.makedirs(root, exist_ok=True)
                backend.extract(todo, root)
            stats["extracted"] += len(selected)
            result["extracted"] = len(selected)

            # Verify on disk rather than trusting the backend's exit status --
            # this gate decides whether we offer to delete the original.
            files = [m.name for m in members if not m.is_dir and is_safe_member(m.name)]
            result["complete"] = (
                result["unsafe"] == 0
                and not self.cancel.is_set()
                and all(os.path.exists(destination_for(root, n)) for n in files)
            )
            return result
        finally:
            backend.close()

    def allow_overwrite(self, target):
        if self.blanket is not None:
            return self.blanket
        choice = self.ask(target)
        if choice == CANCEL:
            self.cancel.set()
            return False
        if choice == YES_ALL:
            self.blanket = True
            return True
        if choice == NO_ALL:
            self.blanket = False
            return False
        return choice == YES


# --- conflict dialog ---------------------------------------------------------

class ConflictDialog(tk.Toplevel):
    """Modal four-way prompt. tkinter's messagebox tops out at three buttons,
    so this is hand-rolled."""

    def __init__(self, parent, path):
        super().__init__(parent)
        self.title("File already exists")
        self.resizable(False, False)
        self.result = NO
        self.transient(parent)

        folder, name = os.path.split(path)
        tk.Label(self, text="This file already exists:", anchor="w").pack(
            fill="x", padx=16, pady=(14, 2))
        tk.Label(self, text=name, anchor="w", font=("TkDefaultFont", 9, "bold")).pack(
            fill="x", padx=16)
        tk.Label(self, text=folder, anchor="w", fg="gray35",
                 wraplength=440, justify="left").pack(fill="x", padx=16, pady=(0, 4))
        tk.Label(self, text="Overwrite it?", anchor="w").pack(
            fill="x", padx=16, pady=(4, 10))

        row = tk.Frame(self)
        row.pack(fill="x", padx=12, pady=(0, 12))
        for text, value in (("Yes", YES), ("No", NO),
                            ("Yes to all", YES_ALL), ("No to all", NO_ALL)):
            tk.Button(row, text=text, width=10,
                      command=lambda v=value: self.choose(v)).pack(side="left", padx=3)

        self.bind("<Escape>", lambda e: self.choose(CANCEL))
        self.protocol("WM_DELETE_WINDOW", lambda: self.choose(CANCEL))

        self.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        self.geometry(f"+{px + (pw - self.winfo_width()) // 2}"
                      f"+{py + (ph - self.winfo_height()) // 2}")

        self.grab_set()
        self.focus_force()

    def choose(self, value):
        self.result = value
        self.destroy()


# --- gui ---------------------------------------------------------------------

class App:
    def __init__(self):
        self.root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        self.root.title("Archive Extractor")
        self.root.geometry("520x350")
        self.root.minsize(470, 320)

        self.archives = []
        self.dest = None
        self.events = queue.Queue()
        self.worker = None
        self.cancel_event = None

        zone_text = ("Drop .zip / .7z / .rar files here" if HAS_DND
                     else "Drag and drop unavailable\n(pip install tkinterdnd2)")
        self.zone = tk.Label(self.root, text=zone_text, relief="ridge",
                             borderwidth=2, justify="center")
        self.zone.pack(fill="both", expand=True, padx=12, pady=(12, 8))

        opts = tk.Frame(self.root)
        opts.pack(fill="x", padx=14)
        self.subfolder = tk.BooleanVar(value=True)
        self.overwrite = tk.BooleanVar(value=False)
        self.autodelete = tk.BooleanVar(value=False)
        tk.Checkbutton(opts, text="Create sub-folder", variable=self.subfolder).pack(side="left")
        tk.Checkbutton(opts, text="Overwrite", variable=self.overwrite).pack(side="left", padx=(14, 0))
        tk.Checkbutton(opts, text="Delete when done", variable=self.autodelete,
                       command=self.on_autodelete_toggle).pack(side="left", padx=(14, 0))

        row = tk.Frame(self.root)
        row.pack(fill="x", padx=12, pady=(8, 0))
        self.browse_btn = tk.Button(row, text="Add archives\u2026", command=self.browse)
        self.browse_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.go_btn = tk.Button(row, text="Extract\u2026", command=self.start, state="disabled")
        self.go_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        self.bar = ttk.Progressbar(self.root, mode="determinate")
        self.bar.pack(fill="x", padx=12, pady=(8, 0))

        self.status = tk.Label(self.root, text="No archives queued.", anchor="w",
                               justify="left", fg="gray30")
        self.status.pack(fill="x", padx=14, pady=(4, 10))
        # No dedicated button any more, so the destination line is the control.
        self.status.bind("<Button-1>", lambda e: self.archives and self.choose_dest())

        if HAS_DND:
            self.zone.drop_target_register(DND_FILES)
            self.zone.dnd_bind("<<Drop>>", self.on_drop)

        self.root.after(80, self.pump)

    # -- input --
    def on_drop(self, event):
        raw = self.root.tk.splitlist(event.data)
        self.add([normalize_dropped(p) for p in raw])
        # Dropping is the trigger for choosing where things go, but only when
        # nothing has been picked yet -- once a destination is set, adding
        # more archives shouldn't re-prompt. Cancelling the picker leaves the
        # queue intact, so a cancel never costs you the drop.
        if self.archives and not self.dest:
            self.choose_dest()

    def browse(self):
        paths = filedialog.askopenfilenames(
            title="Select archives",
            filetypes=[("Archives", "*.zip *.7z *.rar"), ("All files", "*.*")])
        if paths:
            self.add([os.path.abspath(p) for p in paths])
            if self.archives and not self.dest:
                self.choose_dest()

    def add(self, paths):
        # Duplicates are allowed on purpose: queuing the same archive twice
        # is a legitimate way to re-run an extraction (e.g. to replace files
        # after fixing something at the destination). The run loop guards
        # against the case that actually matters -- a repeat entry whose
        # earlier pass already auto-deleted the source.
        added, rejected = 0, 0
        for p in paths:
            if not os.path.isfile(p):
                continue
            if os.path.splitext(p)[1].lower() not in ARCHIVE_EXTS:
                rejected += 1
                continue
            self.archives.append(p)
            added += 1
        self.refresh()
        if rejected and not added:
            self.status.config(text=f"Ignored {rejected} file(s): not .zip/.7z/.rar")

    def on_autodelete_toggle(self):
        """Ticking this removes the confirmation that normally stands between a
        finished extraction and a gone archive. With send2trash installed that
        is recoverable; without it, it is not -- so the consent moves here, to
        the moment the box is ticked, and is asked once."""
        if not self.autodelete.get() or HAS_TRASH:
            return
        ok = messagebox.askyesno(
            "Delete without asking?",
            "send2trash is not installed, so archives will be deleted "
            "permanently \u2014 not moved to the Recycle Bin \u2014 and you will "
            "not be prompted.\n\nInstall it with:  pip install send2trash"
            "\n\nEnable permanent auto-delete anyway?",
            default="no", icon="warning")
        if not ok:
            self.autodelete.set(False)

    def choose_dest(self):
        start = self.dest or os.path.dirname(self.archives[0]) if self.archives else None
        picked = filedialog.askdirectory(
            title="Extract everything to\u2026", mustexist=True, initialdir=start)
        if picked:
            self.dest = os.path.abspath(picked)
        self.refresh()

    def dest_line(self):
        if not self.dest:
            return ""
        text = self.dest
        if len(text) > 58:
            text = "\u2026" + text[-57:]
        return f" | {text}"

    def refresh(self):
        n = len(self.archives)
        self.go_btn.config(state="normal" if (n and self.dest) else "disabled")
        self.status.config(cursor="hand2" if n else "")
        if not n:
            self.zone.config(text="Drop .zip / .7z / .rar files here" if HAS_DND
                             else "Use Add archives\u2026")
            self.status.config(text="No archives queued.")
            return
        names = [os.path.basename(p) for p in self.archives]
        shown = "\n".join(names[:6]) + (f"\n\u2026and {n - 6} more" if n > 6 else "")
        self.zone.config(text=shown)
        head = (f"{n} archive(s) queued." if self.dest
                else f"{n} archive(s) queued \u2014 click here to set a destination.")
        self.status.config(text=head + self.dest_line())

    # -- run --
    def start(self):
        if self.worker and self.worker.is_alive():
            return
        missing = self.missing_backends()
        if missing:
            messagebox.showerror("Missing backend", missing)
            return

        if not self.dest:
            self.choose_dest()
            if not self.dest:
                return
        dest = self.dest

        self.cancel_event = threading.Event()
        job = ExtractJob(ask=self.ask_conflict,
                         log=lambda m: self.events.put(("log", m)),
                         cancel_event=self.cancel_event)

        archives = list(self.archives)
        subfolder, overwrite = self.subfolder.get(), self.overwrite.get()
        autodelete = self.autodelete.get()
        self.bar.config(maximum=len(archives), value=0)
        self.set_busy(True)

        def work():
            stats = {"extracted": 0, "skipped": 0, "unsafe": 0}
            errors, done, removed, delete_failed = [], [], [], []
            try:
                for i, archive in enumerate(archives, 1):
                    if self.cancel_event.is_set():
                        break
                    self.events.put(("progress", (i - 1, os.path.basename(archive))))
                    if autodelete and not os.path.isfile(archive):
                        # A repeat entry: an earlier pass over this same path
                        # already extracted and auto-deleted it, so there is
                        # nothing left to do here.
                        self.events.put(
                            ("log", f"Already handled: {os.path.basename(archive)}"))
                        self.events.put(("progress", (i, os.path.basename(archive))))
                        continue
                    try:
                        result = job.do_one(archive, dest, subfolder, overwrite, stats)
                        if result["complete"]:
                            done.append(archive)
                            # Delete right away rather than batching at the end
                            # of the whole run: space is reclaimed archive by
                            # archive, and if a later archive errors or the run
                            # is cancelled, everything already deleted is
                            # already the confirmed-safe subset.
                            if autodelete:
                                ok, err = self.delete_one(archive)
                                if ok:
                                    removed.append(archive)
                                    self.events.put(
                                        ("log", f"Deleted {os.path.basename(archive)}"))
                                else:
                                    delete_failed.append(err)
                    except Exception as e:
                        errors.append(f"{os.path.basename(archive)}: {e}")
                    self.events.put(("progress", (i, os.path.basename(archive))))
            finally:
                self.events.put(("done", (stats, errors, dest, done, removed, delete_failed)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def ask_conflict(self, path):
        """Called on the worker thread. Tk is not thread-safe, so the dialog is
        scheduled onto the main loop and this thread blocks until it answers."""
        if threading.current_thread() is threading.main_thread():
            return ConflictDialog(self.root, path).result

        box, done = {}, threading.Event()

        def show():
            try:
                dlg = ConflictDialog(self.root, path)
                self.root.wait_window(dlg)
                box["result"] = dlg.result
            except Exception:
                box["result"] = CANCEL
            finally:
                done.set()

        self.root.after(0, show)
        done.wait()
        return box.get("result", CANCEL)

    def pump(self):
        """Drain worker messages on the main thread."""
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    done, name = payload
                    self.bar.config(value=done)
                    self.status.config(text=f"Extracting {name}\u2026")
                elif kind == "log":
                    self.status.config(text=payload)
                elif kind == "done":
                    self.finish(*payload)
        except queue.Empty:
            pass
        self.root.after(80, self.pump)

    def finish(self, stats, errors, dest, done, removed=None, delete_failed=None):
        removed = list(removed or [])
        delete_failed = delete_failed or []
        self.set_busy(False)
        cancelled = self.cancel_event and self.cancel_event.is_set()
        parts = [f"Extracted {stats.get('extracted', 0)} file(s)."]
        if stats.get("skipped"):
            parts.append(f"Skipped {stats['skipped']} existing file(s).")
        if stats.get("unsafe"):
            parts.append(f"Blocked {stats['unsafe']} unsafe path(s).")
        if cancelled:
            parts.append("Cancelled before finishing.")
        if errors:
            parts.append("\nErrors:\n  " + "\n  ".join(errors[:8]))

        self.status.config(text=parts[0])
        self.bar.config(value=0)
        (messagebox.showerror if errors else messagebox.showinfo)(
            "Result", "\n".join(parts) + f"\n\nDestination:\n{dest}")

        if self.autodelete.get():
            # Deletion already happened per-archive during the run; this is
            # just reporting the outcome.
            if delete_failed:
                messagebox.showerror(
                    "Delete failed",
                    f"Removed {len(removed)}, failed {len(delete_failed)}:\n  "
                    + "\n  ".join(delete_failed[:8]))
            elif removed:
                self.status.config(text=f"Removed {len(removed)} archive(s).")
        else:
            removed = self.offer_delete(done)

        for path in removed:
            if path in self.archives:
                self.archives.remove(path)
        if not errors and not cancelled:
            self.archives.clear()
        self.refresh()

    def offer_delete(self, done):
        """Prompt to remove archives whose every member is confirmed on disk.

        Archives that errored, were cancelled part-way, or contained rejected
        paths never reach here -- those are exactly the cases where the archive
        is still the only copy of something. (Auto-delete mode never calls
        this: it deletes each archive as it finishes instead, see `start`.)"""
        if not done:
            return []

        names = [os.path.basename(p) for p in done]
        listing = "\n  ".join(names[:10])
        if len(names) > 10:
            listing += f"\n  \u2026and {len(names) - 10} more"

        if HAS_TRASH:
            where, verb = "Recycle Bin" if IS_WINDOWS else "Trash", "Move"
            question = (f"{verb} {len(done)} extracted archive(s) to the {where}?"
                        f"\n\n  {listing}")
        else:
            question = (
                f"Permanently delete {len(done)} extracted archive(s)?\n\n  {listing}"
                "\n\nThis cannot be undone. Install send2trash "
                "(pip install send2trash) to use the Recycle Bin instead."
            )

        if not messagebox.askyesno("Delete archives?", question, default="no",
                                   icon="warning"):
            return []
        return self.do_delete(done)

    def delete_one(self, path):
        """Delete/trash a single archive. Safe to call from the worker thread:
        no Tk calls, just filesystem I/O."""
        try:
            if HAS_TRASH:
                send2trash(os.path.normpath(path))
            else:
                os.remove(path)
            return True, None
        except OSError as e:
            return False, f"{os.path.basename(path)}: {e.strerror or e}"

    def do_delete(self, done):
        removed, failed = [], []
        for path in done:
            ok, err = self.delete_one(path)
            if ok:
                removed.append(path)
            else:
                failed.append(err)

        if failed:
            messagebox.showerror(
                "Delete failed",
                f"Removed {len(removed)}, failed {len(failed)}:\n  "
                + "\n  ".join(failed[:8]))
        else:
            self.status.config(text=f"Removed {len(removed)} archive(s).")
        return removed

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.browse_btn.config(state=state)
        self.go_btn.config(state=state if self.archives else "disabled")

    def missing_backends(self):
        exts = {os.path.splitext(p)[1].lower() for p in self.archives}
        need = []
        if ".7z" in exts and not HAS_PY7ZR and not SevenZipCliBackend.find_exe():
            need.append(".7z  ->  pip install py7zr, or install 7-Zip")
        if ".rar" in exts and not HAS_RARFILE and not SevenZipCliBackend.find_exe():
            need.append(".rar ->  pip install rarfile (needs unrar), or install 7-Zip")
        return "No backend available for:\n\n" + "\n".join(need) if need else None

    def run(self, initial=None):
        if initial:
            self.root.after(120, lambda: self.add(initial))
        self.root.mainloop()


if __name__ == "__main__":
    App().run(initial=[os.path.abspath(a) for a in sys.argv[1:]])
