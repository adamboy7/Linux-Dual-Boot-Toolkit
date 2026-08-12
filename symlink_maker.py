#!/usr/bin/env python3
"""Pick a target file/folder, pick where the link goes, create a symlink."""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox


def main():
    root = tk.Tk()
    root.withdraw()

    is_dir = messagebox.askyesno(
        "Link target",
        "Link to a folder?\n\nYes = folder    No = file",
    )

    if is_dir:
        target = filedialog.askdirectory(title="Select folder to link to", mustexist=True)
    else:
        target = filedialog.askopenfilename(title="Select file to link to")

    if not target:
        return

    target = os.path.abspath(target)

    link = filedialog.asksaveasfilename(
        title="Save link as",
        initialfile=os.path.basename(target.rstrip("\\/")),
        confirmoverwrite=False,
    )
    if not link:
        return

    link = os.path.abspath(link)

    if os.path.lexists(link):
        messagebox.showerror("Error", f"Path already exists:\n{link}")
        return

    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except OSError as e:
        # WinError 1314: SeCreateSymbolicLinkPrivilege not held
        if getattr(e, "winerror", None) == 1314:
            offer_fallback(target, link, is_dir)
        else:
            messagebox.showerror("Error", f"{type(e).__name__}: {e}")
        return

    messagebox.showinfo("Done", f"{link}\n  ->  {target}")


def offer_fallback(target, link, is_dir):
    """No symlink privilege. Junctions (dirs) and hardlinks (files) don't need it."""
    kind = "junction" if is_dir else "hard link"
    msg = (
        "Symlink creation requires Developer Mode or an elevated process.\n\n"
        f"Create a {kind} instead?"
    )
    if not is_dir:
        msg += "\n\n(Hard links only work within the same volume.)"

    if not messagebox.askyesno("Insufficient privilege", msg):
        return

    try:
        if is_dir:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", link, target],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            os.link(target, link)
    except (OSError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", None) or str(e)
        messagebox.showerror("Error", f"Fallback failed:\n{detail}")
        return

    messagebox.showinfo("Done", f"{kind.capitalize()} created:\n{link}\n  ->  {target}")


if __name__ == "__main__":
    if sys.platform != "win32":
        print("Written for Windows, but os.symlink works fine on POSIX too.")
    main()
