import os
import platform
import sys

if platform.system() != "Windows":
    print("This helper currently only supports Windows.")
    sys.exit(1)

import ctypes
import shutil
import subprocess
import tkinter as tk
from ctypes import wintypes
from tkinter import messagebox

SYSTEM_FLAG = "--launched-as-system"

# ---------- Privilege helpers ----------

def get_windows_username():
    """
    Get the actual Windows account name from the current token.
    More reliable than environment variables when running under PsExec.
    """
    GetUserNameW = ctypes.windll.advapi32.GetUserNameW
    GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]

    size = wintypes.DWORD(0)
    # First call to get required buffer size
    GetUserNameW(None, ctypes.byref(size))
    buf = ctypes.create_unicode_buffer(size.value)
    if not GetUserNameW(buf, ctypes.byref(size)):
        # Fallback to env if call fails for some reason
        return os.environ.get("USERNAME", "")
    return buf.value


def is_system():
    """
    Return True if this process is running as the LocalSystem account.
    Uses GetUserNameW instead of env vars.
    """
    name = get_windows_username().upper()
    return name == "SYSTEM"


def is_admin():
    """
    Return True if this process has an administrator token
    (SYSTEM will also usually be considered admin).
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """
    Relaunch this script with admin rights using a UAC prompt, then exit.
    """
    script = os.path.abspath(sys.argv[0])
    # Rebuild arg list (excluding python.exe)
    params = ' '.join(f'"{arg}"' for arg in [script] + sys.argv[1:])

    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1
    )

    if int(rc) <= 32:
        messagebox.showerror(
            "Elevation failed",
            "Could not elevate to administrator.\n\n"
            f"Return code: {rc}"
        )
    sys.exit(0)


def relaunch_as_system_via_psexec():
    """
    From an elevated admin process, relaunch this script as SYSTEM
    using PsExec (-i for interactive desktop, -s for LocalSystem).
    """
    script = os.path.abspath(sys.argv[0])

    # 1) Try PATH first
    psexec_path = (
        shutil.which("psexec") or
        shutil.which("PsExec64.exe") or
        shutil.which("PsExec.exe")
    )

    # 2) Then try same folder as the script (e.g. C:\PSTools)
    if not psexec_path:
        base_dir = os.path.dirname(script)
        for fn in ("PsExec64.exe", "PsExec.exe", "psexec.exe"):
            candidate = os.path.join(base_dir, fn)
            if os.path.isfile(candidate):
                psexec_path = candidate
                break

    if not psexec_path:
        messagebox.showerror(
            "PsExec not found",
            "Unable to locate PsExec.\n\n"
            "Make sure PsExec is either in PATH or in the same folder as this script."
        )
        sys.exit(1)

    # Build PsExec command:
    #   psexec -accepteula -i -s python test.py --launched-as-system [other args...]
    args = [psexec_path, "-accepteula", "-i", "-s", sys.executable, script, SYSTEM_FLAG]

    # Pass through existing args (but don't duplicate our flag)
    for a in sys.argv[1:]:
        if a != SYSTEM_FLAG:
            args.append(a)

    try:
        subprocess.Popen(args, close_fds=True)
    except Exception as e:
        messagebox.showerror(
            "PsExec launch failed",
            f"Failed to start SYSTEM instance via PsExec:\n\n{e}"
        )
        sys.exit(1)

    # Admin instance can exit now
    sys.exit(0)


# ---------- Tkinter GUI ----------

def run_gui():
    root = tk.Tk()
    root.title("Tkinter running as SYSTEM")

    env_user = os.environ.get("USERNAME", "Unknown")
    env_domain = os.environ.get("USERDOMAIN", "")
    token_user = get_windows_username()

    env_info = f"Env: {env_domain}\\{env_user}" if env_domain else f"Env: {env_user}"
    token_info = f"Token user: {token_user}"

    tk.Label(root, text="Hello from Tkinter!", font=("Segoe UI", 14)).pack(padx=20, pady=(20, 5))
    tk.Label(root, text=env_info).pack(padx=20, pady=2)
    tk.Label(root, text=token_info).pack(padx=20, pady=2)

    tk.Label(
        root,
        text=f"Is SYSTEM: {is_system()}   |   Is admin: {is_admin()}"
    ).pack(padx=20, pady=(5, 20))

    tk.Button(root, text="Quit", command=root.destroy).pack(pady=(0, 20))

    root.mainloop()


# ---------- Entry point / privilege chain ----------

def main():
    # If the script was explicitly launched from PsExec as SYSTEM, skip the whole chain.
    if SYSTEM_FLAG in sys.argv:
        run_gui()
        return

    # Fallback: if for some reason the flag isn't present but we *are* SYSTEM, also just run.
    if is_system():
        run_gui()
        return

    # Not admin yet → UAC
    if not is_admin():
        relaunch_as_admin()
        return

    # Admin but not SYSTEM → PsExec
    relaunch_as_system_via_psexec()


if __name__ == "__main__":
    main()
