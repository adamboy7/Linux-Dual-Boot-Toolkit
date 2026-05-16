from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox, simpledialog
from typing import Optional, Tuple

from .common import APP_NAME, _RESP_HOST_FORWARD, _RESP_HOST_OPEN, _app_icon_path, _is_app_protocol_url, _resource_base_dir

_WIN_PROMPTER = None

# -------------------- Media controller --------------------

class WindowsMediaController:
    async def snapshot(self):
        from winrt.windows.media.control import (
            GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
            GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
        )
        from .common import MediaSnapshot, State
        mgr = await GSMTCManager.request_async()
        session = mgr.get_current_session()
        if session is None:
            return MediaSnapshot(State.NONE)

        playback = session.get_playback_info()
        status = playback.playback_status

        if status == PlaybackStatus.PLAYING:
            s = State.PLAYING
        elif status in (PlaybackStatus.PAUSED, PlaybackStatus.STOPPED):
            s = State.PAUSED
        else:
            s = State.PAUSED

        title = ""
        app = ""
        try:
            props = await session.try_get_media_properties_async()
            if props and props.title:
                title = props.title
        except Exception:
            pass
        try:
            app = session.source_app_user_model_id or ""
        except Exception:
            pass

        return MediaSnapshot(s, app=app, title=title)

    async def command(self, cmd: str) -> bool:
        from winrt.windows.media.control import (
            GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
        )
        mgr = await GSMTCManager.request_async()
        session = mgr.get_current_session()
        if session is None:
            return False
        try:
            if cmd == "play":
                return bool(await session.try_play_async())
            if cmd == "pause":
                return bool(await session.try_pause_async())
            if cmd == "stop":
                return bool(await session.try_stop_async())
        except Exception:
            return False
        return False


# -------------------- Media key hook --------------------

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32
if not hasattr(wintypes, "ULONG_PTR"):
    wintypes.ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
WM_QUIT = 0x0012
VK_MEDIA_STOP = 0xB2
VK_MEDIA_PLAY_PAUSE = 0xB3

_user32.CallNextHookEx.argtypes = (
    wintypes.HHOOK,
    ctypes.c_int,
    wintypes.WPARAM,
    wintypes.LPARAM,
)
_user32.CallNextHookEx.restype = ctypes.c_long


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", wintypes.ULONG_PTR),
    ]


LowLevelKeyboardProc = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)


class WindowsMediaKeyListener:
    def __init__(self, core, swallow: bool = True):
        self._core = core
        self._swallow = swallow
        self._thread = None
        self._hook = None
        self._callback = None
        self._thread_id = None
        self._ready = threading.Event()
        self._stop_evt = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self):
        self._stop_evt.set()
        if self._thread_id:
            _user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=2.0)

    def _handle_vk(self, vk_code: int) -> bool:
        if vk_code == VK_MEDIA_PLAY_PAUSE:
            self._core.ui_toggle(source="hid")
            return True
        if vk_code == VK_MEDIA_STOP:
            self._core.ui_stop_all(source="hid")
            return True
        return False

    def _run(self):
        self._thread_id = _kernel32.GetCurrentThreadId()

        def hook_proc(n_code, w_param, l_param):
            if n_code == 0 and w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                info = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                if self._handle_vk(int(info.vkCode)):
                    if self._swallow:
                        return 1
            return _user32.CallNextHookEx(
                self._hook,
                n_code,
                wintypes.WPARAM(w_param),
                wintypes.LPARAM(l_param),
            )

        self._callback = LowLevelKeyboardProc(hook_proc)
        self._hook = _user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._callback, None, 0)
        self._ready.set()

        msg = wintypes.MSG()
        while not self._stop_evt.is_set():
            result = _user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if result == 0:
                break
            if result == -1:
                break
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))

        if self._hook:
            _user32.UnhookWindowsHookEx(self._hook)
            self._hook = None


# -------------------- Prompt dialogs --------------------

class WinPromptThread:
    def __init__(self):
        self._queue = queue.Queue()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait()

    def _run(self):
        self._root = tk.Tk()
        icon_path = _app_icon_path()
        if os.path.exists(icon_path):
            try:
                self._root.iconbitmap(icon_path)
            except Exception:
                pass
        self._root.withdraw()
        self._ready.set()
        self._root.after(50, self._process_queue)
        self._root.mainloop()

    def _process_queue(self):
        while True:
            try:
                fn, result, done = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                value = fn(self._root)
            except Exception:
                value = None
            result["value"] = value
            done.set()
        self._root.after(50, self._process_queue)

    def _enqueue(self, fn):
        result = {}
        done = threading.Event()
        self._queue.put((fn, result, done))
        done.wait()
        return result.get("value")

    def ask_string(self, prompt: str, initial: str = "") -> Optional[str]:
        return self._enqueue(lambda root: _ask_string_windows(prompt, initial, parent=root))

    def ask_url_confirm(self, url: str, is_ip: bool) -> Optional[dict]:
        return self._enqueue(lambda root: _ask_url_confirm_windows(url, is_ip, parent=root))

    def ask_host_url_confirm(self, url: str, is_ip: bool, client_ip: str) -> Optional[dict]:
        return self._enqueue(lambda root: _ask_host_url_confirm_windows(url, is_ip, client_ip, parent=root))

    def stop(self):
        if self._root:
            self._root.after(0, self._root.quit)


class _IconQueryString(simpledialog._QueryString):
    def __init__(self, title: str, prompt: str, icon_path: str, **kwargs):
        self._icon_path = icon_path
        super().__init__(title, prompt, **kwargs)

    def body(self, master):
        if self._icon_path and os.path.exists(self._icon_path):
            try:
                self.iconbitmap(self._icon_path)
            except Exception:
                pass
        return super().body(master)


def _ask_string_windows(prompt: str, initial: str, parent: Optional[tk.Misc] = None) -> Optional[str]:
    icon_path = _app_icon_path()
    try:
        dialog = _IconQueryString(
            APP_NAME,
            prompt,
            icon_path=icon_path,
            initialvalue=initial,
            parent=parent,
        )
        return dialog.result
    except Exception:
        return simpledialog.askstring(APP_NAME, prompt, initialvalue=initial, parent=parent)


class _WinUrlConfirmDialog(simpledialog.Dialog):
    def __init__(self, parent, url: str, is_ip: bool):
        self.url = url
        self.is_ip = is_ip
        self._accepted = False
        self._trust_domain = tk.BooleanVar(value=False)
        self._trust_session = tk.BooleanVar(value=False)
        self._trust_host = tk.BooleanVar(value=False)
        super().__init__(parent, title=APP_NAME)

    def body(self, master):
        icon_path = _app_icon_path()
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass
        tk.Label(master, text="The host is requesting to open a URL.", anchor="w").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2)
        )
        tk.Label(master, text="Would you like to open:", anchor="w").grid(
            row=1, column=0, sticky="w", padx=8
        )
        tk.Label(master, text=self.url, fg="blue", wraplength=440, anchor="w").grid(
            row=2, column=0, sticky="w", padx=8, pady=(2, 10)
        )
        row = 3
        if not self.is_ip:
            domain_label = "Trust this protocol" if _is_app_protocol_url(self.url) else "Trust this domain"
            tk.Checkbutton(master, text=domain_label, variable=self._trust_domain).grid(
                row=row, column=0, sticky="w", padx=8
            )
            row += 1
        tk.Checkbutton(master, text="Trust this session", variable=self._trust_session).grid(
            row=row, column=0, sticky="w", padx=8
        )
        tk.Checkbutton(master, text="Trust this host", variable=self._trust_host).grid(
            row=row + 1, column=0, sticky="w", padx=8, pady=(0, 8)
        )
        return None

    def buttonbox(self):
        box = tk.Frame(self)
        tk.Button(box, text="Yes", width=8, command=self.ok).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(box, text="No", width=8, command=self.cancel).pack(side=tk.LEFT, padx=5, pady=5)
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def apply(self):
        self._accepted = True

    def get_result(self) -> Optional[dict]:
        if not self._accepted:
            return None
        return {
            "accepted": True,
            "trust_domain": self._trust_domain.get(),
            "trust_session": self._trust_session.get(),
            "trust_host": self._trust_host.get(),
        }


def _ask_url_confirm_windows(url: str, is_ip: bool, parent=None) -> Optional[dict]:
    try:
        dlg = _WinUrlConfirmDialog(parent, url, is_ip)
        return dlg.get_result()
    except Exception:
        return None


class _WinHostUrlConfirmDialog(simpledialog.Dialog):
    def __init__(self, parent, url: str, is_ip: bool, client_ip: str):
        self.url = url
        self.is_ip = is_ip
        self.client_ip = client_ip
        self._was_opened = False
        self._forwarded = False
        self._trust_domain = tk.BooleanVar(value=False)
        self._trust_session = tk.BooleanVar(value=False)
        self._trust_client = tk.BooleanVar(value=False)
        super().__init__(parent, title=APP_NAME)

    def body(self, master):
        icon_path = _app_icon_path()
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass
        tk.Label(master, text=f"Client {self.client_ip} is requesting to open a URL.", anchor="w").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 2)
        )
        tk.Label(master, text=self.url, fg="blue", wraplength=440, anchor="w").grid(
            row=1, column=0, sticky="w", padx=8, pady=(2, 10)
        )
        row = 2
        if not self.is_ip:
            domain_label = "Trust this protocol" if _is_app_protocol_url(self.url) else "Trust this domain"
            tk.Checkbutton(master, text=domain_label, variable=self._trust_domain).grid(
                row=row, column=0, sticky="w", padx=8
            )
            row += 1
        tk.Checkbutton(master, text="Trust this client (session)", variable=self._trust_session).grid(
            row=row, column=0, sticky="w", padx=8
        )
        tk.Checkbutton(master, text="Trust this client (always)", variable=self._trust_client).grid(
            row=row + 1, column=0, sticky="w", padx=8, pady=(0, 8)
        )
        return None

    def buttonbox(self):
        box = tk.Frame(self)
        tk.Button(box, text="Open", width=8, command=self._on_open).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(box, text="Forward", width=8, command=self._on_forward).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(box, text="Cancel", width=8, command=self.cancel).pack(side=tk.LEFT, padx=5, pady=5)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _on_open(self):
        import webbrowser
        webbrowser.open(self.url)
        self._was_opened = True

    def _on_forward(self):
        self._forwarded = True
        self.ok()

    def apply(self):
        pass

    def get_result(self) -> Optional[dict]:
        if not self._was_opened and not self._forwarded:
            return None
        return {
            "forward": self._forwarded,
            "trust_domain": self._trust_domain.get(),
            "trust_session": self._trust_session.get(),
            "trust_client": self._trust_client.get(),
        }


def _ask_host_url_confirm_windows(url: str, is_ip: bool, client_ip: str, parent=None) -> Optional[dict]:
    try:
        dlg = _WinHostUrlConfirmDialog(parent, url, is_ip, client_ip)
        return dlg.get_result()
    except Exception:
        return None


# -------------------- Startup shortcut helpers --------------------

def _windows_startup_dir() -> str:
    appdata = os.getenv("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate Startup folder.")
    return os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")


def _windows_pythonw_path() -> str:
    if sys.executable.lower().endswith("pythonw.exe"):
        return sys.executable
    candidate = os.path.join(sys.exec_prefix, "pythonw.exe")
    if os.path.exists(candidate):
        return candidate
    candidate = sys.executable.replace("python.exe", "pythonw.exe")
    if os.path.exists(candidate):
        return candidate
    raise FileNotFoundError("pythonw.exe not found for Startup shortcut.")


def _vbs_escape(value: str) -> str:
    return value.replace('"', '""')


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ensure_startup_shortcut(script_path: str | None = None) -> Tuple[str, Optional[str]]:
    startup_dir = _windows_startup_dir()
    os.makedirs(startup_dir, exist_ok=True)

    frozen = getattr(sys, "frozen", False)
    icon_path = _app_icon_path()
    if not os.path.exists(icon_path):
        raise FileNotFoundError(f"Icon not found: {icon_path}")

    shortcut_path = os.path.join(startup_dir, f"{APP_NAME}.lnk")
    legacy_vbs_path = os.path.join(startup_dir, f"{APP_NAME}.vbs")
    vbs_path: Optional[str] = None

    for path in (shortcut_path, legacy_vbs_path):
        if os.path.exists(path):
            os.remove(path)

    if frozen:
        target_path = sys.executable
        args_value = ""
        working_dir = os.path.dirname(sys.executable)
    else:
        if script_path is None:
            script_path = os.path.join(_resource_base_dir(), "Media-Sync.py")
        script_dir = os.path.dirname(script_path)
        pythonw_path = _windows_pythonw_path()
        vbs_path = os.path.join(script_dir, f"{APP_NAME}.vbs")
        if os.path.exists(vbs_path):
            os.remove(vbs_path)
        vbs_body = (
            'Set shell = CreateObject("WScript.Shell")\n'
            f'shell.CurrentDirectory = "{_vbs_escape(script_dir)}"\n'
            f'shell.Run """" & "{_vbs_escape(pythonw_path)}" & """ """ & "{_vbs_escape(script_path)}" & """", 0, False\n'
        )
        with open(vbs_path, "w", encoding="utf-8") as handle:
            handle.write(vbs_body)
        target_path = os.path.join(os.getenv("WINDIR", "C:\\Windows"), "System32", "wscript.exe")
        args_value = f'"{vbs_path}"'
        working_dir = script_dir

    ps_script = (
        "$WshShell = New-Object -ComObject WScript.Shell;"
        f"$Shortcut = $WshShell.CreateShortcut({_ps_quote(shortcut_path)});"
        f"$Shortcut.TargetPath = {_ps_quote(target_path)};"
        f"$Shortcut.Arguments = {_ps_quote(args_value)};"
        f"$Shortcut.WorkingDirectory = {_ps_quote(working_dir)};"
        f"$Shortcut.IconLocation = {_ps_quote(icon_path + ',0')};"
        "$Shortcut.Save();"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        check=True,
    )
    return shortcut_path, vbs_path


def _create_shortcut_in_folder(dest_dir: str, script_path: str | None = None) -> str:
    os.makedirs(dest_dir, exist_ok=True)

    frozen = getattr(sys, "frozen", False)
    icon_path = _app_icon_path()
    if not os.path.exists(icon_path):
        raise FileNotFoundError(f"Icon not found: {icon_path}")

    shortcut_path = os.path.join(dest_dir, f"{APP_NAME}.lnk")

    if frozen:
        target_path = sys.executable
        args_value = ""
        working_dir = os.path.dirname(sys.executable)
    else:
        if script_path is None:
            script_path = os.path.join(_resource_base_dir(), "Media-Sync.py")
        script_dir = os.path.dirname(script_path)
        pythonw_path = _windows_pythonw_path()
        vbs_path = os.path.join(script_dir, f"{APP_NAME}.vbs")
        if os.path.exists(vbs_path):
            os.remove(vbs_path)
        vbs_body = (
            'Set shell = CreateObject("WScript.Shell")\n'
            f'shell.CurrentDirectory = "{_vbs_escape(script_dir)}"\n'
            f'shell.Run """" & "{_vbs_escape(pythonw_path)}" & """ """ & "{_vbs_escape(script_path)}" & """", 0, False\n'
        )
        with open(vbs_path, "w", encoding="utf-8") as handle:
            handle.write(vbs_body)
        target_path = os.path.join(os.getenv("WINDIR", "C:\\Windows"), "System32", "wscript.exe")
        args_value = f'"{vbs_path}"'
        working_dir = script_dir

    ps_script = (
        "$WshShell = New-Object -ComObject WScript.Shell;"
        f"$Shortcut = $WshShell.CreateShortcut({_ps_quote(shortcut_path)});"
        f"$Shortcut.TargetPath = {_ps_quote(target_path)};"
        f"$Shortcut.Arguments = {_ps_quote(args_value)};"
        f"$Shortcut.WorkingDirectory = {_ps_quote(working_dir)};"
        f"$Shortcut.IconLocation = {_ps_quote(icon_path + ',0')};"
        "$Shortcut.Save();"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        check=True,
    )
    return shortcut_path
