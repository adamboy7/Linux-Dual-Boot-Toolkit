from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from ctypes import wintypes
from tkinter import filedialog, messagebox, simpledialog
from typing import Optional, Tuple

from .common import (
    APP_NAME,
    _RESP_HOST_FORWARD,
    _RESP_HOST_OPEN,
    _STATE_FILE_LOCK,
    _app_icon_path,
    _atomic_write_json,
    _is_app_protocol_url,
    _load_trusted_clients,
    _load_trusted_domains,
    _load_trusted_hosts,
    _resource_base_dir,
    _strip_pyi_env,
    _trusted_clients_path,
    _trusted_domains_path,
    _trusted_hosts_path,
    load_client_aliases,
)

_WIN_PROMPTER = None
_PROMPTER_LOCK = threading.Lock()

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
        elif status == PlaybackStatus.PAUSED:
            s = State.PAUSED
        elif status == PlaybackStatus.STOPPED:
            s = State.NONE
        else:
            s = State.NONE

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
            if cmd == "next":
                return bool(await session.try_skip_next_async())
            if cmd == "prev":
                return bool(await session.try_skip_previous_async())
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
VK_MEDIA_NEXT_TRACK = 0xB0
VK_MEDIA_PREV_TRACK = 0xB1
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
        if vk_code == VK_MEDIA_NEXT_TRACK:
            self._core.ui_next(source="hid")
            return True
        if vk_code == VK_MEDIA_PREV_TRACK:
            self._core.ui_prev(source="hid")
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
    def __init__(self, init_timeout: float = 5.0):
        self._queue = queue.Queue()
        self._ready = threading.Event()
        self._init_error: Optional[BaseException] = None
        self._root: Optional[tk.Tk] = None
        self._thread = threading.Thread(target=self._run, daemon=True, name="WinPromptThread")
        self._thread.start()
        if not self._ready.wait(timeout=init_timeout):
            raise RuntimeError("WinPromptThread failed to initialize within timeout")
        if self._init_error is not None:
            raise RuntimeError(f"WinPromptThread init failed: {self._init_error}")

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._root is not None)

    def _run(self):
        try:
            self._root = tk.Tk()
            icon_path = _app_icon_path()
            if os.path.exists(icon_path):
                try:
                    self._root.iconbitmap(icon_path)
                except Exception:
                    pass
            self._root.withdraw()
        except BaseException as exc:
            self._init_error = exc
            self._root = None
            self._ready.set()
            return
        self._ready.set()
        self._root.after(50, self._process_queue)
        try:
            self._root.mainloop()
        finally:
            try:
                self._root.destroy()
            except Exception:
                pass
            self._root = None

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

    def ask_url_confirm(self, url: str, is_ip: bool, show_protocol_trust: bool = True, show_peer_trust: bool = True) -> Optional[dict]:
        return self._enqueue(lambda root: _ask_url_confirm_windows(url, is_ip, show_protocol_trust, show_peer_trust, parent=root))

    def ask_host_url_confirm(self, url: str, is_ip: bool, client_ip: str, show_protocol_trust: bool = True, show_peer_trust: bool = True) -> Optional[dict]:
        return self._enqueue(lambda root: _ask_host_url_confirm_windows(url, is_ip, client_ip, show_protocol_trust, show_peer_trust, parent=root))

    def show_kick_dialog(self, peers: dict, kick_fn, get_aliases_fn, set_alias_fn, get_latency_fn=None) -> None:
        self._enqueue(
            lambda root: _show_kick_windows(peers, kick_fn, get_aliases_fn, set_alias_fn, parent=root, get_latency_fn=get_latency_fn)
        )

    def show_trust_manager(self) -> None:
        self._enqueue(lambda root: _show_trust_manager_windows(parent=root))

    def ask_save_file(
        self,
        title: str,
        initialfile: str,
        defaultextension: Optional[str] = None,
    ) -> Optional[str]:
        def _do(root):
            kwargs = dict(title=title, initialfile=initialfile, parent=root)
            if defaultextension:
                kwargs["defaultextension"] = defaultextension
            return filedialog.asksaveasfilename(**kwargs) or None
        return self._enqueue(_do)

    def ask_directory(self, title: str) -> Optional[str]:
        return self._enqueue(
            lambda root: filedialog.askdirectory(title=title, parent=root) or None
        )

    def show_message(self, kind: str, title: str, message: str) -> Optional[bool]:
        def _do(root):
            if kind == "error":
                messagebox.showerror(title, message, parent=root)
                return None
            if kind == "info":
                messagebox.showinfo(title, message, parent=root)
                return None
            if kind == "askyesno":
                return bool(messagebox.askyesno(title, message, parent=root))
            return None
        return self._enqueue(_do)

    def stop(self):
        root = self._root
        if root is not None:
            try:
                root.after(0, root.quit)
            except Exception:
                pass


def get_or_create_prompter() -> Optional["WinPromptThread"]:
    """Return a live WinPromptThread, restarting it if the previous one died."""
    global _WIN_PROMPTER
    with _PROMPTER_LOCK:
        if _WIN_PROMPTER is not None and _WIN_PROMPTER.is_alive():
            return _WIN_PROMPTER
        try:
            _WIN_PROMPTER = WinPromptThread()
        except Exception:
            _WIN_PROMPTER = None
        return _WIN_PROMPTER


def stop_prompter() -> None:
    """Stop and clear the module-level prompter, if any."""
    global _WIN_PROMPTER
    with _PROMPTER_LOCK:
        prompter = _WIN_PROMPTER
        _WIN_PROMPTER = None
    if prompter is None:
        return
    try:
        prompter.stop()
    except Exception:
        pass


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
    def __init__(self, parent, url: str, is_ip: bool, show_protocol_trust: bool = True, show_peer_trust: bool = True):
        self.url = url
        self.is_ip = is_ip
        self._show_protocol_trust = show_protocol_trust
        self._show_peer_trust = show_peer_trust
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
        if not self.is_ip and self._show_protocol_trust:
            domain_label = "Trust this protocol" if _is_app_protocol_url(self.url) else "Trust this domain"
            tk.Checkbutton(master, text=domain_label, variable=self._trust_domain).grid(
                row=row, column=0, sticky="w", padx=8
            )
            row += 1
        if self._show_peer_trust:
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


def _ask_url_confirm_windows(url: str, is_ip: bool, show_protocol_trust: bool = True, show_peer_trust: bool = True, parent=None) -> Optional[dict]:
    try:
        dlg = _WinUrlConfirmDialog(parent, url, is_ip, show_protocol_trust, show_peer_trust)
        return dlg.get_result()
    except Exception:
        return None


class _WinHostUrlConfirmDialog(simpledialog.Dialog):
    def __init__(self, parent, url: str, is_ip: bool, client_ip: str, show_protocol_trust: bool = True, show_peer_trust: bool = True):
        self.url = url
        self.is_ip = is_ip
        self.client_ip = client_ip
        self._show_protocol_trust = show_protocol_trust
        self._show_peer_trust = show_peer_trust
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
        if not self.is_ip and self._show_protocol_trust:
            domain_label = "Trust this protocol" if _is_app_protocol_url(self.url) else "Trust this domain"
            tk.Checkbutton(master, text=domain_label, variable=self._trust_domain).grid(
                row=row, column=0, sticky="w", padx=8
            )
            row += 1
        if self._show_peer_trust:
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


def _ask_host_url_confirm_windows(url: str, is_ip: bool, client_ip: str, show_protocol_trust: bool = True, show_peer_trust: bool = True, parent=None) -> Optional[dict]:
    try:
        dlg = _WinHostUrlConfirmDialog(parent, url, is_ip, client_ip, show_protocol_trust, show_peer_trust)
        return dlg.get_result()
    except Exception:
        return None


# -------------------- Kick clients dialog --------------------

class _WinKickDialog(simpledialog.Dialog):
    def __init__(self, parent, peers: dict, get_aliases_fn, set_alias_fn, get_latency_fn=None):
        self._peers = peers
        self._get_aliases = get_aliases_fn
        self._set_alias = set_alias_fn
        self._get_latency = get_latency_fn or (lambda: {})
        self._live_addrs: list = list(peers.keys())
        self._kicked_addrs: list = []
        super().__init__(parent, title=APP_NAME)

    def body(self, master):
        icon_path = _app_icon_path()
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass
        tk.Label(master, text="Connected clients:", anchor="w").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 2)
        )
        self._listbox = tk.Listbox(master, selectmode=tk.SINGLE, height=8, width=46)
        self._listbox.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 8))
        scrollbar = tk.Scrollbar(master, orient=tk.VERTICAL, command=self._listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 8))
        self._listbox.configure(yscrollcommand=scrollbar.set)
        self._listbox.bind("<Button-3>", self._on_right_click)
        self._rebuild_list()
        self.after(1000, self._tick)
        return self._listbox

    def _rebuild_list(self):
        sel = self._listbox.curselection()
        sel_idx = sel[0] if sel else None
        self._listbox.delete(0, tk.END)
        aliases = self._get_aliases()
        latency = self._get_latency()
        for addr in self._live_addrs:
            ip, port = addr
            alias = aliases.get(ip)
            lat = latency.get(addr)
            suffix = f"  ({int(lat)} ms)" if lat is not None else ""
            label = f"{alias}:{port}{suffix}" if alias else f"{ip}:{port}{suffix}"
            self._listbox.insert(tk.END, label)
        if sel_idx is not None and sel_idx < self._listbox.size():
            self._listbox.selection_set(sel_idx)

    def _tick(self):
        try:
            self._rebuild_list()
            self.after(1000, self._tick)
        except tk.TclError:
            pass

    def buttonbox(self):
        box = tk.Frame(self)
        tk.Button(box, text="Kick", width=8, command=self._on_kick).pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(box, text="Close", width=8, command=self.cancel).pack(side=tk.LEFT, padx=5, pady=5)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _on_kick(self):
        sel = self._listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        addr = self._live_addrs[idx]
        ip, port = addr
        aliases = self._get_aliases()
        display = f"{aliases.get(ip, ip)}:{port}"
        if not messagebox.askyesno(APP_NAME, f"Kick {display}?", parent=self):
            return
        self._kicked_addrs.append(addr)
        self._live_addrs.pop(idx)
        self._rebuild_list()

    def _on_right_click(self, event):
        idx = self._listbox.nearest(event.y)
        if idx < 0 or idx >= len(self._live_addrs):
            return
        self._listbox.selection_clear(0, tk.END)
        self._listbox.selection_set(idx)
        addr = self._live_addrs[idx]
        ip = addr[0]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy IP", command=lambda: self._on_copy_ip(ip))
        menu.add_command(label="Set Alias...", command=lambda: self._on_set_alias(addr))
        menu.tk_popup(event.x_root, event.y_root)

    def _on_copy_ip(self, ip: str):
        self.clipboard_clear()
        self.clipboard_append(ip)

    def _on_set_alias(self, addr):
        ip, _port = addr
        aliases = self._get_aliases()
        current = aliases.get(ip, "")
        new_alias = simpledialog.askstring(
            APP_NAME, f"Set alias for {ip}:", initialvalue=current, parent=self
        )
        if new_alias is None:
            return
        self._set_alias(ip, new_alias)
        self._rebuild_list()

    def apply(self):
        pass

    def get_result(self) -> list:
        return self._kicked_addrs


class _WinTrustManagerDialog(simpledialog.Dialog):
    _PLACEHOLDER = "(Nothing here yet)"

    def __init__(self, parent):
        # Load before super().__init__ because it calls body()
        self._hosts = _load_trusted_hosts()
        self._domains = _load_trusted_domains()
        self._clients = _load_trusted_clients()
        super().__init__(parent, title=APP_NAME)

    def body(self, master):
        icon_path = _app_icon_path()
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        from tkinter import ttk
        notebook = ttk.Notebook(master)
        notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=(4, 0))

        hosts_frame = tk.Frame(notebook)
        notebook.add(hosts_frame, text="Hosts")
        self._hosts_lb = self._make_listbox_tab(hosts_frame, self._on_hosts_right_click)
        self._refresh_hosts()

        url_frame = tk.Frame(notebook)
        notebook.add(url_frame, text="URL")
        self._url_lb = self._make_listbox_tab(url_frame, self._on_url_right_click)
        self._refresh_url()

        clients_frame = tk.Frame(notebook)
        notebook.add(clients_frame, text="Clients")
        self._clients_lb = self._make_listbox_tab(clients_frame, self._on_clients_right_click)
        self._refresh_clients()

        return notebook

    def buttonbox(self):
        box = tk.Frame(self)
        tk.Button(box, text="OK", width=8, command=self.ok).pack(side=tk.LEFT, padx=4, pady=5)
        tk.Button(box, text="Cancel", width=8, command=self.cancel).pack(side=tk.LEFT, padx=4, pady=5)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _make_listbox_tab(self, parent, right_click_handler):
        frame = tk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        lb = tk.Listbox(frame, selectmode=tk.SINGLE, height=10, width=46)
        lb.grid(row=0, column=0, sticky="nsew")
        sb = tk.Scrollbar(frame, orient=tk.VERTICAL, command=lb.yview)
        sb.grid(row=0, column=1, sticky="ns")
        lb.configure(yscrollcommand=sb.set)
        lb.bind("<Button-3>", right_click_handler)
        return lb

    def _refresh_hosts(self):
        self._hosts_lb.delete(0, tk.END)
        if not self._hosts:
            self._hosts_lb.insert(tk.END, self._PLACEHOLDER)
            self._hosts_lb.itemconfig(0, fg="gray")
            return
        aliases = load_client_aliases()
        for ip in self._hosts:
            alias = aliases.get(ip)
            self._hosts_lb.insert(tk.END, f"{alias} ({ip})" if alias else ip)

    def _refresh_url(self):
        self._url_lb.delete(0, tk.END)
        if not self._domains:
            self._url_lb.insert(tk.END, self._PLACEHOLDER)
            self._url_lb.itemconfig(0, fg="gray")
            return
        for domain in self._domains:
            self._url_lb.insert(tk.END, domain)
            if domain == "file":
                self._url_lb.itemconfig(tk.END, fg="red")

    def _refresh_clients(self):
        self._clients_lb.delete(0, tk.END)
        if not self._clients:
            self._clients_lb.insert(tk.END, self._PLACEHOLDER)
            self._clients_lb.itemconfig(0, fg="gray")
            return
        aliases = load_client_aliases()
        for ip in self._clients:
            alias = aliases.get(ip)
            self._clients_lb.insert(tk.END, f"{alias} ({ip})" if alias else ip)

    def _on_hosts_right_click(self, event):
        if not self._hosts:
            return
        idx = self._hosts_lb.nearest(event.y)
        if idx < 0 or idx >= len(self._hosts):
            return
        self._hosts_lb.selection_clear(0, tk.END)
        self._hosts_lb.selection_set(idx)
        ip = self._hosts[idx]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Remove", command=lambda: self._remove_host(idx))
        menu.tk_popup(event.x_root, event.y_root)

    def _remove_host(self, idx: int):
        if idx < len(self._hosts):
            self._hosts.pop(idx)
            self._refresh_hosts()

    def _on_url_right_click(self, event):
        if not self._domains:
            return
        idx = self._url_lb.nearest(event.y)
        if idx < 0 or idx >= len(self._domains):
            return
        self._url_lb.selection_clear(0, tk.END)
        self._url_lb.selection_set(idx)
        domain = self._domains[idx]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Remove", command=lambda: self._remove_domain(idx))
        menu.tk_popup(event.x_root, event.y_root)

    def _remove_domain(self, idx: int):
        if idx < len(self._domains):
            self._domains.pop(idx)
            self._refresh_url()

    def _on_clients_right_click(self, event):
        if not self._clients:
            return
        idx = self._clients_lb.nearest(event.y)
        if idx < 0 or idx >= len(self._clients):
            return
        self._clients_lb.selection_clear(0, tk.END)
        self._clients_lb.selection_set(idx)
        ip = self._clients[idx]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Remove", command=lambda: self._remove_client(idx))
        menu.tk_popup(event.x_root, event.y_root)

    def _remove_client(self, idx: int):
        if idx < len(self._clients):
            self._clients.pop(idx)
            self._refresh_clients()

    def apply(self):
        with _STATE_FILE_LOCK:
            _atomic_write_json(_trusted_hosts_path(), self._hosts)
            _atomic_write_json(_trusted_domains_path(), self._domains)
            _atomic_write_json(_trusted_clients_path(), self._clients)


def _show_trust_manager_windows(parent=None) -> None:
    try:
        _WinTrustManagerDialog(parent)
    except Exception:
        pass


def _show_kick_windows(peers: dict, kick_fn, get_aliases_fn, set_alias_fn, parent=None, get_latency_fn=None) -> None:
    try:
        dlg = _WinKickDialog(parent, peers, get_aliases_fn, set_alias_fn, get_latency_fn=get_latency_fn)
        for addr in dlg.get_result():
            try:
                kick_fn(addr)
            except Exception:
                pass
    except Exception:
        pass


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
    exe_dir = os.path.dirname(sys.executable)
    candidate = os.path.join(exe_dir, "pythonw.exe")
    if os.path.exists(candidate):
        return candidate
    raise FileNotFoundError("pythonw.exe not found for Startup shortcut.")


def _vbs_escape(value: str) -> str:
    return value.replace('"', '""')


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ensure_startup_shortcut(script_path: Optional[str] = None) -> Tuple[str, Optional[str]]:
    startup_dir = _windows_startup_dir()
    os.makedirs(startup_dir, exist_ok=True)

    frozen = getattr(sys, "frozen", False)
    icon_path = sys.executable if frozen else _app_icon_path()
    if not frozen and not os.path.exists(icon_path):
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
        # wscript.exe reads VBS files as ANSI by default. UTF-16 LE with BOM
        # is the safe alternative when a user's path contains non-ASCII chars
        # - UTF-8 without BOM would otherwise be misinterpreted and the
        # launched command path would be wrong.
        with open(vbs_path, "w", encoding="utf-16") as handle:
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


def _create_shortcut_in_folder(dest_dir: str, script_path: Optional[str] = None) -> str:
    os.makedirs(dest_dir, exist_ok=True)

    frozen = getattr(sys, "frozen", False)
    icon_path = sys.executable if frozen else _app_icon_path()
    if not frozen and not os.path.exists(icon_path):
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
        # See _ensure_startup_shortcut: write VBS as UTF-16 LE with BOM so
        # wscript handles non-ASCII paths correctly.
        with open(vbs_path, "w", encoding="utf-16") as handle:
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


def cleanup_old_exe(exe_path: str) -> None:
    old_path = exe_path + ".old"
    if not os.path.exists(old_path):
        return
    # Defender (or another AV) often holds a transient lock on the just-
    # written .exe immediately after rename. Retry with a small backoff so
    # the .old file doesn't linger across launches.
    import time as _time
    delay = 0.2
    for _ in range(6):
        try:
            os.remove(old_path)
            return
        except OSError:
            _time.sleep(delay)
            delay = min(delay * 2, 2.0)

    try:
        MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
        kernel32 = ctypes.windll.kernel32
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move_file_ex.restype = wintypes.BOOL
        if not move_file_ex(old_path, None, MOVEFILE_DELAY_UNTIL_REBOOT):
            err = ctypes.get_last_error()
            print(f"[MediaRelay] cleanup_old_exe: MoveFileExW failed (err={err}).")
    except Exception as exc:
        print(f"[MediaRelay] cleanup_old_exe: reboot-delete fallback failed: {exc}")


def perform_frozen_update(exe_path: str, new_path: str, old_path: str, env_vars_to_clear: list) -> None:
    if os.path.exists(old_path):
        os.remove(old_path)
    os.rename(exe_path, old_path)
    os.rename(new_path, exe_path)

    _env = _strip_pyi_env(os.environ, extra=tuple(env_vars_to_clear))
    _meipass = getattr(sys, "_MEIPASS", None)
    if _meipass:
        _env["PATH"] = os.pathsep.join(
            p for p in _env.get("PATH", "").split(os.pathsep)
            if p and p != _meipass
        )

    exe_dir = os.path.dirname(exe_path) or "."
    bat_path = os.path.join(tempfile.gettempdir(), "_mediarelay_restart.bat")
    with open(bat_path, "w", newline="") as f:
        f.write(
            "@echo off\r\n"
            "set \"_PYI_PARENT_PROCESS_LEVEL=\"\r\n"
            "set \"_PYI_APPLICATION_HOME_DIR=\"\r\n"
            "set \"_PYI_ARCHIVE_FILE=\"\r\n"
            "set \"_PYI_SPLASH_IPC=\"\r\n"
            "set \"_PYIBoot_MEIPASS=\"\r\n"
            "set \"_MEIPASS2=\"\r\n"
            "timeout /t 2 /nobreak >nul\r\n"
            f"start \"\" /D \"{exe_dir}\" \"{exe_path}\"\r\n"
            "del \"%~f0\"\r\n"
        )
    subprocess.Popen(
        ["cmd", "/c", bat_path],
        env=_env,
        cwd=exe_dir,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
    )
    os._exit(0)
