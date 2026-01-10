import asyncio
import json
import importlib.util
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

import pystray
from pystray import MenuItem as Item, Menu as Menu
from PIL import Image, ImageDraw

if sys.platform == "win32":
    import queue
    import tkinter as tk
    from tkinter import simpledialog, messagebox
    import ctypes
    from ctypes import wintypes
else:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    from libraries.permissions.linux import ensure_root_linux

EVDEV_AVAILABLE = importlib.util.find_spec("evdev") is not None
if EVDEV_AVAILABLE:
    import evdev

if sys.platform == "win32":
    # WinRT GSMTC
    from winrt.windows.media.control import (
        GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
    )

APP_NAME = "MediaRelay"
DEFAULT_PORT = 50123
_WIN_PROMPTER = None

# Force selector loop on Windows (more reliable for UDP + sock_recvfrom)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# -------------------- Media control (shared) --------------------

class State(str, Enum):
    NONE = "none"       # No controllable session
    PAUSED = "paused"   # Session exists but not playing
    PLAYING = "playing" # Session playing


class ResumeMode(str, Enum):
    HOST_ONLY = "host_only"
    BLIND = "blind"


@dataclass
class MediaSnapshot:
    state: State
    app: str = ""
    title: str = ""


# -------------------- Media control (Windows) --------------------

if sys.platform == "win32":
    class WindowsMediaController:
        async def snapshot(self) -> MediaSnapshot:
            mgr = await GSMTCManager.request_async()
            session = mgr.get_current_session()
            if session is None:
                return MediaSnapshot(State.NONE)

            # Playback state
            playback = session.get_playback_info()
            status = playback.playback_status

            if status == PlaybackStatus.PLAYING:
                s = State.PLAYING
            elif status in (PlaybackStatus.PAUSED, PlaybackStatus.STOPPED):
                s = State.PAUSED
            else:
                # UNKNOWN / CHANGING / CLOSED -> treat as paused-ish
                s = State.PAUSED

            # Optional metadata (nice for debugging/UI later)
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
            """
            cmd in {'play','pause','stop'}
            """
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


# -------------------- Media control (Linux) --------------------

if sys.platform != "win32":
    class LinuxMediaController:
        def __init__(self):
            self._playerctl = shutil.which("playerctl")

        def _run_playerctl(self, *args: str) -> Optional[subprocess.CompletedProcess]:
            if not self._playerctl:
                return None
            result = subprocess.run(
                [self._playerctl, *args],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return None
            return result

        async def snapshot(self) -> MediaSnapshot:
            result = self._run_playerctl("status")
            if not result:
                return MediaSnapshot(State.NONE)

            status = result.stdout.strip().lower()
            if status == "playing":
                state = State.PLAYING
            elif status in ("paused", "stopped"):
                state = State.PAUSED
            else:
                state = State.NONE

            app = ""
            title = ""
            meta = self._run_playerctl("metadata", "--format", "{{playerName}}||{{title}}")
            if meta:
                parts = meta.stdout.strip().split("||", 1)
                if parts:
                    app = parts[0].strip()
                if len(parts) > 1:
                    title = parts[1].strip()

            return MediaSnapshot(state, app=app, title=title)

        async def command(self, cmd: str) -> bool:
            if cmd not in ("play", "pause", "stop"):
                return False
            result = self._run_playerctl(cmd)
            return result is not None


def build_media_controller():
    if sys.platform == "win32":
        return WindowsMediaController()
    return LinuxMediaController()


# -------------------- Media key hook (Windows) --------------------

if sys.platform == "win32":
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
        def __init__(self, core: "RelayCore", swallow: bool = True):
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
                self._core.ui_toggle()
                return True
            if vk_code == VK_MEDIA_STOP:
                self._core.ui_stop_all()
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
else:
    class WindowsMediaKeyListener:
        def __init__(self, core: "RelayCore", swallow: bool = True):
            self._core = core

        def start(self):
            return

        def stop(self):
            return

# -------------------- Media key hook (Linux) --------------------

if sys.platform != "win32":
    class LinuxMediaKeyListener:
        def __init__(self, core: "RelayCore", swallow: bool = True):
            self._core = core
            self._swallow = swallow
            self._thread = None
            self._stop_evt = threading.Event()
            self._devices = []
            self._uinputs = {}

        def start(self):
            if not EVDEV_AVAILABLE:
                return
            if self._swallow:
                ensure_root_linux()
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

        def stop(self):
            self._stop_evt.set()
            if self._thread:
                self._thread.join(timeout=2.0)
            for dev in self._devices:
                try:
                    dev.ungrab()
                except Exception:
                    pass
                try:
                    dev.close()
                except Exception:
                    pass
            for ui in self._uinputs.values():
                try:
                    ui.close()
                except Exception:
                    pass
            self._devices = []
            self._uinputs = {}

        def _handle_key(self, key_code: int) -> bool:
            if key_code == evdev.ecodes.KEY_PLAYPAUSE:
                self._core.ui_toggle()
                return True
            if key_code == evdev.ecodes.KEY_STOPCD:
                self._core.ui_stop_all()
                return True
            return False

        def _find_devices(self):
            devices = []
            for path in evdev.list_devices():
                try:
                    dev = evdev.InputDevice(path)
                except Exception:
                    continue
                try:
                    caps = dev.capabilities().get(evdev.ecodes.EV_KEY, [])
                except Exception:
                    dev.close()
                    continue
                if evdev.ecodes.KEY_PLAYPAUSE in caps or evdev.ecodes.KEY_STOPCD in caps:
                    devices.append(dev)
                else:
                    dev.close()
            return devices

        def _setup_devices(self):
            if not self._swallow:
                return
            for dev in self._devices:
                try:
                    dev.grab()
                except Exception:
                    pass
                try:
                    self._uinputs[dev.path] = evdev.UInput.from_device(
                        dev,
                        name=f"{dev.name} (MediaRelay)",
                    )
                except Exception:
                    pass

        def _teardown_device(self, dev):
            try:
                dev.ungrab()
            except Exception:
                pass
            try:
                dev.close()
            except Exception:
                pass
            ui = self._uinputs.pop(dev.path, None)
            if ui:
                try:
                    ui.close()
                except Exception:
                    pass

        def _forward_event(self, dev, event):
            ui = self._uinputs.get(dev.path)
            if not ui:
                return
            try:
                if event.type == evdev.ecodes.EV_SYN and event.code == evdev.ecodes.SYN_REPORT:
                    ui.syn()
                else:
                    ui.write_event(event)
            except Exception:
                pass

        def _run(self):
            self._devices = self._find_devices()
            self._setup_devices()

            while not self._stop_evt.is_set():
                if not self._devices:
                    time.sleep(1.0)
                    self._devices = self._find_devices()
                    self._setup_devices()
                    continue

                rlist, _, _ = evdev.util.select(self._devices, [], [], 0.5)
                for dev in rlist:
                    try:
                        for event in dev.read():
                            swallow_event = False
                            if event.type == evdev.ecodes.EV_KEY:
                                if event.code in (evdev.ecodes.KEY_PLAYPAUSE, evdev.ecodes.KEY_STOPCD):
                                    if event.value == 1:
                                        self._handle_key(event.code)
                                    if self._swallow:
                                        swallow_event = True
                            if self._swallow and not swallow_event:
                                self._forward_event(dev, event)
                    except OSError:
                        self._teardown_device(dev)
                        if dev in self._devices:
                            self._devices.remove(dev)
else:
    class LinuxMediaKeyListener:
        def __init__(self, core: "RelayCore", swallow: bool = True):
            self._core = core

        def start(self):
            return

        def stop(self):
            return


def build_media_key_listener(core: "RelayCore", swallow: bool):
    if sys.platform == "win32":
        return WindowsMediaKeyListener(core, swallow=swallow)
    return LinuxMediaKeyListener(core, swallow=swallow)


# -------------------- Arbitration rules --------------------

def decide_actions(host: State, client: State) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (host_cmd, client_cmd) for a single "toggle press" arbitration.

    Your rules (deterministic):
    - If either is PLAYING -> pause intent
      - both playing -> pause both
      - host playing -> pause host only
      - else client playing -> pause client (prioritize client)
    - Else -> play intent
      - if host paused -> play host
      - else if client paused -> play client
      - else none
    """
    if host == State.PLAYING or client == State.PLAYING:
        return "pause", "pause"
    if host == State.PAUSED:
        return "play", None
    return None, None


# -------------------- Storage --------------------

def config_path() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    folder = os.path.join(base, APP_NAME)
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "config.json")


def load_config() -> dict:
    p = config_path()
    if not os.path.exists(p):
        return {
            "listen_port": DEFAULT_PORT,
            "peer_ip": "",
            "peer_port": DEFAULT_PORT,
            "swallow_media_keys": True,
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "bidirectional": True,
        }
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "listen_port": DEFAULT_PORT,
            "peer_ip": "",
            "peer_port": DEFAULT_PORT,
            "swallow_media_keys": True,
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "bidirectional": True,
        }


def save_config(cfg: dict) -> None:
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


# -------------------- Networking / role state machine --------------------

class Role(str, Enum):
    HOST = "host"     # Arbiter; accepts connect requests; processes toggle arbitration
    CLIENT = "client" # Connected to a host; sends toggle/stop requests; answers get_state; executes cmd


def now_ms() -> int:
    return int(time.time() * 1000)


def encode(msg: dict) -> bytes:
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def decode(data: bytes) -> Optional[dict]:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


class RelayCore:
    """
    Runs in an asyncio loop (background thread). Tray callbacks call into this
    using thread-safe methods.
    """
    def __init__(self, listen_port: int, resume_mode: ResumeMode, bidirectional: bool):
        self.listen_port = listen_port
        self.media = build_media_controller()

        self.role: Role = Role.HOST
        self.resume_mode: ResumeMode = resume_mode
        self.bidirectional: bool = bidirectional
        self.peer: Optional[Tuple[str, int]] = None
        self.peer_last_seen: float = 0.0

        self.sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_evt = threading.Event()
        self._auto_connect_enabled = False
        self._auto_connect_task: Optional[asyncio.Task] = None
        self._auto_connect_target: Optional[Tuple[str, int]] = None
        self._last_connect_attempt: Optional[Tuple[str, int]] = None
        self._last_connect_attempt_ts: float = 0.0

        # pending RPCs: id -> Future
        self.pending = {}

        # UI callback hooks (set by tray app)
        self.on_status_change = lambda: None
        self.on_resume_mode_change = lambda mode: None
        self.on_bidirectional_change = lambda enabled: None

    def _log(self, message: str) -> None:
        print(f"[Media-Sync] {message}")

    # ---- public, thread-safe entrypoints ----

    def start_in_thread(self):
        t = threading.Thread(target=self._thread_main, daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop_evt.set()
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: None)

    def ui_connect(self, ip: str, port: int):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._connect_out(ip, port)))

    def ui_disconnect(self):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._disconnect("user")))

    def ui_toggle(self):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._toggle_pressed(source="local")))

    def ui_set_resume_mode(self, resume_mode: ResumeMode):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_resume_mode(resume_mode, source="local"))
            )

    def ui_set_listen_port(self, port: int):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_listen_port(int(port)))
            )

    def ui_set_bidirectional(self, enabled: bool):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_bidirectional(bool(enabled), source="local"))
            )

    def start_auto_connect(self, ip: str, port: int):
        self._auto_connect_target = (ip, int(port))
        self._auto_connect_enabled = True
        if self.loop:
            self.loop.call_soon_threadsafe(self._ensure_auto_connect_task)

    def disable_auto_connect(self):
        self._auto_connect_enabled = False
        if self.loop:
            self.loop.call_soon_threadsafe(self._cancel_auto_connect_task)

    def ui_stop_all(self):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._stop_pressed(source="local")))

    # ---- internal thread/loop ----

    def _thread_main(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._run())
        self.loop.close()

    async def _run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("0.0.0.0", self.listen_port))
            self.sock.setblocking(False)
            self._log(f"Socket started on 0.0.0.0:{self.listen_port}.")
        except OSError as exc:
            self._log(f"Socket error while starting on 0.0.0.0:{self.listen_port}: {exc}")
            raise

        # start tasks
        rx = asyncio.create_task(self._rx_loop())
        hb = asyncio.create_task(self._heartbeat_loop())
        gc = asyncio.create_task(self._peer_timeout_loop())

        self._notify()
        self._ensure_auto_connect_task()

        try:
            while not self._stop_evt.is_set():
                await asyncio.sleep(0.2)
        finally:
            for task in (rx, hb, gc):
                task.cancel()
            try:
                await asyncio.gather(rx, hb, gc, return_exceptions=True)
            except Exception:
                pass
            if self._auto_connect_task:
                self._auto_connect_task.cancel()
                try:
                    await self._auto_connect_task
                except Exception:
                    pass
            try:
                self.sock.close()
                self._log("Socket stopped.")
            except Exception:
                self._log("Socket error while stopping.")

    def _notify(self):
        try:
            self.on_status_change()
        except Exception:
            pass

    def status_text(self) -> str:
        if self.peer:
            return f"{self.role.value.upper()} connected → {self.peer[0]}:{self.peer[1]}"
        return f"{self.role.value.upper()} (no peer)"

    async def _send(self, addr: Tuple[str, int], msg: dict):
        if not self.sock:
            return
        try:
            self.sock.sendto(encode(msg), addr)
        except OSError as exc:
            self._log(f"Socket send error to {addr[0]}:{addr[1]}: {exc}")
            return

    async def _rpc(self, addr: Tuple[str, int], msg: dict, timeout: float = 0.5) -> Optional[dict]:
        rid = uuid.uuid4().hex
        msg = dict(msg)
        msg["id"] = rid
        fut = self.loop.create_future()
        self.pending[rid] = fut
        await self._send(addr, msg)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except Exception:
            return None
        finally:
            self.pending.pop(rid, None)

    async def _rx_loop(self):
        while True:
            try:
                data, addr = await self.loop.sock_recvfrom(self.sock, 65535)
                msg = decode(data)
                if not msg:
                    continue

                mtype = msg.get("t")
                rid = msg.get("id")

                # resolve RPC futures
                if rid and rid in self.pending and not self.pending[rid].done():
                    self.pending[rid].set_result(msg)
                    continue

                # record peer liveness when relevant
                if self.peer and addr == self.peer:
                    self.peer_last_seen = time.time()

                # handle messages
                if mtype == "connect_request":
                    await self._handle_connect_request(addr, msg)
                elif mtype == "connect_ack":
                    # client receives this as part of connect_out flow (rpc handles it)
                    if (
                        msg.get("ok")
                        and not self.peer
                        and self._last_connect_attempt
                        and addr == self._last_connect_attempt
                        and (time.time() - self._last_connect_attempt_ts) < 5.0
                    ):
                        self.role = Role.CLIENT
                        self.peer = addr
                        self.peer_last_seen = time.time()
                        self._auto_connect_target = addr
                        self._auto_connect_enabled = True
                        self._ensure_auto_connect_task()
                        await self._send(self.peer, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
                        self._log(f"Connected to host {addr[0]}:{addr[1]} (late ack).")
                        self._notify()
                elif mtype == "disconnect":
                    # peer asked to disconnect
                    if self.peer and addr == self.peer:
                        await self._disconnect("peer")
                elif mtype == "ping":
                    await self._send(addr, {"t": "pong", "ts": now_ms()})
                elif mtype == "pong":
                    # liveness updated above if addr==peer
                    pass
                elif mtype == "get_state":
                    await self._handle_get_state(addr, msg)
                elif mtype == "cmd":
                    await self._handle_cmd(addr, msg)
                elif mtype == "resume_mode":
                    await self._handle_resume_mode(addr, msg)
                elif mtype == "request_toggle":
                    # client asks host to arbitrate
                    if self.role == Role.HOST and self.peer and addr == self.peer and self.bidirectional:
                        await self._toggle_pressed(source="peer")
                elif mtype == "request_stop":
                    if self.role == Role.HOST and self.peer and addr == self.peer and self.bidirectional:
                        await self._stop_pressed(source="peer")
            except asyncio.CancelledError:
                return
            except (OSError, RuntimeError):
                if self._stop_evt.is_set() or not self.sock or self.sock.fileno() == -1:
                    return
                self._log("Socket receive error; continuing.")
                continue

    async def _handle_connect_request(self, addr, msg):
        # If we are connected as a CLIENT, we don't accept inbound connect (by design).
        if self.role == Role.CLIENT:
            await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": False, "reason": "busy_client", "ts": now_ms()})
            return

        # If we already have a peer, refuse new ones (simple policy).
        if self.peer and addr != self.peer:
            await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": False, "reason": "already_connected", "ts": now_ms()})
            return

        # Accept: we remain/become HOST.
        self.role = Role.HOST
        self.peer = (addr[0], addr[1])
        self.peer_last_seen = time.time()
        await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": True, "ts": now_ms()})
        await self._send(addr, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        self._log(f"Client connected from {addr[0]}:{addr[1]}.")
        self._notify()

    async def _connect_out(self, ip: str, port: int):
        addr = (ip, int(port))
        self._last_connect_attempt = addr
        self._last_connect_attempt_ts = time.time()

        # Send request FIRST — do not mark connected yet
        resp = await self._rpc(
            addr,
            {"t": "connect_request", "ts": now_ms()},
            timeout=0.8,
        )

        if not resp or not resp.get("ok"):
            # Stay / revert as host
            self._log(f"Connection attempt to {addr[0]}:{addr[1]} failed.")
            await self._disconnect("connect_failed")
            return

        # Only now do we become a client
        self.role = Role.CLIENT
        self.peer = addr
        self.peer_last_seen = time.time()
        self._auto_connect_target = addr
        self._auto_connect_enabled = True
        self._ensure_auto_connect_task()
        await self._send(self.peer, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        self._log(f"Connected to host {addr[0]}:{addr[1]}.")
        self._notify()

    async def _disconnect(self, why: str):
        was_client = self.role == Role.CLIENT
        if self.peer:
            try:
                await self._send(self.peer, {"t": "disconnect", "why": why, "ts": now_ms()})
            except Exception:
                pass
            self._log(f"Disconnected from {self.peer[0]}:{self.peer[1]} (reason: {why}).")
        self.peer = None
        self.peer_last_seen = 0.0
        should_retry = (
            self._auto_connect_enabled
            and self._auto_connect_target
            and why not in ("user", "listen_port_changed")
        )
        if should_retry:
            self.role = Role.CLIENT  # stay client so auto-connect keeps retrying
        elif why == "user":
            self.role = Role.HOST  # revert to host when manually disconnected
        elif was_client and self._auto_connect_enabled:
            self.role = Role.CLIENT  # remain client to allow retry
        else:
            self.role = Role.HOST
        self._notify()
        if self._auto_connect_enabled:
            self._ensure_auto_connect_task()

    async def _peer_timeout_loop(self):
        while True:
            await asyncio.sleep(1.0)
            if self.peer:
                # if no pong/ping seen for >6s, drop peer
                if (time.time() - self.peer_last_seen) > 6.0:
                    self._log(f"Connection to {self.peer[0]}:{self.peer[1]} lost (timeout).")
                    await self._disconnect("timeout")

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(2.0)
            if self.peer:
                try:
                    await self._send(self.peer, {"t": "ping", "ts": now_ms()})
                except Exception:
                    pass

    def _cancel_auto_connect_task(self):
        if self._auto_connect_task:
            self._auto_connect_task.cancel()
            self._auto_connect_task = None

    def _ensure_auto_connect_task(self):
        if not self._auto_connect_enabled or not self._auto_connect_target:
            return
        if self._auto_connect_task and not self._auto_connect_task.done():
            return
        self._auto_connect_task = asyncio.create_task(self._auto_connect_loop())

    async def _auto_connect_loop(self):
        while self._auto_connect_enabled and not self._stop_evt.is_set():
            if self.peer:
                await asyncio.sleep(1.0)
                continue
            if not self._auto_connect_target:
                return
            ip, port = self._auto_connect_target
            self._log(f"Retrying connection to {ip}:{port}.")
            await self._connect_out(ip, port)
            if self.peer:
                await asyncio.sleep(1.0)
            else:
                await asyncio.sleep(30.0)

    async def _handle_get_state(self, addr, msg):
        snap = await self.media.snapshot()
        await self._send(addr, {
            "t": "state",
            "id": msg.get("id"),
            "ts": now_ms(),
            "state": snap.state.value,
            "app": snap.app,
            "title": snap.title,
        })

    async def _handle_cmd(self, addr, msg):
        if self.role == Role.HOST and not self.bidirectional:
            await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": False, "cmd": msg.get("cmd")})
            return
        cmd = msg.get("cmd")
        ok = False
        if cmd == "toggle":
            ok = await self._toggle_local()
        elif cmd in ("play", "pause", "stop"):
            ok = await self.media.command(cmd)
        await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": ok, "cmd": cmd})

    async def _handle_resume_mode(self, addr, msg):
        if self.peer and addr != self.peer:
            return
        mode_value = msg.get("mode", "")
        try:
            mode = ResumeMode(mode_value)
        except Exception:
            return
        await self._apply_resume_mode(mode, notify=True)

    async def _apply_resume_mode(self, resume_mode: ResumeMode, notify: bool):
        if resume_mode == self.resume_mode:
            return
        self.resume_mode = resume_mode
        if notify:
            try:
                self.on_resume_mode_change(resume_mode)
            except Exception:
                pass

    async def _apply_bidirectional(self, enabled: bool, notify: bool):
        if enabled == self.bidirectional:
            return
        self.bidirectional = enabled
        if notify:
            try:
                self.on_bidirectional_change(enabled)
            except Exception:
                pass

    async def _set_resume_mode(self, resume_mode: ResumeMode, source: str):
        await self._apply_resume_mode(resume_mode, notify=True)
        if self.peer:
            await self._send(self.peer, {"t": "resume_mode", "mode": resume_mode.value, "ts": now_ms(), "source": source})

    async def _set_bidirectional(self, enabled: bool, source: str):
        await self._apply_bidirectional(enabled, notify=True)

    async def _set_listen_port(self, port: int):
        if port == self.listen_port:
            return
        if self.role == Role.HOST and self.peer:
            await self._disconnect("listen_port_changed")

        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            new_sock.bind(("0.0.0.0", port))
        except OSError:
            new_sock.close()
            return
        new_sock.setblocking(False)

        old_sock = self.sock
        self.sock = new_sock
        self.listen_port = port
        self._log(f"Socket started on 0.0.0.0:{self.listen_port}.")
        if old_sock:
            try:
                old_sock.close()
                self._log("Socket stopped.")
            except Exception:
                self._log("Socket error while stopping.")
        self._notify()

    async def _toggle_local(self) -> bool:
        snap = await self.media.snapshot()
        if snap.state == State.PLAYING:
            return await self.media.command("pause")
        if snap.state == State.PAUSED:
            return await self.media.command("play")
        return False

    async def _toggle_pressed(self, source: str):
        """
        If HOST: run arbitration (query peer state, decide explicit actions).
        If CLIENT: send request_toggle to host unless in blind mode (then relay local intent).
        """
        if not self.peer:
            # no peer: just toggle locally by play/pause based on local state
            await self._toggle_local()
            return

        if self.role == Role.CLIENT:
            if self.resume_mode == ResumeMode.BLIND:
                await self._toggle_local()
                await self._send(self.peer, {"t": "cmd", "cmd": "toggle", "ts": now_ms(), "source": source})
                return
            await self._send(self.peer, {"t": "request_toggle", "ts": now_ms(), "source": source})
            return

        if self.resume_mode == ResumeMode.BLIND:
            await self._toggle_local()
            await self._send(self.peer, {"t": "cmd", "cmd": "toggle", "ts": now_ms(), "source": source})
            return

        # HOST arbitration:
        host_snap = await self.media.snapshot()
        client_state = State.NONE
        resp = await self._rpc(self.peer, {"t": "get_state", "ts": now_ms()}, timeout=0.5)
        if resp and resp.get("t") == "state":
            try:
                client_state = State(resp.get("state", "none"))
            except Exception:
                client_state = State.NONE

        host_cmd, client_cmd = decide_actions(host_snap.state, client_state)

        if host_cmd:
            await self.media.command(host_cmd)
        if client_cmd:
            await self._send(self.peer, {"t": "cmd", "cmd": client_cmd, "ts": now_ms()})

    async def _stop_pressed(self, source: str):
        """
        STOP is always explicit and safe: stop local, and tell peer to stop.
        If CLIENT: request host stop (so host can stop both).
        """
        if not self.peer:
            await self.media.command("stop")
            return

        if self.role == Role.CLIENT:
            if self.resume_mode == ResumeMode.BLIND:
                await self.media.command("stop")
                await self._send(self.peer, {"t": "cmd", "cmd": "stop", "ts": now_ms(), "source": source})
                return
            await self._send(self.peer, {"t": "request_stop", "ts": now_ms(), "source": source})
            return

        # HOST: stop both directly
        await self.media.command("stop")
        await self._send(self.peer, {"t": "cmd", "cmd": "stop", "ts": now_ms()})


# -------------------- Tray UI --------------------

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
                task = self._queue.get_nowait()
            except queue.Empty:
                break
            prompt, initial, result, done = task
            value = _ask_string_windows(prompt, initial, parent=self._root)
            result["value"] = value
            done.set()
        self._root.after(50, self._process_queue)

    def ask_string(self, prompt: str, initial: str = "") -> Optional[str]:
        result = {}
        done = threading.Event()
        self._queue.put((prompt, initial, result, done))
        done.wait()
        return result.get("value")

    def stop(self):
        if self._root:
            self._root.after(0, self._root.quit)


def prompt_string(prompt: str, initial: str = "") -> Optional[str]:
    if sys.platform == "win32":
        if _WIN_PROMPTER is not None:
            return _WIN_PROMPTER.ask_string(prompt, initial)
        return _ask_string_windows(prompt, initial)

    dialog = Gtk.Dialog(title=APP_NAME)
    icon_path = _app_icon_path()
    if os.path.exists(icon_path):
        try:
            dialog.set_icon_from_file(icon_path)
        except Exception:
            pass
    dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    box = dialog.get_content_area()
    label = Gtk.Label(label=prompt)
    label.set_halign(Gtk.Align.START)
    entry = Gtk.Entry()
    entry.set_text(initial)
    entry.set_activates_default(True)
    box.add(label)
    box.add(entry)
    dialog.show_all()
    response = dialog.run()
    value = entry.get_text().strip()
    dialog.destroy()
    if response != Gtk.ResponseType.OK or not value:
        return None
    return value


def prompt_int(prompt: str, initial: int) -> Optional[int]:
    value = prompt_string(prompt, str(initial))
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


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


def _ask_string_windows(prompt: str, initial: str, parent: Optional["tk.Misc"] = None) -> Optional[str]:
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


def make_icon(role: Role, connected: bool) -> Image.Image:
    """
    Simple colored-dot icon:
    - Host: green
    - Client: blue
    - Disconnected: gray border
    """
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    if not connected:
        fill = (130, 130, 130, 255)
    else:
        fill = (60, 180, 75, 255) if role == Role.HOST else (0, 120, 255, 255)

    d.ellipse((10, 10, 54, 54), fill=fill, outline=(20, 20, 20, 255), width=3)
    return img


def _app_icon_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "libraries", "Media-Sync.ico")


def _load_app_icon() -> Image.Image:
    try:
        return Image.open(_app_icon_path()).convert("RGBA")
    except Exception:
        return make_icon(Role.HOST, False)


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


def _ensure_startup_shortcut() -> Tuple[str, str]:
    if sys.platform != "win32":
        raise RuntimeError("Startup shortcut is only supported on Windows.")
    startup_dir = _windows_startup_dir()
    os.makedirs(startup_dir, exist_ok=True)

    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    pythonw_path = _windows_pythonw_path()
    icon_path = os.path.join(script_dir, "libraries", "Media-Sync.ico")
    if not os.path.exists(icon_path):
        raise FileNotFoundError(f"Icon not found: {icon_path}")

    shortcut_path = os.path.join(startup_dir, f"{APP_NAME}.lnk")
    vbs_path = os.path.join(script_dir, f"{APP_NAME}.vbs")
    legacy_vbs_path = os.path.join(startup_dir, f"{APP_NAME}.vbs")

    for path in (shortcut_path, vbs_path, legacy_vbs_path):
        if os.path.exists(path):
            os.remove(path)

    vbs_body = (
        'Set shell = CreateObject("WScript.Shell")\n'
        f'shell.CurrentDirectory = "{_vbs_escape(script_dir)}"\n'
        f'shell.Run """" & "{_vbs_escape(pythonw_path)}" & """ """ & "{_vbs_escape(script_path)}" & """", 0, False\n'
    )
    with open(vbs_path, "w", encoding="utf-8") as handle:
        handle.write(vbs_body)

    wscript_path = os.path.join(os.getenv("WINDIR", "C:\\Windows"), "System32", "wscript.exe")
    args_value = f'"{vbs_path}"'
    ps_script = (
        "$WshShell = New-Object -ComObject WScript.Shell;"
        f"$Shortcut = $WshShell.CreateShortcut({_ps_quote(shortcut_path)});"
        f"$Shortcut.TargetPath = {_ps_quote(wscript_path)};"
        f"$Shortcut.Arguments = {_ps_quote(args_value)};"
        f"$Shortcut.WorkingDirectory = {_ps_quote(script_dir)};"
        f"$Shortcut.IconLocation = {_ps_quote(icon_path + ',0')};"
        "$Shortcut.Save();"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        check=True,
    )
    return shortcut_path, vbs_path


class TrayApp:
    def __init__(self):
        self.cfg = load_config()
        self.listen_port = int(self.cfg.get("listen_port", DEFAULT_PORT))
        self._last_saved_state = {}
        self._tray_state_lock = threading.Lock()
        self._last_tray_state: Optional[Tuple[Role, bool]] = None
        self._tray_watchdog_stop = threading.Event()
        self._tray_watchdog_thread: Optional[threading.Thread] = None

        resume_mode_value = self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value)
        try:
            resume_mode = ResumeMode(resume_mode_value)
        except Exception:
            resume_mode = ResumeMode.HOST_ONLY
        bidirectional = bool(self.cfg.get("bidirectional", True))
        self.core = RelayCore(
            listen_port=self.listen_port,
            resume_mode=resume_mode,
            bidirectional=bidirectional,
        )
        self.core.on_status_change = self._refresh_tray
        self.core.on_resume_mode_change = self._set_resume_mode_from_core
        self.core.on_bidirectional_change = self._set_bidirectional_from_core
        self.media_key_listener = build_media_key_listener(
            self.core,
            swallow=bool(self.cfg.get("swallow_media_keys", True)),
        )

        if sys.platform == "win32":
            global _WIN_PROMPTER
            if _WIN_PROMPTER is None:
                _WIN_PROMPTER = WinPromptThread()

        self.icon = pystray.Icon(APP_NAME, self._tray_icon(), APP_NAME, menu=self._build_menu())

    def _tray_icon(self) -> Image.Image:
        return make_icon(self.core.role, self.core.peer is not None)

    def _desired_tray_state(self) -> Tuple[Role, bool]:
        return (self.core.role, self.core.peer is not None)

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _should_auto_connect(self) -> bool:
        ip = self.cfg.get("peer_ip", "")
        return (
            self.cfg.get("auto_connect")
            and self.cfg.get("last_role") == Role.CLIENT.value
            and ip
            and self._is_valid_ip(ip)
        )

    def _build_menu(self):
        items = [
            Item("Toggle", self._toggle),
            Item("Stop", self._stop),
            Item("Connect…", self._connect),
            Item("Listening Port…", self._configure_listen_port),
            Item("Disconnect", self._disconnect, enabled=lambda item: self.core.peer is not None),
        ]
        if self.core.role == Role.HOST:
            items.append(
                Item(
                    "Bi-Directional",
                    self._toggle_bidirectional,
                    checked=lambda item: self.core.bidirectional,
                )
            )
        items += [
            Item(
                "Resume Mode",
                Menu(
                    Item(
                        "Resume host only",
                        lambda: self._set_resume_mode(ResumeMode.HOST_ONLY),
                        checked=lambda item: self.core.resume_mode == ResumeMode.HOST_ONLY,
                        radio=True,
                    ),
                    Item(
                        "Blind resume",
                        lambda: self._set_resume_mode(ResumeMode.BLIND),
                        checked=lambda item: self.core.resume_mode == ResumeMode.BLIND,
                        radio=True,
                    ),
                ),
            ),
            Item(lambda _item: f"Status: {self.core.status_text()}", None, enabled=False),
        ]
        if sys.platform == "win32":
            items.append(Item("Add to startup", self._add_to_startup))
        items.append(Item("Exit", self._exit))
        return Menu(*items)

    def _refresh_tray(self):
        # Called from core thread; marshal to tray thread
        def do():
            with self._tray_state_lock:
                self._last_tray_state = self._desired_tray_state()
            self.icon.icon = self._tray_icon()
            self.icon.menu = self._build_menu()
            self.icon.title = f"{APP_NAME} - {self.core.status_text()}"
            self._persist_state()
        try:
            # Preferred: marshal to the tray thread if the backend provides a handler queue
            q = getattr(self.icon, "_handler_queue", None)
            if q is not None:
                q.put(do)
            else:
                # Fallback: best-effort direct call (works on some backends)
                do()
        except Exception:
            # Last resort: swallow (but at least we tried)
            pass

    def _start_tray_watchdog(self, interval_s: float = 2.0) -> None:
        if self._tray_watchdog_thread and self._tray_watchdog_thread.is_alive():
            return

        def run_watchdog():
            while not self._tray_watchdog_stop.wait(interval_s):
                with self._tray_state_lock:
                    current_state = self._last_tray_state
                if current_state != self._desired_tray_state():
                    self._refresh_tray()

        self._tray_watchdog_thread = threading.Thread(target=run_watchdog, daemon=True)
        self._tray_watchdog_thread.start()

    def _stop_tray_watchdog(self) -> None:
        self._tray_watchdog_stop.set()
        if self._tray_watchdog_thread:
            self._tray_watchdog_thread.join(timeout=1.0)

    def _persist_state(self):
        if self.core.peer:
            self.cfg["peer_ip"] = self.core.peer[0]
            self.cfg["peer_port"] = int(self.core.peer[1])
            self.cfg["last_role"] = self.core.role.value
            self.cfg["auto_connect"] = self.core.role == Role.CLIENT
        else:
            self.cfg["last_role"] = self.core.role.value
        state = {
            "peer_ip": self.cfg.get("peer_ip", ""),
            "peer_port": self.cfg.get("peer_port", DEFAULT_PORT),
            "last_role": self.cfg.get("last_role", ""),
            "auto_connect": self.cfg.get("auto_connect", False),
            "resume_mode": self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value),
            "bidirectional": self.cfg.get("bidirectional", True),
        }
        if state != self._last_saved_state:
            save_config(self.cfg)
            self._last_saved_state = dict(state)

    def _toggle(self, icon=None, item=None):
        self.core.ui_toggle()

    def _stop(self, icon=None, item=None):
        self.core.ui_stop_all()

    def _set_resume_mode_from_core(self, resume_mode: ResumeMode):
        def do():
            self.cfg["resume_mode"] = resume_mode.value
            save_config(self.cfg)
            self.icon.menu = self._build_menu()
        try:
            q = getattr(self.icon, "_handler_queue", None)
            if q is not None:
                q.put(do)
            else:
                do()
        except Exception:
            pass

    def _set_resume_mode(self, resume_mode: ResumeMode):
        self.core.ui_set_resume_mode(resume_mode)

    def _set_bidirectional_from_core(self, enabled: bool):
        def do():
            self.cfg["bidirectional"] = bool(enabled)
            save_config(self.cfg)
            self.icon.menu = self._build_menu()
        try:
            q = getattr(self.icon, "_handler_queue", None)
            if q is not None:
                q.put(do)
            else:
                do()
        except Exception:
            pass

    def _toggle_bidirectional(self, icon=None, item=None):
        self.core.ui_set_bidirectional(not self.core.bidirectional)

    def _configure_listen_port(self, icon=None, item=None):
        port = prompt_int("Listen Port:", int(self.cfg.get("listen_port", DEFAULT_PORT)))
        if not port:
            return
        port = int(port)
        if port == self.listen_port:
            return
        self.listen_port = port
        self.cfg["listen_port"] = port
        save_config(self.cfg)
        self.core.ui_set_listen_port(port)

    def _connect(self, icon=None, item=None):
        ip = prompt_string("Host IP:", self.cfg.get("peer_ip", ""))
        if not ip:
            return
        port = prompt_int("Host Port:", int(self.cfg.get("peer_port", DEFAULT_PORT)))
        if not port:
            return

        # save defaults
        self.cfg["peer_ip"] = ip
        self.cfg["peer_port"] = int(port)
        save_config(self.cfg)

        self.core.ui_connect(ip, int(port))

    def _disconnect(self, icon=None, item=None):
        self.cfg["auto_connect"] = False
        save_config(self.cfg)
        self.core.disable_auto_connect()
        self.core.ui_disconnect()

    def _exit(self, icon=None, item=None):
        self.core.stop()
        self.media_key_listener.stop()
        self._stop_tray_watchdog()
        self.icon.stop()
        if _WIN_PROMPTER is not None:
            _WIN_PROMPTER.stop()

    def _add_to_startup(self, icon=None, item=None):
        if sys.platform != "win32":
            return
        confirm = messagebox.askyesno(APP_NAME, "Add MediaRelay to startup?")
        if not confirm:
            return
        try:
            shortcut_path, _vbs_path = _ensure_startup_shortcut()
            messagebox.showinfo(APP_NAME, f"Startup shortcut created:\n{shortcut_path}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Failed to add startup shortcut:\n{exc}")

    def run(self):
        # Start core networking
        self.core.start_in_thread()
        self.media_key_listener.start()
        if self._should_auto_connect():
            self.core.start_auto_connect(
                self.cfg.get("peer_ip"),
                int(self.cfg.get("peer_port", DEFAULT_PORT)),
            )
        self._start_tray_watchdog()
        # Run tray
        try:
            self.icon.run()
        finally:
            self._stop_tray_watchdog()


if __name__ == "__main__":
    TrayApp().run()
