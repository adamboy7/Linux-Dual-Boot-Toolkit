import asyncio
import json
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
else:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

if sys.platform == "win32":
    # WinRT GSMTC
    from winrt.windows.media.control import (
        GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
    )

APP_NAME = "MediaRelay"
DEFAULT_PORT = 50123
_WIN_PROMPTER = None


# -------------------- Media control (Windows) --------------------

class State(str, Enum):
    NONE = "none"       # No controllable session
    PAUSED = "paused"   # Session exists but not playing
    PLAYING = "playing" # Session playing


@dataclass
class MediaSnapshot:
    state: State
    app: str = ""
    title: str = ""


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
        if host == State.PLAYING and client == State.PLAYING:
            return "pause", "pause"
        if host == State.PLAYING:
            return "pause", None
        return None, "pause"

    if host == State.PAUSED:
        return "play", None
    if client == State.PAUSED:
        return None, "play"
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
        return {"listen_port": DEFAULT_PORT, "peer_ip": "", "peer_port": DEFAULT_PORT}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"listen_port": DEFAULT_PORT, "peer_ip": "", "peer_port": DEFAULT_PORT}


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
    def __init__(self, listen_port: int):
        self.listen_port = listen_port
        self.media = build_media_controller()

        self.role: Role = Role.HOST
        self.peer: Optional[Tuple[str, int]] = None
        self.peer_last_seen: float = 0.0

        self.sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_evt = threading.Event()

        # pending RPCs: id -> Future
        self.pending = {}

        # UI callback hooks (set by tray app)
        self.on_status_change = lambda: None

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
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", self.listen_port))
        self.sock.setblocking(False)

        # start tasks
        rx = asyncio.create_task(self._rx_loop())
        hb = asyncio.create_task(self._heartbeat_loop())
        gc = asyncio.create_task(self._peer_timeout_loop())

        self._notify()

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
            try:
                self.sock.close()
            except Exception:
                pass

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
        self.sock.sendto(encode(msg), addr)

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
                    pass
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
                elif mtype == "request_toggle":
                    # client asks host to arbitrate
                    if self.role == Role.HOST and self.peer and addr == self.peer:
                        await self._toggle_pressed(source="peer")
                elif mtype == "request_stop":
                    if self.role == Role.HOST and self.peer and addr == self.peer:
                        await self._stop_pressed(source="peer")
            except asyncio.CancelledError:
                return
            except (OSError, RuntimeError):
                if self._stop_evt.is_set() or not self.sock or self.sock.fileno() == -1:
                    return
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
        self._notify()

    async def _connect_out(self, ip: str, port: int):
        addr = (ip, int(port))

        # Send request FIRST — do not mark connected yet
        resp = await self._rpc(
            addr,
            {"t": "connect_request", "ts": now_ms()},
            timeout=0.8,
        )

        if not resp or not resp.get("ok"):
            # Stay / revert as host
            await self._disconnect("connect_failed")
            return

        # Only now do we become a client
        self.role = Role.CLIENT
        self.peer = addr
        self.peer_last_seen = time.time()
        self._notify()

    async def _disconnect(self, why: str):
        if self.peer:
            try:
                await self._send(self.peer, {"t": "disconnect", "why": why, "ts": now_ms()})
            except Exception:
                pass
        self.peer = None
        self.peer_last_seen = 0.0
        self.role = Role.HOST  # revert to host when disconnected
        self._notify()

    async def _peer_timeout_loop(self):
        while True:
            await asyncio.sleep(1.0)
            if self.peer:
                # if no pong/ping seen for >6s, drop peer
                if (time.time() - self.peer_last_seen) > 6.0:
                    await self._disconnect("timeout")

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(2.0)
            if self.peer:
                try:
                    await self._send(self.peer, {"t": "ping", "ts": now_ms()})
                except Exception:
                    pass

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
        cmd = msg.get("cmd")
        ok = False
        if cmd in ("play", "pause", "stop"):
            ok = await self.media.command(cmd)
        await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": ok, "cmd": cmd})

    async def _toggle_pressed(self, source: str):
        """
        If HOST: run arbitration (query peer state, decide explicit actions).
        If CLIENT: send request_toggle to host.
        """
        if not self.peer:
            # no peer: just toggle locally by play/pause based on local state
            snap = await self.media.snapshot()
            if snap.state == State.PLAYING:
                await self.media.command("pause")
            elif snap.state == State.PAUSED:
                await self.media.command("play")
            return

        if self.role == Role.CLIENT:
            await self._send(self.peer, {"t": "request_toggle", "ts": now_ms(), "source": source})
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
            value = simpledialog.askstring(APP_NAME, prompt, initialvalue=initial, parent=self._root)
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
        return simpledialog.askstring(APP_NAME, prompt, initialvalue=initial)

    dialog = Gtk.Dialog(title=APP_NAME)
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


class TrayApp:
    def __init__(self):
        self.cfg = load_config()
        self.listen_port = int(self.cfg.get("listen_port", DEFAULT_PORT))
        self._last_saved_state = {}

        self.core = RelayCore(listen_port=self.listen_port)
        self.core.on_status_change = self._refresh_tray

        if sys.platform == "win32":
            global _WIN_PROMPTER
            if _WIN_PROMPTER is None:
                _WIN_PROMPTER = WinPromptThread()

        self.icon = pystray.Icon(APP_NAME, make_icon(Role.HOST, False), APP_NAME, menu=self._build_menu())

    def _build_menu(self):
        return Menu(
            Item("Toggle (arb)", self._toggle),
            Item("Stop (both)", self._stop),
            Item("Connect…", self._connect),
            Item("Disconnect", self._disconnect, enabled=lambda item: self.core.peer is not None),
            Item(lambda _item: f"Status: {self.core.status_text()}", None, enabled=False),
            Item("Exit", self._exit),
        )

    def _refresh_tray(self):
        # Called from core thread; marshal to tray thread
        def do():
            connected = self.core.peer is not None
            self.icon.icon = make_icon(self.core.role, connected)
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
        }
        if state != self._last_saved_state:
            save_config(self.cfg)
            self._last_saved_state = dict(state)

    def _toggle(self, icon=None, item=None):
        self.core.ui_toggle()

    def _stop(self, icon=None, item=None):
        self.core.ui_stop_all()

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
        self.core.ui_disconnect()

    def _exit(self, icon=None, item=None):
        self.core.stop()
        self.icon.stop()
        if _WIN_PROMPTER is not None:
            _WIN_PROMPTER.stop()

    def run(self):
        # Start core networking
        self.core.start_in_thread()
        if (
            self.cfg.get("auto_connect")
            and self.cfg.get("last_role") == Role.CLIENT.value
            and self.cfg.get("peer_ip")
        ):
            self.core.ui_connect(
                self.cfg.get("peer_ip"),
                int(self.cfg.get("peer_port", DEFAULT_PORT)),
            )
        # Run tray
        self.icon.run()


if __name__ == "__main__":
    TrayApp().run()
