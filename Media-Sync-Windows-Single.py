import argparse
import asyncio
import ipaddress
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from winrt.windows.media.control import (
    GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
)

if sys.platform != "win32":
    raise SystemExit("Media-Sync-Windows-Single requires Windows.")

APP_NAME = "MediaRelay"
DEFAULT_PORT = 50123

# Force selector loop on Windows (more reliable for UDP + sock_recvfrom)
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

class WindowsMediaController:
    async def snapshot(self) -> MediaSnapshot:
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


def build_media_controller():
    return WindowsMediaController()


# -------------------- Arbitration rules --------------------

def decide_actions(host: State, client: State, resume_mode: ResumeMode) -> Tuple[Optional[str], Optional[str]]:
    if resume_mode == ResumeMode.BLIND:
        if host == State.PLAYING or client == State.PLAYING:
            return "pause", "pause"
        if host == State.PAUSED or client == State.PAUSED:
            return "play", "play"
        return None, None

    if host == State.PLAYING or client == State.PLAYING:
        return "pause", "pause"
    if host == State.PAUSED:
        return "play", None
    return None, None


class Role(str, Enum):
    HOST = "host"     # Arbiter; accepts connect requests; processes toggle arbitration
    CLIENT = "client" # Connected to a host; sends toggle/stop requests; answers get_state; executes cmd


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
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "auto_connect": False,
            "last_role": Role.HOST.value,
        }
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "listen_port": DEFAULT_PORT,
            "peer_ip": "",
            "peer_port": DEFAULT_PORT,
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "auto_connect": False,
            "last_role": Role.HOST.value,
        }


def save_config(cfg: dict) -> None:
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


# -------------------- Networking / role state machine --------------------


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
    Runs in an asyncio loop in the main thread.
    """
    def __init__(self, listen_port: int, resume_mode: ResumeMode):
        self.listen_port = listen_port
        self.media = build_media_controller()

        self.role: Role = Role.HOST
        self.resume_mode: ResumeMode = resume_mode
        self.peer: Optional[Tuple[str, int]] = None
        self.peer_last_seen: float = 0.0

        self.sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_evt = asyncio.Event()
        self._ready_evt = asyncio.Event()
        self._auto_connect_enabled = False
        self._auto_connect_task: Optional[asyncio.Task] = None
        self._auto_connect_target: Optional[Tuple[str, int]] = None

        # pending RPCs: id -> Future
        self.pending = {}

    def _log(self, message: str) -> None:
        print(f"[Media-Sync] {message}")

    def stop(self):
        self._stop_evt.set()

    async def wait_ready(self) -> None:
        await self._ready_evt.wait()

    def start_auto_connect(self, ip: str, port: int):
        self._auto_connect_target = (ip, int(port))
        self._auto_connect_enabled = True
        self._ensure_auto_connect_task()

    def disable_auto_connect(self):
        self._auto_connect_enabled = False
        self._cancel_auto_connect_task()

    async def run(self):
        self.loop = asyncio.get_running_loop()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("0.0.0.0", self.listen_port))
            self.sock.setblocking(False)
            self._log(f"Socket started on 0.0.0.0:{self.listen_port}.")
        except OSError as exc:
            self._log(f"Socket error while starting on 0.0.0.0:{self.listen_port}: {exc}")
            raise

        rx = asyncio.create_task(self._rx_loop())
        hb = asyncio.create_task(self._heartbeat_loop())
        gc = asyncio.create_task(self._peer_timeout_loop())

        self._ready_evt.set()
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
                if self.sock:
                    self.sock.close()
                    self._log("Socket stopped.")
            except Exception:
                self._log("Socket error while stopping.")

    async def _send(self, addr: Tuple[str, int], msg: dict):
        if not self.sock:
            return
        try:
            self.sock.sendto(encode(msg), addr)
        except OSError as exc:
            self._log(f"Socket send error to {addr[0]}:{addr[1]}: {exc}")

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

                if rid and rid in self.pending and not self.pending[rid].done():
                    self.pending[rid].set_result(msg)
                    continue

                if self.peer and addr == self.peer:
                    self.peer_last_seen = time.time()

                if mtype == "connect_request":
                    await self._handle_connect_request(addr, msg)
                elif mtype == "disconnect":
                    if self.peer and addr == self.peer:
                        await self._disconnect("peer")
                elif mtype == "ping":
                    await self._send(addr, {"t": "pong", "ts": now_ms()})
                elif mtype == "get_state":
                    await self._handle_get_state(addr, msg)
                elif mtype == "cmd":
                    await self._handle_cmd(addr, msg)
                elif mtype == "resume_mode":
                    await self._handle_resume_mode(addr, msg)
                elif mtype == "request_toggle":
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
                self._log("Socket receive error; continuing.")
                continue

    async def _handle_connect_request(self, addr, msg):
        if self.role == Role.CLIENT:
            await self._send(addr, {
                "t": "connect_ack",
                "id": msg.get("id"),
                "ok": False,
                "reason": "busy_client",
                "ts": now_ms(),
            })
            return

        if self.peer and addr != self.peer:
            await self._send(addr, {
                "t": "connect_ack",
                "id": msg.get("id"),
                "ok": False,
                "reason": "already_connected",
                "ts": now_ms(),
            })
            return

        self.role = Role.HOST
        self.peer = (addr[0], addr[1])
        self.peer_last_seen = time.time()
        await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": True, "ts": now_ms()})
        await self._send(addr, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        self._log(f"Client connected from {addr[0]}:{addr[1]}.")

    async def _connect_out(self, ip: str, port: int):
        addr = (ip, int(port))

        resp = await self._rpc(
            addr,
            {"t": "connect_request", "ts": now_ms()},
            timeout=0.8,
        )

        if not resp or not resp.get("ok"):
            self._log(f"Connection attempt to {addr[0]}:{addr[1]} failed.")
            await self._disconnect("connect_failed")
            return

        self.role = Role.CLIENT
        self.peer = addr
        self.peer_last_seen = time.time()
        self._auto_connect_target = addr
        self._auto_connect_enabled = True
        self._ensure_auto_connect_task()
        await self._send(self.peer, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        self._log(f"Connected to host {addr[0]}:{addr[1]}.")

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
            self.role = Role.CLIENT
        elif why == "user":
            self.role = Role.HOST
        elif was_client and self._auto_connect_enabled:
            self.role = Role.CLIENT
        else:
            self.role = Role.HOST
        if self._auto_connect_enabled:
            self._ensure_auto_connect_task()

    async def _peer_timeout_loop(self):
        while True:
            await asyncio.sleep(1.0)
            if self.peer:
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
        cmd = msg.get("cmd")
        ok = False
        if cmd in ("play", "pause", "stop"):
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
        await self._apply_resume_mode(mode)

    async def _apply_resume_mode(self, resume_mode: ResumeMode):
        if resume_mode == self.resume_mode:
            return
        self.resume_mode = resume_mode

    async def _set_resume_mode(self, resume_mode: ResumeMode, source: str):
        await self._apply_resume_mode(resume_mode)
        if self.peer:
            await self._send(self.peer, {
                "t": "resume_mode",
                "mode": resume_mode.value,
                "ts": now_ms(),
                "source": source,
            })

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

    async def _toggle_pressed(self, source: str):
        if not self.peer:
            snap = await self.media.snapshot()
            if snap.state == State.PLAYING:
                await self.media.command("pause")
            elif snap.state == State.PAUSED:
                await self.media.command("play")
            return

        if self.role == Role.CLIENT:
            await self._send(self.peer, {"t": "request_toggle", "ts": now_ms(), "source": source})
            return

        host_snap = await self.media.snapshot()
        client_state = State.NONE
        resp = await self._rpc(self.peer, {"t": "get_state", "ts": now_ms()}, timeout=0.5)
        if resp and resp.get("t") == "state":
            try:
                client_state = State(resp.get("state", "none"))
            except Exception:
                client_state = State.NONE

        host_cmd, client_cmd = decide_actions(host_snap.state, client_state, self.resume_mode)

        if host_cmd:
            await self.media.command(host_cmd)
        if client_cmd:
            await self._send(self.peer, {"t": "cmd", "cmd": client_cmd, "ts": now_ms()})

    async def _stop_pressed(self, source: str):
        if not self.peer:
            await self.media.command("stop")
            return

        if self.role == Role.CLIENT:
            await self._send(self.peer, {"t": "request_stop", "ts": now_ms(), "source": source})
            return

        await self.media.command("stop")
        await self._send(self.peer, {"t": "cmd", "cmd": "stop", "ts": now_ms()})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Media Sync (Windows, single-threaded)")
    parser.add_argument("--listen-port", type=int, default=None, help="Listen port (default: config)")
    parser.add_argument("--connect", type=str, default=None, help="Connect to host ip[:port]")
    parser.add_argument(
        "--resume-mode",
        choices=[mode.value for mode in ResumeMode],
        default=None,
        help="Resume mode (default: config)",
    )
    parser.add_argument("--auto-connect", action="store_true", help="Enable auto-connect to host")
    parser.add_argument("--no-auto-connect", action="store_true", help="Disable auto-connect")
    return parser.parse_args()


def parse_host(value: str, default_port: int) -> Tuple[str, int]:
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host.strip(), int(port)
    return value.strip(), default_port


def should_auto_connect(cfg: dict) -> bool:
    ip = cfg.get("peer_ip", "")
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return cfg.get("auto_connect") and cfg.get("last_role") == Role.CLIENT.value


async def run_console() -> None:
    args = parse_args()
    cfg = load_config()

    listen_port = args.listen_port or int(cfg.get("listen_port", DEFAULT_PORT))

    resume_mode_value = args.resume_mode or cfg.get("resume_mode", ResumeMode.HOST_ONLY.value)
    try:
        resume_mode = ResumeMode(resume_mode_value)
    except Exception:
        resume_mode = ResumeMode.HOST_ONLY

    core = RelayCore(listen_port=listen_port, resume_mode=resume_mode)

    cfg["listen_port"] = listen_port
    cfg["resume_mode"] = resume_mode.value

    connect_target = None
    if args.connect:
        host, port = parse_host(args.connect, int(cfg.get("peer_port", DEFAULT_PORT)))
        connect_target = (host, port)
        cfg["peer_ip"] = host
        cfg["peer_port"] = port
        cfg["auto_connect"] = True if not args.no_auto_connect else False
        cfg["last_role"] = Role.CLIENT.value
    elif args.no_auto_connect:
        cfg["auto_connect"] = False
        cfg["last_role"] = Role.HOST.value

    save_config(cfg)

    run_task = asyncio.create_task(core.run())
    await core.wait_ready()

    if connect_target:
        await core._connect_out(*connect_target)

    if args.auto_connect or should_auto_connect(cfg):
        target_ip = cfg.get("peer_ip")
        target_port = int(cfg.get("peer_port", DEFAULT_PORT))
        if target_ip:
            core.start_auto_connect(target_ip, target_port)

    try:
        await run_task
    finally:
        core.stop()


def main() -> None:
    try:
        asyncio.run(run_console())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
