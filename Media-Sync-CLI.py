import asyncio
import json
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

if sys.platform == "win32":
    from winrt.windows.media.control import (
        GlobalSystemMediaTransportControlsSessionManager as GSMTCManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus as PlaybackStatus,
    )

APP_NAME = "MediaRelay"
DEFAULT_PORT = 50123

# Force selector loop on Windows (more reliable for UDP + sock_recvfrom)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class State(str, Enum):
    NONE = "none"       # No controllable session
    PAUSED = "paused"   # Session exists but not playing
    PLAYING = "playing" # Session playing


class ResumeMode(str, Enum):
    HOST_ONLY = "host_only"
    CLIENT_ONLY = "client_only"
    BLIND = "blind"


@dataclass
class MediaSnapshot:
    state: State
    app: str = ""
    title: str = ""


if sys.platform == "win32":
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


def decide_actions(
    host: State,
    client: State,
    resume_mode: ResumeMode,
) -> Tuple[Optional[str], Optional[str]]:
    if host == State.PLAYING or client == State.PLAYING:
        if host == State.PLAYING and client == State.PLAYING:
            return "pause", "pause"
        if host == State.PLAYING:
            return "pause", None
        return None, "pause"
    if host == State.PAUSED and client == State.PAUSED:
        if resume_mode == ResumeMode.CLIENT_ONLY:
            return None, "play"
        return "play", None
    if host == State.PAUSED:
        return "play", None
    if client == State.PAUSED:
        return None, "play"
    return None, None


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
            "ignore_client": False,
        }
    try:
        with open(p, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "ignore_client" not in cfg and "bidirectional" in cfg:
            cfg["ignore_client"] = not bool(cfg.get("bidirectional"))
        if "bidirectional" in cfg:
            cfg.pop("bidirectional", None)
        return cfg
    except Exception:
        return {
            "listen_port": DEFAULT_PORT,
            "peer_ip": "",
            "peer_port": DEFAULT_PORT,
            "swallow_media_keys": True,
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "ignore_client": False,
        }


def save_config(cfg: dict) -> None:
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


class Role(str, Enum):
    HOST = "host"
    CLIENT = "client"


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
    def __init__(self, listen_port: int, resume_mode: ResumeMode, ignore_client: bool):
        self.listen_port = listen_port
        self.media = build_media_controller()

        self.role: Role = Role.HOST
        self.resume_mode: ResumeMode = resume_mode
        self.ignore_client: bool = ignore_client
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

        self.pending = {}
        self.on_status_change = lambda: None

    def _log(self, message: str) -> None:
        print(f"[Media-Sync] {message}")

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

    def start_auto_connect(self, ip: str, port: int):
        self._auto_connect_target = (ip, int(port))
        self._auto_connect_enabled = True
        if self.loop:
            self.loop.call_soon_threadsafe(self._ensure_auto_connect_task)

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

    async def _send_policy_to_peer(self, source: str = "core"):
        if not self.peer:
            return
        if self.role != Role.HOST:
            return
        await self._send(self.peer, {
            "t": "policy",
            "ts": now_ms(),
            "resume_mode": self.resume_mode.value,
            "source": source,
        })

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

                if rid and rid in self.pending and not self.pending[rid].done():
                    self.pending[rid].set_result(msg)
                    continue

                if self.peer and addr == self.peer:
                    self.peer_last_seen = time.time()

                if mtype == "connect_request":
                    await self._handle_connect_request(addr, msg)
                elif mtype == "connect_ack":
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
                        self._log(f"Connected to host {addr[0]}:{addr[1]} (late ack).")
                        self._notify()
                elif mtype == "disconnect":
                    if self.peer and addr == self.peer:
                        await self._disconnect("peer")
                elif mtype == "ping":
                    await self._send(addr, {"t": "pong", "ts": now_ms()})
                elif mtype == "pong":
                    pass
                elif mtype == "get_state":
                    await self._handle_get_state(addr, msg)
                elif mtype == "cmd":
                    await self._handle_cmd(addr, msg)
                elif mtype == "resume_mode":
                    await self._handle_resume_mode(addr, msg)
                elif mtype == "policy":
                    await self._handle_policy(addr, msg)
                elif mtype == "request_toggle":
                    if self.role == Role.HOST and self.peer and addr == self.peer and not self.ignore_client:
                        hint = None
                        try:
                            hint = State(msg.get("state", "none"))
                        except Exception:
                            hint = None
                        await self._toggle_pressed(source="peer", client_state_hint=hint)
                elif mtype == "request_stop":
                    if self.role == Role.HOST and self.peer and addr == self.peer and not self.ignore_client:
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
            await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": False, "reason": "busy_client", "ts": now_ms()})
            return

        if self.peer and addr != self.peer:
            await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": False, "reason": "already_connected", "ts": now_ms()})
            return

        self.role = Role.HOST
        self.peer = (addr[0], addr[1])
        self.peer_last_seen = time.time()
        await self._send(addr, {"t": "connect_ack", "id": msg.get("id"), "ok": True, "ts": now_ms()})
        await self._send(addr, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        await self._send_policy_to_peer(source="connect")
        self._log(f"Client connected from {addr[0]}:{addr[1]}.")
        self._notify()

    async def _connect_out(self, ip: str, port: int):
        addr = (ip, int(port))
        self._last_connect_attempt = addr
        self._last_connect_attempt_ts = time.time()

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
            self.role = Role.CLIENT
        elif why == "user":
            self.role = Role.HOST
        elif was_client and self._auto_connect_enabled:
            self.role = Role.CLIENT
        else:
            self.role = Role.HOST
        self._notify()
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
        if self.role == Role.HOST and self.ignore_client:
            await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": False, "cmd": cmd})
            return
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

    async def _handle_policy(self, addr, msg):
        if self.peer and addr != self.peer:
            return
        if self.role == Role.HOST:
            return

        mode_value = msg.get("resume_mode", "")
        if mode_value:
            try:
                mode = ResumeMode(mode_value)
                await self._apply_resume_mode(mode, notify=True)
            except Exception:
                pass

    async def _apply_resume_mode(self, resume_mode: ResumeMode, notify: bool):
        if resume_mode == self.resume_mode:
            return
        self.resume_mode = resume_mode
        if notify:
            self._notify()

    async def _set_resume_mode(self, resume_mode: ResumeMode, source: str):
        await self._apply_resume_mode(resume_mode, notify=True)
        if self.peer:
            if self.role == Role.CLIENT:
                await self._send(self.peer, {"t": "resume_mode", "mode": resume_mode.value, "ts": now_ms(), "source": source})
            else:
                await self._send_policy_to_peer(source=source)

    async def _toggle_local(self) -> bool:
        snap = await self.media.snapshot()
        if snap.state == State.PLAYING:
            return await self.media.command("pause")
        if snap.state == State.PAUSED:
            return await self.media.command("play")
        return False

    async def _toggle_pressed(self, source: str, client_state_hint: Optional[State] = None):
        if not self.peer:
            await self._toggle_local()
            return

        if self.role == Role.CLIENT:
            if self.resume_mode == ResumeMode.BLIND:
                await self._toggle_local()
                await self._send(self.peer, {"t": "cmd", "cmd": "toggle", "ts": now_ms(), "source": source})
                return
            snap = await self.media.snapshot()
            await self._send(self.peer, {
                "t": "request_toggle",
                "ts": now_ms(),
                "source": source,
                "state": snap.state.value,
            })
            return

        if self.resume_mode == ResumeMode.BLIND:
            await self._toggle_local()
            await self._send(self.peer, {"t": "cmd", "cmd": "toggle", "ts": now_ms(), "source": source})
            return

        host_snap = await self.media.snapshot()
        client_state = State.NONE
        resp = await self._rpc(self.peer, {"t": "get_state", "ts": now_ms()}, timeout=0.5)
        if resp and resp.get("t") == "state":
            try:
                client_state = State(resp.get("state", "none"))
            except Exception:
                client_state = State.NONE
        if client_state == State.NONE and client_state_hint and client_state_hint != State.NONE:
            client_state = client_state_hint

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
            if self.resume_mode == ResumeMode.BLIND:
                await self.media.command("stop")
                await self._send(self.peer, {"t": "cmd", "cmd": "stop", "ts": now_ms(), "source": source})
                return
            await self._send(self.peer, {"t": "request_stop", "ts": now_ms(), "source": source})
            return

        await self.media.command("stop")
        await self._send(self.peer, {"t": "cmd", "cmd": "stop", "ts": now_ms()})


def _prompt_for_ip() -> str:
    while True:
        raw = input("Enter host IP: ").strip()
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            print("Invalid IP. Please try again.")
            continue
        return raw


def main() -> int:
    config_file = config_path()
    config_exists = os.path.exists(config_file)
    cfg = load_config()

    if not config_exists:
        cfg["peer_ip"] = _prompt_for_ip()
        cfg["peer_port"] = int(cfg.get("peer_port", DEFAULT_PORT))
        cfg["auto_connect"] = True
        save_config(cfg)

    peer_ip = cfg.get("peer_ip")
    if not peer_ip:
        cfg["peer_ip"] = _prompt_for_ip()
        peer_ip = cfg["peer_ip"]
        cfg["auto_connect"] = True
        save_config(cfg)

    listen_port = int(cfg.get("listen_port", DEFAULT_PORT))
    peer_port = int(cfg.get("peer_port", DEFAULT_PORT))
    resume_mode = ResumeMode(cfg.get("resume_mode", ResumeMode.HOST_ONLY.value))
    ignore_client = bool(cfg.get("ignore_client", False))

    core = RelayCore(listen_port=listen_port, resume_mode=resume_mode, ignore_client=ignore_client)

    def _log_status():
        print(f"[Media-Sync] Status: {core.status_text()}")

    core.on_status_change = _log_status
    core.start_in_thread()
    core.start_auto_connect(peer_ip, peer_port)
    print("[Media-Sync] CLI started. Press Ctrl+C to exit.")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[Media-Sync] Shutting down...")
        core.stop()
        time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
