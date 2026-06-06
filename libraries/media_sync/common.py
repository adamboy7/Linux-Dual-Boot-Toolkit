from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import pystray
from pystray import MenuItem as Item, Menu as Menu
from PIL import Image, ImageDraw

APP_NAME = "MediaRelay"
DEFAULT_PORT = 50123

_RESP_HOST_OPEN = 10
_RESP_HOST_FORWARD = 11


class State(str, Enum):
    NONE = "none"
    PAUSED = "paused"
    PLAYING = "playing"


class ResumeMode(str, Enum):
    HOST_ONLY = "host_only"
    CLIENT_ONLY = "client_only"
    BLIND = "blind"


@dataclass
class MediaSnapshot:
    state: State
    app: str = ""
    title: str = ""


class NullMediaKeyListener:
    def start(self): pass
    def stop(self): pass


def decide_actions(
    host: State,
    client: State,
    resume_mode: ResumeMode,
) -> Tuple[Optional[str], Optional[str]]:
    """Returns (host_cmd, client_cmd) for a single 'toggle press' arbitration."""
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


def decide_track_action(
    host: State,
    client: State,
    resume_mode: ResumeMode,
    track: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Returns (host_cmd, client_cmd) for a Next/Prev press."""
    host_has = host in (State.PLAYING, State.PAUSED)
    client_has = client in (State.PLAYING, State.PAUSED)

    if not host_has and not client_has:
        return None, None
    if host_has and not client_has:
        return track, None
    if client_has and not host_has:
        return None, track
    if host == State.PLAYING and client != State.PLAYING:
        return track, None
    if client == State.PLAYING and host != State.PLAYING:
        return None, track
    if resume_mode == ResumeMode.CLIENT_ONLY:
        return ("pause" if host == State.PLAYING else None), track
    return track, ("pause" if client == State.PLAYING else None)


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
            "ignore_client": False,
            "enable_media_controls": True,
            "enable_links": True,
            "latency_correction": False,
            "installed_version": "Unknown",
        }
    try:
        with open(p, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "ignore_client" not in cfg and "bidirectional" in cfg:
            cfg["ignore_client"] = not bool(cfg.get("bidirectional"))
        if "bidirectional" in cfg:
            cfg.pop("bidirectional", None)
        migrated = False
        if "enable_media_controls" not in cfg:
            cfg["enable_media_controls"] = True
            migrated = True
        if "enable_links" not in cfg:
            cfg["enable_links"] = False
            migrated = True
        if "latency_correction" not in cfg:
            cfg["latency_correction"] = False
            migrated = True
        if "installed_version" not in cfg:
            cfg["installed_version"] = "Unknown"
            migrated = True
        if migrated:
            save_config(cfg)
        return cfg
    except Exception:
        return {
            "listen_port": DEFAULT_PORT,
            "peer_ip": "",
            "peer_port": DEFAULT_PORT,
            "swallow_media_keys": True,
            "resume_mode": ResumeMode.HOST_ONLY.value,
            "ignore_client": False,
            "enable_media_controls": True,
            "enable_links": True,
            "latency_correction": False,
            "installed_version": "Unknown",
        }


# Guards every read-modify-write cycle on the JSON state files so two
# near-simultaneous trust prompts don't last-write-wins each other.
_STATE_FILE_LOCK = threading.Lock()


def _atomic_write_json(path: str, data) -> None:
    """Write JSON atomically: tmp + fsync + os.replace.

    On Windows os.replace is atomic across both NTFS and ReFS, so a crash
    mid-write leaves either the old file intact or the new file complete.
    Without this, a power-loss truncation would lose every saved preference
    (and every trusted host/domain) on the next launch.
    """
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp_path, path)


def save_config(cfg: dict) -> None:
    with _STATE_FILE_LOCK:
        _atomic_write_json(config_path(), cfg)


def get_installed_version(cfg: dict) -> str:
    if not getattr(sys, "frozen", False):
        return "Source"
    return cfg.get("installed_version", "Unknown")


# -------------------- URL trust management --------------------

def _trusted_domains_path() -> str:
    return os.path.join(os.path.dirname(config_path()), "trusted_domains.json")


def _trusted_hosts_path() -> str:
    return os.path.join(os.path.dirname(config_path()), "trusted_hosts.json")


def _load_trusted_domains() -> list:
    p = _trusted_domains_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_trusted_domains(patterns: list) -> None:
    _atomic_write_json(_trusted_domains_path(), patterns)


def _load_trusted_hosts() -> list:
    p = _trusted_hosts_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_trusted_hosts(hosts: list) -> None:
    _atomic_write_json(_trusted_hosts_path(), hosts)


def _is_ip_url(url: str) -> bool:
    """Return True if the URL's host is a raw IP address rather than a domain name."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.hostname or ""
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_STANDARD_SCHEMES = {"http", "https", "ftp", "ftps", "mailto", "file", "data", "ws", "wss"}

# Hard cap on the length of any URL we accept off the wire. Anything longer
# than this is treated as garbage and dropped before reaching webbrowser.open.
_MAX_URL_LENGTH = 8192

# Schemes accepted on the receive path. Intentionally narrower than
# _STANDARD_SCHEMES; in particular `file://` is excluded so a (trusted) peer
# cannot trick the local UI into opening an arbitrary local path.
_INBOUND_ALLOWED_SCHEMES = frozenset({"http", "https", "ftp"})


def _validate_incoming_url(url: str) -> Optional[str]:
    """Sanity-check a URL received from a peer before forwarding to the UI.

    Returns the trimmed URL on success, or None if it should be dropped.
    Mirrors TrayApp._normalize_url but drops file:// (per audit note L12).
    """
    if not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate or len(candidate) > _MAX_URL_LENGTH:
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in _INBOUND_ALLOWED_SCHEMES:
        return None
    if not parsed.netloc:
        return None
    return candidate


def _is_app_protocol_url(url: str) -> bool:
    """Return True if the URL uses a non-standard app/system protocol."""
    scheme = urlparse(url).scheme.lower()
    return bool(scheme) and scheme not in _STANDARD_SCHEMES


def _url_domain(url: str) -> str:
    """Extract the hostname from a URL, or the scheme for app protocol URLs."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        if _is_app_protocol_url(url):
            return parsed.scheme.lower()
        return parsed.hostname or ""
    except Exception:
        return ""


def is_domain_trusted(url: str) -> bool:
    """Return True if the URL's domain matches any saved trusted pattern."""
    domain = _url_domain(url)
    if not domain:
        return False
    for pattern in _load_trusted_domains():
        if fnmatch.fnmatch(domain.lower(), pattern.lower()):
            return True
    return False


def add_trusted_domain(url: str) -> None:
    """Save the URL's domain to the trusted domains list."""
    domain = _url_domain(url)
    if not domain:
        return
    # Hold the file lock across load+modify+save so two concurrent prompts
    # can't last-write-wins each other and drop one of the trust additions.
    with _STATE_FILE_LOCK:
        patterns = _load_trusted_domains()
        if domain not in patterns:
            patterns.append(domain)
            _atomic_write_json(_trusted_domains_path(), patterns)


def is_host_permanently_trusted(host_ip: str) -> bool:
    return host_ip in _load_trusted_hosts()


def add_trusted_host(host_ip: str) -> None:
    with _STATE_FILE_LOCK:
        hosts = _load_trusted_hosts()
        if host_ip not in hosts:
            hosts.append(host_ip)
            _atomic_write_json(_trusted_hosts_path(), hosts)


def _trusted_clients_path() -> str:
    return os.path.join(os.path.dirname(config_path()), "trusted_clients.json")


def _load_trusted_clients() -> list:
    p = _trusted_clients_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_trusted_clients(clients: list) -> None:
    _atomic_write_json(_trusted_clients_path(), clients)


def is_client_permanently_trusted(client_ip: str) -> bool:
    return client_ip in _load_trusted_clients()


def add_trusted_client(client_ip: str) -> None:
    with _STATE_FILE_LOCK:
        clients = _load_trusted_clients()
        if client_ip not in clients:
            clients.append(client_ip)
            _atomic_write_json(_trusted_clients_path(), clients)


# -------------------- Client aliases --------------------

def _client_aliases_path() -> str:
    return os.path.join(os.path.dirname(config_path()), "client_aliases.json")


def load_client_aliases() -> dict:
    p = _client_aliases_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_client_aliases(aliases: dict) -> None:
    _atomic_write_json(_client_aliases_path(), aliases)


def set_client_alias(ip: str, alias: str) -> None:
    with _STATE_FILE_LOCK:
        aliases = load_client_aliases()
        alias = alias.strip()
        if alias:
            aliases[ip] = alias
        else:
            aliases.pop(ip, None)
        _atomic_write_json(_client_aliases_path(), aliases)


def get_client_alias(ip: str) -> Optional[str]:
    return load_client_aliases().get(ip)


def client_display_name(ip: str, port: int) -> str:
    alias = get_client_alias(ip)
    return f"{alias}:{port}" if alias else f"{ip}:{port}"


# -------------------- Networking / role state machine --------------------

class Role(str, Enum):
    HOST = "host"
    CLIENT = "client"


def now_ms() -> int:
    return int(time.time() * 1000)


def _gen_session_token() -> str:
    """Generate a random per-connection session token used to bind link-
    bearing UDP packets to a peer that completed the handshake."""
    return secrets.token_hex(16)


def encode(msg: dict) -> bytes:
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def decode(data: bytes) -> Optional[dict]:
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


class RelayCore:
    """Runs in an asyncio loop (background thread). Tray callbacks call into this
    using thread-safe methods."""

    def __init__(self, listen_port: int, resume_mode: ResumeMode, ignore_client: bool,
                 enable_media_controls: bool = True, enable_links: bool = True,
                 latency_correction: bool = False,
                 media_controller=None):
        self.listen_port = listen_port
        self.media = media_controller

        self.role: Role = Role.HOST
        self.resume_mode: ResumeMode = resume_mode
        self.ignore_client: bool = ignore_client
        self.enable_media_controls: bool = enable_media_controls
        self.enable_links: bool = enable_links
        self.latency_correction: bool = latency_correction
        self.peer: Optional[Tuple[str, int]] = None
        self.peer_last_seen: float = 0.0
        # HOST multi-client: maps each connected client addr -> last_seen timestamp
        self.peers: Dict[Tuple[str, int], float] = {}
        self.peer_latency: Dict[Tuple[str, int], float] = {}
        self._ping_sent_at: Dict[Tuple[str, int], int] = {}

        self.sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._auto_connect_enabled = False
        self._auto_connect_task: Optional[asyncio.Task] = None
        self._auto_connect_target: Optional[Tuple[str, int]] = None
        self._last_connect_attempt: Optional[Tuple[str, int]] = None
        self._last_connect_attempt_ts: float = 0.0

        # pending RPCs: id -> Future
        self.pending = {}

        # Set when _run cannot start (or restart) the UDP socket; surfaced via
        # status_text() and the on_fatal_error callback so the tray app can warn
        # the user instead of presenting a silently-broken icon.
        self.fatal_error: Optional[str] = None

        # UI callback hooks (set by tray app)
        self.on_status_change = lambda: None
        self.on_resume_mode_change = lambda mode: None
        self.on_ignore_client_change = lambda enabled: None
        self.on_open_url = lambda url, host_ip: None
        self.on_receive_url_from_client = lambda url, client_addr: None
        self.on_enable_media_controls_change = lambda enabled: None
        self.on_enable_links_change = lambda enabled: None
        self.on_latency_correction_change = lambda enabled: None
        self.on_fatal_error = lambda message: None
        self.on_listen_port_error = lambda port, message: None
        # Whether the host we're connected to has enable_links = True
        self.host_enable_links: bool = False
        # Host IPs that the client has trusted for the duration of this session
        self.session_trusted_hosts: set = set()
        # Client IPs that the host has trusted for the duration of this session
        self.session_trusted_clients: set = set()

        # Per-peer session tokens (basic anti-IP-spoofing for links)
        self.peer_tokens: Dict[Tuple[str, int], str] = {}
        self.peer_token: Optional[str] = None

    @property
    def _effective_resume_mode(self) -> ResumeMode:
        """BLIND is forced when HOST has more than one client connected."""
        if self.role == Role.HOST and len(self.peers) > 1:
            return ResumeMode.BLIND
        return self.resume_mode

    def _log(self, message: str) -> None:
        print(f"[Media-Sync] {message}")

    # ---- public, thread-safe entrypoints ----

    def start_in_thread(self):
        t = threading.Thread(target=self._thread_main, daemon=True)
        self._thread = t
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

    def ui_kick_client(self, addr: Tuple[str, int]) -> None:
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._disconnect_client(addr, "kicked"))
            )

    def ui_toggle(self, source: str = "local"):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._toggle_pressed(source=source)))

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

    def ui_set_ignore_client(self, enabled: bool):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_ignore_client(bool(enabled), source="local"))
            )

    def ui_set_enable_media_controls(self, enabled: bool):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_enable_media_controls(bool(enabled)))
            )

    def ui_set_enable_links(self, enabled: bool):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_enable_links(bool(enabled)))
            )

    def ui_set_latency_correction(self, enabled: bool):
        if self.loop:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self._set_latency_correction(bool(enabled)))
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

    def ui_stop_all(self, source: str = "local"):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._stop_pressed(source=source)))

    def ui_next(self, source: str = "local"):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._next_pressed(source=source)))

    def ui_prev(self, source: str = "local"):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._prev_pressed(source=source)))

    def ui_send_link(self, url: str, exclude_addr=None):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._send_link(url, exclude_addr)))

    def ui_send_link_to_host(self, url: str):
        if self.loop:
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(self._send_link_to_host(url)))

    # ---- internal thread/loop ----

    def _thread_main(self):
        # Use SelectorEventLoop directly on Windows for UDP reliability
        if sys.platform == "win32":
            self.loop = asyncio.SelectorEventLoop()
        else:
            self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._run())
        except OSError as exc:
            # Most commonly: configured listen port is already in use. Without
            # this, the network thread dies silently and the tray icon stays
            # up looking functional but doing nothing.
            msg = f"Cannot bind 0.0.0.0:{self.listen_port}: {exc}"
            self.fatal_error = msg
            try:
                self.on_fatal_error(msg)
            except Exception:
                pass
            try:
                self.on_status_change()
            except Exception:
                pass
        finally:
            self.loop.close()

    async def _run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                pass
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
        if self.fatal_error:
            return f"ERROR: {self.fatal_error}"
        if self.role == Role.HOST and self.peers:
            if len(self.peers) == 1:
                addr = next(iter(self.peers))
                return f"HOST connected -> {client_display_name(addr[0], addr[1])}"
            return f"HOST connected -> {len(self.peers)} clients"
        if self.role == Role.CLIENT and self.peer:
            return f"CLIENT connected -> {client_display_name(self.peer[0], self.peer[1])}"
        return f"{self.role.value.upper()} (no peer)"

    async def _send_policy_to_peer(self, source: str = "core"):
        if self.role != Role.HOST:
            return
        if not self.peers:
            return
        msg = {
            "t": "policy",
            "ts": now_ms(),
            "resume_mode": self._effective_resume_mode.value,
            "enable_links": self.enable_links,
            "source": source,
        }
        for addr in list(self.peers):
            await self._send(addr, msg)

    async def _send(self, addr: Tuple[str, int], msg: dict):
        if not self.sock:
            return
        if "tok" not in msg:
            token: Optional[str] = None
            if self.role == Role.HOST:
                token = self.peer_tokens.get(addr)
            elif self.role == Role.CLIENT and self.peer == addr:
                token = self.peer_token
            if token:
                msg = {**msg, "tok": token}
        try:
            self.sock.sendto(encode(msg), addr)
        except OSError as exc:
            self._log(f"Socket send error to {addr[0]}:{addr[1]}: {exc}")
            return

    # Message types that MUST carry a valid session token to be accepted.
    _AUTH_REQUIRED_TYPES = frozenset({"client_url", "open_url", "resume_mode"})

    def _validate_source(self, addr: Tuple[str, int], msg: dict, mtype: Optional[str]) -> bool:
        if mtype == "connect_request":
            return True
        if mtype == "connect_ack":
            return bool(
                self._last_connect_attempt
                and addr == self._last_connect_attempt
                and (time.time() - self._last_connect_attempt_ts) < 5.0
            )
        if mtype not in self._AUTH_REQUIRED_TYPES:
            return True
        incoming = msg.get("tok", "")
        if not isinstance(incoming, str) or not incoming:
            self._log(
                f"Dropped {mtype} from {addr[0]}:{addr[1]}: unauthenticated "
                f"peer is not permitted to send links."
            )
            return False
        if self.role == Role.HOST:
            expected = self.peer_tokens.get(addr)
            if not expected:
                self._log(
                    f"Dropped {mtype} from {addr[0]}:{addr[1]}: no session "
                    f"token recorded for this client."
                )
                return False
            if not secrets.compare_digest(expected, incoming):
                self._log(
                    f"Dropped {mtype} from {addr[0]}:{addr[1]}: session "
                    f"token mismatch (possible spoof)."
                )
                return False
            return True
        if self.peer_token:
            expected_addr = self.peer or self._last_connect_attempt
            if expected_addr and addr == expected_addr:
                if secrets.compare_digest(self.peer_token, incoming):
                    return True
                self._log(
                    f"Dropped {mtype} from {addr[0]}:{addr[1]}: session "
                    f"token mismatch (possible spoof)."
                )
                return False
        self._log(
            f"Dropped {mtype} from {addr[0]}:{addr[1]}: no authenticated "
            f"host session."
        )
        return False

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

                if not self._validate_source(addr, msg, mtype):
                    continue

                if rid and rid in self.pending and not self.pending[rid].done():
                    if (
                        mtype == "connect_ack"
                        and msg.get("ok")
                        and self.peer_token is None
                    ):
                        tok = msg.get("tok")
                        if isinstance(tok, str) and tok:
                            self.peer_token = tok
                    self.pending[rid].set_result(msg)
                    continue

                if self.role == Role.HOST and addr in self.peers:
                    self.peers[addr] = time.time()
                elif self.role == Role.CLIENT and self.peer and addr == self.peer:
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
                        tok = msg.get("tok")
                        if isinstance(tok, str) and tok:
                            self.peer_token = tok
                        self._ensure_auto_connect_task()
                        self._log(f"Connected to host {addr[0]}:{addr[1]} (late ack).")
                        self._notify()
                elif mtype == "disconnect":
                    if self.role == Role.HOST and addr in self.peers:
                        await self._disconnect_client(addr, "peer")
                    elif self.role == Role.CLIENT and self.peer and addr == self.peer:
                        await self._disconnect(msg.get("why", "peer"))
                elif mtype == "ping":
                    ts = msg.get("ts")
                    pong = {"t": "pong"} if ts is None else {"t": "pong", "ts": ts}
                    if self.role == Role.HOST and addr in self.peers:
                        await self._send(addr, pong)
                    elif self.role == Role.CLIENT and self.peer and addr == self.peer:
                        await self._send(addr, pong)
                elif mtype == "pong":
                    if self.role == Role.HOST and addr in self.peers:
                        sent = self._ping_sent_at.pop(addr, None)
                        if sent is not None:
                            rtt = now_ms() - sent
                            prev = self.peer_latency.get(addr)
                            self.peer_latency[addr] = rtt if prev is None else 0.25 * rtt + 0.75 * prev
                elif mtype == "get_state":
                    await self._handle_get_state(addr, msg)
                elif mtype == "cmd":
                    await self._handle_cmd(addr, msg)
                elif mtype == "resume_mode":
                    await self._handle_resume_mode(addr, msg)
                elif mtype == "policy":
                    await self._handle_policy(addr, msg)
                elif mtype == "request_toggle":
                    if self.role == Role.HOST and addr in self.peers:
                        if not self.ignore_client:
                            hint = None
                            try:
                                hint = State(msg.get("state", "none"))
                            except Exception:
                                hint = None
                            await self._toggle_pressed(source="peer", client_state_hint=hint, source_addr=None)
                        elif self._effective_resume_mode == ResumeMode.BLIND:
                            await self._send(addr, {"t": "cmd", "cmd": "toggle", "ts": now_ms()})
                elif mtype == "request_stop":
                    if self.role == Role.HOST and addr in self.peers:
                        if not self.ignore_client:
                            await self._stop_pressed(source="peer", source_addr=addr)
                        elif self._effective_resume_mode == ResumeMode.BLIND:
                            await self._send(addr, {"t": "cmd", "cmd": "stop", "ts": now_ms()})
                elif mtype == "request_next":
                    if self.role == Role.HOST and addr in self.peers:
                        if not self.ignore_client:
                            hint = None
                            try:
                                hint = State(msg.get("state", "none"))
                            except Exception:
                                hint = None
                            await self._next_pressed(source="peer", client_state_hint=hint, source_addr=None)
                        elif self._effective_resume_mode == ResumeMode.BLIND:
                            await self._send(addr, {"t": "cmd", "cmd": "next", "ts": now_ms()})
                elif mtype == "request_prev":
                    if self.role == Role.HOST and addr in self.peers:
                        if not self.ignore_client:
                            hint = None
                            try:
                                hint = State(msg.get("state", "none"))
                            except Exception:
                                hint = None
                            await self._prev_pressed(source="peer", client_state_hint=hint, source_addr=None)
                        elif self._effective_resume_mode == ResumeMode.BLIND:
                            await self._send(addr, {"t": "cmd", "cmd": "prev", "ts": now_ms()})
                elif mtype == "open_url":
                    await self._handle_open_url_msg(addr, msg)
                elif mtype == "client_url":
                    await self._handle_client_url_msg(addr, msg)
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

        self.role = Role.HOST
        normalized = (addr[0], addr[1])
        self.peers[normalized] = time.time()
        # Only treat this client as the "primary" self.peer when we don't
        # already have one. Re-assigning here would let any newly connecting
        # client bump itself into the single-client compat path and bypass
        # _handle_resume_mode's addr equality check.
        if self.peer is None:
            self.peer = normalized
            self.peer_last_seen = time.time()
        elif self.peer == normalized:
            self.peer_last_seen = time.time()
        token = _gen_session_token()
        self.peer_tokens[normalized] = token
        await self._send(addr, {
            "t": "connect_ack",
            "id": msg.get("id"),
            "ok": True,
            "tok": token,
            "enable_links": self.enable_links,
            "ts": now_ms(),
        })
        await self._send(addr, {"t": "resume_mode", "mode": self.resume_mode.value, "ts": now_ms()})
        await self._send_policy_to_peer(source="connect")
        self._log(f"Client connected from {addr[0]}:{addr[1]}. Total clients: {len(self.peers)}.")
        self._notify()

    async def _connect_out(self, ip: str, port: int):
        try:
            resolved = await self.loop.run_in_executor(None, socket.gethostbyname, ip)
        except OSError:
            self._log(f"DNS resolution failed for {ip}.")
            await self._disconnect("connect_failed")
            return
        addr = (resolved, int(port))
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
        self.host_enable_links = bool(resp.get("enable_links", True))
        tok = resp.get("tok")
        if isinstance(tok, str) and tok:
            self.peer_token = tok
        self._ensure_auto_connect_task()
        self._log(f"Connected to host {addr[0]}:{addr[1]}.")
        self._notify()

    async def _disconnect(self, why: str):
        was_client = self.role == Role.CLIENT
        _host_ip_before_disconnect = self.peer[0] if (was_client and self.peer) else None
        if self.role == Role.HOST and self.peers:
            for addr in list(self.peers):
                try:
                    await self._send(addr, {"t": "disconnect", "why": why, "ts": now_ms()})
                except Exception:
                    pass
            self._log(f"Disconnected all {len(self.peers)} client(s) (reason: {why}).")
            self.peers.clear()
            self.peer_tokens.clear()
        elif self.peer:
            try:
                await self._send(self.peer, {"t": "disconnect", "why": why, "ts": now_ms()})
            except Exception:
                pass
            self._log(f"Disconnected from {self.peer[0]}:{self.peer[1]} (reason: {why}).")
        self.peer = None
        self.peer_token = None
        self.peer_last_seen = 0.0
        self.host_enable_links = False
        if _host_ip_before_disconnect:
            self.session_trusted_hosts.discard(_host_ip_before_disconnect)
        should_retry = (
            self._auto_connect_enabled
            and self._auto_connect_target
            and why not in ("user", "kicked", "listen_port_changed")
        )
        if should_retry:
            self.role = Role.CLIENT
        elif why in ("user", "kicked"):
            self.role = Role.HOST
        elif was_client and self._auto_connect_enabled:
            self.role = Role.CLIENT
        else:
            self.role = Role.HOST
        if why == "kicked":
            self._auto_connect_enabled = False
            self._cancel_auto_connect_task()
        self._notify()
        if self._auto_connect_enabled:
            self._ensure_auto_connect_task()

    async def _disconnect_client(self, addr: Tuple[str, int], why: str):
        """Remove a single client from the HOST peers dict."""
        if addr not in self.peers:
            return
        try:
            await self._send(addr, {"t": "disconnect", "why": why, "ts": now_ms()})
        except Exception:
            pass
        del self.peers[addr]
        self.peer_latency.pop(addr, None)
        self._ping_sent_at.pop(addr, None)
        self.peer_tokens.pop(addr, None)
        self.session_trusted_clients.discard(addr[0])
        remaining = len(self.peers)
        self._log(f"Client {addr[0]}:{addr[1]} disconnected (reason: {why}). Remaining clients: {remaining}.")
        self.peer = next(iter(self.peers), None)
        self.peer_last_seen = self.peers.get(self.peer, 0.0) if self.peer else 0.0
        if self.peers:
            await self._send_policy_to_peer(source="client_disconnect")
        self._notify()

    async def _peer_timeout_loop(self):
        while True:
            await asyncio.sleep(1.0)
            if self.role == Role.HOST:
                now = time.time()
                timed_out = [addr for addr, ts in list(self.peers.items()) if (now - ts) > 6.0]
                for addr in timed_out:
                    self._log(f"Client {addr[0]}:{addr[1]} timed out.")
                    await self._disconnect_client(addr, "timeout")
            elif self.peer:
                if (time.time() - self.peer_last_seen) > 6.0:
                    self._log(f"Connection to {self.peer[0]}:{self.peer[1]} lost (timeout).")
                    await self._disconnect("timeout")

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(2.0)
            if self.role == Role.HOST:
                for addr in list(self.peers):
                    try:
                        self._ping_sent_at[addr] = now_ms()
                        await self._send(addr, {"t": "ping", "ts": self._ping_sent_at[addr]})
                    except Exception:
                        pass
            elif self.peer:
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
        if self.role == Role.CLIENT and not self.enable_media_controls:
            await self._send(addr, {
                "t": "state",
                "id": msg.get("id"),
                "ts": now_ms(),
                "state": State.NONE.value,
                "app": "",
                "title": "",
            })
            return
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
        if self.role == Role.CLIENT and not self.enable_media_controls:
            await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": False, "cmd": cmd})
            return
        if self.role == Role.HOST and not self.enable_media_controls:
            await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": False, "cmd": cmd})
            if addr in self.peers:
                for other_addr in list(self.peers):
                    if other_addr != addr:
                        await self._send(other_addr, {"t": "cmd", "cmd": cmd, "ts": now_ms(), "relayed": True})
            return
        ok = False
        if cmd == "toggle":
            ok = await self._toggle_local()
        elif cmd in ("play", "pause", "stop", "next", "prev"):
            ok = await self.media.command(cmd)
        await self._send(addr, {"t": "ack", "id": msg.get("id"), "ts": now_ms(), "ok": ok, "cmd": cmd})
        if self.role == Role.HOST and addr in self.peers:
            for other_addr in list(self.peers):
                if other_addr != addr:
                    await self._send(other_addr, {"t": "cmd", "cmd": cmd, "ts": now_ms(), "relayed": True})

    async def _handle_resume_mode(self, addr, msg):
        # Resume-mode is HOST-authoritative (same as policy). If we are HOST,
        # ignore client-initiated mode changes: they should arrive via policy
        # request flow, not via this typed message that bypasses arbitration.
        if self.role == Role.HOST:
            return
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

        enable_links_val = msg.get("enable_links")
        if enable_links_val is not None:
            new_val = bool(enable_links_val)
            if new_val != self.host_enable_links:
                self.host_enable_links = new_val
                self._notify()

    async def _apply_resume_mode(self, resume_mode: ResumeMode, notify: bool):
        if resume_mode == self.resume_mode:
            return
        self.resume_mode = resume_mode
        if notify:
            try:
                self.on_resume_mode_change(resume_mode)
            except Exception:
                pass

    async def _apply_ignore_client(self, enabled: bool, notify: bool):
        if enabled == self.ignore_client:
            return
        self.ignore_client = enabled
        if notify:
            try:
                self.on_ignore_client_change(enabled)
            except Exception:
                pass

    async def _set_resume_mode(self, resume_mode: ResumeMode, source: str):
        await self._apply_resume_mode(resume_mode, notify=True)
        if self.peer:
            if self.role == Role.CLIENT:
                await self._send(self.peer, {"t": "resume_mode", "mode": resume_mode.value, "ts": now_ms(), "source": source})
            else:
                await self._send_policy_to_peer(source=source)

    async def _set_ignore_client(self, enabled: bool, source: str):
        if self.role == Role.CLIENT:
            self._log("Ignoring local ignore-client change (host-controlled).")
            return
        await self._apply_ignore_client(bool(enabled), notify=True)
        await self._send_policy_to_peer(source=source)

    async def _set_enable_media_controls(self, enabled: bool):
        if enabled == self.enable_media_controls:
            return
        self.enable_media_controls = enabled
        try:
            self.on_enable_media_controls_change(enabled)
        except Exception:
            pass

    async def _set_enable_links(self, enabled: bool):
        if enabled == self.enable_links:
            return
        self.enable_links = enabled
        try:
            self.on_enable_links_change(enabled)
        except Exception:
            pass
        await self._send_policy_to_peer(source="enable_links")

    async def _set_latency_correction(self, enabled: bool):
        # HOST-only knob. CLIENTs silently ignore so a stale tray menu can't
        # flip a no-op flag on a client and then surprise the user when they
        # re-host.
        if self.role == Role.CLIENT:
            self._log("Ignoring local latency-correction change (host-only feature).")
            return
        if enabled == self.latency_correction:
            return
        self.latency_correction = enabled
        try:
            self.on_latency_correction_change(enabled)
        except Exception:
            pass

    async def _set_listen_port(self, port: int):
        if port == self.listen_port:
            return
        # Disconnect on either role: HOST tears down its peer list, CLIENT
        # tears down its session so the host's stale (client_ip, OLD_port)
        # tuple doesn't strand heartbeats / link auth against a port the
        # client is no longer listening on.
        if (self.role == Role.HOST and self.peers) or (
            self.role == Role.CLIENT and self.peer
        ):
            await self._disconnect("listen_port_changed")

        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        try:
            new_sock.bind(("0.0.0.0", port))
        except OSError as exc:
            new_sock.close()
            try:
                self.on_listen_port_error(port, str(exc))
            except Exception:
                pass
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

    def _one_way_latency_ms(self, addr: Tuple[str, int]) -> float:
        """Estimate one-way latency to ``addr`` in ms from measured RTT.

        ``peer_latency`` is populated by the ping/pong heartbeat as a
        round-trip in ms; halve it for a one-way estimate. Peers without a
        measurement yet are treated as 0ms (assume best case so we don't
        over-delay an unknown link).
        """
        rtt = self.peer_latency.get(addr, 0.0) or 0.0
        return max(0.0, float(rtt) / 2.0)

    async def _dispatch_with_latency_correction(self, sends, local_action=None):
        """HOST: stagger ``sends`` and ``local_action`` so they take effect together.

        ``sends`` is an iterable of ``(addr, msg)`` tuples to deliver to peers.
        ``local_action`` is an optional zero-arg callable that returns a
        coroutine (e.g. ``self._toggle_local`` or ``lambda: self.media.command(
        "stop")``) for the host's own playback change.

        With ``latency_correction`` off, sends fire immediately and
        ``local_action`` runs synchronously - matches the prior behavior.

        With it on, each peer ``addr`` waits ``(worst_one_way -
        one_way[addr])`` ms before its packet leaves, and the local action
        waits ``worst_one_way`` ms, so every endpoint should toggle at
        approximately the same wall-clock instant (network jitter aside).
        """
        sends_list = list(sends)
        if not self.latency_correction:
            for addr, msg in sends_list:
                await self._send(addr, msg)
            if local_action is not None:
                await local_action()
            return

        # Worst-case is taken across the targets only. A connected but
        # untargeted peer (e.g. the source of a relayed cmd that's been
        # excluded) shouldn't dictate how long we delay the others.
        one_ways = {addr: self._one_way_latency_ms(addr) for addr, _ in sends_list}
        worst = max(one_ways.values(), default=0.0)

        async def send_after(addr, msg):
            delay_ms = max(0.0, worst - one_ways.get(addr, 0.0))
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
            await self._send(addr, msg)

        async def local_after():
            if worst > 0:
                await asyncio.sleep(worst / 1000.0)
            if local_action is not None:
                await local_action()

        tasks = [asyncio.create_task(send_after(a, m)) for a, m in sends_list]
        if local_action is not None:
            tasks.append(asyncio.create_task(local_after()))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _toggle_local(self) -> bool:
        snap = await self.media.snapshot()
        if snap.state == State.PLAYING:
            return await self.media.command("pause")
        if snap.state == State.PAUSED:
            return await self.media.command("play")
        return False

    async def _toggle_pressed(self, source: str, client_state_hint: Optional[State] = None,
                              source_addr: Optional[Tuple[str, int]] = None):
        if self.role == Role.HOST and not self.peers:
            await self._toggle_local()
            return
        if self.role == Role.CLIENT and not self.peer:
            await self._toggle_local()
            return

        if self.role == Role.CLIENT:
            if not self.enable_media_controls:
                await self._toggle_local()
                return
            if self.resume_mode == ResumeMode.BLIND:
                snap = await self.media.snapshot()
                await self._send(self.peer, {
                    "t": "request_toggle",
                    "ts": now_ms(),
                    "source": source,
                    "state": snap.state.value,
                })
                return
            snap = await self.media.snapshot()
            await self._send(self.peer, {
                "t": "request_toggle",
                "ts": now_ms(),
                "source": source,
                "state": snap.state.value,
            })
            return

        if not self.enable_media_controls:
            await self._toggle_local()
            return

        if self._effective_resume_mode == ResumeMode.BLIND:
            ts = now_ms()
            sends = [
                (addr, {"t": "cmd", "cmd": "toggle", "ts": ts, "source": source})
                for addr in list(self.peers)
                if addr != source_addr
            ]
            await self._dispatch_with_latency_correction(
                sends, local_action=self._toggle_local
            )
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

        sends = []
        if client_cmd:
            sends.append((self.peer, {"t": "cmd", "cmd": client_cmd, "ts": now_ms()}))
        local_action = (lambda: self.media.command(host_cmd)) if host_cmd else None
        await self._dispatch_with_latency_correction(sends, local_action=local_action)

    async def _stop_pressed(self, source: str, source_addr: Optional[Tuple[str, int]] = None):
        if self.role == Role.HOST and not self.peers:
            await self.media.command("stop")
            return
        if self.role == Role.CLIENT and not self.peer:
            await self.media.command("stop")
            return

        if self.role == Role.CLIENT:
            if not self.enable_media_controls:
                await self.media.command("stop")
                return
            if self.resume_mode == ResumeMode.BLIND:
                await self._send(self.peer, {"t": "request_stop", "ts": now_ms(), "source": source})
                return
            await self._send(self.peer, {"t": "request_stop", "ts": now_ms(), "source": source})
            return

        if not self.enable_media_controls:
            await self.media.command("stop")
            return

        ts = now_ms()
        sends = [
            (addr, {"t": "cmd", "cmd": "stop", "ts": ts})
            for addr in list(self.peers)
        ]
        await self._dispatch_with_latency_correction(
            sends, local_action=lambda: self.media.command("stop")
        )

    async def _next_pressed(self, source: str, client_state_hint: Optional[State] = None,
                            source_addr=None):
        if self.role == Role.HOST and not self.peers:
            await self.media.command("next")
            return
        if self.role == Role.CLIENT and not self.peer:
            await self.media.command("next")
            return

        if self.role == Role.CLIENT:
            if not self.enable_media_controls:
                await self.media.command("next")
                return
            if self.resume_mode == ResumeMode.BLIND:
                snap = await self.media.snapshot()
                await self._send(self.peer, {
                    "t": "request_next",
                    "ts": now_ms(),
                    "source": source,
                    "state": snap.state.value,
                })
                return
            snap = await self.media.snapshot()
            await self._send(self.peer, {
                "t": "request_next",
                "ts": now_ms(),
                "source": source,
                "state": snap.state.value,
            })
            return

        if not self.enable_media_controls:
            await self.media.command("next")
            return

        if self._effective_resume_mode == ResumeMode.BLIND:
            ts = now_ms()
            sends = [
                (addr, {"t": "cmd", "cmd": "next", "ts": ts, "source": source})
                for addr in list(self.peers)
                if addr != source_addr
            ]
            await self._dispatch_with_latency_correction(
                sends, local_action=lambda: self.media.command("next")
            )
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

        host_cmd, client_cmd = decide_track_action(host_snap.state, client_state, self.resume_mode, "next")
        sends = []
        if client_cmd:
            sends.append((self.peer, {"t": "cmd", "cmd": client_cmd, "ts": now_ms()}))
        local_action = (lambda: self.media.command(host_cmd)) if host_cmd else None
        await self._dispatch_with_latency_correction(sends, local_action=local_action)

    async def _prev_pressed(self, source: str, client_state_hint: Optional[State] = None,
                            source_addr=None):
        if self.role == Role.HOST and not self.peers:
            await self.media.command("prev")
            return
        if self.role == Role.CLIENT and not self.peer:
            await self.media.command("prev")
            return

        if self.role == Role.CLIENT:
            if not self.enable_media_controls:
                await self.media.command("prev")
                return
            if self.resume_mode == ResumeMode.BLIND:
                snap = await self.media.snapshot()
                await self._send(self.peer, {
                    "t": "request_prev",
                    "ts": now_ms(),
                    "source": source,
                    "state": snap.state.value,
                })
                return
            snap = await self.media.snapshot()
            await self._send(self.peer, {
                "t": "request_prev",
                "ts": now_ms(),
                "source": source,
                "state": snap.state.value,
            })
            return

        if not self.enable_media_controls:
            await self.media.command("prev")
            return

        if self._effective_resume_mode == ResumeMode.BLIND:
            ts = now_ms()
            sends = [
                (addr, {"t": "cmd", "cmd": "prev", "ts": ts, "source": source})
                for addr in list(self.peers)
                if addr != source_addr
            ]
            await self._dispatch_with_latency_correction(
                sends, local_action=lambda: self.media.command("prev")
            )
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

        host_cmd, client_cmd = decide_track_action(host_snap.state, client_state, self.resume_mode, "prev")
        sends = []
        if client_cmd:
            sends.append((self.peer, {"t": "cmd", "cmd": client_cmd, "ts": now_ms()}))
        local_action = (lambda: self.media.command(host_cmd)) if host_cmd else None
        await self._dispatch_with_latency_correction(sends, local_action=local_action)

    async def _send_link(self, url: str, exclude_addr=None):
        """HOST: broadcast a URL to all connected clients, optionally skipping one."""
        if self.role != Role.HOST or not self.peers:
            return
        msg = {"t": "open_url", "url": url, "ts": now_ms()}
        for addr in list(self.peers):
            if addr == exclude_addr:
                continue
            await self._send(addr, msg)

    async def _handle_open_url_msg(self, addr, msg):
        """CLIENT: receive a URL from the host and invoke the UI callback."""
        if self.role != Role.CLIENT:
            return
        if not self.enable_links:
            return
        if not self.peer or addr != self.peer:
            return
        url = msg.get("url", "")
        if not url or not isinstance(url, str):
            return
        # Mirror outgoing normalisation on the receive path so a (trusted)
        # peer that sends a garbage or unsupported URL doesn't reach
        # webbrowser.open with raw input.
        validated = _validate_incoming_url(url)
        if validated is None:
            self._log(f"Dropped open_url from {addr[0]}:{addr[1]}: failed validation.")
            return
        try:
            self.on_open_url(validated, addr[0])
        except Exception:
            pass

    async def _send_link_to_host(self, url: str):
        """CLIENT: send a URL to the host."""
        if self.role != Role.CLIENT or not self.peer:
            return
        if not self.host_enable_links:
            return
        msg = {"t": "client_url", "url": url, "ts": now_ms()}
        await self._send(self.peer, msg)

    async def _handle_client_url_msg(self, addr, msg):
        """HOST: receive a URL from a client and invoke the UI callback."""
        if self.role != Role.HOST:
            return
        if not self.enable_links:
            return
        if addr not in self.peers:
            return
        url = msg.get("url", "")
        if not url or not isinstance(url, str):
            return
        validated = _validate_incoming_url(url)
        if validated is None:
            self._log(f"Dropped client_url from {addr[0]}:{addr[1]}: failed validation.")
            return
        try:
            self.on_receive_url_from_client(validated, addr)
        except Exception:
            pass


# -------------------- Icon / resource helpers --------------------

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


def _resource_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _app_icon_path() -> str:
    return os.path.join(_resource_base_dir(), "libraries", "Media-Sync.ico")
