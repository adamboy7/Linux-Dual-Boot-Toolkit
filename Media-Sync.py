from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from typing import Callable, Optional, Tuple

import pystray
from pystray import MenuItem as Item, Menu as Menu
from PIL import Image

from libraries.media_sync import (
    APP_NAME,
    DEFAULT_PORT,
    RelayCore,
    ResumeMode,
    Role,
    _encode_file_url,
    _is_ip_url,
    _strip_pyi_env,
    add_trusted_client,
    add_trusted_domain,
    add_trusted_host,
    build_media_controller,
    build_media_key_listener,
    get_client_alias,
    get_installed_version,
    is_client_permanently_trusted,
    is_domain_trusted,
    is_host_permanently_trusted,
    load_config,
    make_icon,
    prompt_host_url_confirm,
    prompt_int,
    prompt_string,
    prompt_url_confirm,
    save_config,
    show_kick_dialog,
)

log = logging.getLogger(APP_NAME)

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    _TK_AVAILABLE = True
except ImportError:  # pragma: no cover - tkinter missing
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    _TK_AVAILABLE = False

if sys.platform == "win32":
    import libraries.media_sync.windows as _win_mod
    from libraries.media_sync.windows import (
        _create_shortcut_in_folder,
        _ensure_startup_shortcut,
        get_or_create_prompter,
        stop_prompter,
    )


def _ui_show(kind: str, title: str, message: str) -> Optional[bool]:
    """Show a tk messagebox safely from any thread.

    Returns the dialog result for ``askyesno``, otherwise None. Logs and
    returns None if Tk is missing.
    """
    if not _TK_AVAILABLE:
        log.warning("[%s] %s: %s", kind, title, message)
        return None
    if sys.platform == "win32":
        prompter = get_or_create_prompter()
        if prompter is not None:
            return prompter.show_message(kind, title, message)
        log.warning(
            "WinPromptThread unavailable; cannot show %s dialog: %s - %s",
            kind, title, message,
        )
        return None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            if kind == "error":
                messagebox.showerror(title, message, parent=root)
                return None
            if kind == "info":
                messagebox.showinfo(title, message, parent=root)
                return None
            if kind == "askyesno":
                return bool(messagebox.askyesno(title, message, parent=root))
        finally:
            try:
                root.destroy()
            except Exception:
                log.exception("Failed to destroy transient Tk root")
    except Exception:
        log.exception("Tk dialog failed (%s): %s", kind, message)
    return None


def _ui_save_file(
    title: str,
    initialfile: str,
    defaultextension: Optional[str] = None,
) -> Optional[str]:
    """Show a save-file dialog with a per-call hidden Tk root.

    Used as the non-Windows fallback for ``_do_download_release``. On Windows,
    callers should marshal through ``WinPromptThread`` instead.
    """
    if not _TK_AVAILABLE:
        log.warning("tkinter is unavailable; cannot prompt for save location")
        return None
    if sys.platform == "win32":
        log.warning(
            "WinPromptThread unavailable; refusing per-call Tk save dialog "
            "from a worker thread"
        )
        return None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            kwargs = dict(title=title, initialfile=initialfile, parent=root)
            if defaultextension:
                kwargs["defaultextension"] = defaultextension
            return filedialog.asksaveasfilename(**kwargs) or None
        finally:
            try:
                root.destroy()
            except Exception:
                log.exception("Failed to destroy save-dialog root")
    except Exception:
        log.exception("Save dialog failed")
        return None


class TrayApp:
    def __init__(self):
        self.cfg = load_config()
        self.listen_port = int(self.cfg.get("listen_port", DEFAULT_PORT))
        self._last_saved_state = {}
        # Debounce timer to coalesce rapid _persist_state calls into at most
        # one disk write every ~2s. Prevents a fast HOST/CLIENT role bounce
        # from spamming the config file.
        self._persist_debounce_timer: Optional[threading.Timer] = None
        self._persist_debounce_lock = threading.Lock()
        self._persist_debounce_interval = 2.0
        self._tray_state_lock = threading.Lock()
        self._last_tray_state: Optional[Tuple] = None
        self._tray_watchdog_stop = threading.Event()
        self._tray_watchdog_thread: Optional[threading.Thread] = None
        self._download_threads: list[threading.Thread] = []
        self._download_threads_lock = threading.Lock()
        # Guards _update_toolkit / _download_release so a fast second click
        # cannot race over exe_path + ".new" / exe_path + ".old".
        self._update_in_progress = threading.Lock()

        resume_mode_value = self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value)
        try:
            resume_mode = ResumeMode(resume_mode_value)
        except ValueError:
            log.warning("Invalid resume_mode %r in config; falling back to HOST_ONLY", resume_mode_value)
            resume_mode = ResumeMode.HOST_ONLY
        ignore_client = bool(self.cfg.get("ignore_client", False))
        enable_media_controls = bool(self.cfg.get("enable_media_controls", True))
        enable_links = bool(self.cfg.get("enable_links", True))
        latency_correction = bool(self.cfg.get("latency_correction", False))
        media_controller = build_media_controller()
        if media_controller is None:
            log.warning(
                "build_media_controller() returned None - media key actions will be disabled"
            )
        self.core = RelayCore(
            listen_port=self.listen_port,
            resume_mode=resume_mode,
            ignore_client=ignore_client,
            enable_media_controls=enable_media_controls,
            enable_links=enable_links,
            latency_correction=latency_correction,
            media_controller=media_controller,
        )
        with self._tray_state_lock:
            self._last_tray_state = self._desired_tray_state()
        self.core.on_status_change = self._refresh_tray
        self.core.on_resume_mode_change = self._set_resume_mode_from_core
        self.core.on_ignore_client_change = self._set_ignore_client_from_core
        self.core.on_open_url = self._handle_open_url_from_core
        self.core.on_receive_url_from_client = self._handle_url_from_client
        self.core.on_enable_media_controls_change = self._set_enable_media_controls_from_core
        self.core.on_enable_links_change = self._set_enable_links_from_core
        self.core.on_latency_correction_change = self._set_latency_correction_from_core
        self.core.on_fatal_error = self._handle_core_fatal_error
        self.core.on_listen_port_error = self._handle_listen_port_error
        self.media_key_listener = build_media_key_listener(
            self.core,
            swallow=bool(self.cfg.get("swallow_media_keys", True)),
            enabled=enable_media_controls,
        )

        if sys.platform == "win32":
            get_or_create_prompter()

        self.icon = pystray.Icon(APP_NAME, self._tray_icon(), APP_NAME, menu=self._build_menu())

    def _tray_icon(self) -> Image.Image:
        return make_icon(self.core.role, self.core.peer is not None)

    def _desired_tray_state(self) -> Tuple:
        peers = getattr(self.core, "peers", None)
        try:
            peers_key: Tuple = tuple(sorted(peers)) if peers else ()
        except TypeError:
            peers_key = tuple(repr(p) for p in (peers or ()))
        return (
            self.core.role,
            self.core.peer is not None,
            self.core.host_enable_links,
            self.core.enable_media_controls,
            self.core.enable_links,
            self.core.ignore_client,
            self.core.latency_correction,
            self.core.resume_mode,
            peers_key,
        )

    @staticmethod
    def _is_valid_host(host: str) -> bool:
        # Accept a raw IPv4 address or a hostname. IPv6 literals are excluded
        # because the relay socket binds AF_INET only and socket.gethostbyname
        # is IPv4-only; passing an IPv6 literal would fail opaquely at connect.
        try:
            ipaddress.IPv4Address(host)
            return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        import re
        return bool(re.match(
            r'^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*'
            r'[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$',
            host,
        ))

    @staticmethod
    def _is_valid_port(port: object) -> bool:
        # reject non-int, negative, zero, and out-of-range values.
        try:
            p = int(port)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return 1 <= p <= 65535

    def _should_auto_connect(self) -> bool:
        ip = self.cfg.get("peer_ip", "")
        return bool(
            self.cfg.get("auto_connect")
            and self.cfg.get("last_role") == Role.CLIENT.value
            and ip
            and self._is_valid_host(ip)
            and self._is_valid_port(self.cfg.get("peer_port"))
        )

    def _build_menu(self):
        items = [
            Item("Toggle", self._toggle),
            Item("Stop", self._stop),
            Item("Next", self._next),
            Item("Previous", self._prev),
            Item("Connect...", self._connect),
            Item("Disconnect", self._disconnect, enabled=lambda item: self.core.peer is not None),
        ]
        controls_items = [
            Item(
                "Media Controls",
                self._toggle_enable_media_controls,
                checked=lambda item: self.core.enable_media_controls,
            ),
            Item(
                "Receive Links",
                self._toggle_enable_links,
                checked=lambda item: self.core.enable_links,
            ),
        ]
        if self.core.role == Role.HOST:
            controls_items.append(
                Item(
                    "Ignore Client",
                    self._toggle_ignore_client,
                    checked=lambda item: self.core.ignore_client,
                )
            )
            controls_items.append(
                Item(
                    "Latency Correction",
                    self._toggle_latency_correction,
                    checked=lambda item: self.core.latency_correction,
                )
            )
        items += [
            Item("Controls", Menu(*controls_items)),
            Item(
                "Resume Mode",
                Menu(
                    Item(
                        "Resume host only",
                        lambda: self._set_resume_mode(ResumeMode.HOST_ONLY),
                        checked=lambda item: self.core.resume_mode == ResumeMode.HOST_ONLY,
                        radio=True,
                        enabled=lambda item: not self._resume_mode_locked(),
                    ),
                    Item(
                        "Resume client only",
                        lambda: self._set_resume_mode(ResumeMode.CLIENT_ONLY),
                        checked=lambda item: self.core.resume_mode == ResumeMode.CLIENT_ONLY,
                        radio=True,
                        enabled=lambda item: not self._resume_mode_locked(),
                    ),
                    Item(
                        "Blind relay",
                        lambda: self._set_resume_mode(ResumeMode.BLIND),
                        checked=lambda item: self.core.resume_mode == ResumeMode.BLIND,
                        radio=True,
                        enabled=lambda item: not self._resume_mode_locked(),
                    ),
                ),
            ),
            Item(
                lambda _item: f"Status: {self.core.status_text()}",
                lambda icon, item: None,
                enabled=False,
            ),
        ]
        tools_items = []
        if self.core.role == Role.HOST:
            tools_items.append(
                Item(
                    "Send Link...",
                    self._send_link_action,
                    enabled=lambda item: bool(self.core.peers),
                )
            )
            tools_items.append(
                Item(
                    "Kick...",
                    self._kick_action,
                    enabled=lambda item: bool(self.core.peers),
                )
            )
        elif self.core.role == Role.CLIENT:
            tools_items.append(
                Item(
                    "Send Link to Host...",
                    self._send_link_to_host_action,
                    enabled=lambda item: self.core.peer is not None and self.core.host_enable_links,
                )
            )
        tools_items.append(Item("Listening Port...", self._configure_listen_port))
        if sys.platform == "win32":
            tools_items.append(Item("Add to startup", self._add_to_startup))
            tools_items.append(Item("Create Shortcut...", self._create_shortcut))
        tools_items.append(Item("Update Toolkit", self._update_toolkit))
        if getattr(sys, "frozen", False):
            tools_items.append(Item("View Source", self._view_source))
        else:
            tools_items.append(Item("Download Release", self._download_release))
        tools_items.append(Item("Restart", self._restart))
        items.append(Item("Tools", Menu(*tools_items)))
        items.append(Item("Exit", self._exit))
        return Menu(*items)

    def _refresh_tray(self):
        def do():
            self.icon.icon = self._tray_icon()
            self.icon.menu = self._build_menu()
            self.icon.title = f"{APP_NAME} - {self.core.status_text()}"
            self._persist_state()
            with self._tray_state_lock:
                self._last_tray_state = self._desired_tray_state()
        try:
            q = getattr(self.icon, "_handler_queue", None)
            if q is not None:
                q.put(do)
            else:
                do()
        except Exception:
            log.exception("_refresh_tray failed")

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
        new_role = self.core.role.value
        if self.core.peer and self.core.role == Role.CLIENT:
            self.cfg["peer_ip"] = self.core.peer[0]
            self.cfg["peer_port"] = int(self.core.peer[1])
            self.cfg["auto_connect"] = True
        if self.cfg.get("last_role") != new_role:
            self.cfg["last_role"] = new_role
        state = {
            "peer_ip": self.cfg.get("peer_ip", ""),
            "peer_port": self.cfg.get("peer_port", DEFAULT_PORT),
            "last_role": self.cfg.get("last_role", ""),
            "auto_connect": self.cfg.get("auto_connect", False),
            "resume_mode": self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value),
            "ignore_client": self.cfg.get("ignore_client", False),
            "enable_media_controls": self.cfg.get("enable_media_controls", True),
            "enable_links": self.cfg.get("enable_links", True),
            "latency_correction": self.cfg.get("latency_correction", False),
        }
        if state == self._last_saved_state:
            return
        # Debounce so a fast role bounce doesn't spam disk writes. The cfg
        # change is recorded in memory immediately; the on-disk save happens
        # once the timer fires (and is forced via _flush_persist on shutdown).
        with self._persist_debounce_lock:
            if self._persist_debounce_timer is not None:
                self._persist_debounce_timer.cancel()
            self._persist_debounce_timer = threading.Timer(
                self._persist_debounce_interval, self._flush_persist
            )
            self._persist_debounce_timer.daemon = True
            self._persist_debounce_timer.start()

    def _flush_persist(self) -> None:
        """Write pending config changes to disk now.

        Called by the debounce timer and forced once during shutdown.
        """
        with self._persist_debounce_lock:
            self._persist_debounce_timer = None
        state = {
            "peer_ip": self.cfg.get("peer_ip", ""),
            "peer_port": self.cfg.get("peer_port", DEFAULT_PORT),
            "last_role": self.cfg.get("last_role", ""),
            "auto_connect": self.cfg.get("auto_connect", False),
            "resume_mode": self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value),
            "ignore_client": self.cfg.get("ignore_client", False),
            "enable_media_controls": self.cfg.get("enable_media_controls", True),
            "enable_links": self.cfg.get("enable_links", True),
            "latency_correction": self.cfg.get("latency_correction", False),
        }
        if state == self._last_saved_state:
            return
        try:
            save_config(self.cfg)
            self._last_saved_state = dict(state)
        except Exception:
            log.exception("save_config failed")

    def _toggle(self, icon=None, item=None):
        self.core.ui_toggle(source="hid")

    def _stop(self, icon=None, item=None):
        self.core.ui_stop_all(source="hid")

    def _next(self, icon=None, item=None):
        self.core.ui_next(source="local")

    def _prev(self, icon=None, item=None):
        self.core.ui_prev(source="local")

    def _run_on_tray_thread(self, func: Callable[[], None], label: str) -> None:
        """Marshal ``func`` onto pystray's handler thread when available."""
        try:
            q = getattr(self.icon, "_handler_queue", None)
            if q is not None:
                q.put(func)
            else:
                func()
        except Exception:
            log.exception("Failed to marshal %s to tray thread", label)

    def _apply_cfg_and_rebuild(self, key: str, value, label: str) -> None:
        def do():
            self.cfg[key] = value
            save_config(self.cfg)
            self.icon.menu = self._build_menu()
        self._run_on_tray_thread(do, label)

    def _set_resume_mode_from_core(self, resume_mode: ResumeMode):
        self._apply_cfg_and_rebuild("resume_mode", resume_mode.value, "resume_mode")

    def _set_resume_mode(self, resume_mode: ResumeMode):
        self.core.ui_set_resume_mode(resume_mode)

    def _resume_mode_locked(self) -> bool:
        """True when resume-mode menu items should be greyed out.

        Locked whenever more than one client shares the host: the host
        forces BLIND, and clients are told only that they aren't alone so
        they can grey out the same options without learning who else is
        connected.
        """
        if self.core.role == Role.HOST and len(self.core.peers) > 1:
            return True
        if self.core.role == Role.CLIENT and self.core.peer_multi_client:
            return True
        return False

    def _set_ignore_client_from_core(self, enabled: bool):
        self._apply_cfg_and_rebuild("ignore_client", bool(enabled), "ignore_client")

    def _toggle_ignore_client(self, icon=None, item=None):
        self.core.ui_set_ignore_client(not self.core.ignore_client)

    def _set_latency_correction_from_core(self, enabled: bool):
        self._apply_cfg_and_rebuild(
            "latency_correction", bool(enabled), "latency_correction"
        )

    def _toggle_latency_correction(self, icon=None, item=None):
        self.core.ui_set_latency_correction(not self.core.latency_correction)

    def _toggle_enable_media_controls(self, icon=None, item=None):
        new_val = not self.core.enable_media_controls
        self.cfg["enable_media_controls"] = new_val
        save_config(self.cfg)
        self.media_key_listener.stop()
        self.media_key_listener = build_media_key_listener(
            self.core,
            swallow=bool(self.cfg.get("swallow_media_keys", True)),
            enabled=new_val,
        )
        self.media_key_listener.start()
        self.core.ui_set_enable_media_controls(new_val)

    def _toggle_enable_links(self, icon=None, item=None):
        new_val = not self.core.enable_links
        self.cfg["enable_links"] = new_val
        save_config(self.cfg)
        self.core.ui_set_enable_links(new_val)

    def _set_enable_media_controls_from_core(self, enabled: bool):
        self._apply_cfg_and_rebuild(
            "enable_media_controls", bool(enabled), "enable_media_controls"
        )

    def _set_enable_links_from_core(self, enabled: bool):
        self._apply_cfg_and_rebuild("enable_links", bool(enabled), "enable_links")

    def _handle_core_fatal_error(self, message: str) -> None:
        """Called from the core thread when the network loop cannot start.

        Surface it to the user via a dialog (and the tray title via the
        regular status refresh) instead of letting the tray icon sit there
        looking functional but doing nothing.
        """
        def show():
            _ui_show("error", APP_NAME, f"Media-Sync network error:\n{message}")
        threading.Thread(target=show, daemon=True).start()

    def _handle_listen_port_error(self, port: int, message: str) -> None:
        """Called from the core thread when changing the listen port fails."""
        def show():
            _ui_show(
                "error",
                APP_NAME,
                f"Could not switch listen port to {port}: {message}\n\n"
                f"Listening port unchanged.",
            )
        threading.Thread(target=show, daemon=True).start()

    def _configure_listen_port(self, icon=None, item=None):
        result = prompt_int("Listen Port:", int(self.cfg.get("listen_port", DEFAULT_PORT)))
        if result is None:
            return  # user cancelled
        ok, port = result
        if not ok:
            _ui_show("error", APP_NAME, "Port must be an integer between 1 and 65535.")
            return
        if not self._is_valid_port(port):
            _ui_show("error", APP_NAME, "Port must be an integer between 1 and 65535.")
            return
        port = int(port)
        if port == self.listen_port:
            return
        self.listen_port = port
        self.cfg["listen_port"] = port
        save_config(self.cfg)
        self.core.ui_set_listen_port(port)

    def _connect(self, icon=None, item=None):
        ip = prompt_string("Host IP or hostname:", self.cfg.get("peer_ip", ""))
        if ip is None:
            return
        ip = ip.strip()
        if not ip:
            return
        if not self._is_valid_host(ip):
            _ui_show("error", APP_NAME, f"{ip!r} is not a valid IPv4 address or hostname.")
            return
        port_result = prompt_int("Host Port:", int(self.cfg.get("peer_port", DEFAULT_PORT)))
        if port_result is None:
            return
        ok, port = port_result
        if not ok:
            _ui_show("error", APP_NAME, "Port must be an integer between 1 and 65535.")
            return
        if not self._is_valid_port(port):
            _ui_show("error", APP_NAME, "Port must be an integer between 1 and 65535.")
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

    def _shutdown(self, *, join_core: bool, core_timeout: float = 3.0) -> None:
        """Common teardown for ``_exit`` and ``_restart``."""
        if self._has_active_downloads():
            if not _ui_show(
                "askyesno",
                APP_NAME,
                "A download/update is still in progress. Stop anyway?",
            ):
                return
        try:
            self._flush_persist()
        except Exception:
            log.exception("_flush_persist failed during shutdown")
        try:
            self.core.stop()
        except Exception:
            log.exception("core.stop() failed during shutdown")
        try:
            self.media_key_listener.stop()
        except Exception:
            log.exception("media_key_listener.stop() failed during shutdown")
        self._stop_tray_watchdog()
        try:
            self.icon.stop()
        except Exception:
            log.exception("tray icon.stop() failed during shutdown")
        if sys.platform == "win32":
            try:
                stop_prompter()
            except Exception:
                log.exception("WinPrompter stop failed during shutdown")
        if join_core:
            self._join_core(timeout=core_timeout)

    def _join_core(self, timeout: float) -> None:
        """Wait for the core worker thread without poking private attributes."""
        join_method = getattr(self.core, "join", None)
        if callable(join_method):
            try:
                join_method(timeout=timeout)
                return
            except Exception:
                log.exception("core.join() failed; falling back to thread join")
        thread = getattr(self.core, "_thread", None)
        if thread is not None:
            try:
                thread.join(timeout=timeout)
            except Exception:
                log.exception("core thread join failed")

    def _has_active_downloads(self) -> bool:
        current = threading.current_thread()
        with self._download_threads_lock:
            self._download_threads = [t for t in self._download_threads if t.is_alive()]
            return any(t for t in self._download_threads if t is not current)

    def _track_download_thread(self, target: Callable, name: str) -> threading.Thread:
        """Spawn a non-daemon worker for download/update work."""
        thread = threading.Thread(target=target, name=name, daemon=False)
        with self._download_threads_lock:
            self._download_threads.append(thread)
        thread.start()
        return thread

    def _exit(self, icon=None, item=None):
        self._shutdown(join_core=False)

    def _update_toolkit(self, icon=None, item=None):
        if not self._update_in_progress.acquire(blocking=False):
            _ui_show("info", APP_NAME, "An update is already in progress.")
            return
        try:
            if getattr(sys, "frozen", False):
                self._track_download_thread(
                    self._wrap_with_update_lock(self._do_frozen_update),
                    name="frozen-update",
                )
                return
            self._track_download_thread(
                self._wrap_with_update_lock(self._do_source_update),
                name="source-update",
            )
        except BaseException:
            # Couldn't even start the worker - release the gate now.
            try:
                self._update_in_progress.release()
            except RuntimeError:
                pass
            raise

    def _wrap_with_update_lock(self, fn: Callable[[], None]) -> Callable[[], None]:
        """Wrap a download worker so it releases _update_in_progress on exit."""
        def runner():
            try:
                fn()
            finally:
                try:
                    self._update_in_progress.release()
                except RuntimeError:
                    pass
        return runner

    def _do_source_update(self):
        update_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Update-Toolkit.py")
        try:
            result = subprocess.run(
                [sys.executable, update_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            log.exception("Update-Toolkit.py timed out")
            _ui_show("error", APP_NAME, "Update timed out after 10 minutes.")
            return
        except Exception as exc:
            log.exception("Update-Toolkit.py failed to launch")
            _ui_show("error", APP_NAME, f"Update failed to launch:\n{exc}")
            return
        if result.returncode != 0:
            _ui_show("error", APP_NAME, f"Update failed:\n{result.stderr or result.stdout}")
            return
        self._restart()

    def _do_frozen_update(self):
        api_url = "https://api.github.com/repos/adamboy7/Linux-Dual-Boot-Toolkit/releases/latest"
        new_path: Optional[str] = None
        old_path: Optional[str] = None
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "MediaRelay-updater"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read())

            exe_name = os.path.basename(sys.executable)
            # Prefer the canonical asset name stored at install time so users
            # who renamed the exe still receive updates. Fall back to exact
            # match, then to the canonical "MediaRelay*.exe" family.
            canonical = self.cfg.get("asset_name")
            assets = release.get("assets", [])
            asset = None
            if canonical:
                asset = next((a for a in assets if a["name"] == canonical), None)
            if asset is None:
                asset = next((a for a in assets if a["name"] == exe_name), None)
            if asset is None:
                asset = next(
                    (a for a in assets
                     if a["name"].lower().startswith(APP_NAME.lower())
                     and a["name"].lower().endswith(".exe")),
                    None,
                )
            if asset is None:
                _ui_show(
                    "info",
                    APP_NAME,
                    f"No matching update asset found for '{exe_name}'.",
                )
                return
            # Remember the matched asset name for future updates so a rename
            # doesn't break the next round either.
            self.cfg["asset_name"] = asset["name"]

            tag = release.get("tag_name", "unknown")
            current = get_installed_version(self.cfg)
            if current == "Unknown":
                msg = f"Update to {tag}?\n\nThe app will restart automatically."
            else:
                msg = f"Update from {current} to {tag}?\n\nThe app will restart automatically."
            if not _ui_show("askyesno", APP_NAME, msg):
                return

            exe_path = sys.executable
            new_path = exe_path + ".new"
            old_path = exe_path + ".old"

            req2 = urllib.request.Request(
                asset["browser_download_url"], headers={"User-Agent": "MediaRelay-updater"}
            )
            expected_size = asset.get("size")
            total = expected_size if isinstance(expected_size, int) and expected_size > 0 else None
            downloaded = 0
            chunk = 64 * 1024
            last_pct = -1
            original_title = self.icon.title
            try:
                with urllib.request.urlopen(req2, timeout=120) as resp:
                    with open(new_path, "wb") as f:
                        while True:
                            buf = resp.read(chunk)
                            if not buf:
                                break
                            f.write(buf)
                            downloaded += len(buf)
                            if total:
                                pct = int(downloaded * 100 / total)
                                if pct != last_pct:
                                    last_pct = pct
                                    try:
                                        self.icon.title = f"{APP_NAME} - Updating {pct}%"
                                    except Exception:
                                        pass
            finally:
                try:
                    self.icon.title = original_title
                except Exception:
                    pass

            if total is not None and downloaded != total:
                raise IOError(
                    f"Downloaded asset size mismatch: expected {total}, got {downloaded}"
                )

            if sys.platform == "win32":
                _win_mod.perform_frozen_update(
                    exe_path, new_path, old_path,
                    ["_PYIBoot_MEIPASS", "_MEIPASS2"],
                )
            else:
                import libraries.media_sync.linux as _linux_mod
                _linux_mod.perform_frozen_update(
                    exe_path, new_path, old_path,
                    ["_PYIBoot_MEIPASS", "_MEIPASS2"],
                )

            self.cfg["installed_version"] = tag
            save_config(self.cfg)

        except Exception as exc:
            log.exception("Frozen update failed")
            _ui_show("error", APP_NAME, f"Update failed:\n{exc}")
            leftovers: list[str] = []
            for path in (new_path, old_path):
                if not path:
                    continue
                if not os.path.exists(path):
                    continue
                try:
                    os.remove(path)
                except OSError:
                    log.warning("Could not remove leftover %s", path)
                    leftovers.append(path)
            if leftovers:
                _ui_show(
                    "error",
                    APP_NAME,
                    "These files were left behind and may need manual cleanup:\n"
                    + "\n".join(leftovers),
                )

    def _view_source(self, icon=None, item=None):
        webbrowser.open("https://github.com/adamboy7/Linux-Dual-Boot-Toolkit")

    def _download_release(self, icon=None, item=None):
        if not self._update_in_progress.acquire(blocking=False):
            _ui_show("info", APP_NAME, "A download is already in progress.")
            return
        try:
            self._track_download_thread(
                self._wrap_with_update_lock(self._do_download_release),
                name="release-download",
            )
        except BaseException:
            try:
                self._update_in_progress.release()
            except RuntimeError:
                pass
            raise

    def _do_download_release(self):
        if not _TK_AVAILABLE:
            log.error("tkinter is unavailable; cannot prompt for save location")
            return

        api_url = "https://api.github.com/repos/adamboy7/Linux-Dual-Boot-Toolkit/releases/latest"
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "MediaRelay-updater"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read())

            if sys.platform == "win32":
                asset = next((a for a in release["assets"] if a["name"].endswith(".exe")), None)
            else:
                asset = next((a for a in release["assets"] if not a["name"].endswith(".exe")), None)

            if asset is None:
                _ui_show("info", APP_NAME, "No suitable release asset found for this platform.")
                return

            tag = release.get("tag_name", "unknown")
            ext = os.path.splitext(asset["name"])[1] or None
            save_title = f"Save {APP_NAME} {tag}"
            save_path: Optional[str] = None
            if sys.platform == "win32":
                prompter = get_or_create_prompter()
                if prompter is not None:
                    save_path = prompter.ask_save_file(
                        title=save_title,
                        initialfile=asset["name"],
                        defaultextension=ext,
                    )
                else:
                    save_path = _ui_save_file(save_title, asset["name"], ext)
            else:
                save_path = _ui_save_file(save_title, asset["name"], ext)
            if not save_path:
                return

            req2 = urllib.request.Request(
                asset["browser_download_url"], headers={"User-Agent": "MediaRelay-updater"}
            )
            with urllib.request.urlopen(req2, timeout=120) as resp:
                data = resp.read()

            expected_size = asset.get("size")
            if isinstance(expected_size, int) and expected_size >= 0 and len(data) != expected_size:
                raise IOError(
                    f"Downloaded asset size mismatch: expected {expected_size}, got {len(data)}"
                )

            with open(save_path, "wb") as f:
                f.write(data)

            _ui_show("info", APP_NAME, f"Downloaded {asset['name']} to:\n{save_path}")
        except Exception as exc:
            log.exception("Release download failed")
            _ui_show("error", APP_NAME, f"Download failed:\n{exc}")

    def _restart(self, icon=None, item=None):
        self._shutdown(join_core=True)
        _env = self._build_restart_env()
        popen_kwargs: dict = {"env": _env}
        if sys.platform == "win32":
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            popen_kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            popen_kwargs["close_fds"] = True
        else:
            popen_kwargs["start_new_session"] = True
            popen_kwargs["close_fds"] = True
        try:
            if getattr(sys, "frozen", False):
                spawn_args = list(sys.argv)
            else:
                spawn_args = [sys.executable] + list(sys.argv)
            subprocess.Popen(spawn_args, **popen_kwargs)
        except Exception:
            log.exception("Failed to spawn restart process")
        os._exit(0)

    @staticmethod
    def _build_restart_env() -> dict:
        """Strip PyInstaller bootstrap state from the env before re-exec."""
        _env = _strip_pyi_env(os.environ)
        if not getattr(sys, "frozen", False):
            return _env
        _meipass = getattr(sys, "_MEIPASS", None)
        if not _meipass:
            return _env

        def _norm(path: str) -> str:
            stripped = path.rstrip("\\/").rstrip(os.sep)
            return stripped.lower() if sys.platform == "win32" else stripped

        target = _norm(_meipass)
        _env["PATH"] = os.pathsep.join(
            p for p in _env.get("PATH", "").split(os.pathsep)
            if p and _norm(p) != target
        )
        return _env

    def _add_to_startup(self, icon=None, item=None):
        if sys.platform != "win32":
            return
        prompter = get_or_create_prompter()
        confirm = (
            prompter.show_message("askyesno", APP_NAME, "Add MediaRelay to startup?")
            if prompter is not None
            else _ui_show("askyesno", APP_NAME, "Add MediaRelay to startup?")
        )
        if not confirm:
            return
        try:
            shortcut_path, _vbs_path = _ensure_startup_shortcut()
            msg = f"Startup shortcut created:\n{shortcut_path}"
            if prompter is not None:
                prompter.show_message("info", APP_NAME, msg)
            else:
                _ui_show("info", APP_NAME, msg)
        except Exception as exc:
            err = f"Failed to add startup shortcut:\n{exc}"
            if prompter is not None:
                prompter.show_message("error", APP_NAME, err)
            else:
                _ui_show("error", APP_NAME, err)

    def _create_shortcut(self, icon=None, item=None):
        if sys.platform != "win32":
            return
        prompter = get_or_create_prompter()
        if prompter is not None:
            dest_dir = prompter.ask_directory(title="Choose folder for shortcut")
        else:
            dest_dir = self._ask_directory_fallback("Choose folder for shortcut")
        if not dest_dir:
            return
        try:
            shortcut_path = _create_shortcut_in_folder(dest_dir)
            msg = f"Shortcut created:\n{shortcut_path}"
            if prompter is not None:
                prompter.show_message("info", APP_NAME, msg)
            else:
                _ui_show("info", APP_NAME, msg)
        except Exception as exc:
            err = f"Failed to create shortcut:\n{exc}"
            if prompter is not None:
                prompter.show_message("error", APP_NAME, err)
            else:
                _ui_show("error", APP_NAME, err)

    @staticmethod
    def _ask_directory_fallback(title: str) -> Optional[str]:
        """Per-call hidden-root askdirectory; used only when prompter is dead."""
        if not _TK_AVAILABLE:
            return None
        if sys.platform == "win32":
            log.warning(
                "WinPromptThread unavailable; refusing per-call Tk directory "
                "dialog from a worker thread"
            )
            return None
        try:
            root = tk.Tk()
            root.withdraw()
            try:
                return filedialog.askdirectory(title=title, parent=root) or None
            finally:
                try:
                    root.destroy()
                except Exception:
                    log.exception("Failed to destroy directory-dialog root")
        except Exception:
            log.exception("Directory dialog failed")
            return None

    @staticmethod
    def _normalize_url(url: str) -> Optional[str]:
        """Light URL validation for outgoing links."""
        if not url:
            return None
        candidate = url.strip()
        if not candidate:
            return None
        try:
            parsed = urllib.parse.urlparse(candidate)
        except ValueError:
            return None
        looks_like_host_port = (
            bool(parsed.scheme)
            and parsed.scheme.replace("-", "").replace("_", "").isalnum()
            and not parsed.scheme[:1].isdigit()
            and parsed.path.isdigit()
            and not parsed.netloc
            and "/" not in parsed.scheme
        )
        if not parsed.scheme or looks_like_host_port:
            candidate = "https://" + candidate
            try:
                parsed = urllib.parse.urlparse(candidate)
            except ValueError:
                return None
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"} and not parsed.netloc:
            return None
        if scheme == "file" and not parsed.path:
            return None
        if scheme == "file":
            candidate = _encode_file_url(candidate)
        return candidate

    def _send_link_action(self, icon=None, item=None):
        url = prompt_string("URL to send to clients:")
        if not url:
            return
        validated = self._normalize_url(url)
        if validated is None:
            _ui_show("error", APP_NAME, f"Not a valid URL: {url!r}")
            return
        self.core.ui_send_link(validated)

    def _kick_action(self, icon=None, item=None):
        threading.Thread(target=show_kick_dialog, args=(self.core,), daemon=True).start()

    def _handle_open_url_from_core(self, url: str, host_ip: str):
        """Called from the asyncio thread when the client receives a URL from the host."""
        threading.Thread(
            target=self._process_open_url,
            args=(url, host_ip),
            daemon=True,
        ).start()

    def _process_open_url(self, url: str, host_ip: str):
        """Worker thread: check trust settings, prompt if necessary, then open URL."""
        is_ip = _is_ip_url(url)
        scheme = urllib.parse.urlparse(url).scheme.lower()
        is_file = scheme == "file"
        open_url = _encode_file_url(url) if is_file else url
        host_trusted = (
            host_ip in self.core.session_trusted_hosts
            or is_host_permanently_trusted(host_ip)
        )

        if is_file:
            # Untrusted host: refuse silently regardless of domain trust.
            if not host_trusted:
                return
            # Power-user escape: "file" manually added to trusted_domains.json allows auto-open.
            if is_domain_trusted(url):
                webbrowser.open(open_url)
                return
            # Trusted host, protocol not trusted: always prompt.
        else:
            # Non-file: auto-open if the host or protocol/domain is trusted.
            if host_trusted:
                webbrowser.open(open_url)
                return
            if not is_ip and is_domain_trusted(url):
                webbrowser.open(open_url)
                return

        result = prompt_url_confirm(url, is_ip, show_protocol_trust=not is_file, show_peer_trust=not is_file)
        if not result or not result.get("accepted"):
            return

        if result.get("trust_session"):
            self.core.session_trusted_hosts.add(host_ip)
        if result.get("trust_host"):
            add_trusted_host(host_ip)
        # Never persist protocol trust for file:// — it must always prompt.
        if result.get("trust_domain") and not is_ip and not is_file:
            add_trusted_domain(url)

        webbrowser.open(open_url)

    def _handle_url_from_client(self, url: str, client_addr):
        """Called from the asyncio thread when the host receives a URL from a client."""
        threading.Thread(
            target=self._process_url_from_client,
            args=(url, client_addr),
            daemon=True,
        ).start()

    def _process_url_from_client(self, url: str, client_addr):
        """HOST worker thread: check trust, prompt if necessary, open/forward URL from client."""
        client_ip = client_addr[0]
        client_display = get_client_alias(client_ip) or client_ip
        is_ip = _is_ip_url(url)
        scheme = urllib.parse.urlparse(url).scheme.lower()
        is_file = scheme == "file"
        open_url = _encode_file_url(url) if is_file else url
        client_trusted = (
            client_ip in self.core.session_trusted_clients
            or is_client_permanently_trusted(client_ip)
        )

        if is_file:
            # Untrusted client: refuse silently regardless of domain trust.
            if not client_trusted:
                return
            # Power-user escape: "file" manually added to trusted_domains.json allows auto-open.
            if is_domain_trusted(url):
                webbrowser.open(open_url)
                self.core.ui_send_link(open_url, exclude_addr=client_addr)
                return
            # Trusted client, protocol not trusted: always prompt.
        else:
            # Non-file: auto-open and forward if the client or protocol/domain is trusted.
            if client_trusted:
                webbrowser.open(open_url)
                self.core.ui_send_link(open_url, exclude_addr=client_addr)
                return
            if not is_ip and is_domain_trusted(url):
                webbrowser.open(open_url)
                self.core.ui_send_link(open_url, exclude_addr=client_addr)
                return

        result = prompt_host_url_confirm(url, is_ip, client_display, show_protocol_trust=not is_file, show_peer_trust=not is_file)
        if not result or not result.get("accepted"):
            return

        if result.get("trust_session"):
            self.core.session_trusted_clients.add(client_ip)
        if result.get("trust_client"):
            add_trusted_client(client_ip)
        # Never persist protocol trust for file:// — it must always prompt.
        if result.get("trust_domain") and not is_ip and not is_file:
            add_trusted_domain(url)

        webbrowser.open(open_url)
        if result.get("forward"):
            self.core.ui_send_link(open_url, exclude_addr=client_addr)

    def _send_link_to_host_action(self, icon=None, item=None):
        url = prompt_string("URL to send to host:")
        if not url:
            return
        validated = self._normalize_url(url)
        if validated is None:
            _ui_show("error", APP_NAME, f"Not a valid URL: {url!r}")
            return
        if not self.core.peer:
            _ui_show("info", APP_NAME, "Not connected to a host.")
            return
        if not self.core.host_enable_links:
            _ui_show(
                "info",
                APP_NAME,
                "The host has disabled incoming links. Ask them to enable "
                "links before trying again.",
            )
            return
        self.core.ui_send_link_to_host(validated)

    def run(self):
        # Start core networking
        self.core.start_in_thread()
        self.media_key_listener.start()
        if self._should_auto_connect():
            try:
                peer_port = int(self.cfg.get("peer_port", DEFAULT_PORT))
            except (TypeError, ValueError):
                log.warning(
                    "Invalid peer_port %r in config; falling back to %d",
                    self.cfg.get("peer_port"),
                    DEFAULT_PORT,
                )
                peer_port = DEFAULT_PORT
            self.core.start_auto_connect(self.cfg.get("peer_ip"), peer_port)
        self._start_tray_watchdog()

        # Run tray
        def _setup(icon):
            icon.visible = True
            self._refresh_tray()
        try:
            self.icon.run(setup=_setup)
        finally:
            self._stop_tray_watchdog()


if __name__ == "__main__":
    if getattr(sys, "frozen", False) and sys.platform == "win32":
        _win_mod.cleanup_old_exe(sys.executable)
    TrayApp().run()
