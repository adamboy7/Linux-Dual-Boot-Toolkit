from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from typing import Optional, Tuple

import pystray
from pystray import MenuItem as Item, Menu as Menu
from PIL import Image

from libraries.media_sync import (
    APP_NAME,
    DEFAULT_PORT,
    RelayCore,
    ResumeMode,
    Role,
    _is_ip_url,
    add_trusted_client,
    add_trusted_domain,
    add_trusted_host,
    build_media_controller,
    build_media_key_listener,
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
)

if sys.platform == "win32":
    import libraries.media_sync.windows as _win_mod
    from libraries.media_sync.windows import (
        WinPromptThread,
        _create_shortcut_in_folder,
        _ensure_startup_shortcut,
    )
    import tkinter as tk
    from tkinter import filedialog, messagebox


class TrayApp:
    def __init__(self):
        self.cfg = load_config()
        self.listen_port = int(self.cfg.get("listen_port", DEFAULT_PORT))
        self._last_saved_state = {}
        self._tray_state_lock = threading.Lock()
        self._last_tray_state: Optional[Tuple[Role, bool, bool]] = None
        self._tray_watchdog_stop = threading.Event()
        self._tray_watchdog_thread: Optional[threading.Thread] = None

        resume_mode_value = self.cfg.get("resume_mode", ResumeMode.HOST_ONLY.value)
        try:
            resume_mode = ResumeMode(resume_mode_value)
        except Exception:
            resume_mode = ResumeMode.HOST_ONLY
        ignore_client = bool(self.cfg.get("ignore_client", False))
        enable_media_controls = bool(self.cfg.get("enable_media_controls", True))
        enable_links = bool(self.cfg.get("enable_links", True))
        self.core = RelayCore(
            listen_port=self.listen_port,
            resume_mode=resume_mode,
            ignore_client=ignore_client,
            enable_media_controls=enable_media_controls,
            enable_links=enable_links,
            media_controller=build_media_controller(),
        )
        self._last_tray_state = self._desired_tray_state()
        self.core.on_status_change = self._refresh_tray
        self.core.on_resume_mode_change = self._set_resume_mode_from_core
        self.core.on_ignore_client_change = self._set_ignore_client_from_core
        self.core.on_open_url = self._handle_open_url_from_core
        self.core.on_receive_url_from_client = self._handle_url_from_client
        self.core.on_enable_media_controls_change = self._set_enable_media_controls_from_core
        self.core.on_enable_links_change = self._set_enable_links_from_core
        self.media_key_listener = build_media_key_listener(
            self.core,
            swallow=bool(self.cfg.get("swallow_media_keys", True)),
            enabled=enable_media_controls,
        )

        if sys.platform == "win32":
            if _win_mod._WIN_PROMPTER is None:
                _win_mod._WIN_PROMPTER = WinPromptThread()

        self.icon = pystray.Icon(APP_NAME, self._tray_icon(), APP_NAME, menu=self._build_menu())

    def _tray_icon(self) -> Image.Image:
        return make_icon(self.core.role, self.core.peer is not None)

    def _desired_tray_state(self) -> Tuple[Role, bool, bool]:
        return (self.core.role, self.core.peer is not None, self.core.host_enable_links)

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
            and bool(ip)
        )

    def _build_menu(self):
        items = [
            Item("Toggle", self._toggle),
            Item("Stop", self._stop),
            Item("Connect…", self._connect),
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
                    ),
                    Item(
                        "Resume client only",
                        lambda: self._set_resume_mode(ResumeMode.CLIENT_ONLY),
                        checked=lambda item: self.core.resume_mode == ResumeMode.CLIENT_ONLY,
                        radio=True,
                    ),
                    Item(
                        "Blind relay",
                        lambda: self._set_resume_mode(ResumeMode.BLIND),
                        checked=lambda item: self.core.resume_mode == ResumeMode.BLIND,
                        radio=True,
                    ),
                ),
            ),
            Item(lambda _item: f"Status: {self.core.status_text()}", None, enabled=False),
        ]
        tools_items = []
        if self.core.role == Role.HOST:
            tools_items.append(
                Item(
                    "Send Link…",
                    self._send_link_action,
                    enabled=lambda item: bool(self.core.peers),
                )
            )
        elif self.core.role == Role.CLIENT:
            tools_items.append(
                Item(
                    "Send Link to Host…",
                    self._send_link_to_host_action,
                    enabled=lambda item: self.core.peer is not None and self.core.host_enable_links,
                )
            )
        tools_items.append(Item("Listening Port…", self._configure_listen_port))
        if sys.platform == "win32":
            tools_items.append(Item("Add to startup", self._add_to_startup))
            tools_items.append(Item("Create Shortcut…", self._create_shortcut))
        tools_items.append(Item("Update Toolkit", self._update_toolkit))
        tools_items.append(Item("Restart", self._restart))
        items.append(Item("Tools", Menu(*tools_items)))
        items.append(Item("Exit", self._exit))
        return Menu(*items)

    def _refresh_tray(self):
        # Called from core thread; marshal to tray thread
        def do():
            self.icon.icon = self._tray_icon()
            self.icon.menu = self._build_menu()
            self.icon.title = f"{APP_NAME} - {self.core.status_text()}"
            self._persist_state()
            with self._tray_state_lock:
                self._last_tray_state = self._desired_tray_state()
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
            "ignore_client": self.cfg.get("ignore_client", False),
            "enable_media_controls": self.cfg.get("enable_media_controls", True),
            "enable_links": self.cfg.get("enable_links", True),
        }
        if state != self._last_saved_state:
            save_config(self.cfg)
            self._last_saved_state = dict(state)

    def _toggle(self, icon=None, item=None):
        self.core.ui_toggle(source="hid")

    def _stop(self, icon=None, item=None):
        self.core.ui_stop_all(source="hid")

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

    def _set_ignore_client_from_core(self, enabled: bool):
        def do():
            self.cfg["ignore_client"] = bool(enabled)
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

    def _toggle_ignore_client(self, icon=None, item=None):
        self.core.ui_set_ignore_client(not self.core.ignore_client)

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
        def do():
            self.cfg["enable_media_controls"] = bool(enabled)
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

    def _set_enable_links_from_core(self, enabled: bool):
        def do():
            self.cfg["enable_links"] = bool(enabled)
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
        if sys.platform == "win32" and _win_mod._WIN_PROMPTER is not None:
            _win_mod._WIN_PROMPTER.stop()

    def _update_toolkit(self, icon=None, item=None):
        if getattr(sys, "frozen", False):
            threading.Thread(target=self._do_frozen_update, daemon=True).start()
            return
        update_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Update-Toolkit.py")
        result = subprocess.run(
            [sys.executable, update_script],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            if sys.platform == "win32":
                messagebox.showerror(APP_NAME, f"Update failed:\n{result.stderr or result.stdout}")
            return
        self._restart()

    def _do_frozen_update(self):
        api_url = "https://api.github.com/repos/adamboy7/Linux-Dual-Boot-Toolkit/releases/latest"
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "MediaRelay-updater"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read())

            exe_name = os.path.basename(sys.executable)
            asset = next((a for a in release["assets"] if a["name"] == exe_name), None)
            if asset is None:
                messagebox.showinfo(APP_NAME, f"No asset named '{exe_name}' found in the latest release.")
                return

            tag = release.get("tag_name", "unknown")
            if not messagebox.askyesno(APP_NAME, f"Update to {tag}?\n\nThe app will restart automatically."):
                return

            exe_path = sys.executable
            new_path = exe_path + ".new"
            old_path = exe_path + ".old"

            req2 = urllib.request.Request(
                asset["browser_download_url"], headers={"User-Agent": "MediaRelay-updater"}
            )
            with urllib.request.urlopen(req2, timeout=120) as resp:
                data = resp.read()

            with open(new_path, "wb") as f:
                f.write(data)

            # Rename running exe out of the way (Windows allows renaming a running exe),
            # then put the new one in its place.
            if os.path.exists(old_path):
                os.remove(old_path)
            os.rename(exe_path, old_path)
            os.rename(new_path, exe_path)

            # PyInstaller's onefile bootloader signals child processes to
            # reuse the parent's _MEIPASS extraction via environment vars.
            # If any of these leak into the relaunched exe, its bootloader
            # will skip extraction and try to load python3xx.dll out of the
            # OLD temp dir -- which the exiting process is about to delete,
            # producing "LoadLibrary: The specified module could not be
            # found." Strip every known variant before relaunching.
            #
            #   PyInstaller 6.x:  _PYI_PARENT_PROCESS_LEVEL,
            #                     _PYI_APPLICATION_HOME_DIR,
            #                     _PYI_ARCHIVE_FILE,
            #                     _PYI_SPLASH_IPC
            #   PyInstaller 5.x:  _PYIBoot_MEIPASS
            #   PyInstaller 3.x:  _MEIPASS2
            _env = {
                k: v
                for k, v in os.environ.items()
                if not (
                    k.startswith("_PYI_")
                    or k == "_PYIBoot_MEIPASS"
                    or k == "_MEIPASS2"
                )
            }
            _meipass = getattr(sys, "_MEIPASS", None)
            if _meipass:
                _env["PATH"] = os.pathsep.join(
                    p
                    for p in _env.get("PATH", "").split(os.pathsep)
                    if p and p != _meipass
                )

            # Also wipe the same vars inside the batch itself, in case cmd
            # picked them up from somewhere we did not control, and pin the
            # new exe's working directory to its own folder so a stale cwd
            # in the old temp dir cannot redirect it.
            exe_dir = os.path.dirname(exe_path) or "."
            bat_path = os.path.join(tempfile.gettempdir(), "_mediarelay_restart.bat")
            with open(bat_path, "w") as f:
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

        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Update failed:\n{exc}")
            _new = sys.executable + ".new"
            if os.path.exists(_new):
                try:
                    os.remove(_new)
                except OSError:
                    pass

    def _restart(self, icon=None, item=None):
        self.core.stop()
        self.media_key_listener.stop()
        self._stop_tray_watchdog()
        self.icon.stop()
        if sys.platform == "win32" and _win_mod._WIN_PROMPTER is not None:
            _win_mod._WIN_PROMPTER.stop()
        if self.core._thread is not None:
            self.core._thread.join(timeout=3.0)
        subprocess.Popen([sys.executable] + sys.argv)
        os._exit(0)

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

    def _create_shortcut(self, icon=None, item=None):
        if sys.platform != "win32":
            return
        root = tk.Tk()
        root.withdraw()
        dest_dir = filedialog.askdirectory(title="Choose folder for shortcut")
        root.destroy()
        if not dest_dir:
            return
        try:
            shortcut_path = _create_shortcut_in_folder(dest_dir)
            messagebox.showinfo(APP_NAME, f"Shortcut created:\n{shortcut_path}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Failed to create shortcut:\n{exc}")

    def _send_link_action(self, icon=None, item=None):
        url = prompt_string("URL to send to clients:")
        if not url:
            return
        self.core.ui_send_link(url)

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

        # Auto-open if already trusted
        if host_ip in self.core.session_trusted_hosts:
            webbrowser.open(url)
            return
        if is_host_permanently_trusted(host_ip):
            webbrowser.open(url)
            return
        if not is_ip and is_domain_trusted(url):
            webbrowser.open(url)
            return

        result = prompt_url_confirm(url, is_ip)
        if not result or not result.get("accepted"):
            return

        if result.get("trust_session"):
            self.core.session_trusted_hosts.add(host_ip)
        if result.get("trust_host"):
            add_trusted_host(host_ip)
        if result.get("trust_domain") and not is_ip:
            add_trusted_domain(url)

        webbrowser.open(url)

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
        is_ip = _is_ip_url(url)

        # Auto-open and forward if already trusted
        if client_ip in self.core.session_trusted_clients:
            webbrowser.open(url)
            self.core.ui_send_link(url, exclude_addr=client_addr)
            return
        if is_client_permanently_trusted(client_ip):
            webbrowser.open(url)
            self.core.ui_send_link(url, exclude_addr=client_addr)
            return
        if not is_ip and is_domain_trusted(url):
            webbrowser.open(url)
            self.core.ui_send_link(url, exclude_addr=client_addr)
            return

        result = prompt_host_url_confirm(url, is_ip, client_ip)
        if not result or not result.get("accepted"):
            return

        if result.get("trust_session"):
            self.core.session_trusted_clients.add(client_ip)
        if result.get("trust_client"):
            add_trusted_client(client_ip)
        if result.get("trust_domain") and not is_ip:
            add_trusted_domain(url)

        webbrowser.open(url)
        if result.get("forward"):
            self.core.ui_send_link(url, exclude_addr=client_addr)

    def _send_link_to_host_action(self, icon=None, item=None):
        url = prompt_string("URL to send to host:")
        if not url:
            return
        self.core.ui_send_link_to_host(url)

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
        def _setup(icon):
            icon.visible = True
            self._refresh_tray()
        try:
            self.icon.run(setup=_setup)
        finally:
            self._stop_tray_watchdog()


if __name__ == "__main__":
    if getattr(sys, "frozen", False):
        _old_exe = sys.executable + ".old"
        try:
            os.remove(_old_exe)
        except OSError:
            pass
    TrayApp().run()
