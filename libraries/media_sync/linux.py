from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import threading
import time
from typing import Optional

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk

from libraries.permissions.linux import ensure_root_linux
from .common import APP_NAME, _RESP_HOST_FORWARD, _RESP_HOST_OPEN, _app_icon_path, _is_app_protocol_url

EVDEV_AVAILABLE = importlib.util.find_spec("evdev") is not None
if EVDEV_AVAILABLE:
    import evdev


# -------------------- Media controller --------------------

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

    async def snapshot(self):
        from .common import MediaSnapshot, State
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
        if cmd not in ("play", "pause", "stop", "next", "prev"):
            return False
        playerctl_cmd = "previous" if cmd == "prev" else cmd
        result = self._run_playerctl(playerctl_cmd)
        return result is not None


# -------------------- Media key hook --------------------

class LinuxMediaKeyListener:
    def __init__(self, core, swallow: bool = True):
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
            self._core.ui_toggle(source="hid")
            return True
        if key_code == evdev.ecodes.KEY_STOPCD:
            self._core.ui_stop_all(source="hid")
            return True
        if key_code == evdev.ecodes.KEY_NEXTSONG:
            self._core.ui_next(source="hid")
            return True
        if key_code == evdev.ecodes.KEY_PREVIOUSSONG:
            self._core.ui_prev(source="hid")
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
            _MEDIA_KEYS = (
                evdev.ecodes.KEY_PLAYPAUSE,
                evdev.ecodes.KEY_STOPCD,
                evdev.ecodes.KEY_NEXTSONG,
                evdev.ecodes.KEY_PREVIOUSSONG,
            )
            if any(k in caps for k in _MEDIA_KEYS):
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
                            if event.code in (
                                evdev.ecodes.KEY_PLAYPAUSE,
                                evdev.ecodes.KEY_STOPCD,
                                evdev.ecodes.KEY_NEXTSONG,
                                evdev.ecodes.KEY_PREVIOUSSONG,
                            ):
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


# -------------------- GTK dialogs --------------------

def _prompt_string_gtk(prompt: str, initial: str = "") -> Optional[str]:
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


def _prompt_url_confirm_gtk(url: str, is_ip: bool, show_protocol_trust: bool = True) -> Optional[dict]:
    dialog = Gtk.Dialog(title=APP_NAME)
    icon_path = _app_icon_path()
    if os.path.exists(icon_path):
        try:
            dialog.set_icon_from_file(icon_path)
        except Exception:
            pass
    dialog.add_buttons("No", Gtk.ResponseType.NO, "Yes", Gtk.ResponseType.YES)
    dialog.set_default_response(Gtk.ResponseType.YES)

    box = dialog.get_content_area()
    box.set_spacing(6)
    box.set_border_width(12)

    lbl_msg = Gtk.Label(label="The host is requesting to open a URL.\nWould you like to open:")
    lbl_msg.set_halign(Gtk.Align.START)
    lbl_url = Gtk.Label(label=url)
    lbl_url.set_halign(Gtk.Align.START)
    lbl_url.set_line_wrap(True)
    lbl_url.set_max_width_chars(64)
    lbl_url.set_markup(f'<span foreground="blue">{url}</span>')

    box.add(lbl_msg)
    box.add(lbl_url)

    chk_domain = None
    if not is_ip and show_protocol_trust:
        domain_label = "Trust this protocol" if _is_app_protocol_url(url) else "Trust this domain"
        chk_domain = Gtk.CheckButton(label=domain_label)
        box.add(chk_domain)

    chk_session = Gtk.CheckButton(label="Trust this session")
    chk_host = Gtk.CheckButton(label="Trust this host")
    box.add(chk_session)
    box.add(chk_host)

    dialog.show_all()
    response = dialog.run()
    if response == Gtk.ResponseType.YES:
        result = {
            "accepted": True,
            "trust_domain": chk_domain.get_active() if chk_domain else False,
            "trust_session": chk_session.get_active(),
            "trust_host": chk_host.get_active(),
        }
    else:
        result = None
    dialog.destroy()
    return result


def _prompt_host_url_confirm_gtk(url: str, is_ip: bool, client_ip: str, show_protocol_trust: bool = True) -> Optional[dict]:
    dialog = Gtk.Dialog(title=APP_NAME)
    icon_path = _app_icon_path()
    if os.path.exists(icon_path):
        try:
            dialog.set_icon_from_file(icon_path)
        except Exception:
            pass
    dialog.add_buttons(
        "Cancel", Gtk.ResponseType.CANCEL,
        "Open", _RESP_HOST_OPEN,
        "Forward", _RESP_HOST_FORWARD,
    )
    dialog.set_default_response(_RESP_HOST_FORWARD)

    box = dialog.get_content_area()
    box.set_spacing(6)
    box.set_border_width(12)

    lbl_msg = Gtk.Label(label=f"Client {client_ip} is requesting to open a URL.")
    lbl_msg.set_halign(Gtk.Align.START)
    lbl_url = Gtk.Label(label=url)
    lbl_url.set_halign(Gtk.Align.START)
    lbl_url.set_line_wrap(True)
    lbl_url.set_max_width_chars(64)
    lbl_url.set_markup(f'<span foreground="blue">{url}</span>')

    box.add(lbl_msg)
    box.add(lbl_url)

    chk_domain = None
    if not is_ip and show_protocol_trust:
        domain_label = "Trust this protocol" if _is_app_protocol_url(url) else "Trust this domain"
        chk_domain = Gtk.CheckButton(label=domain_label)
        box.add(chk_domain)

    chk_session = Gtk.CheckButton(label="Trust this client (session)")
    chk_client = Gtk.CheckButton(label="Trust this client (always)")
    box.add(chk_session)
    box.add(chk_client)

    dialog.show_all()

    was_opened = False
    forwarded = False
    while True:
        response = dialog.run()
        if response == _RESP_HOST_OPEN:
            import webbrowser
            webbrowser.open(url)
            was_opened = True
        elif response == _RESP_HOST_FORWARD:
            forwarded = True
            break
        else:
            break

    if not was_opened and not forwarded:
        result = None
    else:
        result = {
            "forward": forwarded,
            "trust_domain": chk_domain.get_active() if chk_domain else False,
            "trust_session": chk_session.get_active(),
            "trust_client": chk_client.get_active(),
        }
    dialog.destroy()
    return result


def _show_kick_gtk(peers: dict, kick_fn, get_aliases_fn, set_alias_fn, get_latency_fn=None) -> None:
    dialog = Gtk.Dialog(title=APP_NAME)
    icon_path = _app_icon_path()
    if os.path.exists(icon_path):
        try:
            dialog.set_icon_from_file(icon_path)
        except Exception:
            pass

    box = dialog.get_content_area()
    box.set_spacing(6)
    box.set_border_width(12)

    lbl = Gtk.Label(label="Connected clients:")
    lbl.set_halign(Gtk.Align.START)
    box.add(lbl)

    store = Gtk.ListStore(str, str)  # display_name, "ip:port" key
    current_addrs = list(peers.keys())

    def _rebuild_store():
        sel_model, sel_iter = tree.get_selection().get_selected()
        sel_idx = sel_model.get_path(sel_iter).get_indices()[0] if sel_iter else None
        store.clear()
        aliases = get_aliases_fn()
        latency = get_latency_fn() if get_latency_fn else {}
        for addr in current_addrs:
            ip, port = addr
            alias = aliases.get(ip)
            lat = latency.get(addr)
            suffix = f"  ({int(lat)} ms)" if lat is not None else ""
            label = f"{alias}:{port}{suffix}" if alias else f"{ip}:{port}{suffix}"
            store.append([label, f"{ip}:{port}"])
        if sel_idx is not None and sel_idx < len(current_addrs):
            tree.get_selection().select_path(Gtk.TreePath.new_from_indices([sel_idx]))

    _rebuild_store()

    tree = Gtk.TreeView(model=store)
    col = Gtk.TreeViewColumn("Client", Gtk.CellRendererText(), text=0)
    tree.append_column(col)
    tree.set_headers_visible(False)

    def _on_right_click(widget, event):
        if event.button != 3:
            return
        path_info = tree.get_path_at_pos(int(event.x), int(event.y))
        if not path_info:
            return
        path = path_info[0]
        tree.get_selection().select_path(path)
        idx = path.get_indices()[0]
        if idx >= len(current_addrs):
            return
        ip = current_addrs[idx][0]
        menu = Gtk.Menu()
        copy_item = Gtk.MenuItem(label="Copy IP")
        def _on_copy_ip(_item, _ip=ip):
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(_ip, -1)
            clipboard.store()
        copy_item.connect("activate", _on_copy_ip)
        menu.append(copy_item)
        item = Gtk.MenuItem(label="Set Alias…")
        def _on_set_alias(_item, _ip=ip, _idx=idx):
            aliases = get_aliases_fn()
            current = aliases.get(_ip, "")
            new_alias = _prompt_string_gtk(f"Set alias for {_ip}:", current)
            if new_alias is None:
                return
            set_alias_fn(_ip, new_alias)
            _rebuild_store()
        item.connect("activate", _on_set_alias)
        menu.append(item)
        menu.show_all()
        menu.popup_at_pointer(event)

    tree.connect("button-press-event", _on_right_click)

    scroll = Gtk.ScrolledWindow()
    scroll.set_min_content_height(150)
    scroll.set_min_content_width(260)
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.add(tree)
    box.add(scroll)

    kick_btn = Gtk.Button(label="Kick Selected")
    box.add(kick_btn)

    def _on_kick(_btn):
        sel = tree.get_selection()
        model, treeiter = sel.get_selected()
        if not treeiter:
            return
        idx = model.get_path(treeiter).get_indices()[0]
        if idx >= len(current_addrs):
            return
        addr = current_addrs[idx]
        ip, port = addr
        aliases = get_aliases_fn()
        display = f"{aliases.get(ip, ip)}:{port}"
        confirm = Gtk.MessageDialog(
            transient_for=dialog,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text=f"Kick {display}?",
        )
        response = confirm.run()
        confirm.destroy()
        if response == Gtk.ResponseType.YES:
            try:
                kick_fn(addr)
            except Exception:
                pass
            current_addrs.pop(idx)
            _rebuild_store()

    kick_btn.connect("clicked", _on_kick)

    def _tick():
        _rebuild_store()
        return True

    timer_id = GLib.timeout_add(1000, _tick)
    dialog.connect("destroy", lambda w: GLib.source_remove(timer_id))

    dialog.add_button("Close", Gtk.ResponseType.CLOSE)
    dialog.show_all()
    dialog.run()
    dialog.destroy()


def perform_frozen_update(exe_path: str, new_path: str, old_path: str, env_vars_to_clear: list) -> None:
    raise NotImplementedError("Linux frozen update not yet implemented")
