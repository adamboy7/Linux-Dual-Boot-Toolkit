from __future__ import annotations

import sys
from typing import Optional

from .common import (
    APP_NAME,
    DEFAULT_PORT,
    NullMediaKeyListener,
    RelayCore,
    ResumeMode,
    Role,
    State,
    MediaSnapshot,
    _RESP_HOST_FORWARD,
    _RESP_HOST_OPEN,
    _app_icon_path,
    _is_app_protocol_url,
    _is_ip_url,
    _resource_base_dir,
    _url_domain,
    add_trusted_client,
    add_trusted_domain,
    add_trusted_host,
    client_display_name,
    config_path,
    decide_actions,
    decode,
    encode,
    get_client_alias,
    is_client_permanently_trusted,
    is_domain_trusted,
    is_host_permanently_trusted,
    get_installed_version,
    load_client_aliases,
    load_config,
    make_icon,
    now_ms,
    save_client_aliases,
    save_config,
    set_client_alias,
)


def build_media_controller():
    """Return the platform-appropriate media controller."""
    if sys.platform == "win32":
        from .windows import WindowsMediaController
        return WindowsMediaController()
    from .linux import LinuxMediaController
    return LinuxMediaController()


def build_media_key_listener(core: RelayCore, swallow: bool, enabled: bool = True):
    """Return the platform-appropriate media key listener.

    When ``enabled`` is False, a Null listener is returned: an opted-out HOST
    must not initiate media events toward clients, and an opted-out CLIENT
    must not send external media toggles. Client→client relay through an
    opted-out host happens inside ``RelayCore._handle_cmd``.
    """
    if not enabled:
        return NullMediaKeyListener()
    if sys.platform == "win32":
        from .windows import WindowsMediaKeyListener
        return WindowsMediaKeyListener(core, swallow=swallow)
    from .linux import LinuxMediaKeyListener
    return LinuxMediaKeyListener(core, swallow=swallow)


def prompt_string(prompt: str, initial: str = "") -> Optional[str]:
    """Cross-platform string prompt dialog."""
    if sys.platform == "win32":
        from . import windows as _w
        if _w._WIN_PROMPTER is not None:
            return _w._WIN_PROMPTER.ask_string(prompt, initial)
        from .windows import _ask_string_windows
        return _ask_string_windows(prompt, initial)
    from .linux import _prompt_string_gtk
    return _prompt_string_gtk(prompt, initial)


def prompt_int(prompt: str, initial: int) -> Optional[int]:
    """Cross-platform integer prompt dialog."""
    value = prompt_string(prompt, str(initial))
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def prompt_url_confirm(url: str, is_ip: bool) -> Optional[dict]:
    """Show a URL open-confirmation dialog (cross-platform).

    Returns a dict with ``accepted=True`` and trust flags, or None if rejected.
    """
    if sys.platform == "win32":
        from . import windows as _w
        if _w._WIN_PROMPTER is not None:
            return _w._WIN_PROMPTER.ask_url_confirm(url, is_ip)
        from .windows import _ask_url_confirm_windows
        return _ask_url_confirm_windows(url, is_ip)
    from .linux import _prompt_url_confirm_gtk
    return _prompt_url_confirm_gtk(url, is_ip)


def show_kick_dialog(core: "RelayCore") -> None:
    """Open the Kick Clients dialog (cross-platform, HOST only)."""
    peers_snapshot = dict(core.peers)
    if not peers_snapshot:
        return
    kick_fn = core.ui_kick_client
    get_aliases_fn = load_client_aliases

    def set_alias_fn(ip: str, alias: str) -> None:
        set_client_alias(ip, alias)
        core._notify()
    if sys.platform == "win32":
        from . import windows as _w
        if _w._WIN_PROMPTER is not None:
            _w._WIN_PROMPTER.show_kick_dialog(peers_snapshot, kick_fn, get_aliases_fn, set_alias_fn)
        else:
            from .windows import _show_kick_windows
            _show_kick_windows(peers_snapshot, kick_fn, get_aliases_fn, set_alias_fn)
    else:
        from .linux import _show_kick_gtk
        _show_kick_gtk(peers_snapshot, kick_fn, get_aliases_fn, set_alias_fn)


def prompt_host_url_confirm(url: str, is_ip: bool, client_ip: str) -> Optional[dict]:
    """Show a host-side URL dialog for a URL received from a client (cross-platform).

    Returns a dict with ``forward`` and trust flags, or None if cancelled without
    opening.
    """
    if sys.platform == "win32":
        from . import windows as _w
        if _w._WIN_PROMPTER is not None:
            return _w._WIN_PROMPTER.ask_host_url_confirm(url, is_ip, client_ip)
        from .windows import _ask_host_url_confirm_windows
        return _ask_host_url_confirm_windows(url, is_ip, client_ip)
    from .linux import _prompt_host_url_confirm_gtk
    return _prompt_host_url_confirm_gtk(url, is_ip, client_ip)


__all__ = [
    "APP_NAME",
    "DEFAULT_PORT",
    "State",
    "ResumeMode",
    "MediaSnapshot",
    "Role",
    "NullMediaKeyListener",
    "RelayCore",
    "decide_actions",
    "client_display_name",
    "config_path",
    "get_client_alias",
    "get_installed_version",
    "load_client_aliases",
    "load_config",
    "save_client_aliases",
    "save_config",
    "set_client_alias",
    "show_kick_dialog",
    "is_domain_trusted",
    "add_trusted_domain",
    "is_host_permanently_trusted",
    "add_trusted_host",
    "is_client_permanently_trusted",
    "add_trusted_client",
    "_is_ip_url",
    "_is_app_protocol_url",
    "_url_domain",
    "_RESP_HOST_OPEN",
    "_RESP_HOST_FORWARD",
    "now_ms",
    "encode",
    "decode",
    "make_icon",
    "_resource_base_dir",
    "_app_icon_path",
    "build_media_controller",
    "build_media_key_listener",
    "prompt_string",
    "prompt_int",
    "prompt_url_confirm",
    "prompt_host_url_confirm",
]
