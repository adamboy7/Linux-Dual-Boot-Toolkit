from __future__ import annotations

import logging
import sys
from typing import Optional

log = logging.getLogger(__name__)

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
    _encode_file_url,
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

    The listener always intercepts hardware media keys and routes them to the
    core. Whether to relay those events to peers is decided by the core based
    on ``enable_media_controls``; the listener itself is always active so that
    local playback control is never lost when opting out of networked sync.
    ``enabled`` is accepted for backwards compatibility but has no effect.
    """
    if sys.platform == "win32":
        from .windows import WindowsMediaKeyListener
        return WindowsMediaKeyListener(core, swallow=swallow)
    from .linux import LinuxMediaKeyListener
    return LinuxMediaKeyListener(core, swallow=swallow)


def prompt_string(prompt: str, initial: str = "") -> Optional[str]:
    """Cross-platform string prompt dialog."""
    if sys.platform == "win32":
        from .windows import get_or_create_prompter
        prompter = get_or_create_prompter()
        if prompter is not None:
            return prompter.ask_string(prompt, initial)
        log.warning("WinPromptThread unavailable; cannot prompt for string: %s", prompt)
        return None
    from .linux import _prompt_string_gtk
    return _prompt_string_gtk(prompt, initial)


def prompt_int(prompt: str, initial: int):
    """Cross-platform integer prompt dialog.

    Returns None when the user cancelled, otherwise a ``(ok, value)`` tuple:
    - ``(True, int)`` for a valid integer.
    - ``(False, raw_str)`` for unparseable input so callers can surface an
      explicit error rather than treating "abc" as "user cancelled".
    """
    value = prompt_string(prompt, str(initial))
    if value is None:
        return None
    text = value.strip()
    try:
        return (True, int(text))
    except ValueError:
        return (False, text)


def prompt_url_confirm(url: str, is_ip: bool, show_protocol_trust: bool = True, show_peer_trust: bool = True) -> Optional[dict]:
    """Show a URL open-confirmation dialog (cross-platform).

    Returns a dict with ``accepted=True`` and trust flags, or None if rejected.
    Pass ``show_protocol_trust=False`` to hide the protocol-trust checkbox (e.g. for file://).
    Pass ``show_peer_trust=False`` to hide the session/host trust checkboxes (e.g. for file://).
    """
    if sys.platform == "win32":
        from .windows import get_or_create_prompter
        prompter = get_or_create_prompter()
        if prompter is not None:
            return prompter.ask_url_confirm(url, is_ip, show_protocol_trust, show_peer_trust)
        log.warning("WinPromptThread unavailable; cannot confirm URL: %s", url)
        return None
    from .linux import _prompt_url_confirm_gtk
    return _prompt_url_confirm_gtk(url, is_ip, show_protocol_trust, show_peer_trust)


def show_kick_dialog(core: "RelayCore") -> None:
    """Open the Kick Clients dialog (cross-platform, HOST only)."""
    peers_snapshot = dict(core.peers)
    if not peers_snapshot:
        return
    kick_fn = core.ui_kick_client
    get_aliases_fn = load_client_aliases
    get_latency_fn = lambda: dict(core.peer_latency)

    def set_alias_fn(ip: str, alias: str) -> None:
        set_client_alias(ip, alias)
        core._notify()
    if sys.platform == "win32":
        from .windows import get_or_create_prompter
        prompter = get_or_create_prompter()
        if prompter is not None:
            prompter.show_kick_dialog(peers_snapshot, kick_fn, get_aliases_fn, set_alias_fn, get_latency_fn)
        else:
            log.warning("WinPromptThread unavailable; cannot show kick dialog")
    else:
        from .linux import _show_kick_gtk
        _show_kick_gtk(peers_snapshot, kick_fn, get_aliases_fn, set_alias_fn, get_latency_fn)


def prompt_host_url_confirm(url: str, is_ip: bool, client_ip: str, show_protocol_trust: bool = True, show_peer_trust: bool = True) -> Optional[dict]:
    """Show a host-side URL dialog for a URL received from a client (cross-platform).

    Returns a dict with ``forward`` and trust flags, or None if cancelled
    without opening.
    Pass ``show_protocol_trust=False`` to hide the protocol-trust checkbox (e.g. for file://).
    Pass ``show_peer_trust=False`` to hide the session/client trust checkboxes (e.g. for file://).
    """
    if sys.platform == "win32":
        from .windows import get_or_create_prompter
        prompter = get_or_create_prompter()
        if prompter is not None:
            return prompter.ask_host_url_confirm(url, is_ip, client_ip, show_protocol_trust, show_peer_trust)
        log.warning(
            "WinPromptThread unavailable; cannot confirm host-side URL: %s", url
        )
        return None
    from .linux import _prompt_host_url_confirm_gtk
    return _prompt_host_url_confirm_gtk(url, is_ip, client_ip, show_protocol_trust, show_peer_trust)


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
    "_encode_file_url",
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
