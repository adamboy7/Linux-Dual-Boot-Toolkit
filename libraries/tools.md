# OS-Abstracted Helpers

This toolkit includes small helper functions that hide platform-specific privilege
handling and Bluetooth management behind a consistent interface.

## Bluetooth discovery and management

### `bluetooth.get_bluetooth_backend(base_dir: str = "/var/lib/bluetooth")`
* Returns a backend object tailored to the current OS (`LinuxBluetoothBackend` on Linux, `WindowsBluetoothBackend` on Windows).
* Accepts an optional `base_dir` to override the Linux adapter root for testing or custom layouts.
* Use this when you need direct access to backend methods (e.g., importing/exporting keys) while keeping code platform-agnostic.

### `bluetooth.get_bluetooth_adapters(base_dir: str = "/var/lib/bluetooth")`
* Lists available Bluetooth adapters on the current platform using the appropriate backend.
* Linux: reads adapter metadata from `/var/lib/bluetooth` combined with `bluetoothctl list` output.
* Windows: queries the registry for adapter entries and normalizes MAC formatting.
* Returns lightweight adapter objects usable with other helper functions.

Example:
```python
from libraries.bluetooth import get_bluetooth_adapters

adapters = get_bluetooth_adapters()
for adapter in adapters:
    print(adapter.address, adapter.name)
```

### `bluetooth.get_devices_for_adapter(adapter)`
* Retrieves paired devices for a given adapter object regardless of platform.
* Linux: gathers device info from `/var/lib/bluetooth/<adapter>/` directories and resolves names/keys from info files.
* Windows: reads paired devices and keys from the registry for the adapter.

Example:
```python
from libraries.bluetooth import get_bluetooth_adapters, get_devices_for_adapter

adapters = get_bluetooth_adapters()
if not adapters:
    raise SystemExit("No Bluetooth adapters found")

devices = get_devices_for_adapter(adapters[0])
for device in devices:
    print(device.address, device.name)
```

### `bluetooth.reload_bluetooth()`
* Attempts to restart Bluetooth services in a platform-aware way and returns `(success: bool, detail: str)`.
* Linux: tries `systemctl restart bluetooth`, then `service bluetooth restart`, collecting errors if commands fail or are missing.
* Windows: runs `Restart-Service bthserv` via PowerShell, falling back to `net stop bthserv`/`net start bthserv` if needed.
* Use this after operations that modify adapter or device state and may require a service refresh.

## `permissions.get_platform_privileges(system_flag: Optional[str] = None)`
* Returns a tuple ``(is_admin, is_system)`` describing the current privilege
  level for the host OS.
* Windows:
  * ``is_admin`` is ``True`` when the token has administrator privileges.
  * ``is_system`` is ``True`` when running as LocalSystem **or** when the
    process was launched with the provided ``system_flag`` to indicate a
    PsExec-based SYSTEM relaunch.
* Linux: root (UID 0) is both admin and system. There is no higher privilege
  than ``sudo``/root, so when ``geteuid() == 0`` both values are ``True``.
* Other platforms: both values are ``False``.

Example usage:
```python
from libraries.permissions import get_platform_privileges

is_admin, is_system = get_platform_privileges(system_flag="--as-system")
print(is_admin, is_system)
```

## `permissions.ensure_platform_permissions(system_flag: Optional[str] = None)`
* Dispatches to the correct platform helper based on `platform.system()`.
* Linux: calls [`ensure_root_linux`](#ensure_root_linux) to guarantee the process is running as root.
* Windows: calls [`ensure_windows_system`](#ensure_windows_system) to ensure the process is running as `SYSTEM`.
* Use this when a script needs elevated privileges but should remain cross-platform.

Example usage:
```python
from libraries.permissions import ensure_platform_permissions

# Must be run early in your script, before privileged operations
ensure_platform_permissions(system_flag="--as-system")
```

### Behavior details
* **Linux**: If the user is not already root, the function attempts to relaunch
  the script via `pkexec` or `sudo` while preserving common GUI environment
  variables.
* **Windows**: If the current token is not `SYSTEM`, the function relaunches the
  script with UAC elevation (if needed) and then uses PsExec to spawn a SYSTEM
  instance. Pass a unique `system_flag` (e.g., `"--as-system"`) so the relaunched
  process can detect it was started by the helper.

## Linux-specific helper

### `permissions.linux.ensure_root_linux()`
* No-op on non-Linux platforms.
* If already running as root, returns immediately.
* Otherwise attempts to restart the script with elevated privileges:
  1. Prefer `pkexec env ... python script.py ...` preserving display-related
     environment variables for GUI apps.
  2. Fallback to `sudo -E ...` preserving the environment.
  3. Emits an error to stderr and exits if neither tool is available.

## Windows-specific helpers

### `permissions.windows.ensure_windows_system(system_flag: str)`
* No-op if the current process is already running as `SYSTEM` or if `system_flag`
  is present in `sys.argv` (to avoid relaunch loops).
* If not running as admin, restarts the script with UAC elevation via
  `ShellExecuteW`.
* From an elevated admin context, relaunches the script as SYSTEM using PsExec
  while forwarding the original arguments (minus the `system_flag`) and any
  additional args supplied to the launcher.

### Supporting helpers
* `permissions.get_platform_privileges(system_flag: Optional[str] = None)` –
  reports the current `(is_admin, is_system)` tuple for the running platform.
* `permissions.windows.is_admin()` – returns `True` when the current token has
  administrator privileges.
* `permissions.windows.is_system()` – returns `True` when running under the
  LocalSystem account.
* `permissions.windows.relaunch_as_admin()` – triggers a UAC prompt and exits
  the current process; used internally by `ensure_windows_system`.
* `permissions.windows.relaunch_as_system_via_psexec(system_flag, additional_args=None)` –
  starts a new instance under SYSTEM using PsExec. Typically called from
  `ensure_windows_system` and rarely needed directly.

## Usage tips
* **Requesting Windows administrator**: call
  `permissions.windows.relaunch_as_admin()` from a Windows-only entrypoint when
  you need admin rights but do **not** require SYSTEM. The function shows a UAC
  prompt and exits the current process after starting the elevated copy.
* **Requesting Windows SYSTEM**: use `permissions.windows.ensure_windows_system`
  with a unique `system_flag` (e.g., `"--as-system"`). If already running as
  admin, it will spawn a SYSTEM instance via PsExec; otherwise it first relaunches
  as admin and then escalates to SYSTEM. `ensure_platform_permissions` wraps this
  automatically for cross-platform callers.
* **Linux admin vs. system**: Linux treats root as both administrator and
  system. Calling `permissions.linux.ensure_root_linux()` (or the cross-platform
  `ensure_platform_permissions`) ensures the process is running as UID 0; there
  is no separate SYSTEM concept on Linux.
* Call `ensure_platform_permissions` early in the entrypoint of CLI or GUI tools
  that require elevated permissions to manage Bluetooth devices or system files.
* On Windows, bundle PsExec with your script or ensure it is discoverable in the
  PATH so SYSTEM elevation can succeed.
* Choose a distinctive `system_flag` when calling `ensure_platform_permissions`
  to prevent accidental recursion in relaunched processes.
