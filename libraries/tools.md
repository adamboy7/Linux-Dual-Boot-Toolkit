# OS-Abstracted Helpers

This toolkit includes small helper functions that hide platform-specific privilege
handling behind a consistent interface.

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
* Call `ensure_platform_permissions` early in the entrypoint of CLI or GUI tools
  that require elevated permissions to manage Bluetooth devices or system files.
* On Windows, bundle PsExec with your script or ensure it is discoverable in the
  PATH so SYSTEM elevation can succeed.
* Choose a distinctive `system_flag` when calling `ensure_platform_permissions`
  to prevent accidental recursion in relaunched processes.
