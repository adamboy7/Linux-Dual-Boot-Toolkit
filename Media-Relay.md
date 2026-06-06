# Media Relay

A cross-platform system tray app that synchronizes media playback controls between two PCs over the network. One PC acts as the **HOST**, the other connects as a **CLIENT**. Both machines can control media on each other in real time using hardware media keys, tray menu buttons, or automatic arbitration logic.

Supports Windows and Linux with identical behavior.

---

## Features

### Playback Synchronization
- Relay play, pause, stop, next, and previous commands between PCs in real time
- Hardware media key interception — pressing a media key on one PC sends it to the other
- Intelligent arbitration decides what happens on each side depending on playback state

### Resume Modes
The **Resume Mode** controls how a toggle press is handled. In **Host Only** and **Client Only**, the HOST checks the playback state of both sides and decides which commands to send (arbitration). In **Blind**, the HOST skips that check and relays the toggle directly to all clients regardless of their current state.

| Mode | Behavior |
|---|---|
| **Host Only** | Arbitrated — HOST decides based on state. When both are paused, only the HOST resumes. |
| **Client Only** | Arbitrated — HOST decides based on state. When both are paused, only the CLIENT resumes. |
| **Blind** | No arbitration — toggle is sent to all clients as-is, regardless of playback state. |

### Multi-Client HOST Mode
- A single HOST can accept connections from multiple CLIENTs simultaneously
- When more than one client is connected, **Blind** mode is automatically enforced to prevent conflicts

### URL Sharing
- Send a URL from one PC to the other via the tray menu
- Recipient gets a prompt to open, trust (permanently or for this session), or deny the link
- Trusted domains and protocols are remembered; untrusted sources bring up a user side confirmation
- All URL schemes are supported — including custom app protocols such as `beatsaver://`, `steam://`, or `calculator://`
- Trusting a protocol allows future links using that protocol to open automatically, even from untrusted peers
- `file://` links have additional restrictions: they are silently refused from untrusted peers, always prompt even from trusted peers, and can never be set to auto-open through the UI

### Latency Correction
- Measures round-trip time to the peer using ping/pong heartbeats with exponential moving average smoothing
- When enabled, adjusts command timing to compensate for network delay so both sides respond simultaneously

### Persistent Configuration
- Remembers the last connected HOST address and can auto-reconnect on startup
- Resume mode, port, and all toggle settings persist across restarts
- Per-client aliases let you give connected peers a custom name

### Tools Menu Updater
- Built-in updater checks GitHub releases and installs new versions from the tray menu. When running from source the button downloads the latest source from github, running from a built EXE downloads the latest released build.

---

## Requirements

### Windows
- Python 3.10+
- `pystray >= 0.19.5`
- `Pillow >= 10.0.0`
- `pywinrt` packages (Windows Media Transport Controls API)
  - `winrt-runtime`
  - `winrt-Windows.Foundation`
  - `winrt-Windows.Media.Control`
  - `winrt-Windows.Storage.Streams`

### Linux
- Python 3.10+
- `pystray >= 0.19.5`
- `Pillow >= 10.0.0`
- `PyGObject >= 3.42.0` (GTK 3 tray and dialogs)
- `playerctl` (external CLI tool — install via your package manager)
- `evdev >= 1.6.0` (optional — required for hardware media key interception)

Install Python dependencies:
```
pip install -r requirements-Media-Sync.txt
```

---

## Running

**Windows (console):**
```
python Media-Sync.py
```

**Windows (no console window):**
```
wscript MediaRelay.vbs
```

**Linux:**
```
python3 Media-Sync.py
```

The app runs silently in the system tray. Right-click the tray icon to access all controls.

On Windows you can also add it to startup or create a desktop shortcut from the tray menu under **Tools**.

---

## Usage

### Connecting

1. On the machine that will act as HOST, right-click the tray icon — it is already listening on the configured port (default **50123**)
2. On the CLIENT machine, click **Connect...** and enter the HOST's IP address
3. Once connected, the status line updates and media controls are linked

### Tray Menu

| Item | Description |
|---|---|
| **Toggle** | Play/pause on the local machine (relayed to peer if connected) |
| **Stop** | Stop playback on both sides |
| **Next** | Skip to next track |
| **Previous** | Go to previous track |
| **Connect...** | Enter HOST IP to connect as a client |
| **Disconnect** | Drop the current peer connection |

### Controls Submenu

| Option | Description |
|---|---|
| **Media Controls** | Enable/disable media key events sent from peers |
| **Receive Links** | Accept or block incoming URL-share requests |
| **Ignore Client** *(HOST)* | Accept the connection but ignore commands from the client |
| **Latency Correction** *(HOST)* | Offset command timing by the measured peer RTT |

### Resume Mode Submenu
Select **Host Only**, **Client Only**, or **Blind** to control which side resumes after a mutual pause.

### Tools Submenu

| Option | Description |
|---|---|
| **Send Link...** | Send a URL to the connected peer |
| **Kick...** *(HOST)* | Disconnect a specific client |
| **Listening Port...** | Change the UDP port the app binds to (default 50123) |
| **Add to Startup** *(Windows)* | Register the app to launch at login |
| **Create Shortcut...** *(Windows)* | Create a desktop or Start Menu shortcut |
| **Update Toolkit** | Check for and install the latest version |
| **Restart** | Restart the app |

---

## Configuration

Config files are stored at:
- **Windows:** `%APPDATA%\MediaRelay\`
- **Linux:** `~/.config/MediaRelay/`

| File | Contents |
|---|---|
| `config.json` | Port, role, resume mode, toggle settings, last peer address |
| `trusted_hosts.json` | HOST IPs that are permanently trusted for URL sharing |
| `trusted_clients.json` | CLIENT IPs that are permanently trusted for URL sharing |
| `trusted_domains.json` | URL domain patterns and protocol schemes permanently allowed to open |
| `client_aliases.json` | Custom display names for connected clients |

You do not need to edit these files manually — all settings are managed from the tray menu.

### Advanced: Enabling `file://` Auto-Open

> **Not recommended.** Allowing `file://` links to open automatically means any peer can silently open arbitrary files or folders on your machine without confirmation. Only do this in a fully trusted, controlled environment such as a personal LAN where both machines belong to you.

By design, the app never lets you trust the `file://` protocol through the UI — it will always prompt, even from trusted peers. If you want `file://` links to auto-open (for example, to instantly open a shared project folder on your other PC without clicking through a dialog every time), you can enable it by manually editing `trusted_domains.json`:

1. Close the app.
2. Open `trusted_domains.json` in the config directory.
3. Add `"file"` to the JSON array, e.g.:
   ```json
   ["youtube.com", "beatsaver", "file"]
   ```
4. Save the file and restart the app.

To revert, remove `"file"` from the list and restart.

---

## Architecture

Media Relay uses a lightweight **UDP** transport with JSON messages. The HOST binds a port and waits; CLIENTs initiate the handshake.

Key message types:

| Message | Purpose |
|---|---|
| `connect_request` / `connect_ack` | Handshake and session token exchange |
| `ping` / `pong` | Heartbeat and RTT measurement |
| `get_state` | Query remote playback state |
| `cmd` | Execute a media command on the peer |
| `toggle` / `request_toggle` | Synchronized toggle with state hints |
| `resume_mode` / `policy` | Propagate resume mode setting to peers |
| `open_url` / `client_url` | URL sharing with trust checks |
| `disconnect` | Graceful teardown |

Session tokens are issued during the handshake and required for sensitive messages, preventing spoofed commands from untrusted IPs.
