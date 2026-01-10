use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::time::timeout;
use uuid::Uuid;

use rdev::{Event, EventType, Key};
use tray_item::{IconSource, TrayItem};

#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{IDI_APPLICATION, LoadIconW};

const APP_NAME: &str = "MediaRelay";
const DEFAULT_PORT: u16 = 50123;

#[derive(Parser, Debug)]
#[command(name = "media-sync", version, about = "Media sync relay (Rust)")]
struct Args {
    #[arg(long, default_value_t = DEFAULT_PORT)]
    listen_port: u16,

    #[arg(long)]
    peer_ip: Option<IpAddr>,

    #[arg(long, default_value_t = DEFAULT_PORT)]
    peer_port: u16,

    #[arg(long, default_value = "host_only")]
    resume_mode: String,

    #[arg(long)]
    auto_connect: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State {
    None,
    Paused,
    Playing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResumeMode {
    HostOnly,
    Blind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Host,
    Client,
}

#[derive(Debug, Clone)]
struct MediaSnapshot {
    state: State,
    app: String,
    title: String,
}

trait MediaController: Send + Sync {
    fn snapshot(&self) -> Result<MediaSnapshot>;
    fn command(&self, cmd: &str) -> Result<bool>;
}

#[cfg(windows)]
mod media_windows {
    use super::{MediaController, MediaSnapshot, Result, State};
    use windows::Media::Control::{
        GlobalSystemMediaTransportControlsSessionManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus,
    };

    pub struct WindowsMediaController;

    impl WindowsMediaController {
        fn get_session(
        ) -> windows::core::Result<Option<windows::Media::Control::GlobalSystemMediaTransportControlsSession>> {
            let manager = GlobalSystemMediaTransportControlsSessionManager::RequestAsync()?.get()?;
            Ok(manager.GetCurrentSession().ok())
        }
    }

    impl MediaController for WindowsMediaController {
        fn snapshot(&self) -> Result<MediaSnapshot> {
            let session = match Self::get_session()? {
                Some(session) => session,
                None => {
                    return Ok(MediaSnapshot {
                        state: State::None,
                        app: String::new(),
                        title: String::new(),
                    })
                }
            };

            let playback = session.GetPlaybackInfo()?;
            let status = playback.PlaybackStatus()?;
            let state = match status {
                GlobalSystemMediaTransportControlsSessionPlaybackStatus::Playing => State::Playing,
                GlobalSystemMediaTransportControlsSessionPlaybackStatus::Paused
                | GlobalSystemMediaTransportControlsSessionPlaybackStatus::Stopped => State::Paused,
                _ => State::Paused,
            };

            let mut title = String::new();
            let mut app = String::new();

            if let Ok(props) = session.TryGetMediaPropertiesAsync()?.get() {
                if let Ok(value) = props.Title() {
                    title = value.to_string();
                }
            }

            if let Ok(value) = session.SourceAppUserModelId() {
                app = value.to_string();
            }

            Ok(MediaSnapshot { state, app, title })
        }

        fn command(&self, cmd: &str) -> Result<bool> {
            let session = match Self::get_session()? {
                Some(session) => session,
                None => return Ok(false),
            };

            let result = match cmd {
                "play" => session.TryPlayAsync()?.get(),
                "pause" => session.TryPauseAsync()?.get(),
                "stop" => session.TryStopAsync()?.get(),
                _ => return Ok(false),
            };

            Ok(result.unwrap_or(false))
        }
    }
}

#[cfg(not(windows))]
mod media_linux {
    use super::{MediaController, MediaSnapshot, Result, State};
    use std::process::Command;

    pub struct LinuxMediaController;

    impl LinuxMediaController {
        fn playerctl(args: &[&str]) -> Result<Option<String>> {
            let output = Command::new("playerctl").args(args).output();
            let output = match output {
                Ok(output) => output,
                Err(_) => return Ok(None),
            };
            if !output.status.success() {
                return Ok(None);
            }
            Ok(Some(String::from_utf8_lossy(&output.stdout).trim().to_string()))
        }
    }

    impl MediaController for LinuxMediaController {
        fn snapshot(&self) -> Result<MediaSnapshot> {
            let status = Self::playerctl(&["status"])?;
            let state = match status.as_deref() {
                Some("Playing") | Some("playing") => State::Playing,
                Some("Paused") | Some("paused") | Some("Stopped") | Some("stopped") => State::Paused,
                _ => State::None,
            };

            let mut app = String::new();
            let mut title = String::new();
            if let Some(meta) = Self::playerctl(&["metadata", "--format", "{{playerName}}||{{title}}"])? {
                let mut parts = meta.splitn(2, "||");
                if let Some(value) = parts.next() {
                    app = value.trim().to_string();
                }
                if let Some(value) = parts.next() {
                    title = value.trim().to_string();
                }
            }

            Ok(MediaSnapshot { state, app, title })
        }

        fn command(&self, cmd: &str) -> Result<bool> {
            let result = match cmd {
                "play" | "pause" | "stop" => Self::playerctl(&[cmd])?,
                _ => None,
            };
            Ok(result.is_some())
        }
    }
}

fn build_media_controller() -> Arc<dyn MediaController> {
    #[cfg(windows)]
    {
        Arc::new(media_windows::WindowsMediaController)
    }
    #[cfg(not(windows))]
    {
        Arc::new(media_linux::LinuxMediaController)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WireMessage {
    t: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct StoredConfig {
    listen_port: u16,
    peer_ip: Option<IpAddr>,
    peer_port: u16,
    resume_mode: ResumeMode,
    auto_connect: bool,
}

#[derive(Debug)]
struct PendingMap {
    pending: HashMap<String, oneshot::Sender<WireMessage>>,
}

impl PendingMap {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct RuntimeState {
    role: Role,
    resume_mode: ResumeMode,
    peer: Option<SocketAddr>,
    peer_last_seen: Instant,
    auto_connect_enabled: bool,
    auto_connect_target: Option<SocketAddr>,
}

impl RuntimeState {
    fn new(resume_mode: ResumeMode) -> Self {
        Self {
            role: Role::Host,
            resume_mode,
            peer: None,
            peer_last_seen: Instant::now(),
            auto_connect_enabled: false,
            auto_connect_target: None,
        }
    }
}

struct App {
    socket: Arc<UdpSocket>,
    media: Arc<dyn MediaController>,
    state: Arc<RwLock<RuntimeState>>,
    pending: Arc<Mutex<PendingMap>>,
}

impl App {
    async fn send(&self, addr: SocketAddr, msg: &WireMessage) -> Result<()> {
        let data = serde_json::to_vec(msg).context("serialize message")?;
        self.socket
            .send_to(&data, addr)
            .await
            .context("send udp")?;
        Ok(())
    }

    async fn rpc(&self, addr: SocketAddr, mut msg: WireMessage, timeout_ms: u64) -> Result<Option<WireMessage>> {
        let id = Uuid::new_v4().to_string();
        msg.id = Some(id.clone());
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.pending.insert(id.clone(), tx);
        }
        self.send(addr, &msg).await?;
        let response = timeout(Duration::from_millis(timeout_ms), rx).await;
        let response = match response {
            Ok(Ok(msg)) => Some(msg),
            _ => None,
        };
        let mut pending = self.pending.lock().await;
        pending.pending.remove(&id);
        Ok(response)
    }

    async fn handle_message(&self, msg: WireMessage, addr: SocketAddr) -> Result<()> {
        let mut pending_match = None;
        if let Some(id) = msg.id.as_deref() {
            let mut pending = self.pending.lock().await;
            if let Some(tx) = pending.pending.remove(id) {
                pending_match = Some(tx);
            }
        }

        if let Some(tx) = pending_match {
            let _ = tx.send(msg);
            return Ok(());
        }

        let msg_type = msg.t.as_str();

        match msg_type {
            "ping" => {
                self.update_peer_seen(addr).await;
                Ok(())
            }
            "connect_request" => self.handle_connect_request(addr, msg).await,
            "disconnect" => self.handle_disconnect(addr, msg).await,
            "get_state" => self.handle_get_state(addr, msg).await,
            "cmd" => self.handle_cmd(addr, msg).await,
            "request_toggle" => self.handle_request_toggle(addr).await,
            "request_stop" => self.handle_request_stop(addr).await,
            "resume_mode" => self.handle_resume_mode(addr, msg).await,
            _ => Ok(()),
        }
    }

    async fn update_peer_seen(&self, addr: SocketAddr) {
        let mut state = self.state.write().await;
        if let Some(peer) = state.peer {
            if peer == addr {
                state.peer_last_seen = Instant::now();
            }
        }
    }

    async fn handle_connect_request(&self, addr: SocketAddr, msg: WireMessage) -> Result<()> {
        let mut state = self.state.write().await;
        if state.role == Role::Client {
            drop(state);
            self.send(
                addr,
                &WireMessage {
                    t: "connect_ack".to_string(),
                    id: msg.id,
                    ts: Some(now_ms()),
                    ok: Some(false),
                    reason: Some("busy_client".to_string()),
                    cmd: None,
                    mode: None,
                    state: None,
                    app: None,
                    title: None,
                    source: None,
                },
            )
            .await?;
            return Ok(());
        }

        if state.peer.is_some() && state.peer != Some(addr) {
            drop(state);
            self.send(
                addr,
                &WireMessage {
                    t: "connect_ack".to_string(),
                    id: msg.id,
                    ts: Some(now_ms()),
                    ok: Some(false),
                    reason: Some("already_connected".to_string()),
                    cmd: None,
                    mode: None,
                    state: None,
                    app: None,
                    title: None,
                    source: None,
                },
            )
            .await?;
            return Ok(());
        }

        state.role = Role::Host;
        state.peer = Some(addr);
        state.peer_last_seen = Instant::now();
        drop(state);

        self.send(
            addr,
            &WireMessage {
                t: "connect_ack".to_string(),
                id: msg.id,
                ts: Some(now_ms()),
                ok: Some(true),
                reason: None,
                cmd: None,
                mode: None,
                state: None,
                app: None,
                title: None,
                source: None,
            },
        )
        .await?;

        self.send(
            addr,
            &WireMessage {
                t: "resume_mode".to_string(),
                id: None,
                ts: Some(now_ms()),
                ok: None,
                reason: None,
                cmd: None,
                mode: Some(self.state.read().await.resume_mode.to_string()),
                state: None,
                app: None,
                title: None,
                source: None,
            },
        )
        .await?;

        println!("[Media-Sync] Client connected from {}", addr);
        Ok(())
    }

    async fn handle_disconnect(&self, addr: SocketAddr, msg: WireMessage) -> Result<()> {
        let mut state = self.state.write().await;
        if state.peer == Some(addr) {
            println!("[Media-Sync] Disconnected from {} (reason: {:?})", addr, msg.reason);
            state.peer = None;
            if state.auto_connect_enabled {
                state.role = Role::Client;
            } else {
                state.role = Role::Host;
            }
        }
        Ok(())
    }

    async fn handle_get_state(&self, addr: SocketAddr, msg: WireMessage) -> Result<()> {
        let snap = self.media.snapshot()?;
        let response = WireMessage {
            t: "state".to_string(),
            id: msg.id,
            ts: Some(now_ms()),
            ok: None,
            reason: None,
            cmd: None,
            mode: None,
            state: Some(match snap.state {
                State::None => "none",
                State::Paused => "paused",
                State::Playing => "playing",
            }
            .to_string()),
            app: Some(snap.app),
            title: Some(snap.title),
            source: None,
        };
        self.send(addr, &response).await?;
        Ok(())
    }

    async fn handle_cmd(&self, addr: SocketAddr, msg: WireMessage) -> Result<()> {
        let cmd = msg.cmd.clone().unwrap_or_default();
        let ok = if matches!(cmd.as_str(), "play" | "pause" | "stop") {
            self.media.command(&cmd).unwrap_or(false)
        } else {
            false
        };
        let response = WireMessage {
            t: "ack".to_string(),
            id: msg.id,
            ts: Some(now_ms()),
            ok: Some(ok),
            reason: None,
            cmd: Some(cmd),
            mode: None,
            state: None,
            app: None,
            title: None,
            source: None,
        };
        self.send(addr, &response).await?;
        self.update_peer_seen(addr).await;
        Ok(())
    }

    async fn handle_request_toggle(&self, addr: SocketAddr) -> Result<()> {
        let state = self.state.read().await;
        if state.role == Role::Host && state.peer == Some(addr) {
            drop(state);
            self.toggle_pressed("peer").await?;
        }
        Ok(())
    }

    async fn handle_request_stop(&self, addr: SocketAddr) -> Result<()> {
        let state = self.state.read().await;
        if state.role == Role::Host && state.peer == Some(addr) {
            drop(state);
            self.stop_pressed("peer").await?;
        }
        Ok(())
    }

    async fn handle_resume_mode(&self, addr: SocketAddr, msg: WireMessage) -> Result<()> {
        let mut state = self.state.write().await;
        if state.peer != Some(addr) {
            return Ok(());
        }
        let mode = match msg.mode.as_deref() {
            Some("blind") => ResumeMode::Blind,
            Some("host_only") => ResumeMode::HostOnly,
            _ => return Ok(()),
        };
        if state.resume_mode != mode {
            state.resume_mode = mode;
            println!("[Media-Sync] Resume mode set to {:?}", mode);
        }
        Ok(())
    }

    async fn connect_out(&self, addr: SocketAddr) -> Result<()> {
        let response = self
            .rpc(
                addr,
                WireMessage {
                    t: "connect_request".to_string(),
                    id: None,
                    ts: Some(now_ms()),
                    ok: None,
                    reason: None,
                    cmd: None,
                    mode: None,
                    state: None,
                    app: None,
                    title: None,
                    source: None,
                },
                800,
            )
            .await?;

        if response.as_ref().and_then(|resp| resp.ok) != Some(true) {
            self.disconnect("connect_failed").await?;
            println!("[Media-Sync] Connection attempt to {} failed", addr);
            return Ok(());
        }

        let mut state = self.state.write().await;
        state.role = Role::Client;
        state.peer = Some(addr);
        state.peer_last_seen = Instant::now();
        state.auto_connect_target = Some(addr);
        state.auto_connect_enabled = true;
        drop(state);

        self.send(
            addr,
            &WireMessage {
                t: "resume_mode".to_string(),
                id: None,
                ts: Some(now_ms()),
                ok: None,
                reason: None,
                cmd: None,
                mode: Some(self.state.read().await.resume_mode.to_string()),
                state: None,
                app: None,
                title: None,
                source: None,
            },
        )
        .await?;

        println!("[Media-Sync] Connected to host {}", addr);
        Ok(())
    }

    async fn disconnect(&self, reason: &str) -> Result<()> {
        let mut state = self.state.write().await;
        if let Some(peer) = state.peer {
            let msg = WireMessage {
                t: "disconnect".to_string(),
                id: None,
                ts: Some(now_ms()),
                ok: None,
                reason: Some(reason.to_string()),
                cmd: None,
                mode: None,
                state: None,
                app: None,
                title: None,
                source: None,
            };
            drop(state);
            let _ = self.send(peer, &msg).await;
            state = self.state.write().await;
        }
        state.peer = None;
        if state.auto_connect_enabled && reason != "user" {
            state.role = Role::Client;
        } else {
            state.role = Role::Host;
        }
        Ok(())
    }

    async fn toggle_local(&self) -> Result<()> {
        let snap = self.media.snapshot()?;
        match snap.state {
            State::Playing => {
                self.media.command("pause")?;
            }
            State::Paused => {
                self.media.command("play")?;
            }
            State::None => {}
        }
        Ok(())
    }

    async fn stop_pressed(&self, source: &str) -> Result<()> {
        let state = self.state.read().await;
        if let Some(peer) = state.peer {
            if state.role == Role::Client {
                drop(state);
                self.send(
                    peer,
                    &WireMessage {
                        t: "request_stop".to_string(),
                        id: None,
                        ts: Some(now_ms()),
                        ok: None,
                        reason: None,
                        cmd: None,
                        mode: None,
                        state: None,
                        app: None,
                        title: None,
                        source: Some(source.to_string()),
                    },
                )
                .await?;
                return Ok(());
            }
        }
        drop(state);

        self.media.command("stop")?;
        Ok(())
    }

    async fn host_arbitrated_toggle(&self) -> Result<()> {
        let state = self.state.read().await;
        let peer = match state.peer {
            Some(peer) => peer,
            None => return Ok(()),
        };
        let resume_mode = state.resume_mode;
        drop(state);

        let host_snap = self.media.snapshot()?;
        let mut client_state = State::None;
        let response = self
            .rpc(
                peer,
                WireMessage {
                    t: "get_state".to_string(),
                    id: None,
                    ts: Some(now_ms()),
                    ok: None,
                    reason: None,
                    cmd: None,
                    mode: None,
                    state: None,
                    app: None,
                    title: None,
                    source: None,
                },
                500,
            )
            .await?;
        if let Some(resp) = response {
            if let Some(state_str) = resp.state.as_deref() {
                client_state = match state_str {
                    "playing" => State::Playing,
                    "paused" => State::Paused,
                    _ => State::None,
                };
            }
        }

        let (host_cmd, client_cmd) = decide_actions(host_snap.state, client_state, resume_mode);
        if let Some(cmd) = host_cmd {
            let _ = self.media.command(cmd);
        }
        if let Some(cmd) = client_cmd {
            let _ = self.send(
                peer,
                &WireMessage {
                    t: "cmd".to_string(),
                    id: None,
                    ts: Some(now_ms()),
                    ok: None,
                    reason: None,
                    cmd: Some(cmd.to_string()),
                    mode: None,
                    state: None,
                    app: None,
                    title: None,
                    source: None,
                },
            )
            .await;
        }

        Ok(())
    }

    async fn set_resume_mode(&self, mode: ResumeMode) -> Result<()> {
        let mut state = self.state.write().await;
        if state.resume_mode == mode {
            return Ok(());
        }
        state.resume_mode = mode;
        let peer = state.peer;
        drop(state);

        if let Some(peer) = peer {
            let _ = self
                .send(
                    peer,
                    &WireMessage {
                        t: "resume_mode".to_string(),
                        id: None,
                        ts: Some(now_ms()),
                        ok: None,
                        reason: None,
                        cmd: None,
                        mode: Some(mode.to_string()),
                        state: None,
                        app: None,
                        title: None,
                        source: None,
                    },
                )
                .await;
        }
        println!("[Media-Sync] Resume mode set to {:?}", mode);
        Ok(())
    }

    async fn stop_all(&self) -> Result<()> {
        let state = self.state.read().await;
        let peer = state.peer;
        let role = state.role;
        drop(state);

        if let Some(peer) = peer {
            if role == Role::Client {
                self.send(
                    peer,
                    &WireMessage {
                        t: "request_stop".to_string(),
                        id: None,
                        ts: Some(now_ms()),
                        ok: None,
                        reason: None,
                        cmd: None,
                        mode: None,
                        state: None,
                        app: None,
                        title: None,
                        source: Some("local".to_string()),
                    },
                )
                .await?;
            } else {
                self.media.command("stop")?;
                self.send(
                    peer,
                    &WireMessage {
                        t: "cmd".to_string(),
                        id: None,
                        ts: Some(now_ms()),
                        ok: None,
                        reason: None,
                        cmd: Some("stop".to_string()),
                        mode: None,
                        state: None,
                        app: None,
                        title: None,
                        source: None,
                    },
                )
                .await?;
            }
        } else {
            self.media.command("stop")?;
        }
        Ok(())
    }

    async fn heartbeat_loop(&self) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let state = self.state.read().await;
            if let Some(peer) = state.peer {
                drop(state);
                let _ = self
                    .send(
                        peer,
                        &WireMessage {
                            t: "ping".to_string(),
                            id: None,
                            ts: Some(now_ms()),
                            ok: None,
                            reason: None,
                            cmd: None,
                            mode: None,
                            state: None,
                            app: None,
                            title: None,
                            source: None,
                        },
                    )
                    .await;
            }
        }
    }

    async fn peer_timeout_loop(&self) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut state = self.state.write().await;
            if let Some(peer) = state.peer {
                if state.peer_last_seen.elapsed() > Duration::from_secs(6) {
                    println!("[Media-Sync] Connection to {} lost (timeout)", peer);
                    state.peer = None;
                    state.role = if state.auto_connect_enabled {
                        Role::Client
                    } else {
                        Role::Host
                    };
                }
            }
        }
    }

    async fn auto_connect_loop(&self) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let state = self.state.read().await;
            if !state.auto_connect_enabled || state.peer.is_some() {
                continue;
            }
            let Some(target) = state.auto_connect_target else {
                continue;
            };
            drop(state);
            println!("[Media-Sync] Retrying connection to {}", target);
            let _ = self.connect_out(target).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn toggle_pressed(&self, source: &str) -> Result<()> {
        let state = self.state.read().await;
        let peer = state.peer;
        let role = state.role;
        drop(state);

        match (peer, role) {
            (Some(peer), Role::Client) => {
                self.send(
                    peer,
                    &WireMessage {
                        t: "request_toggle".to_string(),
                        id: None,
                        ts: Some(now_ms()),
                        ok: None,
                        reason: None,
                        cmd: None,
                        mode: None,
                        state: None,
                        app: None,
                        title: None,
                        source: Some(source.to_string()),
                    },
                )
                .await?;
                Ok(())
            }
            (Some(_), Role::Host) => self.host_arbitrated_toggle().await,
            (None, _) => self.toggle_local().await,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum UiCommand {
    Toggle,
    Stop,
    Connect,
    Disconnect,
    ResumeMode(ResumeMode),
    Quit,
}

#[cfg(windows)]
fn tray_icon_source() -> IconSource {
    let icon = unsafe { LoadIconW(0, IDI_APPLICATION) };
    IconSource::RawIcon(icon)
}

#[cfg(not(windows))]
fn tray_icon_source() -> IconSource {
    IconSource::Resource("media-playback-start")
}

fn start_tray(tx: mpsc::UnboundedSender<UiCommand>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let icon = tray_icon_source();
        let mut tray = match TrayItem::new(APP_NAME, icon) {
            Ok(tray) => tray,
            Err(err) => {
                eprintln!("[Media-Sync] Tray init failed: {:?}", err);
                return;
            }
        };

        let tx_toggle = tx.clone();
        let _ = tray.add_menu_item("Toggle", move || {
            let _ = tx_toggle.send(UiCommand::Toggle);
        });

        let tx_stop = tx.clone();
        let _ = tray.add_menu_item("Stop", move || {
            let _ = tx_stop.send(UiCommand::Stop);
        });

        let tx_connect = tx.clone();
        let _ = tray.add_menu_item("Connect (last peer)", move || {
            let _ = tx_connect.send(UiCommand::Connect);
        });

        let tx_disconnect = tx.clone();
        let _ = tray.add_menu_item("Disconnect", move || {
            let _ = tx_disconnect.send(UiCommand::Disconnect);
        });

        let tx_host = tx.clone();
        let _ = tray.add_menu_item("Resume: host only", move || {
            let _ = tx_host.send(UiCommand::ResumeMode(ResumeMode::HostOnly));
        });

        let tx_blind = tx.clone();
        let _ = tray.add_menu_item("Resume: blind", move || {
            let _ = tx_blind.send(UiCommand::ResumeMode(ResumeMode::Blind));
        });

        let tx_quit = tx.clone();
        let _ = tray.add_menu_item("Quit", move || {
            let _ = tx_quit.send(UiCommand::Quit);
        });

        loop {
            thread::park();
        }
    })
}

fn start_media_key_listener(tx: mpsc::UnboundedSender<UiCommand>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let callback = move |event: Event| {
            if let EventType::KeyPress(key) = event.event_type {
                match key {
                    Key::PlayPause => {
                        let _ = tx.send(UiCommand::Toggle);
                    }
                    Key::Stop => {
                        let _ = tx.send(UiCommand::Stop);
                    }
                    _ => {}
                }
            }
        };

        if let Err(err) = rdev::listen(callback) {
            eprintln!("[Media-Sync] Media key listener failed: {:?}", err);
        }
    })
}

fn decide_actions(host: State, client: State, resume_mode: ResumeMode) -> (Option<&'static str>, Option<&'static str>) {
    if resume_mode == ResumeMode::Blind {
        if host == State::Playing || client == State::Playing {
            return (Some("pause"), Some("pause"));
        }
        if host == State::Paused || client == State::Paused {
            return (Some("play"), Some("play"));
        }
        return (None, None);
    }

    if host == State::Playing || client == State::Playing {
        return (Some("pause"), Some("pause"));
    }
    if host == State::Paused {
        return (Some("play"), None);
    }
    (None, None)
}

fn now_ms() -> u64 {
    use std::time::SystemTime;
    let since = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    since.as_millis() as u64
}

fn config_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("missing config dir"))?;
    let folder = base.join(APP_NAME);
    std::fs::create_dir_all(&folder).context("create config dir")?;
    Ok(folder.join("config.json"))
}

fn load_config() -> Result<StoredConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(StoredConfig {
            listen_port: DEFAULT_PORT,
            peer_ip: None,
            peer_port: DEFAULT_PORT,
            resume_mode: ResumeMode::HostOnly,
            auto_connect: false,
        });
    }
    let content = std::fs::read_to_string(&path).context("read config")?;
    let cfg = serde_json::from_str(&content).context("parse config")?;
    Ok(cfg)
}

fn save_config(config: &StoredConfig) -> Result<()> {
    let path = config_path()?;
    let data = serde_json::to_string_pretty(config).context("serialize config")?;
    std::fs::write(path, data).context("write config")?;
    Ok(())
}

impl ResumeMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "host_only" => Ok(ResumeMode::HostOnly),
            "blind" => Ok(ResumeMode::Blind),
            _ => Err(anyhow!("unknown resume mode: {}", value)),
        }
    }
}

impl std::fmt::Display for ResumeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            ResumeMode::HostOnly => "host_only",
            ResumeMode::Blind => "blind",
        };
        write!(f, "{}", value)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = load_config().unwrap_or(StoredConfig {
        listen_port: DEFAULT_PORT,
        peer_ip: None,
        peer_port: DEFAULT_PORT,
        resume_mode: ResumeMode::HostOnly,
        auto_connect: false,
    });

    config.listen_port = args.listen_port;
    if let Some(peer_ip) = args.peer_ip {
        config.peer_ip = Some(peer_ip);
    }
    config.peer_port = args.peer_port;
    config.resume_mode = ResumeMode::parse(&args.resume_mode).unwrap_or(ResumeMode::HostOnly);
    if args.auto_connect {
        config.auto_connect = true;
    }
    let _ = save_config(&config);

    let socket = UdpSocket::bind(("0.0.0.0", config.listen_port))
        .await
        .with_context(|| format!("bind to 0.0.0.0:{}", config.listen_port))?;
    println!("[Media-Sync] Listening on 0.0.0.0:{}", config.listen_port);

    let media = build_media_controller();
    let state = Arc::new(RwLock::new(RuntimeState::new(config.resume_mode)));

    let pending = Arc::new(Mutex::new(PendingMap::new()));
    let config = Arc::new(Mutex::new(config));
    let app = Arc::new(App {
        socket: Arc::new(socket),
        media,
        state: state.clone(),
        pending: pending.clone(),
    });

    {
        let cfg = config.lock().await;
        if cfg.auto_connect {
            if let Some(ip) = cfg.peer_ip {
                let addr = SocketAddr::new(ip, cfg.peer_port);
                {
                    let mut st = state.write().await;
                    st.auto_connect_enabled = true;
                    st.auto_connect_target = Some(addr);
                    st.role = Role::Client;
                }
                let _ = app.connect_out(addr).await;
            }
        }
    }

    let app_clone = app.clone();
    tokio::spawn(async move {
        let _ = app_clone.heartbeat_loop().await;
    });

    let app_clone = app.clone();
    tokio::spawn(async move {
        let _ = app_clone.peer_timeout_loop().await;
    });

    let app_clone = app.clone();
    tokio::spawn(async move {
        let _ = app_clone.auto_connect_loop().await;
    });

    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel();
    let _tray_handle = start_tray(ui_tx.clone());
    let _media_key_handle = start_media_key_listener(ui_tx.clone());

    let app_clone = app.clone();
    let config_clone = config.clone();
    tokio::spawn(async move {
        while let Some(cmd) = ui_rx.recv().await {
            match cmd {
                UiCommand::Toggle => {
                    let _ = app_clone.toggle_pressed("ui").await;
                }
                UiCommand::Stop => {
                    let _ = app_clone.stop_all().await;
                }
                UiCommand::Connect => {
                    let cfg = config_clone.lock().await;
                    if let Some(ip) = cfg.peer_ip {
                        let addr = SocketAddr::new(ip, cfg.peer_port);
                        drop(cfg);
                        let _ = app_clone.connect_out(addr).await;
                    } else {
                        eprintln!("[Media-Sync] No peer configured for auto-connect");
                    }
                }
                UiCommand::Disconnect => {
                    let _ = app_clone.disconnect("user").await;
                }
                UiCommand::ResumeMode(mode) => {
                    {
                        let mut cfg = config_clone.lock().await;
                        cfg.resume_mode = mode;
                        let _ = save_config(&cfg);
                    }
                    let _ = app_clone.set_resume_mode(mode).await;
                }
                UiCommand::Quit => {
                    let _ = app_clone.disconnect("user").await;
                    std::process::exit(0);
                }
            }
        }
    });

    let app_clone = app.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.eq_ignore_ascii_case("toggle") {
                let _ = app_clone.toggle_pressed("cli").await;
            } else if line.eq_ignore_ascii_case("stop") {
                let _ = app_clone.stop_all().await;
            } else if line.eq_ignore_ascii_case("quit") || line.eq_ignore_ascii_case("exit") {
                let _ = app_clone.disconnect("user").await;
                std::process::exit(0);
            }
        }
    });

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, addr) = app.socket.recv_from(&mut buf).await?;
        let msg: WireMessage = match serde_json::from_slice(&buf[..len]) {
            Ok(msg) => msg,
            Err(_) => continue,
        };
        app.handle_message(msg, addr).await?;
    }
}
