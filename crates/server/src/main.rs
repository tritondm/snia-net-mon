//! Snia-Net-Mon – Einstiegspunkt: Konfiguration laden und Collector, Speicher, Tracer und Web-Server verdrahten.
//!
//! Datenfluss:
//! ```text
//! pfSense (softflowd) ──UDP 2055──▶ collector ──batch──┬──▶ db (Writer-Thread → SQLite, Retention-Task)
//!                                                      └──▶ api::LiveHub ──WebSocket──▶ Browser
//! Browser ──REST──▶ api ──▶ db (Abfragen) / tracer ──SSH──▶ tcpdump auf der pfSense
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Config {
    server: ServerConfig,
    network: NetworkSection,
    collector: CollectorSection,
    storage: StorageSection,
    tracer: TracerSection,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    listen: SocketAddr,
    frontend_dir: PathBuf,
    api_token: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { listen: "127.0.0.1:8080".parse().expect("Adresse"), frontend_dir: "frontend/dist".into(), api_token: String::new() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkSection {
    /// Interne Netze (CIDR). Verkehr von extern nach hier = "in" (Download), von hier nach extern = "out" (Upload).
    local_networks: Vec<String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self { local_networks: model::LocalNetworks::DEFAULT.iter().map(|s| s.to_string()).collect() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CollectorSection {
    listen: SocketAddr,
    workers: usize,
    recv_buffer_mb: usize,
}

impl Default for CollectorSection {
    fn default() -> Self {
        Self { listen: "0.0.0.0:2055".parse().expect("Adresse"), workers: 2, recv_buffer_mb: 16 }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StorageSection {
    path: PathBuf,
    retention_hours: u64,
    cleanup_interval_secs: u64,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self { path: "data/flows.db".into(), retention_hours: model::MAX_RETENTION_HOURS, cleanup_interval_secs: 60 }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TracerSection {
    backend: String,
    storage_dir: PathBuf,
    max_duration_secs: u32,
    max_packets: u32,
    max_concurrent: usize,
    ssh: Option<SshSection>,
}

impl Default for TracerSection {
    fn default() -> Self {
        Self { backend: "mock".into(), storage_dir: "data/traces".into(), max_duration_secs: 300, max_packets: 100_000, max_concurrent: 2, ssh: None }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshSection {
    host: String,
    #[serde(default = "default_ssh_port")]
    port: u16,
    user: String,
    private_key: Option<PathBuf>,
    private_key_passphrase: Option<String>,
    password: Option<String>,
    host_key_sha256: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

fn load_config() -> Result<Config> {
    let mut args = std::env::args().skip(1);
    let path = match args.next().as_deref() {
        Some("-h" | "--help") => {
            println!("Aufruf: snia-net-mon [config.toml]\nOhne Angabe wird ./config.toml gelesen (falls vorhanden), sonst gelten die Standardwerte.");
            std::process::exit(0);
        }
        Some(p) => Some(PathBuf::from(p)),
        None => Some(PathBuf::from("config.toml")).filter(|p| p.exists()),
    };
    match path {
        Some(path) => {
            let text = std::fs::read_to_string(&path).with_context(|| format!("{} nicht lesbar", path.display()))?;
            let config = toml::from_str(&text).with_context(|| format!("{} ungültig", path.display()))?;
            tracing::info!(config = %path.display(), "Konfiguration geladen");
            Ok(config)
        }
        None => {
            tracing::info!("keine config.toml gefunden – Standardwerte (Demo-Modus)");
            Ok(Config::default())
        }
    }
}

fn tracer_backend(section: &TracerSection) -> Result<tracer::Backend> {
    match section.backend.as_str() {
        "mock" => Ok(tracer::Backend::Mock),
        "ssh" => {
            let ssh = section.ssh.as_ref().context("tracer.backend = \"ssh\" braucht einen Abschnitt [tracer.ssh]")?;
            Ok(tracer::Backend::Ssh(tracer::SshConfig {
                host: ssh.host.clone(),
                port: ssh.port,
                user: ssh.user.clone(),
                private_key: ssh.private_key.clone(),
                private_key_passphrase: ssh.private_key_passphrase.clone(),
                password: ssh.password.clone(),
                host_key_sha256: ssh.host_key_sha256.clone().filter(|s| s.starts_with("SHA256:") && s.len() > 10),
            }))
        }
        other => anyhow::bail!("unbekanntes tracer.backend {other:?} (erlaubt: \"mock\", \"ssh\")"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()))
        .init();
    let config = load_config()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Speicher
    let database = db::Database::open(&db::DbConfig {
        path: config.storage.path.clone(),
        retention_hours: config.storage.retention_hours,
        cleanup_interval: Duration::from_secs(config.storage.cleanup_interval_secs.clamp(10, 3600)),
    })
    .context("Datenbank konnte nicht geöffnet werden")?;
    let (db_tx, db_rx) = mpsc::channel(1024);
    let writer = database.spawn_writer(db_rx)?;
    let cleanup = database.spawn_cleanup(shutdown_rx.clone());

    // --- Collector + Live-Ansicht
    let local_networks = model::LocalNetworks::parse(&config.network.local_networks)
        .map_err(|e| anyhow::anyhow!("network.local_networks: {e}"))?;
    tracing::info!(networks = ?config.network.local_networks, "interne Netze für die Richtungserkennung");
    let metrics = Arc::new(collector::CollectorMetrics::default());
    let (live_tx, live_rx) = mpsc::channel(256);
    let live = api::LiveHub::spawn(live_rx, metrics.clone(), shutdown_rx.clone());
    let collectors = collector::spawn_collector(
        collector::CollectorConfig {
            bind: config.collector.listen,
            workers: config.collector.workers.clamp(1, 64),
            recv_buffer_bytes: config.collector.recv_buffer_mb.clamp(1, 1024) * 1024 * 1024,
            local_networks: Arc::new(local_networks),
            ..Default::default()
        },
        vec![db_tx, live_tx],
        metrics.clone(),
        shutdown_rx.clone(),
    )
    .with_context(|| format!("UDP {} konnte nicht geöffnet werden", config.collector.listen))?;

    // --- Tracer (gleiche Retention wie die Flow-Daten)
    let tracer = tracer::Tracer::new(tracer::TracerConfig {
        backend: tracer_backend(&config.tracer)?,
        storage_dir: config.tracer.storage_dir.clone(),
        max_duration_secs: config.tracer.max_duration_secs.clamp(1, 3600),
        max_packets: config.tracer.max_packets.max(1),
        max_concurrent: config.tracer.max_concurrent.max(1),
        retention_hours: config.storage.retention_hours,
    })?;
    tracing::info!(backend = tracer.backend_name(), "Tracer bereit");
    let trace_cleanup = {
        let tracer = tracer.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let t = tracer.clone();
                        if let Ok(n) = tokio::task::spawn_blocking(move || t.cleanup_expired()).await && n > 0 {
                            tracing::info!(deleted = n, "Retention: alte Traces gelöscht");
                        }
                    }
                    _ = shutdown.changed() => if *shutdown.borrow() { return },
                }
            }
        })
    };

    // --- Web-Server
    let token = config.server.api_token.trim();
    if token.is_empty() && !config.server.listen.ip().is_loopback() {
        tracing::warn!("Web-UI ist ohne api_token aus dem Netz erreichbar – bitte api_token setzen");
    }
    let state = api::AppState {
        db: database.clone(),
        tracer,
        metrics,
        live,
        api_token: (!token.is_empty()).then(|| Arc::from(token)),
        started_ms: model::now_ms(),
    };
    if !config.server.frontend_dir.join("index.html").exists() {
        tracing::warn!(dir = %config.server.frontend_dir.display(), "Frontend nicht gebaut (cd frontend && npm install && npm run build) – nur die API ist verfügbar");
    }
    let app = api::router(state, config.server.frontend_dir.clone());
    let listener = tokio::net::TcpListener::bind(config.server.listen)
        .await
        .with_context(|| format!("{} konnte nicht geöffnet werden", config.server.listen))?;
    tracing::info!("Web-UI: http://{}", config.server.listen);
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;

    // --- Geordnet herunterfahren: Collector leeren, dann den Writer den Rest schreiben lassen
    tracing::info!("wird beendet …");
    let _ = shutdown_tx.send(true);
    for handle in collectors {
        let _ = handle.await;
    }
    let _ = tokio::join!(cleanup, trace_cleanup);
    tokio::task::spawn_blocking(move || writer.join()).await?.ok();
    tracing::info!("beendet");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
