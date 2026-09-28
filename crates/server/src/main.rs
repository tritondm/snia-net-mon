//! Snia-Net-Mon – Einstiegspunkt: Konfiguration laden und Collector, Speicher und Web-Server verdrahten.
//!
//! Datenfluss:
//! ```text
//! pfSense (softflowd) ──UDP 2055──▶ collector ──batch──┬──▶ db (Writer-Thread → SQLite, Retention-Task)
//!                                                      └──▶ api::LiveHub ──WebSocket──▶ Browser
//! Browser ──REST──▶ api ──▶ db (Abfragen)
//! ```

mod geoupdate;

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
    geoip: GeoipSection,
    pcap: PcapSection,
    /// Früherer Abschnitt `[tracer]` – wird nur noch toleriert, damit alte config.toml-Dateien weiter laden.
    tracer: Option<toml::Value>,
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

/// MaxMind-GeoLite2-Datenbanken (kostenlos nach Registrierung bei maxmind.com). Fehlende Dateien = keine Geo-Daten.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GeoipSection {
    country_db: PathBuf,
    asn_db: PathBuf,
    /// Für das automatische Update (maxmind.com → Manage License Keys). Alternativ per Umgebungsvariable
    /// `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`, damit der Schlüssel nicht in der Datei stehen muss.
    account_id: String,
    license_key: String,
    /// Wie oft nach einer neuen Ausgabe gesucht wird
    update_interval_hours: u64,
}

impl Default for GeoipSection {
    fn default() -> Self {
        Self {
            country_db: "data/GeoLite2-Country.mmdb".into(),
            asn_db: "data/GeoLite2-ASN.mmdb".into(),
            account_id: String::new(),
            license_key: String::new(),
            update_interval_hours: 24,
        }
    }
}

impl GeoipSection {
    fn credentials(&self) -> Option<geoupdate::Credentials> {
        let pick = |env: &str, value: &str| {
            std::env::var(env).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| value.to_string()).trim().to_string()
        };
        let account_id = pick("MAXMIND_ACCOUNT_ID", &self.account_id);
        let license_key = pick("MAXMIND_LICENSE_KEY", &self.license_key);
        match (account_id.is_empty(), license_key.is_empty()) {
            (false, false) if !account_id.bytes().all(|b| b.is_ascii_digit()) => {
                let hint = if license_key.bytes().all(|b| b.is_ascii_digit()) { " – account_id und license_key vertauscht?" } else { "" };
                tracing::warn!("GeoIP-Update: account_id muss die Konto-Nummer (nur Ziffern) sein{hint} – automatisches Update ist aus");
                None
            }
            (false, false) => Some(geoupdate::Credentials { account_id, license_key }),
            (true, true) => None,
            _ => {
                tracing::warn!("GeoIP-Update braucht account_id UND license_key – automatisches Update ist aus");
                None
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PcapSection {
    max_upload_mb: u64,
    /// Eigene App-Regeln (JSON wie crates/pcap/apps.json); leer = mitgelieferte Regeln
    app_rules: Option<PathBuf>,
    /// Ablage für Uploads während der Analyse
    upload_dir: PathBuf,
}

impl Default for PcapSection {
    fn default() -> Self {
        Self { max_upload_mb: 512, app_rules: None, upload_dir: "data/uploads".into() }
    }
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()))
        .init();
    let config = load_config()?;
    if config.tracer.is_some() {
        tracing::warn!("Abschnitt [tracer] in der Konfiguration wird ignoriert (Tracing wurde entfernt)");
    }
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
    let geo = Arc::new(geo::GeoLookup::open(Some(&config.geoip.country_db), Some(&config.geoip.asn_db)));
    let geo_credentials = config.geoip.credentials();
    if !geo.enabled() && geo_credentials.is_none() {
        tracing::warn!("keine GeoIP-Datenbanken gefunden – Länder/ASN bleiben leer (siehe [geoip] in config.example.toml)");
    }
    let geo_updater = geoupdate::spawn(
        geo.clone(),
        geoupdate::UpdaterConfig {
            credentials: geo_credentials,
            interval: Duration::from_secs(config.geoip.update_interval_hours.clamp(1, 24 * 30) * 3600),
        },
        shutdown_rx.clone(),
    );
    let (live_tx, live_rx) = mpsc::channel(256);
    let live = api::LiveHub::spawn(live_rx, metrics.clone(), geo.clone(), shutdown_rx.clone());
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

    // --- Web-Server
    let token = config.server.api_token.trim();
    if token.is_empty() && !config.server.listen.ip().is_loopback() {
        tracing::warn!("Web-UI ist ohne api_token aus dem Netz erreichbar – bitte api_token setzen");
    }
    let state = api::AppState {
        db: database.clone(),
        metrics,
        live,
        api_token: (!token.is_empty()).then(|| Arc::from(token)),
        started_ms: model::now_ms(),
        geo,
        pcap: api::PcapSettings {
            upload_dir: config.pcap.upload_dir.clone(),
            max_upload_bytes: config.pcap.max_upload_mb.clamp(1, 16 * 1024) * 1024 * 1024,
            apps: Arc::new(match &config.pcap.app_rules {
                Some(path) => pcap::AppRules::load(path),
                None => pcap::AppRules::builtin(),
            }),
        },
    };
    // Reste abgebrochener Uploads (z. B. nach einem Absturz) entfernen
    if let Ok(entries) = std::fs::read_dir(&config.pcap.upload_dir) {
        for entry in entries.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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
    let _ = cleanup.await;
    geo_updater.abort();
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
