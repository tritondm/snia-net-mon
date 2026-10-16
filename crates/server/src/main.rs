//! Snia-Net-Mon – Einstiegspunkt: Konfiguration laden und Collector, Speicher und Web-Server verdrahten.
//!
//! Datenfluss:
//! ```text
//! pfSense (softflowd) ──UDP 2055──▶ collector ──batch──┬──▶ db (Writer-Thread → SQLite, Retention-Task)
//!   (ausgenommene Netze werden hier verworfen)         │      └─ nach 48 h ──▶ Historie ──ab 50 GB──▶ zstd-Archiv
//!                                                      ├──▶ api::LiveHub ──WebSocket──▶ Browser
//!                                                      └──▶ alert (Upload > Schwelle je Verbindung) ──SMTP──▶ Admins
//! Browser ──REST──▶ api ──▶ db (Abfragen auf Live, Historie oder entpacktem Archiv)
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
    history: HistorySection,
    alerts: AlertsSection,
    email: EmailSection,
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
    /// Ausgenommene Netze (CIDR): Flows mit Quelle ODER Ziel darin werden weder gespeichert noch angezeigt.
    exclude_networks: Vec<String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self { local_networks: model::LocalNetworks::DEFAULT.iter().map(|s| s.to_string()).collect(), exclude_networks: Vec::new() }
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
    /// Verzeichnis der Live-Daten (`index.db` und eine Datei pro Stunde)
    dir: PathBuf,
    retention_hours: u64,
    cleanup_interval_secs: u64,
    /// Gelöschte Flows in der Datei überschreiben (gilt auch für die Historie)
    secure_delete: bool,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self { dir: "data/live".into(), retention_hours: 48, cleanup_interval_secs: 60, secure_delete: true }
    }
}

/// Historie: Flows nach dem Live-Fenster, bis `max_size_gb`; danach Rotation in ein zstd-Archiv.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HistorySection {
    /// `false` = Flows nach dem Live-Fenster löschen (Verhalten ohne Historie)
    enabled: bool,
    dir: PathBuf,
    max_size_gb: f64,
    archive_dir: PathBuf,
    archive_retention_days: u64,
    compression_level: i32,
}

impl Default for HistorySection {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: "data/history".into(),
            max_size_gb: 50.0,
            archive_dir: "data/archive".into(),
            archive_retention_days: 90,
            compression_level: 19,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AlertsSection {
    /// Upload-Alarm ab so vielen MiB in einer Verbindung; 0 = aus
    upload_threshold_mb: u64,
    /// Ohne neue Flows so lange gilt eine Verbindung als beendet
    session_idle_secs: u64,
    max_mails_per_hour: u32,
}

impl Default for AlertsSection {
    fn default() -> Self {
        Self { upload_threshold_mb: 1024, session_idle_secs: 600, max_mails_per_hour: 20 }
    }
}

/// SMTP-Zugang für Mails an die Admins. Leerer `smtp_host` = kein Mailversand.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EmailSection {
    smtp_host: String,
    smtp_port: u16,
    /// `starttls` (Port 587), `tls` (Port 465) oder `none` (nur Relay im eigenen Netz)
    security: String,
    username: String,
    /// Alternativ per Umgebungsvariable `SNIA_SMTP_PASSWORD`
    password: String,
    from: String,
    admins: Vec<String>,
    timeout_secs: u64,
}

impl Default for EmailSection {
    fn default() -> Self {
        Self {
            smtp_host: String::new(),
            smtp_port: 587,
            security: "starttls".into(),
            username: String::new(),
            password: String::new(),
            from: String::new(),
            admins: Vec::new(),
            timeout_secs: 30,
        }
    }
}

impl EmailSection {
    /// Mailer aus der Konfiguration; `Ok(None)`, wenn kein SMTP-Server eingetragen ist.
    fn mailer(&self) -> Result<Option<alert::Mailer>> {
        if self.smtp_host.trim().is_empty() {
            return Ok(None);
        }
        let security = alert::Security::parse(&self.security)
            .ok_or_else(|| anyhow::anyhow!("email.security: erlaubt sind starttls, tls, none – nicht {:?}", self.security))?;
        let password = std::env::var("SNIA_SMTP_PASSWORD").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| self.password.clone());
        let mailer = alert::Mailer::new(&alert::MailConfig {
            host: self.smtp_host.clone(),
            port: self.smtp_port,
            security,
            username: self.username.clone(),
            password,
            from: self.from.clone(),
            to: self.admins.clone(),
            timeout: Duration::from_secs(self.timeout_secs.clamp(5, 300)),
        })
        .map_err(|e| anyhow::anyhow!("email: {e}"))?;
        Ok(Some(mailer))
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

/// Kommandozeile: `[--test-mail] [config.toml]`
struct Args {
    config: Option<PathBuf>,
    test_mail: bool,
}

fn parse_args() -> Args {
    let mut args = Args { config: None, test_mail: false };
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!(
                    "Aufruf: snia-net-mon [--test-mail] [config.toml]\n\
                     Ohne Angabe wird ./config.toml gelesen (falls vorhanden), sonst gelten die Standardwerte.\n\
                     --test-mail  schickt eine Test-Mail an die Admins aus [email] und beendet sich"
                );
                std::process::exit(0);
            }
            "--test-mail" => args.test_mail = true,
            path => args.config = Some(PathBuf::from(path)),
        }
    }
    args
}

fn load_config(path: Option<PathBuf>) -> Result<Config> {
    let path = path.or_else(|| Some(PathBuf::from("config.toml")).filter(|p| p.exists()));
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
    let args = parse_args();
    let config = load_config(args.config)?;
    if args.test_mail {
        let mailer = config.email.mailer()?.context("email.smtp_host ist leer – kein Mailversand konfiguriert")?;
        mailer
            .send("[snia-net-mon] Test-Mail", "Diese Test-Mail bestätigt, dass der Mailversand von Snia-Net-Mon funktioniert.\n")
            .await
            .map_err(|e| anyhow::anyhow!("Test-Mail fehlgeschlagen: {e}"))?;
        println!("Test-Mail gesendet an {}", mailer.recipients());
        return Ok(());
    }
    if config.tracer.is_some() {
        tracing::warn!("Abschnitt [tracer] in der Konfiguration wird ignoriert (Tracing wurde entfernt)");
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Speicher
    let database = db::Database::open(&db::DbConfig {
        dir: config.storage.dir.clone(),
        retention_hours: config.storage.retention_hours,
        cleanup_interval: Duration::from_secs(config.storage.cleanup_interval_secs.clamp(10, 3600)),
        secure_delete: config.storage.secure_delete,
    })
    .context("Datenbank konnte nicht geöffnet werden")?;
    let history = if config.history.enabled {
        let h = &config.history;
        let history = db::History::open(db::HistoryConfig {
            dir: h.dir.clone(),
            max_bytes: (h.max_size_gb.max(0.01) * 1024.0 * 1024.0 * 1024.0) as u64,
            archive_dir: h.archive_dir.clone(),
            archive_retention: Duration::from_secs(h.archive_retention_days.clamp(1, 3650) * 86_400),
            compression_level: h.compression_level.clamp(1, 22),
            secure_delete: config.storage.secure_delete,
        })
        .context("Historie konnte nicht geöffnet werden")?;
        tracing::info!(
            live_hours = config.storage.retention_hours.min(model::MAX_RETENTION_HOURS),
            max_gb = h.max_size_gb,
            archive_days = h.archive_retention_days,
            "Historie aktiv: live → Historie → Archiv"
        );
        Some(history)
    } else {
        tracing::info!("Historie abgeschaltet – Flows werden nach dem Live-Fenster gelöscht");
        None
    };
    let (db_tx, db_rx) = mpsc::channel(1024);
    let writer = database.spawn_writer(db_rx)?;
    let cleanup = database.spawn_cleanup(history.clone(), shutdown_rx.clone());

    // --- Collector + Live-Ansicht
    let local_networks = model::LocalNetworks::parse(&config.network.local_networks)
        .map_err(|e| anyhow::anyhow!("network.local_networks: {e}"))?;
    tracing::info!(networks = ?config.network.local_networks, "interne Netze für die Richtungserkennung");
    let exclude_networks = model::LocalNetworks::parse(&config.network.exclude_networks)
        .map_err(|e| anyhow::anyhow!("network.exclude_networks: {e}"))?;
    if !exclude_networks.is_empty() {
        tracing::info!(networks = ?config.network.exclude_networks, "ausgenommene Netze – deren Verkehr wird verworfen");
    }
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
    let mut sinks = vec![db_tx, live_tx];

    // --- Upload-Alarm
    let mailer = config.email.mailer()?;
    let alerts = &config.alerts;
    let upload_watch = if alerts.upload_threshold_mb > 0 {
        match &mailer {
            Some(m) => tracing::info!(threshold_mb = alerts.upload_threshold_mb, to = %m.recipients(), "Upload-Alarm aktiv"),
            None => tracing::warn!(threshold_mb = alerts.upload_threshold_mb, "Upload-Alarm ohne Mailversand ([email] smtp_host leer) – nur im Log"),
        }
        let (alert_tx, alert_rx) = mpsc::channel(256);
        sinks.push(alert_tx);
        Some(alert::spawn_upload_watch(
            alert::UploadAlertConfig {
                threshold_bytes: alerts.upload_threshold_mb * 1024 * 1024,
                session_idle: Duration::from_secs(alerts.session_idle_secs.clamp(60, 86_400)),
                max_mails_per_hour: alerts.max_mails_per_hour.max(1),
            },
            alert_rx,
            geo.clone(),
            mailer,
            shutdown_rx.clone(),
        ))
    } else {
        None
    };
    let collectors = collector::spawn_collector(
        collector::CollectorConfig {
            bind: config.collector.listen,
            workers: config.collector.workers.clamp(1, 64),
            recv_buffer_bytes: config.collector.recv_buffer_mb.clamp(1, 1024) * 1024 * 1024,
            local_networks: Arc::new(local_networks),
            exclude_networks: Arc::new(exclude_networks),
            ..Default::default()
        },
        sinks,
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
        history,
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
    if let Some(watch) = upload_watch {
        let _ = watch.await;
    }
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
