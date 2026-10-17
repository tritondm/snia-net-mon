//! Automatische Anomalie-Erkennung auf den NetFlow-Daten.
//!
//! * [`features`] – Merkmale je internem Host und Zeitfenster (Volumen, Flows, Gegenstellen, Dienste, Länder)
//! * [`baseline`] – Variante 1: EWMA-Baseline je Netzgruppe und Wochen-Slot, in festen Netzen auch je Host, Z-Score
//!   auf Log-Werten
//! * [`forest`] – Variante 2: Isolation Forest auf denselben Merkmalen als „zweite Meinung“
//! * feste Regeln: Portscan (SYN ohne ACK), DNS an externe Resolver, erstes Land einer Gruppe
//! * [`policy`] – Netz-Regeln: Zonen und eine geordnete Regelliste (z. B. „schüler → verwaltung“ melden)
//! * [`store`] – `anomaly.db`: Baselines, Trainingsvektoren (ohne IP), gemeldete Auffälligkeiten
//!
//! Der Task hängt wie der Upload-Alarm am Flow-Strom des Collectors, sammelt ein Fenster (Standard 10 min) und wertet es
//! danach in einem Blocking-Thread aus. Ergebnisse zeigt die Web-UI; Mails sind optional (`anomaly.mail`).

pub mod baseline;
mod engine;
pub mod features;
pub mod forest;
pub mod policy;
pub mod store;

pub use engine::{MlStatus, Status, WindowInfo};
pub use store::{Counts, Event, EventFilter, EventRow, Kind, Severity};

use alert::Mailer;
use engine::Engine;
use features::{FEATURES, Filters, Window};
use geo::GeoLookup;
use model::{FlowRecord, LocalNetworks, fmt_utc, now_ms};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub enum Error {
    Sqlite(rusqlite::Error),
    Join(tokio::task::JoinError),
    Config(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sqlite(e) => write!(f, "SQLite: {e}"),
            Error::Join(e) => write!(f, "Hintergrund-Task abgebrochen: {e}"),
            Error::Config(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::Join(e)
    }
}

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub db_path: PathBuf,
    pub secure_delete: bool,
    /// Länge eines Auswertungsfensters
    pub window: Duration,
    /// So lange nach dem ersten Start wird nur gelernt (Statistik, ML und neue Länder melden nichts)
    pub learning_days: u64,
    pub z_threshold: f64,
    /// Mindestwerte je Merkmal (Rohwerte pro Fenster), Reihenfolge wie [`features::NAMES`]
    pub minimums: [f64; FEATURES],
    /// Eigene Gruppen (CIDR oder einzelne IP), z. B. ein Server-Netz oder ein Server mit fester IP
    pub groups: Vec<String>,
    pub group_prefix_v4: u8,
    pub group_prefix_v6: u8,
    /// Zusätzlich ein eigenes Profil je Host (außer in `dynamic_networks`)
    pub host_profiles: bool,
    /// Netze mit wechselnden Adressen (DHCP, z. B. Schüler-WLAN): dort nur das Gruppenprofil
    pub dynamic_networks: LocalNetworks,
    /// Hosts, die nicht ausgewertet werden
    pub ignore: LocalNetworks,
    /// Erlaubte externe DNS-Resolver
    pub dns_servers: LocalNetworks,
    pub dns_rule: bool,
    /// Fehlgeschlagene Verbindungsversuche je Fenster, ab denen ein Portscan gemeldet wird; 0 = aus
    pub scan_threshold: usize,
    pub new_country: bool,
    pub ml: bool,
    pub ml_threshold: f64,
    pub ml_training_days: u64,
    pub event_retention_days: u64,
    /// IANA-Zeitzone für die Wochen-Slots; `None` = Systemzeitzone
    pub timezone: Option<String>,
    pub mail: bool,
    pub mail_min_severity: Severity,
    pub max_mails_per_hour: u32,
    /// Netz-Regeln (leer = keine)
    pub policy: policy::Policy,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        const MIB: f64 = 1024.0 * 1024.0;
        Self {
            db_path: "data/anomaly.db".into(),
            secure_delete: true,
            window: Duration::from_secs(600),
            learning_days: 7,
            z_threshold: 4.0,
            // upload, download, flows, externe Ziele, interne Ziele, Ports, Länder
            minimums: [100.0 * MIB, 1024.0 * MIB, 1000.0, 100.0, 50.0, 30.0, 10.0],
            groups: Vec::new(),
            group_prefix_v4: 24,
            group_prefix_v6: 64,
            host_profiles: true,
            dynamic_networks: LocalNetworks::none(),
            ignore: LocalNetworks::none(),
            dns_servers: LocalNetworks::none(),
            dns_rule: true,
            scan_threshold: 100,
            new_country: true,
            ml: true,
            ml_threshold: 0.65,
            ml_training_days: 14,
            event_retention_days: 30,
            timezone: None,
            mail: false,
            mail_min_severity: Severity::High,
            max_mails_per_hour: 20,
            policy: policy::Policy::default(),
        }
    }
}

/// Zugriff der API auf Auffälligkeiten und Status.
#[derive(Clone)]
pub struct Anomaly {
    engine: Arc<Mutex<Engine>>,
}

impl Anomaly {
    fn lock(engine: &Mutex<Engine>) -> std::sync::MutexGuard<'_, Engine> {
        engine.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub async fn events(&self, filter: EventFilter) -> Result<Vec<EventRow>, Error> {
        let engine = self.engine.clone();
        Ok(tokio::task::spawn_blocking(move || Self::lock(&engine).events(&filter)).await??)
    }

    pub async fn status(&self) -> Result<Status, Error> {
        let engine = self.engine.clone();
        Ok(tokio::task::spawn_blocking(move || Self::lock(&engine).status(now_ms())).await??)
    }
}

/// Erkennung als Task starten. `mailer` wird nur mit `config.mail = true` benutzt.
pub fn spawn(
    config: AnomalyConfig,
    mut rx: mpsc::Receiver<Arc<Vec<FlowRecord>>>,
    geo: Arc<GeoLookup>,
    mailer: Option<Mailer>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(Anomaly, tokio::task::JoinHandle<()>), Error> {
    let engine = Engine::open(config.clone(), now_ms())?;
    tracing::info!(
        window_min = config.window.as_secs() / 60,
        learning_days = config.learning_days,
        timezone = %engine.timezone_name(),
        ml = config.ml,
        policy_rules = config.policy.rules.len(),
        mail = config.mail && mailer.is_some(),
        "Anomalie-Erkennung aktiv"
    );
    if config.mail && mailer.is_none() {
        tracing::warn!("anomaly.mail = true, aber kein SMTP-Server in [email] – Auffälligkeiten nur in der Web-UI");
    }
    let handle = Anomaly { engine: Arc::new(Mutex::new(engine)) };
    let engine = handle.engine.clone();
    let task = tokio::spawn(async move {
        let window_ms = config.window.as_millis() as i64;
        let filters = Filters { ignore: config.ignore.clone(), dns_servers: config.dns_servers.clone(), policy: config.policy.clone() };
        let new_window = |now: i64| {
            let start = now - now.rem_euclid(window_ms);
            Window::new(start, now - start > window_ms / 10)
        };
        let mut window = new_window(now_ms());
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut sent: VecDeque<i64> = VecDeque::new();
        loop {
            tokio::select! {
                batch = rx.recv() => {
                    let Some(batch) = batch else { return };
                    for flow in batch.iter() {
                        window.add(flow, &filters, &geo);
                    }
                }
                _ = tick.tick() => {
                    let now = now_ms();
                    if now < window.start_ms + window_ms {
                        continue;
                    }
                    let done = std::mem::replace(&mut window, new_window(now));
                    let engine = engine.clone();
                    match tokio::task::spawn_blocking(move || Anomaly::lock(&engine).finish_window(done, now)).await {
                        Ok(Ok(created)) => notify(created, &config, mailer.as_ref(), &mut sent),
                        Ok(Err(err)) => tracing::error!(%err, "Anomalie-Erkennung: Fenster konnte nicht gespeichert werden"),
                        Err(err) => tracing::error!(%err, "Anomalie-Erkennung: Auswertung abgebrochen"),
                    }
                }
                _ = shutdown.changed() => if *shutdown.borrow() { return },
            }
        }
    });
    Ok((handle, task))
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Stat => "statistik",
        Kind::Ml => "ml",
        Kind::Scan => "portscan",
        Kind::Dns => "externes dns",
        Kind::Country => "neues land",
        Kind::Policy => "netz-regel",
    }
}

fn notify(events: Vec<Event>, config: &AnomalyConfig, mailer: Option<&Mailer>, sent: &mut VecDeque<i64>) {
    for e in events {
        if e.severity >= Severity::Warn {
            tracing::warn!(host = %e.host, kind = kind_label(e.kind), severity = e.severity.name(), "Auffälligkeit: {}", e.title);
        } else {
            tracing::info!(host = %e.host, kind = kind_label(e.kind), "Auffälligkeit: {}", e.title);
        }
        let Some(mailer) = mailer.filter(|_| config.mail && e.severity >= config.mail_min_severity) else { continue };
        let now = now_ms();
        while sent.front().is_some_and(|&t| now - t > 3_600_000) {
            sent.pop_front();
        }
        if sent.len() >= config.max_mails_per_hour as usize {
            tracing::warn!(limit = config.max_mails_per_hour, "Mail-Limit pro Stunde erreicht – Auffälligkeit nur in der Web-UI");
            continue;
        }
        sent.push_back(now);
        let (subject, body) = render(&e);
        let mailer = mailer.clone();
        tokio::spawn(async move {
            if let Err(err) = mailer.send(&subject, &body).await {
                tracing::error!(%err, "Auffälligkeit: Mail konnte nicht gesendet werden");
            }
        });
    }
}

/// Betreff und Text der Mail zu einer Auffälligkeit.
pub fn render(e: &Event) -> (String, String) {
    let subject = format!("[snia-net-mon] {} bei {}: {}", kind_label(e.kind), e.host, e.title);
    let body = format!(
        "Snia-Net-Mon hat eine Auffälligkeit erkannt.\n\
         \n\
         Art:      {kind} ({severity})\n\
         Host:     {host}\n\
         Gruppe:   {group}\n\
         Fenster:  bis {ts}\n\
         Befund:   {title}\n\
         \n\
         Details:\n{detail}\n\
         \n\
         Wiederholungen derselben Auffälligkeit werden nicht erneut gemeldet.\n\
         Alles Weitere in der Web-UI unter anomalien (Alt+5).\n",
        kind = kind_label(e.kind),
        severity = e.severity.name(),
        host = e.host,
        group = e.group,
        ts = fmt_utc(e.ts),
        title = e.title,
        detail = serde_json::to_string_pretty(&e.detail).unwrap_or_default(),
    );
    (subject, body)
}
