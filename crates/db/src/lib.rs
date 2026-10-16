//! Flow-Speicher auf Basis von SQLite (WAL-Modus), aufgeteilt in eine Datei pro Stunde.
//!
//! * **Aufbau:** Ein Speicher ist ein Verzeichnis mit `index.db` (Aggregate, PCAP-Analysen) und je Stunde einer Datei
//!   mit den Einzel-Flows (siehe [`store`]).
//! * **Ingestion:** ein eigener Writer-Thread nimmt Flow-Batches aus einem Kanal und schreibt sie in großen Transaktionen
//!   mit vorbereitetem Statement in die Stundendatei(en) und die Aggregate. Staut sich etwas an, fasst er alle wartenden
//!   Batches zu einer Transaktion zusammen (natürliches Batching: je höher die Last, desto größer die Transaktionen).
//! * **Retention:** die Live-Datenbank hält höchstens 72 Stunden ([`model::MAX_RETENTION_HOURS`]), Standard 48. Ein
//!   Hintergrund-Task verschiebt jede Stundendatei, die ganz vor dem Fenster liegt, in die [`History`] – oder löscht sie,
//!   wenn die Historie abgeschaltet ist. Das kostet unabhängig von der Datenmenge fast nichts und sperrt den Writer nicht.
//!   Nur die kleinen Aggregat- und PCAP-Tabellen in `index.db` werden zeilenweise gelöscht. Abfragen liefern trotzdem
//!   minutengenau nichts, was älter als das Retention-Fenster ist.
//! * **Historie und Archiv:** siehe [`history`].
//! * **Voraggregation:** Summen je Minute und Stunde (siehe [`rollup`]) machen die Dashboard-Statistiken unabhängig von
//!   der Zahl der Flows schnell; nur die Ränder eines Zeitfensters kommen aus den Stundendateien.

pub mod history;
mod pcap;
mod query;
mod rollup;
mod schema;
mod store;

pub use history::{ArchiveInfo, History, HistoryConfig, HistoryStatus};
pub use pcap::PcapSummary;

pub use query::{
    ConnectionStat, DirectionStat, FlowFilter, FlowRow, PeerStat, PortStat, ProtocolStat, SankeyGraph, SankeyLink, SankeyNode, TalkerStat, TimePoint,
};

use model::{FlowRecord, MAX_RETENTION_HOURS, ip_to_bytes, now_ms};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

use rollup::{HOUR_MS, MINUTE_MS};
use store::hour_of;

/// Zeilen pro Lösch-Transaktion beim Kürzen einer Stundendatei auf die harte 72-h-Grenze
const DELETE_CHUNK: usize = 5_000;
/// So oft versucht der Writer eine gesperrte Datenbank erneut (jeweils mit 10 s Busy-Timeout), bevor er verwirft.
const WRITE_ATTEMPTS: u32 = 6;
/// Abstand des Writers zur Retention-Grenze: In Stunden, die in den nächsten Minuten verschoben werden könnten, schreibt
/// er nicht mehr (solche Flows liegen ohnehin außerhalb des Fensters).
const WRITE_MARGIN_MS: i64 = 10 * MINUTE_MS;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Hintergrund-Task abgebrochen")]
    Join(#[from] tokio::task::JoinError),
    #[error("ungültiger Filter: {0}")]
    InvalidFilter(String),
    #[error("E/A: {0}")]
    Io(#[from] std::io::Error),
    /// Datenquelle gerade nicht abfragbar (Archiv wird entpackt, Historie wird rotiert …)
    #[error("{0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Verzeichnis der Live-Daten (`index.db` und Stundendateien)
    pub dir: PathBuf,
    /// Aufbewahrung in Stunden; wird auf höchstens [`MAX_RETENTION_HOURS`] begrenzt.
    pub retention_hours: u64,
    pub cleanup_interval: Duration,
    /// Gelöschte Inhalte überschreiben: in `index.db` per `PRAGMA secure_delete` samt Bereinigung von WAL und freien
    /// Seiten, gelöschte Stundendateien vor dem Entfernen mit Nullen.
    pub secure_delete: bool,
}

#[derive(Debug, Default)]
struct Counters {
    inserted: AtomicU64,
    deleted: AtomicU64,
    rows: AtomicI64,
    late: AtomicU64,
    last_cleanup_ms: AtomicI64,
    write_batches: AtomicU64,
    last_write_micros: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DbStats {
    pub rows: i64,
    pub inserted: u64,
    pub deleted: u64,
    /// Flows, deren Zeitstempel schon vor dem Retention-Fenster lag – nicht gespeichert
    pub late_flows: u64,
    pub oldest_ts_ms: Option<i64>,
    pub retention_hours: u64,
    pub last_cleanup_ms: i64,
    pub file_bytes: u64,
    pub write_batches: u64,
    pub last_write_micros: u64,
}

/// Handle auf den Speicher. Günstig zu klonen.
#[derive(Clone)]
pub struct Database {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    /// Entpacktes Archiv: Verzeichnis mit den gepackten Stundendateien, die bei Bedarf nach `dir` entpackt werden
    packed: Option<PathBuf>,
    /// `None` = unbegrenzt (Historie, geöffnetes Archiv): keine Retention, Abfragen ohne Untergrenze
    retention: Option<(i64, u64)>,
    /// Grenze der letzten Verschiebung in die Historie (Unix-ms, 0 = noch keine). Alles davor liegt in der Historie.
    moved_until: AtomicI64,
    cleanup_interval: Duration,
    secure_delete: bool,
    /// Verbindungen auf `index.db`
    readers: Mutex<Vec<Connection>>,
    /// Lesende Abfragen halten die Lese-Sperre, solange sie Stundendateien angehängt haben; Verschieben und Löschen von
    /// Stundendateien nehmen die Schreib-Sperre. So verschwindet keine Datei unter einer laufenden Abfrage.
    files: RwLock<()>,
    /// Entpacken aus dem Archiv – eine Datei nach der anderen
    unpack: Mutex<()>,
    counters: Counters,
    /// Aggregate für Statistiken nutzen (in Tests abschaltbar, um gegen die Rohdaten zu vergleichen)
    rollups: AtomicBool,
    /// Flows vor dem Retention-Fenster verwerfen (in Tests abschaltbar, um alte Stunden anzulegen)
    reject_late: AtomicBool,
}

impl Database {
    pub fn open(config: &DbConfig) -> Result<Self> {
        let retention_hours = config.retention_hours.clamp(1, MAX_RETENTION_HOURS);
        if retention_hours != config.retention_hours {
            tracing::warn!(requested = config.retention_hours, used = retention_hours, "Retention auf 1–72 Stunden begrenzt");
        }
        let db = Self::create(&config.dir, None, Some((retention_hours as i64 * HOUR_MS, retention_hours)), config.cleanup_interval, config.secure_delete)?;
        // Zeilenzahl aus den höchsten IDs der Stundendateien: ein Indexzugriff pro Datei statt eines Scans
        let mut rows = 0;
        for (_, path) in store::list_hours(&config.dir, "")? {
            rows += store::count_flows(&path)?;
        }
        db.inner.counters.rows.store(rows, Relaxed);
        Ok(db)
    }

    /// Unbegrenzten Speicher öffnen (Historie): gleiches Schema, keine Retention, kein Zeilenzähler.
    pub fn open_store(dir: &Path, secure_delete: bool) -> Result<Self> {
        Self::create(dir, None, None, Duration::from_secs(60), secure_delete)
    }

    /// Entpacktes Archiv öffnen: `index.db` liegt in `dir`, die Stundendateien werden bei Bedarf aus `packed` entpackt.
    pub(crate) fn open_view(dir: &Path, packed: &Path) -> Result<Self> {
        Self::create(dir, Some(packed.to_path_buf()), None, Duration::from_secs(60), false)
    }

    fn create(dir: &Path, packed: Option<PathBuf>, retention: Option<(i64, u64)>, cleanup_interval: Duration, secure_delete: bool) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let conn = schema::open_connection(&dir.join(store::INDEX), secure_delete)?;
        schema::create_index(&conn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir: dir.to_path_buf(),
                packed,
                retention,
                moved_until: AtomicI64::new(0),
                cleanup_interval,
                secure_delete,
                readers: Mutex::new(Vec::new()),
                files: RwLock::new(()),
                unpack: Mutex::new(()),
                counters: Counters::default(),
                rollups: AtomicBool::new(true),
                reject_late: AtomicBool::new(true),
            }),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }

    pub(crate) fn index_path(&self) -> PathBuf {
        self.inner.dir.join(store::INDEX)
    }

    /// Neue Verbindung auf `index.db` mit den Pragmas dieses Speichers.
    pub(crate) fn connect(&self) -> rusqlite::Result<Connection> {
        schema::open_connection(&self.index_path(), self.inner.secure_delete)
    }

    pub fn retention_ms(&self) -> i64 {
        self.inner.retention.map_or(i64::MAX, |(ms, _)| ms)
    }

    /// Nominelle Grenze des Retention-Fensters: jetzt minus Aufbewahrung.
    fn nominal_floor_ms(&self) -> i64 {
        match self.inner.retention {
            Some((ms, _)) => now_ms() - ms,
            None => i64::MIN,
        }
    }

    /// Frühester Zeitpunkt, den Abfragen liefern dürfen. Mit Historie ist das die Grenze der letzten Verschiebung –
    /// so entsteht zwischen zwei Cleanup-Läufen keine Lücke zwischen Live-Daten und Historie.
    pub fn retention_floor_ms(&self) -> i64 {
        let floor = self.nominal_floor_ms();
        match self.inner.moved_until.load(Relaxed) {
            0 => floor,
            moved => floor.min(moved),
        }
    }

    /// Stunden mit Flow-Dateien, die `[lo, hi)` berühren, aufsteigend.
    pub(crate) fn hours(&self, lo: i64, hi: i64) -> Result<Vec<i64>> {
        let (dir, suffix) = match &self.inner.packed {
            Some(packed) => (packed.as_path(), store::PACKED_EXT),
            None => (self.inner.dir.as_path(), ""),
        };
        Ok(store::list_hours(dir, suffix)?.into_iter().map(|(hour, _)| hour).filter(|&h| h < hi && h + HOUR_MS > lo).collect())
    }

    /// Pfad der Stundendatei; in einem Archiv wird sie beim ersten Zugriff entpackt.
    pub(crate) fn hour_path(&self, hour: i64) -> Result<PathBuf> {
        let path = self.inner.dir.join(store::hour_name(hour));
        if let Some(packed) = &self.inner.packed {
            let _lock = self.inner.unpack.lock().expect("Entpack-Mutex");
            if !path.exists() {
                history::decompress(&packed.join(format!("{}{}", store::hour_name(hour), store::PACKED_EXT)), &path)?;
            }
        }
        Ok(path)
    }

    // -------------------------------------------------------------------------------------------------- Schreiben

    /// Writer-Thread starten. Er läuft, bis alle Sender des Kanals geschlossen sind, und schreibt dann den Rest weg.
    pub fn spawn_writer(&self, mut rx: mpsc::Receiver<Arc<Vec<FlowRecord>>>) -> Result<std::thread::JoinHandle<()>> {
        let mut conn = self.connect()?;
        let db = self.clone();
        let handle = std::thread::Builder::new().name("db-writer".into()).spawn(move || {
            let mut attached = BTreeSet::new();
            let mut pending: Vec<Arc<Vec<FlowRecord>>> = Vec::new();
            while let Some(first) = rx.blocking_recv() {
                pending.push(first);
                // Alles mitnehmen, was inzwischen wartet (bis ~50k Zeilen pro Transaktion)
                let mut rows: usize = pending[0].len();
                while rows < 50_000 {
                    match rx.try_recv() {
                        Ok(batch) => {
                            rows += batch.len();
                            pending.push(batch);
                        }
                        Err(_) => break,
                    }
                }
                let started = Instant::now();
                let mut result = db.insert_batches(&mut conn, &mut attached, &pending);
                for attempt in 2..=WRITE_ATTEMPTS {
                    if !result.as_ref().is_err_and(is_busy) {
                        break;
                    }
                    tracing::warn!(attempt, rows, "Datenbank gesperrt – Flows werden erneut geschrieben");
                    result = db.insert_batches(&mut conn, &mut attached, &pending);
                }
                match result {
                    Ok(n) => {
                        let c = &db.inner.counters;
                        c.inserted.fetch_add(n as u64, Relaxed);
                        c.rows.fetch_add(n as i64, Relaxed);
                        c.write_batches.fetch_add(1, Relaxed);
                        c.last_write_micros.store(started.elapsed().as_micros() as u64, Relaxed);
                    }
                    Err(err) => tracing::error!(%err, rows, "Flows konnten nicht gespeichert werden"),
                }
                pending.clear();
            }
            tracing::debug!("DB-Writer beendet");
        })?;
        Ok(handle)
    }

    /// Batches in die Stundendateien (je Stunde ein angehängtes Schema) und die Aggregate schreiben – eine Transaktion.
    fn insert_batches(&self, conn: &mut Connection, attached: &mut BTreeSet<i64>, batches: &[Arc<Vec<FlowRecord>>]) -> Result<usize> {
        // Stunden, die gleich verschoben oder gelöscht werden könnten, nicht mehr anfassen
        let first_hour = match self.inner.retention {
            Some((ms, _)) if self.inner.reject_late.load(Relaxed) => hour_of(now_ms() - ms + WRITE_MARGIN_MS),
            _ => i64::MIN,
        };
        let mut by_hour: BTreeMap<i64, Vec<&FlowRecord>> = BTreeMap::new();
        let mut late = 0u64;
        for flow in batches.iter().flat_map(|b| b.iter()) {
            match hour_of(flow.ts_ms) {
                hour if hour < first_hour => late += 1,
                hour => by_hour.entry(hour).or_default().push(flow),
            }
        }
        // Anhängen geht nur außerhalb einer Transaktion
        for &hour in by_hour.keys() {
            if !attached.contains(&hour) {
                let name = writer_schema(hour);
                conn.execute(&format!("ATTACH DATABASE ?1 AS {name}"), [self.inner.dir.join(store::hour_name(hour)).to_string_lossy()])?;
                attached.insert(hour);
                conn.query_row(&format!("PRAGMA {name}.journal_mode = WAL"), [], |_| Ok(()))?;
                schema::create_flows(conn, &name)?;
            }
        }
        let tx = conn.transaction()?;
        let mut count = 0;
        let mut sums = rollup::Rollup::default();
        for (&hour, flows) in &by_hour {
            let mut stmt = tx.prepare_cached(&format!(
                "INSERT INTO {}.flows (ts, start_ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags, in_if, out_if, exporter, dir)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                writer_schema(hour)
            ))?;
            for flow in flows {
                stmt.execute(params![
                    flow.ts_ms,
                    flow.start_ms,
                    &ip_to_bytes(flow.src_ip)[..],
                    &ip_to_bytes(flow.dst_ip)[..],
                    flow.src_port,
                    flow.dst_port,
                    flow.proto,
                    // SQLite-Integer sind vorzeichenbehaftet: extrem große Zähler kappen statt überlaufen
                    flow.bytes.min(i64::MAX as u64) as i64,
                    flow.packets.min(i64::MAX as u64) as i64,
                    flow.tcp_flags,
                    flow.in_if,
                    flow.out_if,
                    &ip_to_bytes(flow.exporter)[..],
                    flow.direction.as_u8(),
                ])?;
                sums.add(flow);
                count += 1;
            }
        }
        sums.write(&tx)?;
        tx.commit()?;
        // Nur die neueste Stunde angehängt lassen: ältere Dateien müssen verschoben werden können
        let newest = attached.last().copied();
        while let Some(&hour) = attached.first().filter(|&&h| Some(h) != newest) {
            conn.execute_batch(&format!("DETACH DATABASE {}", writer_schema(hour)))?;
            attached.remove(&hour);
        }
        if late > 0 {
            self.inner.counters.late.fetch_add(late, Relaxed);
            tracing::debug!(late, "Flows vor dem Retention-Fenster verworfen");
        }
        Ok(count)
    }

    #[cfg(test)]
    pub(crate) fn accept_late_flows(&self) {
        self.inner.reject_late.store(false, Relaxed);
    }

    // -------------------------------------------------------------------------------------------------- Retention

    /// Hintergrund-Task für die Retention: sofort beim Start und danach im Intervall. Mit `history` werden abgelaufene
    /// Stunden in die Historie verschoben und danach Rotation und Archiv-Aufräumen erledigt.
    pub fn spawn_cleanup(&self, history: Option<History>, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let db = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(db.inner.cleanup_interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let result = match &history {
                            Some(history) => db.move_to_history(history).await,
                            None => db.cleanup_now().await,
                        };
                        match result {
                            Ok(0) => {}
                            Ok(n) if history.is_some() => tracing::info!(moved = n, "Retention: alte Flows in die Historie verschoben"),
                            Ok(n) => tracing::info!(deleted = n, "Retention: alte Flows gelöscht"),
                            Err(err) => tracing::error!(%err, "Retention-Cleanup fehlgeschlagen"),
                        }
                        if let Some(history) = &history {
                            history.maintain().await;
                        }
                    }
                    _ = shutdown.changed() => if *shutdown.borrow() { return },
                }
            }
        })
    }

    /// Alle Stunden, die ganz vor dem Retention-Fenster liegen, in die Historie verschieben. Scheitert das, gilt weiter die
    /// harte Obergrenze von 72 h: Älteres wird trotzdem gelöscht.
    pub async fn move_to_history(&self, history: &History) -> Result<usize> {
        self.move_before(history, hour_of(self.nominal_floor_ms())).await
    }

    /// Stunden vor `cutoff` (Stundenbeginn) samt Aggregaten in die Historie verschieben.
    pub(crate) async fn move_before(&self, history: &History, cutoff: i64) -> Result<usize> {
        let (db, h) = (self.clone(), history.clone());
        match tokio::task::spawn_blocking(move || h.absorb(&db, cutoff)).await? {
            Ok(moved) => {
                self.inner.moved_until.store(cutoff, Relaxed);
                let (db, pcap_cutoff) = (self.clone(), self.nominal_floor_ms());
                tokio::task::spawn_blocking(move || db.remove_old(cutoff, None, pcap_cutoff)).await??;
                let c = &self.inner.counters;
                c.deleted.fetch_add(moved as u64, Relaxed);
                c.rows.fetch_sub(moved as i64, Relaxed);
                Ok(moved)
            }
            Err(err) => {
                tracing::error!(%err, "Verschieben in die Historie fehlgeschlagen – Flows älter als 72 h werden gelöscht");
                self.cleanup_before(now_ms() - MAX_RETENTION_HOURS as i64 * HOUR_MS).await?;
                Err(err)
            }
        }
    }

    /// Ohne Historie: alle Stunden löschen, die ganz vor dem Retention-Fenster liegen, und die harte 72-h-Grenze auch
    /// innerhalb einer Stunde durchsetzen. Rückgabe: Anzahl gelöschter Flows.
    pub async fn cleanup_now(&self) -> Result<usize> {
        let (db, floor) = (self.clone(), self.retention_floor_ms());
        let hard = now_ms() - MAX_RETENTION_HOURS as i64 * HOUR_MS;
        tokio::task::spawn_blocking(move || db.remove_old(floor, Some(hard), floor)).await?
    }

    /// Alle Flows mit `ts < cutoff_ms` unwiderruflich löschen (die Stunde, in die `cutoff_ms` fällt, zeilenweise).
    pub async fn cleanup_before(&self, cutoff_ms: i64) -> Result<usize> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.remove_old(cutoff_ms, Some(cutoff_ms), cutoff_ms)).await?
    }

    /// Stundendateien, die ganz vor `cutoff` liegen, löschen; mit `trim` zusätzlich die Flows davor aus der Stunde, in
    /// die `trim` fällt. Aggregate vor `cutoff` bzw. `trim` und PCAP-Analysen vor `pcap_cutoff` werden gelöscht.
    fn remove_old(&self, cutoff: i64, trim: Option<i64>, pcap_cutoff: i64) -> Result<usize> {
        let secure = self.inner.secure_delete;
        let mut total = 0usize;
        {
            let _files = self.inner.files.write().expect("Datei-Sperre");
            for (hour, path) in store::list_hours(&self.inner.dir, "")? {
                if hour + HOUR_MS <= cutoff {
                    total += store::count_flows(&path)? as usize;
                    store::remove_file(&path, secure)?;
                }
            }
        }
        let conn = self.connect()?;
        if let Some(trim) = trim {
            let path = self.inner.dir.join(store::hour_name(hour_of(trim)));
            if path.exists() {
                let _f = store::attach(&conn, &path, "f")?;
                loop {
                    let deleted = conn.execute(
                        "DELETE FROM f.flows WHERE id IN (SELECT id FROM f.flows WHERE ts < ?1 ORDER BY ts LIMIT ?2)",
                        params![trim, DELETE_CHUNK as i64],
                    )?;
                    total += deleted;
                    if deleted < DELETE_CHUNK {
                        break;
                    }
                }
            }
        }
        // Aggregate: ganze Minuten/Stunden, sobald sie teilweise vor der Grenze liegen (nie länger als die Rohdaten)
        let agg_cutoff = trim.map_or(cutoff, |t| t.max(cutoff));
        let mut changed = 0;
        for table in rollup::tables() {
            changed += conn.execute(&format!("DELETE FROM {table} WHERE t < ?1"), params![agg_cutoff])?;
        }
        // Gespeicherte PCAP-Analysen unterliegen derselben Frist
        let pcaps = conn.execute("DELETE FROM pcap_analyses WHERE created_ms < ?1", params![pcap_cutoff])?;
        if pcaps > 0 {
            tracing::info!(deleted = pcaps, "Retention: alte PCAP-Analysen gelöscht");
        }
        if changed + pcaps > 0 {
            if secure {
                // Freie Seiten zurückgeben und gelöschte Inhalte auch aus dem WAL entfernen
                conn.execute_batch("PRAGMA incremental_vacuum;")?;
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            } else {
                // Freie Seiten nutzt der Writer wieder; nur zurückgeben, wenn auffällig viele brachliegen
                let (pages, free): (i64, i64) =
                    conn.query_row("SELECT * FROM pragma_page_count(), pragma_freelist_count()", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
                if free > pages / 4 {
                    conn.execute_batch("PRAGMA incremental_vacuum;")?;
                }
            }
        }
        let c = &self.inner.counters;
        if trim.is_some() {
            // Beim Verschieben zählt move_before selbst
            c.deleted.fetch_add(total as u64, Relaxed);
            c.rows.fetch_sub(total as i64, Relaxed);
        }
        c.last_cleanup_ms.store(now_ms(), Relaxed);
        Ok(total)
    }

    // -------------------------------------------------------------------------------------------------- Status

    pub async fn stats(&self) -> Result<DbStats> {
        let (oldest, _) = self.time_range().await?;
        let c = &self.inner.counters;
        Ok(DbStats {
            rows: c.rows.load(Relaxed).max(0),
            inserted: c.inserted.load(Relaxed),
            deleted: c.deleted.load(Relaxed),
            late_flows: c.late.load(Relaxed),
            oldest_ts_ms: oldest,
            retention_hours: self.inner.retention.map_or(0, |(_, hours)| hours),
            last_cleanup_ms: c.last_cleanup_ms.load(Relaxed),
            file_bytes: store::dir_size(&self.inner.dir),
            write_batches: c.write_batches.load(Relaxed),
            last_write_micros: c.last_write_micros.load(Relaxed),
        })
    }

    /// Ältester und jüngster gespeicherter Flow (aus der ersten und letzten Stundendatei).
    pub async fn time_range(&self) -> Result<(Option<i64>, Option<i64>)> {
        self.with_reader(|_, db| {
            let hours = db.hours(i64::MIN, i64::MAX)?;
            let (Some(&first), Some(&last)) = (hours.first(), hours.last()) else { return Ok((None, None)) };
            Ok((store::ts_bound(&db.hour_path(first)?, false)?, store::ts_bound(&db.hour_path(last)?, true)?))
        })
        .await
    }

    /// Lese-Abfrage auf einer gepoolten Verbindung (auf `index.db`) in einem Blocking-Thread ausführen. Solange sie läuft,
    /// werden keine Stundendateien verschoben oder gelöscht.
    pub(crate) async fn with_reader<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Database) -> Result<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = match db.inner.readers.lock().expect("Pool-Mutex").pop() {
                Some(conn) => conn,
                None => db.connect()?,
            };
            let result = {
                let _files = db.inner.files.read().expect("Datei-Sperre");
                f(&conn, &db)
            };
            let mut pool = db.inner.readers.lock().expect("Pool-Mutex");
            if pool.len() < 8 {
                pool.push(conn);
            }
            result
        })
        .await?
    }
}

/// Schema-Name einer Stundendatei in der Verbindung des Writers
fn writer_schema(hour: i64) -> String {
    format!("h{}", hour.div_euclid(HOUR_MS))
}

/// Datenbank von einer anderen Verbindung gesperrt (Busy-Timeout abgelaufen) – ein erneuter Versuch kann gelingen.
fn is_busy(err: &DbError) -> bool {
    matches!(err, DbError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
        if matches!(e.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked))
}

#[cfg(test)]
mod tests;
