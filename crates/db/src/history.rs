//! Historie und Archiv – Aufbewahrung über das Live-Fenster hinaus.
//!
//! ```text
//! Live-DB (flows.db, 48 h) ──jede Minute──▶ Historie (history.db) ──ab max_size──▶ Archiv (flows_<von>_<bis>.db.zst)
//!                                                                                  └── nach archive_retention gelöscht
//! ```
//!
//! * **Verschieben:** Der Retention-Task kopiert alles vor der minutengenauen Grenze in die Historie – Flows und
//!   Minuten-Aggregate, die Stunden-Aggregate werden dort neu berechnet – und löscht es danach in der Live-Datenbank.
//!   Die Grenze steht in derselben Transaktion in `meta.moved_until` der Historie. Bricht der Prozess zwischen Kopieren
//!   und Löschen ab, kopiert der nächste Lauf deshalb nichts doppelt.
//! * **Rotation:** Erreicht die Historie `max_bytes`, wird sie geschlossen, in `<path>.rotating` umbenannt und durch eine
//!   leere Datei ersetzt. Ein eigener Thread komprimiert sie mit zstd (Multithreading, Long-Distance-Matching) nach
//!   `archive_dir`. Wird der Prozess dabei beendet, setzt der nächste Start die Komprimierung fort.
//! * **Archive ansehen:** Ein Archiv wird auf Anfrage nach `archive_dir/.view/` entpackt und wie die Historie abgefragt.
//!   Es ist immer nur ein Archiv entpackt; nach 30 Minuten ohne Abfrage wird es wieder gelöscht.

use crate::{Database, DbError, Result, db_file_size, file_size, rollup, schema, with_suffix};
use model::{civil_from_days, days_from_civil, now_ms};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Flows pro Kopier-Transaktion: 10 Minuten (minutengenau, damit die Minuten-Aggregate vollständig mitgehen)
const MOVE_CHUNK_MS: i64 = 10 * rollup::MINUTE_MS;
/// Ein entpacktes Archiv wird nach so langer Zeit ohne Abfrage wieder gelöscht.
const VIEW_IDLE: Duration = Duration::from_secs(30 * 60);
const ARCHIVE_EXT: &str = ".db.zst";

#[derive(Debug, Clone)]
pub struct HistoryConfig {
    pub path: PathBuf,
    /// Größe (Datei + WAL), ab der die Historie ins Archiv rotiert wird
    pub max_bytes: u64,
    pub archive_dir: PathBuf,
    /// Archive werden so lange nach ihrem jüngsten Flow aufbewahrt
    pub archive_retention: Duration,
    /// zstd-Stufe 1–22
    pub compression_level: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryStatus {
    pub bytes: u64,
    pub max_bytes: u64,
    pub oldest_ts_ms: Option<i64>,
    pub newest_ts_ms: Option<i64>,
    /// Eine rotierte Historie wird gerade komprimiert
    pub compressing: bool,
    pub archive_retention_days: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfo {
    pub name: String,
    pub from_ms: i64,
    pub to_ms: i64,
    /// Größe der komprimierten Datei
    pub bytes: u64,
    /// Zeitpunkt der automatischen Löschung
    pub expires_ms: i64,
    /// `packed`, `unpacking`, `ready` oder `failed`
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Handle auf Historie und Archiv. Günstig zu klonen.
#[derive(Clone)]
pub struct History {
    inner: Arc<Inner>,
}

struct Inner {
    config: HistoryConfig,
    /// Aktuelle Historie; `None` nur kurz während der Rotation
    current: RwLock<Option<Database>>,
    compressing: AtomicBool,
    view: Mutex<Option<View>>,
}

struct View {
    name: String,
    state: ViewState,
    last_used: Instant,
}

enum ViewState {
    Unpacking,
    Ready(Database),
    Failed(String),
}

impl History {
    pub fn open(config: HistoryConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.archive_dir)?;
        // Reste abgebrochener Komprimierungen und entpackter Archive entfernen
        for entry in std::fs::read_dir(&config.archive_dir)?.flatten() {
            if entry.file_name().to_string_lossy().ends_with(".part") {
                std::fs::remove_file(entry.path())?;
            }
        }
        let _ = std::fs::remove_dir_all(view_dir(&config));
        let current = Database::open_store(&config.path)?;
        let history = Self {
            inner: Arc::new(Inner { current: RwLock::new(Some(current)), compressing: AtomicBool::new(false), view: Mutex::new(None), config }),
        };
        if rotating_path(&history.inner.config).exists() {
            tracing::info!("Historie: abgebrochene Archivierung wird fortgesetzt");
            history.spawn_compress();
        }
        Ok(history)
    }

    pub fn config(&self) -> &HistoryConfig {
        &self.inner.config
    }

    /// Aktuelle Historie für Abfragen.
    pub fn current(&self) -> Result<Database> {
        self.inner.current.read().expect("Historie-Lock").clone().ok_or_else(|| DbError::Unavailable("Historie wird gerade rotiert – bitte gleich noch einmal".into()))
    }

    /// Flows und Aggregate der Live-Datenbank `live` vor `cutoff` übernehmen (blockierend). Rückgabe: Anzahl Flows.
    pub(crate) fn absorb(&self, live: &Path, cutoff: i64) -> Result<usize> {
        let conn = schema::open_connection(live)?;
        conn.execute("ATTACH DATABASE ?1 AS hist", [self.inner.config.path.to_string_lossy()])?;
        let result = absorb_attached(&conn, cutoff);
        let _ = conn.execute_batch("DETACH DATABASE hist");
        result
    }

    /// Rotation bei Überschreiten der Größe, abgelaufene Archive löschen, unbenutztes entpacktes Archiv schließen.
    pub async fn maintain(&self) {
        let history = self.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            history.close_idle_view();
            history.expire_archives()?;
            let size = db_file_size(&history.inner.config.path);
            if size >= history.inner.config.max_bytes && !history.inner.compressing.load(Relaxed) {
                tracing::info!(bytes = size, max = history.inner.config.max_bytes, "Historie voll – Rotation ins Archiv");
                history.rotate()?;
            }
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "Historie/Archiv-Wartung fehlgeschlagen"),
            Err(err) => tracing::error!(%err, "Historie/Archiv-Wartung abgebrochen"),
        }
    }

    /// Historie schließen, umbenennen, durch eine leere ersetzen und im Hintergrund komprimieren.
    fn rotate(&self) -> Result<()> {
        let config = &self.inner.config;
        let rotating = rotating_path(config);
        if rotating.exists() {
            return Ok(()); // vorherige Rotation noch nicht fertig komprimiert
        }
        let old = self.inner.current.write().expect("Historie-Lock").take();
        // Warten, bis laufende Abfragen ihre Verbindungen zurückgegeben haben; danach sind alle geschlossen
        if let Some(old) = old {
            let deadline = Instant::now() + Duration::from_secs(120);
            while Arc::strong_count(&old.inner) > 1 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let result = (|| -> Result<()> {
            let moved_until = {
                let conn = schema::open_connection(&config.path)?;
                let moved: Option<i64> = conn.query_row("SELECT value FROM meta WHERE key = 'moved_until'", [], |r| r.get(0)).optional()?;
                // Alles aus dem WAL in die Hauptdatei, danach ohne WAL: das Archiv ist dann genau eine Datei
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
                conn.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))?;
                moved
            };
            std::fs::rename(&config.path, &rotating)?;
            for suffix in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(with_suffix(&config.path, suffix));
            }
            let fresh = Database::open_store(&config.path)?;
            if let Some(moved) = moved_until {
                let conn = schema::open_connection(&config.path)?;
                set_moved_until(&conn, "main", moved)?;
            }
            *self.inner.current.write().expect("Historie-Lock") = Some(fresh);
            Ok(())
        })();
        if result.is_err() && self.inner.current.read().expect("Historie-Lock").is_none() {
            // Rotation gescheitert: mit der bisherigen Datei weitermachen
            if let Ok(db) = Database::open_store(&config.path) {
                *self.inner.current.write().expect("Historie-Lock") = Some(db);
            }
        }
        result?;
        self.spawn_compress();
        Ok(())
    }

    /// `<path>.rotating` komprimieren. Eigener Thread statt `spawn_blocking`: das kann bei 50 GB lange dauern und soll
    /// das Herunterfahren nicht aufhalten – ein abgebrochener Lauf wird beim nächsten Start wiederholt.
    fn spawn_compress(&self) {
        if self.inner.compressing.swap(true, Relaxed) {
            return;
        }
        let history = self.clone();
        let spawned = std::thread::Builder::new().name("archive-compress".into()).spawn(move || {
            let started = Instant::now();
            let config = &history.inner.config;
            match compress(&rotating_path(config), &config.archive_dir, config.compression_level) {
                Ok(Some((name, raw, packed))) => tracing::info!(
                    archive = %name, raw_bytes = raw, packed_bytes = packed, secs = started.elapsed().as_secs(),
                    "Historie archiviert"
                ),
                Ok(None) => tracing::info!("Historie war leer – kein Archiv angelegt"),
                Err(err) => tracing::error!(%err, "Archivierung fehlgeschlagen – wird bei der nächsten Wartung wiederholt"),
            }
            history.inner.compressing.store(false, Relaxed);
        });
        if let Err(err) = spawned {
            tracing::error!(%err, "Archiv-Thread konnte nicht gestartet werden");
            self.inner.compressing.store(false, Relaxed);
        }
    }

    /// Wiederholt eine gescheiterte Archivierung (die rotierte Datei liegt dann noch da).
    fn retry_pending_compress(&self) {
        if !self.inner.compressing.load(Relaxed) && rotating_path(&self.inner.config).exists() {
            self.spawn_compress();
        }
    }

    fn expire_archives(&self) -> Result<()> {
        self.retry_pending_compress();
        let now = now_ms();
        for archive in self.list_archives()? {
            if archive.expires_ms <= now {
                self.close_view_if(&archive.name);
                std::fs::remove_file(self.inner.config.archive_dir.join(&archive.name))?;
                tracing::info!(archive = %archive.name, "Archiv abgelaufen und gelöscht");
            }
        }
        Ok(())
    }

    pub async fn status(&self) -> Result<HistoryStatus> {
        let range = match self.current() {
            Ok(db) => db.with_reader(|conn| Ok(conn.query_row("SELECT MIN(ts), MAX(ts) FROM flows", [], |r| Ok((r.get(0)?, r.get(1)?)))?)).await?,
            Err(_) => (None, None),
        };
        let config = &self.inner.config;
        Ok(HistoryStatus {
            bytes: db_file_size(&config.path),
            max_bytes: config.max_bytes,
            oldest_ts_ms: range.0,
            newest_ts_ms: range.1,
            compressing: self.inner.compressing.load(Relaxed),
            archive_retention_days: config.archive_retention.as_secs() / 86_400,
        })
    }

    /// Archive, neueste zuerst.
    pub fn archives(&self) -> Result<Vec<ArchiveInfo>> {
        let mut list = self.list_archives()?;
        let view = self.inner.view.lock().expect("View-Lock");
        for archive in &mut list {
            if let Some(v) = view.as_ref().filter(|v| v.name == archive.name) {
                (archive.state, archive.error) = match &v.state {
                    ViewState::Unpacking => ("unpacking", None),
                    ViewState::Ready(_) => ("ready", None),
                    ViewState::Failed(err) => ("failed", Some(err.clone())),
                };
            }
        }
        Ok(list)
    }

    fn list_archives(&self) -> Result<Vec<ArchiveInfo>> {
        let retention = self.inner.config.archive_retention.as_millis() as i64;
        let mut list = Vec::new();
        for entry in std::fs::read_dir(&self.inner.config.archive_dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some((from_ms, to_ms)) = parse_archive_name(&name) else { continue };
            list.push(ArchiveInfo {
                bytes: file_size(&entry.path()),
                expires_ms: to_ms + retention,
                name,
                from_ms,
                to_ms,
                state: "packed",
                error: None,
            });
        }
        list.sort_by_key(|a| std::cmp::Reverse(a.to_ms));
        Ok(list)
    }

    /// Archiv zum Ansehen entpacken (im Hintergrund). Ein anderes entpacktes Archiv wird dabei geschlossen.
    pub fn open_archive(&self, name: &str) -> Result<&'static str> {
        let config = &self.inner.config;
        if parse_archive_name(name).is_none() || !config.archive_dir.join(name).is_file() {
            return Err(DbError::InvalidFilter(format!("unbekanntes Archiv: {name}")));
        }
        let mut view = self.inner.view.lock().expect("View-Lock");
        match view.as_mut() {
            Some(v) if v.name == name && !matches!(v.state, ViewState::Failed(_)) => {
                v.last_used = Instant::now();
                return Ok(if matches!(v.state, ViewState::Ready(_)) { "ready" } else { "unpacking" });
            }
            Some(v) if matches!(v.state, ViewState::Unpacking) => {
                return Err(DbError::Unavailable(format!("{} wird gerade entpackt – bitte warten", v.name)));
            }
            _ => {}
        }
        if let Some(old) = view.take() {
            remove_view_files(config, &old.name);
        }
        *view = Some(View { name: name.to_string(), state: ViewState::Unpacking, last_used: Instant::now() });
        drop(view);

        let history = self.clone();
        let name = name.to_string();
        std::thread::Builder::new().name("archive-unpack".into()).spawn(move || {
            let started = Instant::now();
            let config = &history.inner.config;
            let target = view_path(config, &name);
            let state = match decompress(&config.archive_dir.join(&name), &target).and_then(|_| Database::open_store(&target)) {
                Ok(db) => {
                    tracing::info!(archive = %name, secs = started.elapsed().as_secs(), "Archiv entpackt");
                    ViewState::Ready(db)
                }
                Err(err) => {
                    tracing::error!(archive = %name, %err, "Archiv konnte nicht entpackt werden");
                    remove_view_files(config, &name);
                    ViewState::Failed(err.to_string())
                }
            };
            let mut view = history.inner.view.lock().expect("View-Lock");
            match view.as_mut() {
                Some(v) if v.name == name => v.state = state,
                // inzwischen abgelaufen/geschlossen
                _ => remove_view_files(config, &name),
            }
        })?;
        Ok("unpacking")
    }

    /// Entpacktes Archiv für Abfragen.
    pub fn archive(&self, name: &str) -> Result<Database> {
        let mut view = self.inner.view.lock().expect("View-Lock");
        match view.as_mut() {
            Some(v) if v.name == name => {
                v.last_used = Instant::now();
                match &v.state {
                    ViewState::Ready(db) => Ok(db.clone()),
                    ViewState::Unpacking => Err(DbError::Unavailable(format!("{name} wird noch entpackt"))),
                    ViewState::Failed(err) => Err(DbError::Unavailable(format!("{name} konnte nicht entpackt werden: {err}"))),
                }
            }
            _ => Err(DbError::Unavailable(format!("{name} ist nicht geöffnet"))),
        }
    }

    fn close_idle_view(&self) {
        let mut view = self.inner.view.lock().expect("View-Lock");
        if let Some(v) = view.as_ref().filter(|v| !matches!(v.state, ViewState::Unpacking) && v.last_used.elapsed() > VIEW_IDLE) {
            tracing::info!(archive = %v.name, "entpacktes Archiv unbenutzt – wird geschlossen");
            remove_view_files(&self.inner.config, &v.name);
            *view = None;
        }
    }

    fn close_view_if(&self, name: &str) {
        let mut view = self.inner.view.lock().expect("View-Lock");
        if view.as_ref().is_some_and(|v| v.name == name) {
            remove_view_files(&self.inner.config, name);
            *view = None;
        }
    }
}

fn absorb_attached(conn: &Connection, cutoff: i64) -> Result<usize> {
    schema::create_meta_in(conn, "hist")?;
    let moved: Option<i64> = conn.query_row("SELECT value FROM hist.meta WHERE key = 'moved_until'", [], |r| r.get(0)).optional()?;
    // Ohne bisherige Grenze (oder nach einer Lücke) beim ältesten Live-Flow beginnen, minutengenau
    let oldest: Option<i64> = conn.query_row("SELECT MIN(ts) FROM main.flows", [], |r| r.get(0))?;
    let Some(oldest) = oldest.map(|ts| ts.div_euclid(rollup::MINUTE_MS) * rollup::MINUTE_MS) else {
        set_moved_until(conn, "hist", moved.unwrap_or(0).max(cutoff))?;
        return Ok(0);
    };
    let mut lo = moved.unwrap_or(oldest).max(oldest);
    let mut total = 0usize;
    while lo < cutoff {
        let hi = ((lo.div_euclid(MOVE_CHUNK_MS) + 1) * MOVE_CHUNK_MS).min(cutoff);
        let tx = conn.unchecked_transaction()?;
        total += tx.execute(
            "INSERT INTO hist.flows (ts, start_ts, bucket, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags, in_if, out_if, exporter, dir)
             SELECT ts, start_ts, bucket, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags, in_if, out_if, exporter, dir
             FROM main.flows WHERE ts >= ?1 AND ts < ?2",
            params![lo, hi],
        )?;
        rollup::copy_range(&tx, "main", "hist", lo, hi)?;
        set_moved_until(&tx, "hist", hi)?;
        tx.commit()?;
        lo = hi;
    }
    Ok(total)
}

fn set_moved_until(conn: &Connection, schema: &str, value: i64) -> rusqlite::Result<()> {
    conn.execute(
        &format!("INSERT INTO {schema}.meta (key, value) VALUES ('moved_until', ?1) ON CONFLICT (key) DO UPDATE SET value = excluded.value"),
        [value],
    )?;
    Ok(())
}

fn rotating_path(config: &HistoryConfig) -> PathBuf {
    with_suffix(&config.path, ".rotating")
}

fn view_dir(config: &HistoryConfig) -> PathBuf {
    config.archive_dir.join(".view")
}

fn view_path(config: &HistoryConfig, name: &str) -> PathBuf {
    view_dir(config).join(name.trim_end_matches(".zst"))
}

fn remove_view_files(config: &HistoryConfig, name: &str) {
    let path = view_path(config, name);
    for suffix in ["", "-wal", "-shm", ".part"] {
        let _ = std::fs::remove_file(with_suffix(&path, suffix));
    }
}

/// Rotierte Historie `src` nach `dir/flows_<von>_<bis>.db.zst` komprimieren und danach löschen.
/// Rückgabe: Name, Größe vorher, Größe nachher – `None`, wenn die Datei keine Flows enthielt.
fn compress(src: &Path, dir: &Path, level: i32) -> Result<Option<(String, u64, u64)>> {
    let range: (Option<i64>, Option<i64>) = {
        let conn = Connection::open_with_flags(src, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.query_row("SELECT MIN(ts), MAX(ts) FROM flows", [], |r| Ok((r.get(0)?, r.get(1)?)))?
    };
    let (Some(from), Some(to)) = range else {
        std::fs::remove_file(src)?;
        return Ok(None);
    };
    let name = archive_name(from, to);
    let part = dir.join(format!("{name}.part"));
    let raw = file_size(src);
    let mut input = std::fs::File::open(src)?;
    let mut encoder = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, std::fs::File::create(&part)?), level.clamp(1, 22))?;
    // Die Hälfte der Kerne: schnell genug, ohne den Collector auszubremsen
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get() / 2).max(1) as u32;
    encoder.multithread(threads)?;
    encoder.long_distance_matching(true)?;
    encoder.include_checksum(true)?;
    encoder.set_pledged_src_size(Some(raw))?;
    std::io::copy(&mut input, &mut encoder)?;
    let mut out = encoder.finish()?;
    out.flush()?;
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    std::fs::rename(&part, dir.join(&name))?;
    std::fs::remove_file(src)?;
    Ok(Some((name.clone(), raw, file_size(&dir.join(&name)))))
}

fn decompress(archive: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let part = with_suffix(target, ".part");
    let mut decoder = zstd::Decoder::new(std::fs::File::open(archive)?)?;
    // Long-Distance-Matching nutzt große Fenster – beim Entpacken erlauben
    decoder.window_log_max(31)?;
    let mut out = BufWriter::with_capacity(1 << 20, std::fs::File::create(&part)?);
    std::io::copy(&mut decoder, &mut out)?;
    out.flush()?;
    drop(out);
    std::fs::rename(&part, target)?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------ Archiv-Namen

/// `flows_20260701-000000_20260915-120000.db.zst` (UTC, Zeitraum des ältesten und jüngsten Flows)
fn archive_name(from_ms: i64, to_ms: i64) -> String {
    format!("flows_{}_{}{ARCHIVE_EXT}", fmt_utc(from_ms), fmt_utc(to_ms))
}

fn parse_archive_name(name: &str) -> Option<(i64, i64)> {
    let (from, to) = name.strip_prefix("flows_")?.strip_suffix(ARCHIVE_EXT)?.split_once('_')?;
    Some((parse_utc(from)?, parse_utc(to)?))
}

fn fmt_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", s / 3600, s % 3600 / 60, s % 60)
}

fn parse_utc(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 15 || b[8] != b'-' || !text[..8].bytes().chain(text[9..].bytes()).all(|c| c.is_ascii_digit()) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| text[r].parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hh, mm, ss) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    Some((days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss) * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_names_roundtrip_utc() {
        // 2026-09-30 13:45:07 UTC
        let ms = 1_790_775_907_000;
        assert_eq!(fmt_utc(ms), "20260930-134507");
        assert_eq!(parse_utc("20260930-134507"), Some(ms));
        let name = archive_name(0, ms + 999);
        assert_eq!(name, "flows_19700101-000000_20260930-134507.db.zst");
        assert_eq!(parse_archive_name(&name), Some((0, ms)));
        for bad in ["flows_x_y.db.zst", "flows_20261301-000000_20260101-000000.db.zst", "../etc/passwd", "flows_20260101-000000.db.zst"] {
            assert_eq!(parse_archive_name(bad), None, "{bad}");
        }
    }
}
