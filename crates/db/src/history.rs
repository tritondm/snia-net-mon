//! Historie und Archiv – Aufbewahrung über das Live-Fenster hinaus.
//!
//! ```text
//! live/ (48 h) ──jede volle Stunde──▶ history/ ──ab max_size──▶ archive/flows_<von>_<bis>/ (jede Datei einzeln zstd)
//!                                                               └── nach archive_retention gelöscht
//! ```
//!
//! * **Verschieben:** Der Retention-Task kopiert die Minuten-Aggregate aller Stunden, die ganz vor dem Live-Fenster
//!   liegen, in die `index.db` der Historie und berechnet dort die Stunden-Aggregate neu. Die Grenze steht in derselben
//!   Transaktion in `meta.moved_until`. Danach werden die Stundendateien abgeschlossen (WAL zurückgeschrieben) und per
//!   `rename` verschoben – kein Kopieren von Einzel-Flows. Bricht der Prozess dazwischen ab, verschiebt der nächste Lauf
//!   die übrigen Dateien, ohne Aggregate doppelt zu zählen.
//! * **Rotation:** Erreicht die Historie `max_bytes`, wird ihr Verzeichnis in `<dir>.rotating` umbenannt und durch ein
//!   leeres ersetzt. Ein eigener Thread packt jede Datei einzeln mit zstd (Multithreading, Long-Distance-Matching) nach
//!   `archive_dir/flows_<von>_<bis>/`. Wird der Prozess dabei beendet, setzt der nächste Start die Komprimierung fort.
//! * **Archive ansehen:** Beim Öffnen wird nur `index.db` nach `archive_dir/.view/` entpackt – damit sind die Statistiken
//!   sofort abfragbar. Eine Stundendatei entpackt erst die Abfrage, die sie braucht; die Flow-Suche (neueste zuerst) kommt
//!   meist mit den letzten Stunden aus. Es ist immer nur ein Archiv geöffnet; nach 30 Minuten ohne Abfrage wird das
//!   Entpackte wieder gelöscht.

use crate::store::{self, INDEX, PACKED_EXT, dir_size, fmt_utc, parse_utc};
use crate::{Database, DbError, Result, rollup, schema};
use model::now_ms;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Ein entpacktes Archiv wird nach so langer Zeit ohne Abfrage wieder gelöscht.
const VIEW_IDLE: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Verzeichnis der Historie (`index.db` und Stundendateien)
    pub dir: PathBuf,
    /// Größe des Verzeichnisses, ab der die Historie ins Archiv rotiert wird
    pub max_bytes: u64,
    pub archive_dir: PathBuf,
    /// Archive werden so lange nach ihrem jüngsten Flow aufbewahrt
    pub archive_retention: Duration,
    /// zstd-Stufe 1–22
    pub compression_level: i32,
    /// wie [`DbConfig::secure_delete`](crate::DbConfig::secure_delete)
    pub secure_delete: bool,
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
    /// Größe der gepackten Dateien
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
                std::fs::remove_dir_all(entry.path())?;
            }
        }
        let _ = std::fs::remove_dir_all(view_dir(&config));
        let current = Database::open_store(&config.dir, config.secure_delete)?;
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

    /// Aggregate und Stundendateien der Live-Datenbank vor `cutoff` (Stundenbeginn) übernehmen (blockierend).
    /// Rückgabe: Anzahl verschobener Flows.
    pub(crate) fn absorb(&self, live: &Database, cutoff: i64) -> Result<usize> {
        let hist = self.current()?;
        {
            let conn = live.connect()?;
            let _hist = store::attach(&conn, &hist.index_path(), "hist")?;
            let moved: Option<i64> = conn.query_row("SELECT value FROM hist.meta WHERE key = 'moved_until'", [], |r| r.get(0)).optional()?;
            let lo = moved.unwrap_or(0);
            if lo < cutoff {
                let tx = conn.unchecked_transaction()?;
                rollup::copy_range(&tx, "main", "hist", lo, cutoff)?;
                set_moved_until(&tx, "hist", cutoff)?;
                tx.commit()?;
            }
        }
        let _files = live.inner.files.write().expect("Datei-Sperre");
        let mut total = 0usize;
        for (hour, path) in store::list_hours(live.dir(), "")? {
            if hour >= cutoff {
                break;
            }
            let target = hist.dir().join(store::hour_name(hour));
            if target.exists() {
                tracing::warn!(file = %path.display(), "Stunde liegt schon in der Historie – die Live-Datei wird verworfen");
                continue;
            }
            store::seal(&path)?;
            total += store::count_flows(&path)? as usize;
            store::move_file(&path, &target)?;
        }
        Ok(total)
    }

    /// Rotation bei Überschreiten der Größe, abgelaufene Archive löschen, unbenutztes entpacktes Archiv schließen.
    pub async fn maintain(&self) {
        let history = self.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            history.close_idle_view();
            history.expire_archives()?;
            let size = dir_size(&history.inner.config.dir);
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

    /// Historie schließen, umbenennen, durch eine leere ersetzen und im Hintergrund packen.
    fn rotate(&self) -> Result<()> {
        let config = &self.inner.config;
        let rotating = rotating_path(config);
        if rotating.exists() {
            return Ok(()); // vorherige Rotation noch nicht fertig gepackt
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
            let index = config.dir.join(INDEX);
            let moved_until = {
                let conn = schema::open_connection(&index, config.secure_delete)?;
                let moved: Option<i64> = conn.query_row("SELECT value FROM meta WHERE key = 'moved_until'", [], |r| r.get(0)).optional()?;
                moved
            };
            // Alles aus dem WAL in die Hauptdatei, danach ohne WAL: jede Datei des Archivs ist dann genau eine Datei
            store::seal(&index)?;
            std::fs::rename(&config.dir, &rotating)?;
            let fresh = Database::open_store(&config.dir, config.secure_delete)?;
            if let Some(moved) = moved_until {
                set_moved_until(&fresh.connect()?, "main", moved)?;
            }
            *self.inner.current.write().expect("Historie-Lock") = Some(fresh);
            Ok(())
        })();
        if result.is_err() && self.inner.current.read().expect("Historie-Lock").is_none() {
            // Rotation gescheitert: mit dem bisherigen Verzeichnis weitermachen
            if let Ok(db) = Database::open_store(&config.dir, config.secure_delete) {
                *self.inner.current.write().expect("Historie-Lock") = Some(db);
            }
        }
        result?;
        self.spawn_compress();
        Ok(())
    }

    /// `<dir>.rotating` packen. Eigener Thread statt `spawn_blocking`: das kann bei 50 GB lange dauern und soll das
    /// Herunterfahren nicht aufhalten – ein abgebrochener Lauf wird beim nächsten Start wiederholt.
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

    /// Wiederholt eine gescheiterte Archivierung (das rotierte Verzeichnis liegt dann noch da).
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
                std::fs::remove_dir_all(self.inner.config.archive_dir.join(&archive.name))?;
                tracing::info!(archive = %archive.name, "Archiv abgelaufen und gelöscht");
            }
        }
        Ok(())
    }

    pub async fn status(&self) -> Result<HistoryStatus> {
        let range = match self.current() {
            Ok(db) => db.time_range().await?,
            Err(_) => (None, None),
        };
        let config = &self.inner.config;
        Ok(HistoryStatus {
            bytes: dir_size(&config.dir),
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
            if !entry.path().is_dir() {
                continue;
            }
            list.push(ArchiveInfo {
                bytes: dir_size(&entry.path()),
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

    /// Archiv zum Ansehen öffnen: `index.db` im Hintergrund entpacken. Ein anderes geöffnetes Archiv wird geschlossen.
    pub fn open_archive(&self, name: &str) -> Result<&'static str> {
        let config = &self.inner.config;
        if parse_archive_name(name).is_none() || !config.archive_dir.join(name).is_dir() {
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
            let (packed, target) = (config.archive_dir.join(&name), view_dir(config).join(&name));
            let opened = decompress(&packed.join(format!("{INDEX}{PACKED_EXT}")), &target.join(INDEX)).and_then(|_| Database::open_view(&target, &packed));
            let state = match opened {
                Ok(db) => {
                    tracing::info!(archive = %name, ms = started.elapsed().as_millis() as u64, "Archiv geöffnet");
                    ViewState::Ready(db)
                }
                Err(err) => {
                    tracing::error!(archive = %name, %err, "Archiv konnte nicht geöffnet werden");
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

    /// Geöffnetes Archiv für Abfragen.
    pub fn archive(&self, name: &str) -> Result<Database> {
        let mut view = self.inner.view.lock().expect("View-Lock");
        match view.as_mut() {
            Some(v) if v.name == name => {
                v.last_used = Instant::now();
                match &v.state {
                    ViewState::Ready(db) => Ok(db.clone()),
                    ViewState::Unpacking => Err(DbError::Unavailable(format!("{name} wird noch entpackt"))),
                    ViewState::Failed(err) => Err(DbError::Unavailable(format!("{name} konnte nicht geöffnet werden: {err}"))),
                }
            }
            _ => Err(DbError::Unavailable(format!("{name} ist nicht geöffnet"))),
        }
    }

    fn close_idle_view(&self) {
        let mut view = self.inner.view.lock().expect("View-Lock");
        if let Some(v) = view.as_ref().filter(|v| !matches!(v.state, ViewState::Unpacking) && v.last_used.elapsed() > VIEW_IDLE) {
            tracing::info!(archive = %v.name, "geöffnetes Archiv unbenutzt – Entpacktes wird gelöscht");
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

fn set_moved_until(conn: &Connection, schema: &str, value: i64) -> rusqlite::Result<()> {
    conn.execute(
        &format!("INSERT INTO {schema}.meta (key, value) VALUES ('moved_until', ?1) ON CONFLICT (key) DO UPDATE SET value = excluded.value"),
        [value],
    )?;
    Ok(())
}

fn rotating_path(config: &HistoryConfig) -> PathBuf {
    store::with_suffix(&config.dir, ".rotating")
}

fn view_dir(config: &HistoryConfig) -> PathBuf {
    config.archive_dir.join(".view")
}

fn remove_view_files(config: &HistoryConfig, name: &str) {
    let _ = std::fs::remove_dir_all(view_dir(config).join(name));
}

/// Rotierte Historie `src` nach `dir/flows_<von>_<bis>/` packen (jede Datei einzeln) und danach löschen.
/// Rückgabe: Name, Größe vorher, Größe nachher – `None`, wenn sie keine Flows enthielt.
fn compress(src: &Path, dir: &Path, level: i32) -> Result<Option<(String, u64, u64)>> {
    let hours = store::list_hours(src, "")?;
    let (Some((_, first)), Some((_, last))) = (hours.first(), hours.last()) else {
        std::fs::remove_dir_all(src)?;
        return Ok(None);
    };
    let (Some(from), Some(to)) = (store::ts_bound(first, false)?, store::ts_bound(last, true)?) else {
        std::fs::remove_dir_all(src)?;
        return Ok(None);
    };
    let name = archive_name(from, to);
    let part = dir.join(format!("{name}.part"));
    let _ = std::fs::remove_dir_all(&part);
    std::fs::create_dir_all(&part)?;
    let raw = dir_size(src);
    for path in std::iter::once(src.join(INDEX)).chain(hours.into_iter().map(|(_, path)| path)) {
        let file_name = path.file_name().expect("Dateiname").to_string_lossy().into_owned();
        compress_file(&path, &part.join(format!("{file_name}{PACKED_EXT}")), level)?;
    }
    let target = dir.join(&name);
    std::fs::rename(&part, &target)?;
    std::fs::remove_dir_all(src)?;
    Ok(Some((name, raw, dir_size(&target))))
}

fn compress_file(src: &Path, dst: &Path, level: i32) -> Result<()> {
    let mut input = std::fs::File::open(src)?;
    let mut encoder = zstd::Encoder::new(BufWriter::with_capacity(1 << 20, std::fs::File::create(dst)?), level.clamp(1, 22))?;
    // Die Hälfte der Kerne: schnell genug, ohne den Collector auszubremsen
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get() / 2).max(1) as u32;
    encoder.multithread(threads)?;
    encoder.long_distance_matching(true)?;
    encoder.include_checksum(true)?;
    encoder.set_pledged_src_size(Some(store::file_size(src)))?;
    std::io::copy(&mut input, &mut encoder)?;
    let mut out = encoder.finish()?;
    out.flush()?;
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(())
}

pub(crate) fn decompress(archive: &Path, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let part = store::with_suffix(target, ".part");
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

/// `flows_20260701-000000_20260915-120000` (UTC, Zeitraum des ältesten und jüngsten Flows)
fn archive_name(from_ms: i64, to_ms: i64) -> String {
    format!("flows_{}_{}", fmt_utc(from_ms), fmt_utc(to_ms))
}

fn parse_archive_name(name: &str) -> Option<(i64, i64)> {
    let (from, to) = name.strip_prefix("flows_")?.split_once('_')?;
    Some((parse_utc(from)?, parse_utc(to)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_names_roundtrip_utc() {
        // 2026-09-30 13:45:07 UTC
        let ms = 1_790_775_907_000;
        let name = archive_name(0, ms + 999);
        assert_eq!(name, "flows_19700101-000000_20260930-134507");
        assert_eq!(parse_archive_name(&name), Some((0, ms)));
        for bad in [
            "flows_x_y",
            "flows_20261301-000000_20260101-000000",
            "../history",
            "flows_20260101-000000",
            "flows_20260101-000000_20260102-000000.part",
        ] {
            assert_eq!(parse_archive_name(bad), None, "{bad}");
        }
    }
}
