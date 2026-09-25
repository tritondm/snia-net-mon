//! Flow-Speicher auf Basis von SQLite (WAL-Modus).
//!
//! * **Ingestion:** ein eigener Writer-Thread nimmt Flow-Batches aus einem Kanal und schreibt sie in großen Transaktionen
//!   mit vorbereitetem Statement. Staut sich etwas an, fasst er alle wartenden Batches zu einer Transaktion zusammen
//!   (natürliches Batching: je höher die Last, desto größer die Transaktionen).
//! * **Partitionierung:** jeder Datensatz trägt seinen Stunden-Bucket (`bucket = ts / 1h`), Abfragen und Löschungen
//!   laufen über den Zeitindex.
//! * **Retention:** höchstens 72 Stunden ([`model::MAX_RETENTION_HOURS`]). Ein Hintergrund-Task löscht ältere Datensätze
//!   in Blöcken. `secure_delete` überschreibt gelöschte Inhalte in der Datei, danach werden WAL (Checkpoint + Truncate)
//!   und freie Seiten (`incremental_vacuum`) bereinigt – die Daten sind damit auch forensisch nicht mehr in der Datei.
//!   Zusätzlich liefert keine Abfrage jemals Daten, die älter als das Retention-Fenster sind.

mod query;
mod schema;

pub use query::{
    DirectionStat, FlowFilter, FlowRow, PortStat, ProtocolStat, SankeyGraph, SankeyLink, SankeyNode, TalkerStat, TimePoint,
};

use model::{FlowRecord, MAX_RETENTION_HOURS, ip_to_bytes, now_ms};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, watch};

const HOUR_MS: i64 = 3_600_000;
/// Anzahl Zeilen pro Lösch-Transaktion – hält die Sperre auf die Datenbank kurz, damit der Writer nicht blockiert.
const DELETE_CHUNK: usize = 20_000;

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
}

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub path: PathBuf,
    /// Aufbewahrung in Stunden; wird auf höchstens [`MAX_RETENTION_HOURS`] begrenzt.
    pub retention_hours: u64,
    pub cleanup_interval: Duration,
}

#[derive(Debug, Default)]
struct Counters {
    inserted: AtomicU64,
    deleted: AtomicU64,
    rows: AtomicI64,
    last_cleanup_ms: AtomicI64,
    write_batches: AtomicU64,
    last_write_micros: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DbStats {
    pub rows: i64,
    pub inserted: u64,
    pub deleted: u64,
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
    path: PathBuf,
    retention_ms: i64,
    retention_hours: u64,
    cleanup_interval: Duration,
    readers: Mutex<Vec<Connection>>,
    counters: Counters,
}

impl Database {
    pub fn open(config: &DbConfig) -> Result<Self> {
        if let Some(parent) = config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let retention_hours = config.retention_hours.clamp(1, MAX_RETENTION_HOURS);
        if retention_hours != config.retention_hours {
            tracing::warn!(requested = config.retention_hours, used = retention_hours, "Retention auf 1–72 Stunden begrenzt");
        }
        let conn = schema::open_connection(&config.path)?;
        schema::migrate(&conn)?;
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))?;
        let db = Self {
            inner: Arc::new(Inner {
                path: config.path.clone(),
                retention_ms: retention_hours as i64 * HOUR_MS,
                retention_hours,
                cleanup_interval: config.cleanup_interval,
                readers: Mutex::new(Vec::new()),
                counters: Counters::default(),
            }),
        };
        db.inner.counters.rows.store(rows, Relaxed);
        Ok(db)
    }

    pub fn retention_ms(&self) -> i64 {
        self.inner.retention_ms
    }

    /// Frühester Zeitpunkt, den Abfragen liefern dürfen.
    pub fn retention_floor_ms(&self) -> i64 {
        now_ms() - self.inner.retention_ms
    }

    /// Writer-Thread starten. Er läuft, bis alle Sender des Kanals geschlossen sind, und schreibt dann den Rest weg.
    pub fn spawn_writer(&self, mut rx: mpsc::Receiver<Arc<Vec<FlowRecord>>>) -> Result<std::thread::JoinHandle<()>> {
        let mut conn = schema::open_connection(&self.inner.path)?;
        let db = self.clone();
        let handle = std::thread::Builder::new().name("db-writer".into()).spawn(move || {
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
                match insert_batches(&mut conn, &pending) {
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

    /// Hintergrund-Task für die Retention: sofort beim Start und danach im Intervall.
    pub fn spawn_cleanup(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let db = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(db.inner.cleanup_interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match db.cleanup_now().await {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(deleted = n, "Retention: alte Flows gelöscht"),
                            Err(err) => tracing::error!(%err, "Retention-Cleanup fehlgeschlagen"),
                        }
                    }
                    _ = shutdown.changed() => if *shutdown.borrow() { return },
                }
            }
        })
    }

    /// Alle Flows älter als das Retention-Fenster löschen. Rückgabe: Anzahl gelöschter Zeilen.
    pub async fn cleanup_now(&self) -> Result<usize> {
        self.cleanup_before(self.retention_floor_ms()).await
    }

    /// Alle Flows mit `ts < cutoff_ms` unwiderruflich löschen.
    pub async fn cleanup_before(&self, cutoff_ms: i64) -> Result<usize> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || -> Result<usize> {
            let conn = schema::open_connection(&db.inner.path)?;
            let mut total = 0usize;
            loop {
                let deleted = conn.execute(
                    "DELETE FROM flows WHERE id IN (SELECT id FROM flows WHERE ts < ?1 ORDER BY ts LIMIT ?2)",
                    params![cutoff_ms, DELETE_CHUNK as i64],
                )?;
                total += deleted;
                if deleted < DELETE_CHUNK {
                    break;
                }
            }
            if total > 0 {
                // Freie Seiten zurückgeben und gelöschte Inhalte auch aus dem WAL entfernen
                conn.execute_batch("PRAGMA incremental_vacuum;")?;
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
                let c = &db.inner.counters;
                c.deleted.fetch_add(total as u64, Relaxed);
                c.rows.fetch_sub(total as i64, Relaxed);
            }
            db.inner.counters.last_cleanup_ms.store(now_ms(), Relaxed);
            Ok(total)
        })
        .await?
    }

    pub async fn stats(&self) -> Result<DbStats> {
        let oldest: Option<i64> = self.with_reader(|conn| Ok(conn.query_row("SELECT MIN(ts) FROM flows", [], |r| r.get(0))?)).await?;
        let file_bytes = file_size(&self.inner.path) + file_size(&wal_path(&self.inner.path));
        let c = &self.inner.counters;
        Ok(DbStats {
            rows: c.rows.load(Relaxed).max(0),
            inserted: c.inserted.load(Relaxed),
            deleted: c.deleted.load(Relaxed),
            oldest_ts_ms: oldest,
            retention_hours: self.inner.retention_hours,
            last_cleanup_ms: c.last_cleanup_ms.load(Relaxed),
            file_bytes,
            write_batches: c.write_batches.load(Relaxed),
            last_write_micros: c.last_write_micros.load(Relaxed),
        })
    }

    /// Lese-Abfrage auf einer gepoolten Verbindung in einem Blocking-Thread ausführen.
    pub(crate) async fn with_reader<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = match db.inner.readers.lock().expect("Pool-Mutex").pop() {
                Some(conn) => conn,
                None => schema::open_connection(&db.inner.path)?,
            };
            let result = f(&conn);
            let mut pool = db.inner.readers.lock().expect("Pool-Mutex");
            if pool.len() < 8 {
                pool.push(conn);
            }
            result
        })
        .await?
    }
}

fn insert_batches(conn: &mut Connection, batches: &[Arc<Vec<FlowRecord>>]) -> Result<usize> {
    let tx = conn.transaction()?;
    let mut count = 0;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO flows (ts, start_ts, bucket, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags, in_if, out_if, exporter, dir)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )?;
        for flow in batches.iter().flat_map(|b| b.iter()) {
            stmt.execute(params![
                flow.ts_ms,
                flow.start_ms,
                flow.ts_ms.div_euclid(HOUR_MS),
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
            count += 1;
        }
    }
    tx.commit()?;
    Ok(count)
}

fn wal_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push("-wal");
    PathBuf::from(p)
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests;
