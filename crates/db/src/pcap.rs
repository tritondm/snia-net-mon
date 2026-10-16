//! Gespeicherte PCAP-Analysen. Die Capture-Datei selbst wird nie gespeichert, nur das Analyse-Ergebnis – und das
//! unterliegt derselben Retention wie die Flows.

use crate::{Database, Result};
use model::now_ms;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PcapSummary {
    pub id: i64,
    pub created_ms: i64,
    pub name: String,
    pub size: i64,
    pub packets: i64,
    pub bytes: i64,
}

impl Database {
    /// Analyse-Ergebnis (JSON) speichern; liefert die neue ID.
    pub async fn save_pcap(&self, name: String, size: u64, packets: u64, bytes: u64, result: String) -> Result<i64> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || -> Result<i64> {
            let conn = db.connect()?;
            conn.execute(
                "INSERT INTO pcap_analyses (created_ms, name, size, packets, bytes, result) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![now_ms(), name, size as i64, packets as i64, bytes as i64, result],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    /// Analysen im Retention-Fenster, neueste zuerst.
    pub async fn list_pcaps(&self, limit: u32) -> Result<Vec<PcapSummary>> {
        let floor = self.retention_floor_ms();
        self.with_reader(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT id, created_ms, name, size, packets, bytes FROM pcap_analyses WHERE created_ms >= ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![floor, limit.clamp(1, 500)], |r| {
                Ok(PcapSummary { id: r.get(0)?, created_ms: r.get(1)?, name: r.get(2)?, size: r.get(3)?, packets: r.get(4)?, bytes: r.get(5)? })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Gespeichertes Ergebnis als JSON-Text (`None`, wenn unbekannt oder abgelaufen).
    pub async fn get_pcap(&self, id: i64) -> Result<Option<String>> {
        let floor = self.retention_floor_ms();
        self.with_reader(move |conn| {
            Ok(conn
                .query_row("SELECT result FROM pcap_analyses WHERE id = ?1 AND created_ms >= ?2", params![id, floor], |r| r.get(0))
                .optional()?)
        })
        .await
    }

    /// Analyse löschen; `false`, wenn es sie nicht gab.
    pub async fn delete_pcap(&self, id: i64) -> Result<bool> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let conn = db.connect()?;
            Ok(conn.execute("DELETE FROM pcap_analyses WHERE id = ?1", params![id])? > 0)
        })
        .await?
    }
}
