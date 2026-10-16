//! Dateien eines Speichers.
//!
//! Ein Speicher (live, Historie, entpacktes Archiv) ist ein Verzeichnis:
//!
//! ```text
//! index.db                 Aggregate, PCAP-Analysen, Meta
//! flows_20261016-14.db     Einzel-Flows mit ts in [14:00, 15:00) UTC – eine Datei pro Stunde
//! ```
//!
//! Alte Daten verschwinden, indem ganze Stundendateien gelöscht oder verschoben werden – kein `DELETE` über Millionen
//! Zeilen samt ihren Indizes.

use crate::rollup::HOUR_MS;
use model::{civil_from_days, days_from_civil};
use rusqlite::Connection;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub(crate) const INDEX: &str = "index.db";
const FLOWS_EXT: &str = ".db";
/// Endung gepackter Dateien im Archiv
pub(crate) const PACKED_EXT: &str = ".zst";

/// Beginn der Stunde (Unix-ms), in die ein Zeitpunkt fällt.
pub(crate) fn hour_of(ts_ms: i64) -> i64 {
    ts_ms.div_euclid(HOUR_MS) * HOUR_MS
}

/// `flows_YYYYMMDD-HH.db` (UTC)
pub(crate) fn hour_name(hour: i64) -> String {
    format!("flows_{}{FLOWS_EXT}", &fmt_utc(hour)[..11])
}

/// Stunde aus einem Dateinamen `flows_YYYYMMDD-HH.db` + `suffix` (z. B. `.zst` im Archiv).
pub(crate) fn parse_hour_name(name: &str, suffix: &str) -> Option<i64> {
    let stem = name.strip_suffix(suffix)?.strip_prefix("flows_")?.strip_suffix(FLOWS_EXT)?;
    if stem.len() != 11 {
        return None;
    }
    parse_utc(&format!("{stem}0000"))
}

/// Stundendateien in `dir` (Endung `.db` + `suffix`), aufsteigend nach Stunde. Ein fehlendes Verzeichnis ist leer.
pub(crate) fn list_hours(dir: &Path, suffix: &str) -> std::io::Result<Vec<(i64, PathBuf)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut out: Vec<(i64, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| parse_hour_name(&entry.file_name().to_string_lossy(), suffix).map(|hour| (hour, entry.path())))
        .collect();
    out.sort_by_key(|(hour, _)| *hour);
    Ok(out)
}

/// Datei eines anderen Speichers für die Dauer des Guards unter `name` an die Verbindung hängen.
pub(crate) struct Attached<'c> {
    conn: &'c Connection,
    name: &'static str,
}

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch(&format!("DETACH DATABASE {}", self.name));
    }
}

pub(crate) fn attach<'c>(conn: &'c Connection, path: &Path, name: &'static str) -> rusqlite::Result<Attached<'c>> {
    conn.execute(&format!("ATTACH DATABASE ?1 AS {name}"), [path.to_string_lossy()])?;
    Ok(Attached { conn, name })
}

/// Höchste Zeilen-ID einer Stundendatei – ohne Löschungen gleich der Zahl der Flows, ohne einen Scan.
pub(crate) fn count_flows(path: &Path) -> rusqlite::Result<i64> {
    let conn = Connection::open(path)?;
    conn.query_row("SELECT COALESCE(MAX(id), 0) FROM flows", [], |r| r.get(0))
}

/// Ältester bzw. jüngster Flow einer Stundendatei.
pub(crate) fn ts_bound(path: &Path, newest: bool) -> rusqlite::Result<Option<i64>> {
    let conn = Connection::open(path)?;
    conn.query_row(if newest { "SELECT MAX(ts) FROM flows" } else { "SELECT MIN(ts) FROM flows" }, [], |r| r.get(0))
}

/// Stundendatei abschließen: WAL zurückschreiben und auf Rollback-Journal umstellen. Danach ist sie genau eine Datei, die
/// sich verschieben und packen lässt. Darf nur laufen, wenn keine andere Verbindung die Datei offen hat.
pub(crate) fn seal(path: &Path) -> rusqlite::Result<()> {
    {
        let conn = Connection::open(path)?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        conn.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))?;
    }
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(with_suffix(path, suffix));
    }
    Ok(())
}

/// Datei verschieben; liegt das Ziel auf einem anderen Dateisystem, wird kopiert und danach gelöscht.
pub(crate) fn move_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Err(err) if err.kind() == std::io::ErrorKind::CrossesDevices => {
            let part = with_suffix(dst, ".part");
            std::fs::copy(src, &part)?;
            std::fs::File::open(&part)?.sync_all()?;
            std::fs::rename(&part, dst)?;
            std::fs::remove_file(src)
        }
        other => other,
    }
}

/// Datei samt WAL löschen; mit `overwrite` vorher mit Nullen überschreiben. Auf Dateisystemen mit Copy-on-Write (btrfs,
/// ZFS) und auf SSDs landen die Nullen allerdings nicht zwingend auf denselben Blöcken.
pub(crate) fn remove_file(path: &Path, overwrite: bool) -> std::io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let p = with_suffix(path, suffix);
        if overwrite
            && suffix != "-shm"
            && let Ok(file) = std::fs::OpenOptions::new().write(true).open(&p)
        {
            let mut left = file.metadata()?.len();
            let mut out = BufWriter::with_capacity(1 << 20, &file);
            let zeros = vec![0u8; 1 << 20];
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                out.write_all(&zeros[..n])?;
                left -= n as u64;
            }
            out.flush()?;
            drop(out);
            file.sync_all()?;
        }
        match std::fs::remove_file(&p) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
    }
    Ok(())
}

/// Pfad mit angehängtem Suffix (`flows.db` → `flows.db-wal`)
pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

pub(crate) fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Summe der Dateigrößen in einem Verzeichnis (nicht rekursiv).
pub(crate) fn dir_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|entries| entries.flatten().filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

/// `20260930-134507` (UTC)
pub(crate) fn fmt_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", s / 3600, s % 3600 / 60, s % 60)
}

pub(crate) fn parse_utc(text: &str) -> Option<i64> {
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
    fn hour_names_roundtrip_utc() {
        // 2026-09-30 13:45:07 UTC
        let ms = 1_790_775_907_000;
        assert_eq!(fmt_utc(ms), "20260930-134507");
        assert_eq!(parse_utc("20260930-134507"), Some(ms));
        let hour = hour_of(ms);
        assert_eq!(hour_name(hour), "flows_20260930-13.db");
        assert_eq!(parse_hour_name("flows_20260930-13.db", ""), Some(hour));
        assert_eq!(parse_hour_name("flows_20260930-13.db.zst", PACKED_EXT), Some(hour));
        for bad in ["flows_20260930-13.db-wal", "flows_20260930-1.db", "index.db", "flows_20261330-13.db"] {
            assert_eq!(parse_hour_name(bad, ""), None, "{bad}");
        }
    }
}
