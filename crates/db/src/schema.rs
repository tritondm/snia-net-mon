use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// Verbindung mit den Pragmas öffnen, die jede Verbindung braucht. `secure_delete`: gelöschte Inhalte in der Datei
/// überschreiben (kostet beim Löschen viel Schreibarbeit, siehe `storage.secure_delete`).
pub(crate) fn open_connection(path: &Path, secure_delete: bool) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;      -- im WAL-Modus sicher gegen Korruption, nur die letzten ms können bei Stromausfall fehlen
         PRAGMA secure_delete = {};
         PRAGMA journal_size_limit = 67108864; -- WAL nach einem Checkpoint auf höchstens 64 MiB kürzen
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -65536;       -- 64 MiB Seiten-Cache pro Verbindung
         PRAGMA mmap_size = 268435456;",
        if secure_delete { "ON" } else { "OFF" }
    ))?;
    Ok(conn)
}

/// Schema anlegen bzw. aktualisieren. `writable = false` für entpackte Archive: dort wird nie geschrieben, das
/// Entfernen der Spalte `bucket` (schreibt die ganze Tabelle neu) wird übersprungen.
pub(crate) fn migrate(conn: &Connection, writable: bool) -> rusqlite::Result<()> {
    create(conn)?;
    // Dateien aus der ersten Version haben noch keine Richtungs-Spalte
    let has_dir: bool = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name = 'dir'", [], |r| r.get::<_, i64>(0))? > 0;
    if !has_dir {
        conn.execute_batch("ALTER TABLE flows ADD COLUMN dir INTEGER NOT NULL DEFAULT 0;")?;
    }
    // Version 2: Voraggregation – bei bestehenden Dateien einmalig aus den gespeicherten Flows aufbauen
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 2 {
        let started = std::time::Instant::now();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = crate::rollup::create_tables(conn)
            .and_then(|_| crate::rollup::backfill(conn))
            .and_then(|_| conn.execute_batch("PRAGMA user_version = 2; COMMIT"));
        if let Err(err) = result {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(err);
        }
        tracing::info!(ms = started.elapsed().as_millis() as u64, "Aggregat-Tabellen angelegt");
    }
    // Version 3: Spalte `bucket` (nie abgefragt) und Index auf dst_port (vom Port-Filter `src_port = ? OR dst_port = ?`
    // nie genutzt) entfallen – ein B-Baum und eine Spalte weniger pro Insert
    if version < 3 && writable {
        let has_bucket: bool =
            conn.query_row("SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name = 'bucket'", [], |r| r.get::<_, i64>(0))? > 0;
        let started = std::time::Instant::now();
        if has_bucket {
            tracing::info!("Datenbank wird umgestellt (Spalte bucket entfällt) – bei großen Dateien dauert das einige Minuten");
        }
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            conn.execute_batch("DROP INDEX IF EXISTS idx_flows_dport_ts;")?;
            if has_bucket {
                conn.execute_batch("ALTER TABLE flows DROP COLUMN bucket;")?;
            }
            conn.execute_batch("PRAGMA user_version = 3; COMMIT")
        })();
        if let Err(err) = result {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(err);
        }
        if has_bucket {
            tracing::info!(ms = started.elapsed().as_millis() as u64, "Datenbank umgestellt");
        }
    }
    Ok(())
}

/// Schlüssel/Wert-Tabelle der Historie (z. B. `moved_until`: bis wohin Flows aus der Live-Datenbank übernommen sind).
pub(crate) fn create_meta(conn: &Connection) -> rusqlite::Result<()> {
    create_meta_in(conn, "main")
}

pub(crate) fn create_meta_in(conn: &Connection, schema: &str) -> rusqlite::Result<()> {
    conn.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {schema}.meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);"))
}

fn create(conn: &Connection) -> rusqlite::Result<()> {
    // auto_vacuum muss vor dem Anlegen der ersten Tabelle gesetzt sein (bei bestehenden Dateien wirkungslos)
    conn.execute_batch(
        "PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS flows (
             id        INTEGER PRIMARY KEY,
             ts        INTEGER NOT NULL,   -- Flow-Ende, Unix-ms
             start_ts  INTEGER NOT NULL,   -- Flow-Beginn, Unix-ms
             src_ip    BLOB    NOT NULL,   -- 16 Byte, IPv4 als IPv4-mapped IPv6
             dst_ip    BLOB    NOT NULL,
             src_port  INTEGER NOT NULL,
             dst_port  INTEGER NOT NULL,
             proto     INTEGER NOT NULL,
             bytes     INTEGER NOT NULL,
             packets   INTEGER NOT NULL,
             tcp_flags INTEGER NOT NULL,
             in_if     INTEGER NOT NULL,
             out_if    INTEGER NOT NULL,
             exporter  BLOB    NOT NULL,
             dir       INTEGER NOT NULL DEFAULT 0  -- 0 extern, 1 in, 2 out, 3 intern (model::Direction)
         );
         CREATE INDEX IF NOT EXISTS idx_flows_ts       ON flows (ts);
         CREATE INDEX IF NOT EXISTS idx_flows_src_ts   ON flows (src_ip, ts);
         CREATE INDEX IF NOT EXISTS idx_flows_dst_ts   ON flows (dst_ip, ts);
         CREATE TABLE IF NOT EXISTS pcap_analyses (
             id         INTEGER PRIMARY KEY,
             created_ms INTEGER NOT NULL,   -- Zeitpunkt der Analyse, Unix-ms (Grundlage der Retention)
             name       TEXT    NOT NULL,   -- ursprünglicher Dateiname
             size       INTEGER NOT NULL,   -- Dateigröße in Byte
             packets    INTEGER NOT NULL,
             bytes      INTEGER NOT NULL,
             result     TEXT    NOT NULL    -- Analyse-Ergebnis als JSON
         );
         CREATE INDEX IF NOT EXISTS idx_pcap_created ON pcap_analyses (created_ms);",
    )
}
