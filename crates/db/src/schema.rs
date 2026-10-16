use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// Verbindung mit den Pragmas öffnen, die jede Verbindung braucht. `secure_delete`: gelöschte Inhalte in der Datei
/// überschreiben (siehe `storage.secure_delete`).
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

/// Tabellen der Index-Datenbank: Aggregate, PCAP-Analysen, Schlüssel/Wert-Tabelle (in der Historie z. B. `moved_until`:
/// bis wohin Daten aus der Live-Datenbank übernommen sind).
pub(crate) fn create_index(conn: &Connection) -> rusqlite::Result<()> {
    // auto_vacuum muss vor dem Anlegen der ersten Tabelle gesetzt sein (bei bestehenden Dateien wirkungslos)
    conn.execute_batch(
        "PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS pcap_analyses (
             id         INTEGER PRIMARY KEY,
             created_ms INTEGER NOT NULL,   -- Zeitpunkt der Analyse, Unix-ms (Grundlage der Retention)
             name       TEXT    NOT NULL,   -- ursprünglicher Dateiname
             size       INTEGER NOT NULL,   -- Dateigröße in Byte
             packets    INTEGER NOT NULL,
             bytes      INTEGER NOT NULL,
             result     TEXT    NOT NULL    -- Analyse-Ergebnis als JSON
         );
         CREATE INDEX IF NOT EXISTS idx_pcap_created ON pcap_analyses (created_ms);
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);",
    )?;
    crate::rollup::create_tables(conn)
}

/// Tabelle der Einzel-Flows in einer Stundendatei, die unter `schema` angehängt ist.
pub(crate) fn create_flows(conn: &Connection, schema: &str) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {schema}.flows (
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
             dir       INTEGER NOT NULL    -- 0 extern, 1 in, 2 out, 3 intern (model::Direction)
         );
         CREATE INDEX IF NOT EXISTS {schema}.idx_flows_ts     ON flows (ts);
         CREATE INDEX IF NOT EXISTS {schema}.idx_flows_src_ts ON flows (src_ip, ts);
         CREATE INDEX IF NOT EXISTS {schema}.idx_flows_dst_ts ON flows (dst_ip, ts);"
    ))
}
