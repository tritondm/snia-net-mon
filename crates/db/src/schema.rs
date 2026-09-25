use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// Verbindung mit den Pragmas öffnen, die jede Verbindung braucht.
pub(crate) fn open_connection(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;      -- im WAL-Modus sicher gegen Korruption, nur die letzten ms können bei Stromausfall fehlen
         PRAGMA secure_delete = ON;        -- gelöschte Inhalte werden in der Datei überschrieben
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -65536;       -- 64 MiB Seiten-Cache pro Verbindung
         PRAGMA mmap_size = 268435456;",
    )?;
    Ok(conn)
}

pub(crate) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    create(conn)?;
    // Dateien aus der ersten Version haben noch keine Richtungs-Spalte
    let has_dir: bool = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name = 'dir'", [], |r| r.get::<_, i64>(0))? > 0;
    if !has_dir {
        conn.execute_batch("ALTER TABLE flows ADD COLUMN dir INTEGER NOT NULL DEFAULT 0;")?;
    }
    Ok(())
}

fn create(conn: &Connection) -> rusqlite::Result<()> {
    // auto_vacuum muss vor dem Anlegen der ersten Tabelle gesetzt sein (bei bestehenden Dateien wirkungslos)
    conn.execute_batch(
        "PRAGMA auto_vacuum = INCREMENTAL;
         CREATE TABLE IF NOT EXISTS flows (
             id        INTEGER PRIMARY KEY,
             ts        INTEGER NOT NULL,   -- Flow-Ende, Unix-ms
             start_ts  INTEGER NOT NULL,   -- Flow-Beginn, Unix-ms
             bucket    INTEGER NOT NULL,   -- Stunden-Partition: ts / 3600000
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
         CREATE INDEX IF NOT EXISTS idx_flows_dport_ts ON flows (dst_port, ts);",
    )
}
