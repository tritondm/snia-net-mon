//! Voraggregation für die Dashboard-Statistiken.
//!
//! Neben jedem Flow schreibt der Writer in derselben Transaktion Summen je Minute und je Stunde in drei Arten von
//! Tabellen (jeweils `_1m` und `_1h`):
//!
//! | Tabelle     | Schlüssel                                   | dient für                                 |
//! |-------------|---------------------------------------------|-------------------------------------------|
//! | `agg_ip`    | Zeit, Richtung, IP (Quelle und Ziel)        | Top Talker, Länder/ASN                    |
//! | `agg_svc`   | Zeit, Richtung, Protokoll, Dienst-Port      | Top Ports, Protokolle, Richtungen, Zeitreihe |
//! | `agg_pair`  | Zeit, Richtung, Quelle, Ziel, Protokoll, Dienst-Port | Sankey, Gegenstellen je Talker   |
//!
//! Eine Abfrage zerlegt ihr Zeitfenster in volle Stunden, volle Minuten und die Ränder davor/danach. Volle Stunden und
//! Minuten kommen aus den Aggregaten, nur die Ränder (unter einer Minute) aus den Einzel-Flows – das Ergebnis ist exakt
//! dasselbe wie über die Rohdaten, liest aber statt Millionen Flows nur einige tausend Summenzeilen.

use model::{FlowRecord, ip_to_bytes};
use rusqlite::{Connection, Transaction, params};
use std::collections::HashMap;
use std::hash::Hash;

pub(crate) const MINUTE_MS: i64 = 60_000;
pub(crate) const HOUR_MS: i64 = 3_600_000;

/// Dienst-Port eines Flows: der kleinere der beiden Ports. softflowd exportiert Anfrage (Client → Server) und Antwort
/// (Server → Client) getrennt; bei der Antwort steht der Dienst-Port (443, 53, 22 …) auf der Quellseite, der
/// Client-Port ist in beiden Fällen der größere (ephemere) Port. Protokolle ohne Ports (ICMP …) bekommen 0.
pub(crate) const SERVICE_PORT_SQL: &str = "CASE WHEN proto IN (6, 17, 132) THEN MIN(src_port, dst_port) ELSE 0 END";

fn service_port(flow: &FlowRecord) -> u16 {
    match flow.proto {
        6 | 17 | 132 => flow.src_port.min(flow.dst_port),
        _ => 0,
    }
}

/// Zeitauflösung einer Datenquelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Raw,
    Minute,
    Hour,
}

impl Level {
    pub(crate) fn ms(self) -> i64 {
        match self {
            Level::Raw => 1,
            Level::Minute => MINUTE_MS,
            Level::Hour => HOUR_MS,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Level::Raw => unreachable!("Rohdaten haben keine Aggregat-Tabelle"),
            Level::Minute => "1m",
            Level::Hour => "1h",
        }
    }

    fn finer(self) -> Level {
        match self {
            Level::Hour => Level::Minute,
            _ => Level::Raw,
        }
    }
}

const LEVELS: [Level; 2] = [Level::Minute, Level::Hour];

/// Art der Aggregat-Tabelle.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    Ip,
    Svc,
    Pair,
}

impl Kind {
    const ALL: [Kind; 3] = [Kind::Ip, Kind::Svc, Kind::Pair];

    fn name(self) -> &'static str {
        match self {
            Kind::Ip => "agg_ip",
            Kind::Svc => "agg_svc",
            Kind::Pair => "agg_pair",
        }
    }

    /// Schlüsselspalten nach `t`
    fn key_columns(self) -> &'static str {
        match self {
            Kind::Ip => "dir, ip",
            Kind::Svc => "dir, proto, port",
            Kind::Pair => "dir, src_ip, dst_ip, proto, port",
        }
    }

    fn key_ddl(self) -> &'static str {
        match self {
            Kind::Ip => "dir INTEGER NOT NULL, ip BLOB NOT NULL",
            Kind::Svc => "dir INTEGER NOT NULL, proto INTEGER NOT NULL, port INTEGER NOT NULL",
            Kind::Pair => "dir INTEGER NOT NULL, src_ip BLOB NOT NULL, dst_ip BLOB NOT NULL, proto INTEGER NOT NULL, port INTEGER NOT NULL",
        }
    }

    /// Spalten, die eine Datenquelle dieser Art liefert (Rohdaten und Aggregat einheitlich)
    fn select_columns(self) -> &'static str {
        match self {
            Kind::Ip => "ip, bytes, packets, flows",
            Kind::Svc => "t, dir, proto, port, bytes, packets, flows",
            Kind::Pair => "src_ip, dst_ip, proto, port, bytes, packets, flows",
        }
    }

    /// Dieselben Spalten aus den Einzel-Flows; `{c}` ist die WHERE-Bedingung.
    fn raw_select(self, cond: &str) -> String {
        match self {
            Kind::Ip => format!(
                "SELECT src_ip AS ip, bytes, packets, 1 AS flows FROM flows WHERE {cond}
                 UNION ALL SELECT dst_ip, bytes, packets, 1 FROM flows WHERE {cond}"
            ),
            Kind::Svc => format!("SELECT ts AS t, dir, proto, {SERVICE_PORT_SQL} AS port, bytes, packets, 1 AS flows FROM flows WHERE {cond}"),
            Kind::Pair => format!("SELECT src_ip, dst_ip, proto, {SERVICE_PORT_SQL} AS port, bytes, packets, 1 AS flows FROM flows WHERE {cond}"),
        }
    }

    /// Wie oft die Parameter der Bedingung in [`raw_select`](Self::raw_select) vorkommen
    fn raw_param_repeat(self) -> usize {
        match self {
            Kind::Ip => 2,
            _ => 1,
        }
    }

    pub(crate) fn table(self, level: Level) -> String {
        format!("{}_{}", self.name(), level.suffix())
    }
}

pub(crate) fn tables() -> impl Iterator<Item = String> {
    Kind::ALL.into_iter().flat_map(|kind| LEVELS.into_iter().map(move |level| kind.table(level)))
}

pub(crate) fn create_tables(conn: &Connection) -> rusqlite::Result<()> {
    for kind in Kind::ALL {
        for level in LEVELS {
            conn.execute_batch(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                     t       INTEGER NOT NULL,   -- Beginn der Minute/Stunde, Unix-ms
                     {keys},
                     bytes   INTEGER NOT NULL,
                     packets INTEGER NOT NULL,
                     flows   INTEGER NOT NULL,
                     PRIMARY KEY (t, {key_columns})
                 ) WITHOUT ROWID;",
                table = kind.table(level),
                keys = kind.key_ddl(),
                key_columns = kind.key_columns(),
            ))?;
        }
    }
    Ok(())
}

/// Aggregate aus bereits gespeicherten Flows aufbauen (einmalig beim Upgrade einer bestehenden Datenbank).
pub(crate) fn backfill(conn: &Connection) -> rusqlite::Result<()> {
    let minute = |col: &str| format!("({col} / {MINUTE_MS}) * {MINUTE_MS}");
    let t = minute("ts");
    for kind in Kind::ALL {
        let table = kind.table(Level::Minute);
        let sql = match kind {
            Kind::Ip => format!(
                "INSERT INTO {table} SELECT t, dir, ip, SUM(bytes), SUM(packets), COUNT(*) FROM (
                     SELECT {t} AS t, dir, src_ip AS ip, bytes, packets FROM flows
                     UNION ALL SELECT {t}, dir, dst_ip, bytes, packets FROM flows
                 ) GROUP BY 1, 2, 3"
            ),
            Kind::Svc => format!(
                "INSERT INTO {table} SELECT {t}, dir, proto, {SERVICE_PORT_SQL}, SUM(bytes), SUM(packets), COUNT(*) FROM flows GROUP BY 1, 2, 3, 4"
            ),
            Kind::Pair => format!(
                "INSERT INTO {table} SELECT {t}, dir, src_ip, dst_ip, proto, {SERVICE_PORT_SQL}, SUM(bytes), SUM(packets), COUNT(*)
                 FROM flows GROUP BY 1, 2, 3, 4, 5, 6"
            ),
        };
        conn.execute(&sql, [])?;
        // Stunden aus den Minuten
        let keys = kind.key_columns();
        conn.execute(
            &format!(
                "INSERT INTO {hour} SELECT (t / {HOUR_MS}) * {HOUR_MS}, {keys}, SUM(bytes), SUM(packets), SUM(flows)
                 FROM {table} GROUP BY 1, {keys}",
                hour = kind.table(Level::Hour),
            ),
            [],
        )?;
    }
    Ok(())
}

#[derive(Default, Clone, Copy)]
struct Sums {
    bytes: i64,
    packets: i64,
    flows: i64,
}

impl Sums {
    fn add(&mut self, bytes: i64, packets: i64) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.packets = self.packets.saturating_add(packets);
        self.flows += 1;
    }
}

type Ip = [u8; 16];

/// Summen einer Schreib-Transaktion je Zeitauflösung – erst im Speicher zusammengefasst, dann per Upsert geschrieben.
#[derive(Default)]
struct LevelSums {
    ip: HashMap<(i64, u8, Ip), Sums>,
    svc: HashMap<(i64, u8, u8, u16), Sums>,
    pair: HashMap<(i64, u8, Ip, Ip, u8, u16), Sums>,
}

#[derive(Default)]
pub(crate) struct Rollup {
    levels: [LevelSums; 2],
}

impl Rollup {
    pub(crate) fn add(&mut self, flow: &FlowRecord) {
        let bytes = flow.bytes.min(i64::MAX as u64) as i64;
        let packets = flow.packets.min(i64::MAX as u64) as i64;
        let dir = flow.direction.as_u8();
        let (src, dst) = (ip_to_bytes(flow.src_ip), ip_to_bytes(flow.dst_ip));
        let port = service_port(flow);
        for (sums, level) in self.levels.iter_mut().zip(LEVELS) {
            let t = flow.ts_ms.div_euclid(level.ms()) * level.ms();
            sums.ip.entry((t, dir, src)).or_default().add(bytes, packets);
            sums.ip.entry((t, dir, dst)).or_default().add(bytes, packets);
            sums.svc.entry((t, dir, flow.proto, port)).or_default().add(bytes, packets);
            sums.pair.entry((t, dir, src, dst, flow.proto, port)).or_default().add(bytes, packets);
        }
    }

    pub(crate) fn write(&self, tx: &Transaction) -> rusqlite::Result<()> {
        for (sums, level) in self.levels.iter().zip(LEVELS) {
            upsert(tx, Kind::Ip, level, &sums.ip, |stmt, &(t, dir, ip), s| {
                stmt.execute(params![t, dir, &ip[..], s.bytes, s.packets, s.flows])
            })?;
            upsert(tx, Kind::Svc, level, &sums.svc, |stmt, &(t, dir, proto, port), s| {
                stmt.execute(params![t, dir, proto, port, s.bytes, s.packets, s.flows])
            })?;
            upsert(tx, Kind::Pair, level, &sums.pair, |stmt, &(t, dir, src, dst, proto, port), s| {
                stmt.execute(params![t, dir, &src[..], &dst[..], proto, port, s.bytes, s.packets, s.flows])
            })?;
        }
        Ok(())
    }
}

fn upsert<K: Eq + Hash>(
    tx: &Transaction,
    kind: Kind,
    level: Level,
    rows: &HashMap<K, Sums>,
    exec: impl Fn(&mut rusqlite::CachedStatement, &K, &Sums) -> rusqlite::Result<usize>,
) -> rusqlite::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let keys = kind.key_columns();
    let placeholders = vec!["?"; keys.split(',').count() + 4].join(", ");
    let mut stmt = tx.prepare_cached(&format!(
        "INSERT INTO {table} (t, {keys}, bytes, packets, flows) VALUES ({placeholders})
         ON CONFLICT (t, {keys}) DO UPDATE SET
             bytes = bytes + excluded.bytes, packets = packets + excluded.packets, flows = flows + excluded.flows",
        table = kind.table(level),
    ))?;
    for (key, sums) in rows {
        exec(&mut stmt, key, sums)?;
    }
    Ok(())
}

/// Ein Zeitabschnitt einer Abfrage `[lo, hi)`: Einzel-Flows oder eine Aggregat-Tabelle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
    pub level: Level,
    pub lo: i64,
    pub hi: i64,
}

/// `[lo, hi)` in möglichst grobe Abschnitte zerlegen, höchstens bis zur Auflösung `max`.
pub(crate) fn segments(lo: i64, hi: i64, max: Level) -> Vec<Segment> {
    let mut out = Vec::new();
    split(lo, hi, max, &mut out);
    out
}

fn split(lo: i64, hi: i64, level: Level, out: &mut Vec<Segment>) {
    if lo >= hi {
        return;
    }
    if level == Level::Raw {
        out.push(Segment { level, lo, hi });
        return;
    }
    let ms = level.ms();
    let (a, b) = ((lo + ms - 1).div_euclid(ms) * ms, hi.div_euclid(ms) * ms);
    if a < b {
        split(lo, a, level.finer(), out);
        out.push(Segment { level, lo: a, hi: b });
        split(b, hi, level.finer(), out);
    } else {
        split(lo, hi, level.finer(), out);
    }
}

/// Datenquelle für eine Aggregations-Abfrage: `UNION ALL` über die Abschnitte, mit einheitlichen Spalten je [`Kind`].
pub(crate) fn source(kind: Kind, segments: &[Segment], dir: Option<u8>) -> (String, Vec<rusqlite::types::Value>) {
    use rusqlite::types::Value;
    let dir_sql = if dir.is_some() { " AND dir = ?" } else { "" };
    let mut parts = Vec::with_capacity(segments.len());
    let mut params = Vec::new();
    for seg in segments {
        let mut seg_params = vec![Value::Integer(seg.lo), Value::Integer(seg.hi)];
        seg_params.extend(dir.map(|d| Value::Integer(d as i64)));
        if seg.level == Level::Raw {
            parts.push(kind.raw_select(&format!("ts >= ? AND ts < ?{dir_sql}")));
            for _ in 0..kind.raw_param_repeat() {
                params.extend(seg_params.iter().cloned());
            }
        } else {
            parts.push(format!("SELECT {} FROM {} WHERE t >= ? AND t < ?{dir_sql}", kind.select_columns(), kind.table(seg.level)));
            params.extend(seg_params);
        }
    }
    (parts.join("\nUNION ALL "), params)
}

/// Datenquelle nur aus den Einzel-Flows mit beliebiger Filterbedingung (für Filter, die die Aggregate nicht kennen).
pub(crate) fn raw_source(kind: Kind, cond: &str, cond_params: &[rusqlite::types::Value]) -> (String, Vec<rusqlite::types::Value>) {
    let params = (0..kind.raw_param_repeat()).flat_map(|_| cond_params.iter().cloned()).collect();
    (kind.raw_select(cond), params)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: i64 = MINUTE_MS;
    const H: i64 = HOUR_MS;

    #[test]
    fn window_is_split_into_hours_minutes_and_raw_edges() {
        let base = 1000 * H;
        let segs = segments(base + 5 * M + 7, base + 3 * H + 2 * M + 30, Level::Hour);
        let expected = [
            (Level::Raw, base + 5 * M + 7, base + 6 * M),
            (Level::Minute, base + 6 * M, base + H),
            (Level::Hour, base + H, base + 3 * H),
            (Level::Minute, base + 3 * H, base + 3 * H + 2 * M),
            (Level::Raw, base + 3 * H + 2 * M, base + 3 * H + 2 * M + 30),
        ];
        assert_eq!(segs, expected.map(|(level, lo, hi)| Segment { level, lo, hi }));
        // lückenlos und ohne Überlappung
        assert!(segs.windows(2).all(|w| w[0].hi == w[1].lo));

        assert_eq!(segments(base, base + 2 * H, Level::Hour), vec![Segment { level: Level::Hour, lo: base, hi: base + 2 * H }]);
        assert_eq!(segments(base + 10, base + 50, Level::Hour), vec![Segment { level: Level::Raw, lo: base + 10, hi: base + 50 }]);
        assert!(segments(base, base + 2 * H, Level::Minute).iter().all(|s| s.level == Level::Minute));
        assert!(segments(base, base, Level::Hour).is_empty());
    }
}
