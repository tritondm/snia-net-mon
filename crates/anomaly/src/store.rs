//! Eigene kleine SQLite-Datei (`anomaly.db`): Baselines je Gruppe und Slot, bekannte Länder je Gruppe, Trainingsvektoren
//! für den Isolation Forest (**ohne IP-Adresse**) und die gemeldeten Auffälligkeiten.

use crate::baseline::{Profile, Stat};
use crate::features::FEATURES;
use crate::forest::{DIMS, Vector};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// Art einer Auffälligkeit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// statistisch: ein oder mehrere Merkmale weit über der Baseline
    Stat,
    /// nur der Isolation Forest schlägt an
    Ml,
    Scan,
    Dns,
    Country,
    /// Verstoß gegen eine Netz-Regel
    Policy,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Stat, Kind::Ml, Kind::Scan, Kind::Dns, Kind::Country, Kind::Policy];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Stat => "stat",
            Kind::Ml => "ml",
            Kind::Scan => "scan",
            Kind::Dns => "dns",
            Kind::Country => "country",
            Kind::Policy => "policy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == value.trim())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Warn = 1,
    High = 2,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::High => "high",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Severity::Info, Severity::Warn, Severity::High].into_iter().find(|s| s.name() == value.trim().to_ascii_lowercase())
    }

    fn from_i64(value: i64) -> Self {
        match value {
            2 => Severity::High,
            1 => Severity::Warn,
            _ => Severity::Info,
        }
    }
}

/// Eine neu erkannte Auffälligkeit.
#[derive(Debug, Clone)]
pub struct Event {
    /// Ende des Fensters, in dem sie auftrat (Unix-ms)
    pub ts: i64,
    pub host: String,
    pub group: String,
    pub kind: Kind,
    /// Unterscheidet Auffälligkeiten derselben Art beim selben Host (z. B. die Netz-Regel) beim Zusammenfassen
    pub tag: String,
    pub severity: Severity,
    /// Stärke zum Vergleichen gleichartiger Ereignisse (Z-Score, ML-Score, Anzahl Versuche …)
    pub score: f64,
    pub title: String,
    pub detail: serde_json::Value,
}

/// Gespeicherte Auffälligkeit, wie die API sie ausliefert. Wiederholt sie sich in Folgefenstern, wird dieselbe Zeile
/// verlängert (`last_ts`, `count`) statt eine neue anzulegen.
#[derive(Debug, Clone, Serialize)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub last_ts: i64,
    pub count: i64,
    pub host: String,
    pub group: String,
    pub kind: &'static str,
    pub severity: &'static str,
    pub score: f64,
    pub title: String,
    pub detail: serde_json::Value,
}

/// Filter für `GET /api/anomalies`.
#[derive(Debug, Default, Deserialize)]
pub struct EventFilter {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub kind: Option<String>,
    pub host: Option<String>,
    /// Mindest-Schwere: `info`, `warn`, `high`
    pub severity: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counts {
    pub info: u64,
    pub warn: u64,
    pub high: u64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path, secure_delete: bool) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.execute_batch(&format!(
            "PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = {};
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS baselines (
                 grp  TEXT    NOT NULL,   -- Netzgruppe, z. B. 10.0.3.0/24
                 slot INTEGER NOT NULL,   -- 0–167 Wochentag × Stunde, 168–191 Stunde
                 data BLOB    NOT NULL,   -- je Merkmal n, Mittelwert, Varianz als f64 (Log-Skala)
                 PRIMARY KEY (grp, slot)
             );
             CREATE TABLE IF NOT EXISTS countries (
                 grp      TEXT    NOT NULL,
                 cc       TEXT    NOT NULL,
                 first_ms INTEGER NOT NULL,
                 PRIMARY KEY (grp, cc)
             );
             CREATE TABLE IF NOT EXISTS vectors (
                 ts   INTEGER NOT NULL,   -- Fensterende, Unix-ms
                 data BLOB    NOT NULL    -- Merkmalsvektor als f32, ohne IP-Adresse
             );
             CREATE INDEX IF NOT EXISTS idx_vectors_ts ON vectors (ts);
             CREATE TABLE IF NOT EXISTS events (
                 id       INTEGER PRIMARY KEY,
                 ts       INTEGER NOT NULL,   -- erstes Fenster (Ende, Unix-ms)
                 last_ts  INTEGER NOT NULL,   -- letztes Fenster
                 count    INTEGER NOT NULL,   -- Anzahl Fenster
                 host     TEXT    NOT NULL,
                 grp      TEXT    NOT NULL,
                 kind     TEXT    NOT NULL,
                 severity INTEGER NOT NULL,   -- 0 info, 1 warn, 2 high
                 score    REAL    NOT NULL,
                 title    TEXT    NOT NULL,
                 detail   TEXT    NOT NULL    -- JSON
             );
             CREATE INDEX IF NOT EXISTS idx_events_last ON events (last_ts);",
            if secure_delete { "ON" } else { "OFF" }
        ))?;
        Ok(Self { conn })
    }

    pub fn meta(&self, key: &str) -> rusqlite::Result<Option<i64>> {
        self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()
    }

    pub fn set_meta(&self, key: &str, value: i64) -> rusqlite::Result<()> {
        self.conn.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }

    pub fn load_baselines(&self) -> rusqlite::Result<HashMap<(String, u16), Profile>> {
        let mut stmt = self.conn.prepare("SELECT grp, slot, data FROM baselines")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u16>(1)?, r.get::<_, Vec<u8>>(2)?)))?;
        let mut map = HashMap::new();
        for row in rows {
            let (group, slot, data) = row?;
            if data.len() != FEATURES * 3 * 8 {
                continue;
            }
            let f = |i: usize| f64::from_le_bytes(data[i * 8..i * 8 + 8].try_into().expect("8 Byte"));
            let profile: Profile = std::array::from_fn(|k| Stat { n: f(k * 3), mean: f(k * 3 + 1), var: f(k * 3 + 2) });
            map.insert((group, slot), profile);
        }
        Ok(map)
    }

    pub fn save_baselines(&mut self, profiles: &[((String, u16), Profile)]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT OR REPLACE INTO baselines (grp, slot, data) VALUES (?1, ?2, ?3)")?;
            for ((group, slot), profile) in profiles {
                let data: Vec<u8> = profile.iter().flat_map(|s| [s.n, s.mean, s.var]).flat_map(f64::to_le_bytes).collect();
                stmt.execute(params![group, slot, data])?;
            }
        }
        tx.commit()
    }

    pub fn load_countries(&self) -> rusqlite::Result<HashMap<String, HashSet<String>>> {
        let mut stmt = self.conn.prepare("SELECT grp, cc FROM countries")?;
        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (group, cc) = row?;
            map.entry(group).or_default().insert(cc);
        }
        Ok(map)
    }

    pub fn add_country(&self, group: &str, cc: &str, ts: i64) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR IGNORE INTO countries (grp, cc, first_ms) VALUES (?1, ?2, ?3)", params![group, cc, ts])?;
        Ok(())
    }

    pub fn add_vectors(&mut self, ts: i64, vectors: &[Vector]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT INTO vectors (ts, data) VALUES (?1, ?2)")?;
            for v in vectors {
                let data: Vec<u8> = v.iter().flat_map(|&x| (x as f32).to_le_bytes()).collect();
                stmt.execute(params![ts, data])?;
            }
        }
        tx.commit()
    }

    pub fn vectors(&self, since: i64) -> rusqlite::Result<Vec<Vector>> {
        let mut stmt = self.conn.prepare("SELECT data FROM vectors WHERE ts >= ?1")?;
        let rows = stmt.query_map([since], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for data in rows {
            let data = data?;
            if data.len() == DIMS * 4 {
                out.push(std::array::from_fn(|i| f32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().expect("4 Byte")) as f64));
            }
        }
        Ok(out)
    }

    pub fn vector_count(&self) -> rusqlite::Result<u64> {
        self.conn.query_row("SELECT count(*) FROM vectors", [], |r| r.get::<_, i64>(0)).map(|n| n as u64)
    }

    pub fn insert_event(&self, e: &Event) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO events (ts, last_ts, count, host, grp, kind, severity, score, title, detail) VALUES (?1, ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![e.ts, e.host, e.group, e.kind.name(), e.severity as i64, e.score, e.title, e.detail.to_string()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Bestehende Auffälligkeit um ein Fenster verlängern. Ist die neue Messung stärker, ersetzt sie Text und Details;
    /// die Schwere steigt höchstens.
    pub fn extend_event(&self, id: i64, e: &Event, stronger: bool) -> rusqlite::Result<()> {
        if stronger {
            self.conn.execute(
                "UPDATE events SET last_ts = ?2, count = count + 1, severity = max(severity, ?3), score = ?4, title = ?5, detail = ?6 WHERE id = ?1",
                params![id, e.ts, e.severity as i64, e.score, e.title, e.detail.to_string()],
            )?;
        } else {
            self.conn.execute(
                "UPDATE events SET last_ts = ?2, count = count + 1, severity = max(severity, ?3) WHERE id = ?1",
                params![id, e.ts, e.severity as i64],
            )?;
        }
        Ok(())
    }

    pub fn events(&self, f: &EventFilter) -> rusqlite::Result<Vec<EventRow>> {
        let kind = f.kind.as_deref().filter(|k| !k.is_empty()).map(|k| Kind::parse(k).map(Kind::name).unwrap_or("?"));
        let severity = f.severity.as_deref().and_then(Severity::parse).unwrap_or(Severity::Info) as i64;
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, ts, last_ts, count, host, grp, kind, severity, score, title, detail FROM events
             WHERE last_ts >= ?1 AND ts <= ?2 AND (?3 IS NULL OR kind = ?3) AND (?4 IS NULL OR host = ?4) AND severity >= ?5
             ORDER BY last_ts DESC, id DESC LIMIT ?6",
        )?;
        let host = f.host.as_deref().map(str::trim).filter(|h| !h.is_empty());
        let limit = f.limit.unwrap_or(500).clamp(1, 5000);
        let rows = stmt.query_map(params![f.from.unwrap_or(0), f.to.unwrap_or(i64::MAX), kind, host, severity, limit], |r| {
            let kind: String = r.get(6)?;
            let detail: String = r.get(10)?;
            Ok(EventRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                last_ts: r.get(2)?,
                count: r.get(3)?,
                host: r.get(4)?,
                group: r.get(5)?,
                kind: Kind::parse(&kind).map(Kind::name).unwrap_or("stat"),
                severity: Severity::from_i64(r.get(7)?).name(),
                score: r.get(8)?,
                title: r.get(9)?,
                detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
            })
        })?;
        rows.collect()
    }

    /// Anzahl Auffälligkeiten je Schwere, die seit `since` noch aktiv waren.
    pub fn counts(&self, since: i64) -> rusqlite::Result<Counts> {
        let mut stmt = self.conn.prepare_cached("SELECT severity, count(*) FROM events WHERE last_ts >= ?1 GROUP BY severity")?;
        let mut counts = Counts::default();
        for row in stmt.query_map([since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64)))? {
            let (severity, n) = row?;
            match Severity::from_i64(severity) {
                Severity::Info => counts.info = n,
                Severity::Warn => counts.warn = n,
                Severity::High => counts.high = n,
            }
        }
        Ok(counts)
    }

    /// Alte Trainingsvektoren und Auffälligkeiten löschen.
    pub fn prune(&self, vectors_before: i64, events_before: i64) -> rusqlite::Result<(usize, usize)> {
        let vectors = self.conn.execute("DELETE FROM vectors WHERE ts < ?1", [vectors_before])?;
        let events = self.conn.execute("DELETE FROM events WHERE last_ts < ?1", [events_before])?;
        if vectors + events > 0 {
            self.conn.execute_batch("PRAGMA incremental_vacuum;")?;
        }
        Ok((vectors, events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("snm-anomaly-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("anomaly.db")
    }

    fn event(ts: i64, kind: Kind, severity: Severity) -> Event {
        Event {
            ts,
            host: "10.0.0.5".into(),
            group: "10.0.0.0/24".into(),
            kind,
            tag: String::new(),
            severity,
            score: 1.0,
            title: "test".into(),
            detail: serde_json::json!({ "x": 1 }),
        }
    }

    #[test]
    fn roundtrip_of_baselines_vectors_and_events() {
        let path = temp_path("store");
        let mut store = Store::open(&path, true).unwrap();
        let profile: Profile = std::array::from_fn(|i| Stat { n: 40.0, mean: i as f64, var: 0.25 });
        store.save_baselines(&[(("10.0.0.0/24".into(), 8), profile)]).unwrap();
        store.add_country("10.0.0.0/24", "AT", 1).unwrap();
        store.add_vectors(1000, &[[1.5; DIMS], [2.5; DIMS]]).unwrap();
        store.set_meta("started_ms", 42).unwrap();
        drop(store);

        let store = Store::open(&path, true).unwrap();
        assert_eq!(store.load_baselines().unwrap()[&("10.0.0.0/24".to_string(), 8)], profile);
        assert!(store.load_countries().unwrap()["10.0.0.0/24"].contains("AT"));
        assert_eq!(store.vectors(0).unwrap(), vec![[1.5; DIMS], [2.5; DIMS]]);
        assert_eq!(store.meta("started_ms").unwrap(), Some(42));

        let id = store.insert_event(&event(600_000, Kind::Stat, Severity::Warn)).unwrap();
        store.extend_event(id, &event(1_200_000, Kind::Stat, Severity::High), false).unwrap();
        store.insert_event(&event(1_200_000, Kind::Scan, Severity::Info)).unwrap();
        let rows = store.events(&EventFilter::default()).unwrap();
        assert_eq!(rows.len(), 2);
        let stat = rows.iter().find(|r| r.kind == "stat").unwrap();
        assert_eq!((stat.ts, stat.last_ts, stat.count, stat.severity), (600_000, 1_200_000, 2, "high"));
        assert_eq!(stat.detail["x"], 1);
        let only_high = store.events(&EventFilter { severity: Some("high".into()), ..Default::default() }).unwrap();
        assert_eq!(only_high.len(), 1);
        let scans = store.events(&EventFilter { kind: Some("scan".into()), ..Default::default() }).unwrap();
        assert_eq!(scans.len(), 1);
        assert!(store.events(&EventFilter { kind: Some("unsinn".into()), ..Default::default() }).unwrap().is_empty());
        let c = store.counts(0).unwrap();
        assert_eq!((c.info, c.warn, c.high), (1, 0, 1));

        assert_eq!(store.prune(2000, 1_000_000).unwrap(), (2, 0));
        assert_eq!(store.prune(2000, 1_300_000).unwrap(), (0, 2));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
