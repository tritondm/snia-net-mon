//! Lese-Abfragen: Flow-Suche und Aggregationen für die Dashboard-Widgets.

use crate::rollup::{self, Kind, Level};
use crate::{Database, DbError, Result};
use model::{Direction, cidr_range, ip_from_bytes, now_ms, proto_name};
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Filter für Suche und Aggregationen. Alle Felder optional; Zeitangaben in Unix-ms.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowFilter {
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// IP oder CIDR – trifft Quelle ODER Ziel.
    pub ip: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    /// Port – trifft Quell- ODER Zielport.
    pub port: Option<u16>,
    pub proto: Option<u8>,
    /// Richtung: `in`, `out`, `internal` oder `external` (leer = alle).
    pub dir: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRow {
    pub id: i64,
    pub ts: i64,
    pub start_ts: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub proto_name: &'static str,
    pub bytes: i64,
    pub packets: i64,
    pub tcp_flags: u8,
    pub exporter: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Serialize)]
pub struct TalkerStat {
    pub ip: String,
    pub bytes: i64,
    pub packets: i64,
    pub flows: i64,
    /// Mittlere Bandbreite über das Zeitfenster in Bit/s.
    pub bps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortStat {
    pub port: u16,
    pub proto: u8,
    pub proto_name: &'static str,
    pub bytes: i64,
    pub flows: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolStat {
    pub proto: u8,
    pub proto_name: &'static str,
    pub bytes: i64,
    pub packets: i64,
    pub flows: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimePoint {
    pub ts: i64,
    pub bytes: i64,
    /// davon eingehend (Download) bzw. ausgehend (Upload)
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub packets: i64,
    pub flows: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectionStat {
    pub direction: Direction,
    pub bytes: i64,
    pub packets: i64,
    pub flows: i64,
    /// Mittlere Bandbreite über das Zeitfenster in Bit/s.
    pub bps: f64,
}

/// Verbindung (5-Tupel) mit dem summierten Verkehr aller ihrer Flows im Zeitfenster.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionStat {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub proto_name: &'static str,
    pub direction: Direction,
    pub bytes: i64,
    pub packets: i64,
    pub flows: i64,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// Verkehr zwischen zwei IPs über einen Dienst (Protokoll + Dienst-Port), Client-Ports zusammengefasst.
#[derive(Debug, Clone, Serialize)]
pub struct PeerStat {
    pub src_ip: String,
    pub dst_ip: String,
    pub proto: u8,
    pub proto_name: &'static str,
    /// Dienst-Port (der kleinere der beiden Ports); 0 bei Protokollen ohne Ports
    pub port: u16,
    pub bytes: i64,
    pub packets: i64,
    pub flows: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SankeyNode {
    pub id: String,
    pub label: String,
    /// "src", "service" oder "dst" – bestimmt die Spalte im Diagramm.
    pub kind: &'static str,
    /// Ländercode der IP (wird von der API aus GeoIP ergänzt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SankeyLink {
    pub source: String,
    pub target: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SankeyGraph {
    pub nodes: Vec<SankeyNode>,
    pub links: Vec<SankeyLink>,
}

/// Aus einem Filter gebaute WHERE-Klausel mit Parametern.
struct Where {
    sql: String,
    params: Vec<Value>,
    from: i64,
    to: i64,
}

/// Datenquelle einer Aggregations-Abfrage: Aggregate + Rand-Flows, oder nur Einzel-Flows, wenn der Filter Felder
/// enthält, die in den Aggregaten nicht vorkommen (IP, Port, Protokoll).
struct Plan {
    w: Where,
    rollup: Option<(Vec<rollup::Segment>, Option<u8>)>,
}

impl Plan {
    fn source(&self, kind: Kind) -> (String, Vec<Value>) {
        match &self.rollup {
            Some((segments, dir)) => rollup::source(kind, segments, *dir),
            None => rollup::raw_source(kind, &self.w.sql, &self.w.params),
        }
    }

    fn seconds(&self) -> f64 {
        ((self.w.to - self.w.from) as f64 / 1000.0).max(1.0)
    }
}

impl Database {
    fn build_where(&self, f: &FlowFilter) -> Result<Where> {
        let floor = self.retention_floor_ms();
        let to = f.to.unwrap_or_else(now_ms);
        // Nie Daten außerhalb des Retention-Fensters liefern – auch nicht, wenn der Cleanup noch nicht gelaufen ist
        let from = f.from.unwrap_or(to - 3_600_000).max(floor);
        if from > to {
            return Err(DbError::InvalidFilter("Zeitfenster: from liegt nach to".into()));
        }
        let mut sql = String::from("ts >= ? AND ts <= ?");
        let mut params = vec![Value::Integer(from), Value::Integer(to)];

        let range = |label: &str, input: &Option<String>| -> Result<Option<(Vec<u8>, Vec<u8>)>> {
            match input.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => Ok(None),
                Some(s) => cidr_range(s)
                    .map(|(lo, hi)| Some((lo.to_vec(), hi.to_vec())))
                    .ok_or_else(|| DbError::InvalidFilter(format!("{label}: keine gültige IP/CIDR: {s}"))),
            }
        };
        if let Some((lo, hi)) = range("ip", &f.ip)? {
            sql.push_str(" AND ((src_ip BETWEEN ? AND ?) OR (dst_ip BETWEEN ? AND ?))");
            params.extend([Value::Blob(lo.clone()), Value::Blob(hi.clone()), Value::Blob(lo), Value::Blob(hi)]);
        }
        if let Some((lo, hi)) = range("src", &f.src)? {
            sql.push_str(" AND src_ip BETWEEN ? AND ?");
            params.extend([Value::Blob(lo), Value::Blob(hi)]);
        }
        if let Some((lo, hi)) = range("dst", &f.dst)? {
            sql.push_str(" AND dst_ip BETWEEN ? AND ?");
            params.extend([Value::Blob(lo), Value::Blob(hi)]);
        }
        if let Some(port) = f.port {
            sql.push_str(" AND (src_port = ? OR dst_port = ?)");
            params.extend([Value::Integer(port as i64), Value::Integer(port as i64)]);
        }
        if let Some(proto) = f.proto {
            sql.push_str(" AND proto = ?");
            params.push(Value::Integer(proto as i64));
        }
        if let Some(dir) = f.dir.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let dir = Direction::parse(dir).ok_or_else(|| DbError::InvalidFilter(format!("dir: erlaubt sind in, out, internal, external – nicht {dir}")))?;
            sql.push_str(" AND dir = ?");
            params.push(Value::Integer(dir.as_u8() as i64));
        }
        Ok(Where { sql, params, from, to })
    }

    /// Abfrageplan für Statistiken; `max` begrenzt die gröbste Zeitauflösung der Aggregate.
    fn plan(&self, f: &FlowFilter, max: Level) -> Result<Plan> {
        let w = self.build_where(f)?;
        let blank = |v: &Option<String>| v.as_deref().is_none_or(|s| s.trim().is_empty());
        let aggregatable = blank(&f.ip) && blank(&f.src) && blank(&f.dst) && f.port.is_none() && f.proto.is_none();
        if !aggregatable || max == Level::Raw || !self.inner.rollups.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(Plan { w, rollup: None });
        }
        let dir = f.dir.as_deref().map(str::trim).filter(|s| !s.is_empty()).and_then(Direction::parse).map(Direction::as_u8);
        // `to` ist inklusive, Abschnitte sind halboffen
        let segments = rollup::segments(w.from, w.to + 1, max);
        Ok(Plan { w, rollup: Some((segments, dir)) })
    }

    #[cfg(test)]
    pub(crate) fn set_rollups(&self, on: bool) {
        self.inner.rollups.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Flows suchen (neueste zuerst).
    pub async fn query_flows(&self, filter: FlowFilter) -> Result<Vec<FlowRow>> {
        let w = self.build_where(&filter)?;
        let limit = filter.limit.unwrap_or(500).clamp(1, 5000) as i64;
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT id, ts, start_ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, tcp_flags, exporter, dir
                 FROM flows WHERE {} ORDER BY ts DESC LIMIT {limit}",
                w.sql
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
                let proto: u8 = r.get(7)?;
                Ok(FlowRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    start_ts: r.get(2)?,
                    src_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(3)?).to_string(),
                    dst_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(4)?).to_string(),
                    src_port: r.get(5)?,
                    dst_port: r.get(6)?,
                    proto,
                    proto_name: proto_name(proto),
                    bytes: r.get(8)?,
                    packets: r.get(9)?,
                    tcp_flags: r.get(10)?,
                    exporter: ip_from_bytes(&r.get::<_, Vec<u8>>(11)?).to_string(),
                    direction: Direction::from_u8(r.get(12)?),
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Top Talker: Summe über Quelle UND Ziel je IP (eine IP zählt, egal in welche Richtung sie Verkehr erzeugt).
    pub async fn top_talkers(&self, filter: FlowFilter) -> Result<Vec<TalkerStat>> {
        let limit = filter.limit.unwrap_or(10).clamp(1, 100);
        self.talkers(filter, limit).await
    }

    /// Volumen je IP für bis zu `limit` IPs (Grundlage der Länder-/ASN-Statistik).
    pub async fn ip_totals(&self, filter: FlowFilter, limit: u32) -> Result<Vec<TalkerStat>> {
        self.talkers(filter, limit.clamp(1, 100_000)).await
    }

    async fn talkers(&self, filter: FlowFilter, limit: u32) -> Result<Vec<TalkerStat>> {
        let plan = self.plan(&filter, Level::Hour)?;
        let seconds = plan.seconds();
        self.with_reader(move |conn| {
            let (source, params) = plan.source(Kind::Ip);
            let sql = format!("SELECT ip, SUM(bytes), SUM(packets), SUM(flows) FROM ({source}) GROUP BY ip ORDER BY 2 DESC LIMIT {limit}");
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                let bytes: i64 = r.get(1)?;
                Ok(TalkerStat {
                    ip: ip_from_bytes(&r.get::<_, Vec<u8>>(0)?).to_string(),
                    bytes,
                    packets: r.get(2)?,
                    flows: r.get(3)?,
                    bps: bytes as f64 * 8.0 / seconds,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Top Dienst-Ports (nur TCP/UDP/SCTP – ICMP hat keine Ports).
    pub async fn top_ports(&self, filter: FlowFilter) -> Result<Vec<PortStat>> {
        let plan = self.plan(&filter, Level::Hour)?;
        let limit = filter.limit.unwrap_or(10).clamp(1, 100) as i64;
        self.with_reader(move |conn| {
            let (source, params) = plan.source(Kind::Svc);
            let sql = format!(
                "SELECT port, proto, SUM(bytes), SUM(flows) FROM ({source})
                 WHERE proto IN (6, 17, 132) GROUP BY port, proto ORDER BY 3 DESC LIMIT {limit}"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                let proto: u8 = r.get(1)?;
                Ok(PortStat { port: r.get(0)?, proto, proto_name: proto_name(proto), bytes: r.get(2)?, flows: r.get(3)? })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn protocols(&self, filter: FlowFilter) -> Result<Vec<ProtocolStat>> {
        let plan = self.plan(&filter, Level::Hour)?;
        self.with_reader(move |conn| {
            let (source, params) = plan.source(Kind::Svc);
            let sql = format!("SELECT proto, SUM(bytes), SUM(packets), SUM(flows) FROM ({source}) GROUP BY proto ORDER BY 2 DESC");
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                let proto: u8 = r.get(0)?;
                Ok(ProtocolStat { proto, proto_name: proto_name(proto), bytes: r.get(1)?, packets: r.get(2)?, flows: r.get(3)? })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Zeitreihe mit ca. `points` Stützstellen über das Zeitfenster. Ab einer Minute Schrittweite wird der Schritt auf
    /// ganze Minuten (ab einer Stunde auf ganze Stunden) gerundet, damit jede Stützstelle ganze Aggregate enthält.
    pub async fn timeseries(&self, filter: FlowFilter, points: u32) -> Result<(i64, Vec<TimePoint>)> {
        let w = self.build_where(&filter)?;
        let points = points.clamp(10, 1000) as i64;
        let mut step = ((w.to - w.from) / points).max(1000);
        let level = [Level::Hour, Level::Minute].into_iter().find(|l| step >= l.ms()).unwrap_or(Level::Raw);
        step = (step + level.ms() - 1) / level.ms() * level.ms();
        let plan = self.plan(&filter, level)?;
        self.with_reader(move |conn| {
            let (source, params) = plan.source(Kind::Svc);
            let sql = format!(
                "SELECT (t / {step}) * {step} AS slot, SUM(bytes), SUM(packets), SUM(flows),
                        SUM(CASE WHEN dir = 1 THEN bytes ELSE 0 END), SUM(CASE WHEN dir = 2 THEN bytes ELSE 0 END)
                 FROM ({source}) GROUP BY slot ORDER BY slot"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                Ok(TimePoint { ts: r.get(0)?, bytes: r.get(1)?, packets: r.get(2)?, flows: r.get(3)?, bytes_in: r.get(4)?, bytes_out: r.get(5)? })
            })?;
            Ok((step, rows.collect::<rusqlite::Result<Vec<_>>>()?))
        })
        .await
    }

    /// Verkehr je Richtung (Download, Upload, intern, extern) im Zeitfenster.
    pub async fn directions(&self, filter: FlowFilter) -> Result<Vec<DirectionStat>> {
        let plan = self.plan(&filter, Level::Hour)?;
        let seconds = plan.seconds();
        let found = self
            .with_reader(move |conn| {
                let (source, params) = plan.source(Kind::Svc);
                let sql = format!("SELECT dir, SUM(bytes), SUM(packets), SUM(flows) FROM ({source}) GROUP BY dir");
                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                    Ok((Direction::from_u8(r.get(0)?), r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
                })?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await?;
        // Immer alle vier Richtungen liefern (auch mit 0), in fester Reihenfolge
        Ok(Direction::ALL
            .into_iter()
            .map(|direction| {
                let (bytes, packets, flows) = found
                    .iter()
                    .find(|(d, ..)| *d == direction)
                    .map(|&(_, b, p, f)| (b, p, f))
                    .unwrap_or((0, 0, 0));
                DirectionStat { direction, bytes, packets, flows, bps: bytes as f64 * 8.0 / seconds }
            })
            .collect())
    }

    /// Verbindungen (5-Tupel) mit dem meisten Verkehr im Zeitfenster.
    pub async fn connections(&self, filter: FlowFilter) -> Result<Vec<ConnectionStat>> {
        let w = self.build_where(&filter)?;
        let limit = filter.limit.unwrap_or(200).clamp(1, 2000) as i64;
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT src_ip, dst_ip, src_port, dst_port, proto, MAX(dir), SUM(bytes), SUM(packets), COUNT(*), MIN(start_ts), MAX(ts)
                 FROM flows WHERE {} GROUP BY src_ip, dst_ip, src_port, dst_port, proto ORDER BY 7 DESC LIMIT {limit}",
                w.sql
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
                let proto: u8 = r.get(4)?;
                Ok(ConnectionStat {
                    src_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(0)?).to_string(),
                    dst_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(1)?).to_string(),
                    src_port: r.get(2)?,
                    dst_port: r.get(3)?,
                    proto,
                    proto_name: proto_name(proto),
                    direction: Direction::from_u8(r.get(5)?),
                    bytes: r.get(6)?,
                    packets: r.get(7)?,
                    flows: r.get(8)?,
                    first_seen: r.get(9)?,
                    last_seen: r.get(10)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Stärkste Gegenstellen-Paare (Quelle, Ziel, Dienst) im Zeitfenster – Client-Ports zusammengefasst.
    pub async fn peers(&self, filter: FlowFilter) -> Result<Vec<PeerStat>> {
        let plan = self.plan(&filter, Level::Hour)?;
        let limit = filter.limit.unwrap_or(200).clamp(1, 5000) as i64;
        self.with_reader(move |conn| {
            let (source, params) = plan.source(Kind::Pair);
            let sql = format!(
                "SELECT src_ip, dst_ip, proto, port, SUM(bytes), SUM(packets), SUM(flows) FROM ({source})
                 GROUP BY src_ip, dst_ip, proto, port ORDER BY 5 DESC LIMIT {limit}"
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                let proto: u8 = r.get(2)?;
                Ok(PeerStat {
                    src_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(0)?).to_string(),
                    dst_ip: ip_from_bytes(&r.get::<_, Vec<u8>>(1)?).to_string(),
                    proto,
                    proto_name: proto_name(proto),
                    port: r.get(3)?,
                    bytes: r.get(4)?,
                    packets: r.get(5)?,
                    flows: r.get(6)?,
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Sankey-Graph: Quelle → Dienst (Protokoll/Port) → Ziel, die `limit` stärksten Verbindungen nach Bytes.
    pub async fn sankey(&self, filter: FlowFilter) -> Result<SankeyGraph> {
        let plan = self.plan(&filter, Level::Hour)?;
        let limit = filter.limit.unwrap_or(25).clamp(1, 200) as i64;
        let rows = self
            .with_reader(move |conn| {
                let (source, params) = plan.source(Kind::Pair);
                let sql = format!(
                    "SELECT src_ip, proto, port, dst_ip, SUM(bytes) FROM ({source})
                     GROUP BY src_ip, proto, port, dst_ip ORDER BY 5 DESC LIMIT {limit}"
                );
                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                    Ok((
                        ip_from_bytes(&r.get::<_, Vec<u8>>(0)?).to_string(),
                        r.get::<_, u8>(1)?,
                        r.get::<_, u16>(2)?,
                        ip_from_bytes(&r.get::<_, Vec<u8>>(3)?).to_string(),
                        r.get::<_, i64>(4)?,
                    ))
                })?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await?;
        Ok(build_sankey(rows))
    }
}

fn build_sankey(rows: Vec<(String, u8, u16, String, i64)>) -> SankeyGraph {
    let mut graph = SankeyGraph::default();
    let mut seen: HashMap<String, ()> = HashMap::new();
    let mut links: HashMap<(String, String), i64> = HashMap::new();
    let mut add_node = |graph: &mut SankeyGraph, id: String, label: String, kind: &'static str| {
        if seen.insert(id.clone(), ()).is_none() {
            graph.nodes.push(SankeyNode { id, label, kind, cc: None });
        }
    };
    for (src, proto, port, dst, bytes) in rows {
        let service_label = match proto {
            6 | 17 | 132 => format!("{}/{}", proto_name(proto), port),
            _ => proto_name(proto).to_string(),
        };
        // Präfixe halten die Spalten getrennt, auch wenn eine IP Quelle und Ziel zugleich ist (sonst entstünden Zyklen)
        let (src_id, svc_id, dst_id) = (format!("s:{src}"), format!("p:{service_label}"), format!("d:{dst}"));
        add_node(&mut graph, src_id.clone(), src, "src");
        add_node(&mut graph, svc_id.clone(), service_label, "service");
        add_node(&mut graph, dst_id.clone(), dst, "dst");
        *links.entry((src_id, svc_id.clone())).or_default() += bytes;
        *links.entry((svc_id, dst_id)).or_default() += bytes;
    }
    let mut links: Vec<SankeyLink> = links.into_iter().map(|((source, target), value)| SankeyLink { source, target, value }).collect();
    links.sort_by_key(|l| std::cmp::Reverse(l.value));
    graph.links = links;
    graph
}
