//! Lese-Abfragen: Flow-Suche und Aggregationen für die Dashboard-Widgets.

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

#[derive(Debug, Clone, Serialize)]
pub struct SankeyNode {
    pub id: String,
    pub label: String,
    /// "src", "service" oder "dst" – bestimmt die Spalte im Diagramm.
    pub kind: &'static str,
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

/// Dienst-Port eines Flows: der kleinere der beiden Ports. softflowd exportiert Anfrage (Client → Server) und Antwort
/// (Server → Client) getrennt; bei der Antwort steht der Dienst-Port (443, 53, 22 …) auf der Quellseite, der
/// Client-Port ist in beiden Fällen der größere (ephemere) Port.
const SERVICE_PORT: &str = "MIN(src_port, dst_port)";

/// Aus einem Filter gebaute WHERE-Klausel mit Parametern.
struct Where {
    sql: String,
    params: Vec<Value>,
    from: i64,
    to: i64,
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
        let w = self.build_where(&filter)?;
        let limit = filter.limit.unwrap_or(10).clamp(1, 100) as i64;
        let seconds = ((w.to - w.from) as f64 / 1000.0).max(1.0);
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT ip, SUM(bytes), SUM(packets), COUNT(*) FROM (
                    SELECT src_ip AS ip, bytes, packets FROM flows WHERE {0}
                    UNION ALL
                    SELECT dst_ip AS ip, bytes, packets FROM flows WHERE {0}
                 ) GROUP BY ip ORDER BY 2 DESC LIMIT {limit}",
                w.sql
            );
            let params: Vec<&Value> = w.params.iter().chain(w.params.iter()).collect();
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
        let w = self.build_where(&filter)?;
        let limit = filter.limit.unwrap_or(10).clamp(1, 100) as i64;
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT {SERVICE_PORT} AS port, proto, SUM(bytes), COUNT(*) FROM flows
                 WHERE {} AND proto IN (6, 17, 132)
                 GROUP BY port, proto ORDER BY 3 DESC LIMIT {limit}",
                w.sql
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
                let proto: u8 = r.get(1)?;
                Ok(PortStat { port: r.get(0)?, proto, proto_name: proto_name(proto), bytes: r.get(2)?, flows: r.get(3)? })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    pub async fn protocols(&self, filter: FlowFilter) -> Result<Vec<ProtocolStat>> {
        let w = self.build_where(&filter)?;
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT proto, SUM(bytes), SUM(packets), COUNT(*) FROM flows WHERE {} GROUP BY proto ORDER BY 2 DESC",
                w.sql
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
                let proto: u8 = r.get(0)?;
                Ok(ProtocolStat { proto, proto_name: proto_name(proto), bytes: r.get(1)?, packets: r.get(2)?, flows: r.get(3)? })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Zeitreihe mit ca. `points` Stützstellen über das Zeitfenster.
    pub async fn timeseries(&self, filter: FlowFilter, points: u32) -> Result<(i64, Vec<TimePoint>)> {
        let w = self.build_where(&filter)?;
        let points = points.clamp(10, 1000) as i64;
        let step = ((w.to - w.from) / points).max(1000);
        self.with_reader(move |conn| {
            let sql = format!(
                "SELECT (ts / {step}) * {step} AS slot, SUM(bytes), SUM(packets), COUNT(*),
                        SUM(CASE WHEN dir = 1 THEN bytes ELSE 0 END), SUM(CASE WHEN dir = 2 THEN bytes ELSE 0 END)
                 FROM flows WHERE {} GROUP BY slot ORDER BY slot",
                w.sql
            );
            let mut stmt = conn.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
                Ok(TimePoint { ts: r.get(0)?, bytes: r.get(1)?, packets: r.get(2)?, flows: r.get(3)?, bytes_in: r.get(4)?, bytes_out: r.get(5)? })
            })?;
            Ok((step, rows.collect::<rusqlite::Result<Vec<_>>>()?))
        })
        .await
    }

    /// Verkehr je Richtung (Download, Upload, intern, extern) im Zeitfenster.
    pub async fn directions(&self, filter: FlowFilter) -> Result<Vec<DirectionStat>> {
        let w = self.build_where(&filter)?;
        let seconds = ((w.to - w.from) as f64 / 1000.0).max(1.0);
        let found = self
            .with_reader(move |conn| {
                let sql = format!("SELECT dir, SUM(bytes), SUM(packets), COUNT(*) FROM flows WHERE {} GROUP BY dir", w.sql);
                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
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

    /// Sankey-Graph: Quelle → Dienst (Protokoll/Port) → Ziel, die `limit` stärksten Verbindungen nach Bytes.
    pub async fn sankey(&self, filter: FlowFilter) -> Result<SankeyGraph> {
        let w = self.build_where(&filter)?;
        let limit = filter.limit.unwrap_or(25).clamp(1, 200) as i64;
        let rows = self
            .with_reader(move |conn| {
                let sql = format!(
                    "SELECT src_ip, proto, {SERVICE_PORT} AS port, dst_ip, SUM(bytes) FROM flows WHERE {}
                     GROUP BY src_ip, proto, port, dst_ip ORDER BY 5 DESC LIMIT {limit}",
                    w.sql
                );
                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(w.params.iter()), |r| {
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
            graph.nodes.push(SankeyNode { id, label, kind });
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
