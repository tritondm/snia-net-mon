//! Live-Ansicht: hält die aktiven Verbindungen der letzten Sekunden im Speicher und verteilt jede Sekunde einen
//! kompakten Snapshot per Broadcast an alle WebSocket-Clients. Der Snapshot wird einmal serialisiert und dann nur noch
//! geteilt – die Kosten sind unabhängig von der Anzahl der Clients.

use collector::{CollectorMetrics, MetricsSnapshot};
use geo::{GeoInfo, GeoLookup};
use model::{Direction, FlowKey, FlowRecord, now_ms, proto_name};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch};

/// Verbindungen ohne neue Flow-Daten seit so vielen Millisekunden gelten als beendet.
const ACTIVE_TTL_MS: i64 = 90_000;
const TOP_CONNECTIONS: usize = 150;
const HISTORY_POINTS: usize = 300;

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConnection {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub proto_name: &'static str,
    pub direction: Direction,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Bytes, die in der letzten Sekunde dazukamen.
    pub recent_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_geo: Option<GeoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RatePoint {
    pub ts: i64,
    pub bytes: u64,
    /// davon eingehend (Download) bzw. ausgehend (Upload) – Rest ist interner/externer Verkehr
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
    pub flows: u64,
}

impl RatePoint {
    const fn empty(ts: i64) -> Self {
        Self { ts, bytes: 0, bytes_in: 0, bytes_out: 0, packets: 0, flows: 0 }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LiveMessage<'a> {
    Tick {
        ts: i64,
        rate: RatePoint,
        active: usize,
        connections: &'a [ActiveConnection],
        collector: MetricsSnapshot,
    },
    History {
        points: Vec<RatePoint>,
    },
}

struct Entry {
    direction: Direction,
    first_seen: i64,
    last_seen: i64,
    bytes: u64,
    packets: u64,
    flows: u64,
    recent_bytes: u64,
}

#[derive(Clone)]
pub struct LiveHub {
    tx: broadcast::Sender<Arc<str>>,
    history: Arc<Mutex<VecDeque<RatePoint>>>,
}

impl LiveHub {
    /// Hub starten: konsumiert Flow-Batches vom Collector und sendet jede Sekunde einen Snapshot.
    pub fn spawn(
        mut rx: mpsc::Receiver<Arc<Vec<FlowRecord>>>,
        metrics: Arc<CollectorMetrics>,
        geo: Arc<GeoLookup>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Self {
        let (tx, _) = broadcast::channel(16);
        let hub = Self { tx: tx.clone(), history: Arc::new(Mutex::new(VecDeque::with_capacity(HISTORY_POINTS))) };
        let history = hub.history.clone();
        tokio::spawn(async move {
            let mut table: HashMap<FlowKey, Entry> = HashMap::new();
            let mut window = RatePoint::empty(0);
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    batch = rx.recv() => {
                        let Some(batch) = batch else { return };
                        let now = now_ms();
                        for flow in batch.iter() {
                            window.bytes += flow.bytes;
                            match flow.direction {
                                Direction::In => window.bytes_in += flow.bytes,
                                Direction::Out => window.bytes_out += flow.bytes,
                                Direction::Internal | Direction::External => {}
                            }
                            window.packets += flow.packets;
                            window.flows += 1;
                            let entry = table.entry(flow.key()).or_insert(Entry {
                                direction: flow.direction,
                                first_seen: flow.start_ms.min(now),
                                last_seen: now,
                                bytes: 0,
                                packets: 0,
                                flows: 0,
                                recent_bytes: 0,
                            });
                            entry.last_seen = now;
                            entry.bytes += flow.bytes;
                            entry.packets += flow.packets;
                            entry.flows += 1;
                            entry.recent_bytes += flow.bytes;
                        }
                    }
                    _ = ticker.tick() => {
                        let now = now_ms();
                        table.retain(|_, e| now - e.last_seen <= ACTIVE_TTL_MS);
                        let rate = RatePoint { ts: now, ..window };
                        window = RatePoint::empty(now);
                        {
                            let mut h = history.lock().expect("History-Mutex");
                            if h.len() == HISTORY_POINTS {
                                h.pop_front();
                            }
                            h.push_back(rate);
                        }
                        if tx.receiver_count() > 0 {
                            let connections = top_connections(&table, &geo);
                            let message = LiveMessage::Tick { ts: now, rate, active: table.len(), connections: &connections, collector: metrics.snapshot() };
                            if let Ok(json) = serde_json::to_string(&message) {
                                let _ = tx.send(Arc::from(json));
                            }
                        }
                        table.values_mut().for_each(|e| e.recent_bytes = 0);
                    }
                    _ = shutdown.changed() => if *shutdown.borrow() { return },
                }
            }
        });
        hub
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.tx.subscribe()
    }

    /// Verlauf der letzten Minuten – bekommt jeder Client beim Verbinden, damit der Chart sofort gefüllt ist.
    pub fn history_message(&self) -> String {
        let points = self.history.lock().expect("History-Mutex").iter().copied().collect();
        serde_json::to_string(&LiveMessage::History { points }).unwrap_or_default()
    }
}

/// Die Verbindungen mit dem meisten aktuellen Verkehr (dann Gesamtvolumen) – partielle Sortierung, O(n).
fn top_connections(table: &HashMap<FlowKey, Entry>, geo: &GeoLookup) -> Vec<ActiveConnection> {
    let mut entries: Vec<(&FlowKey, &Entry)> = table.iter().collect();
    let rank = |e: &Entry| (e.recent_bytes, e.bytes);
    if entries.len() > TOP_CONNECTIONS {
        entries.select_nth_unstable_by(TOP_CONNECTIONS, |a, b| rank(b.1).cmp(&rank(a.1)));
        entries.truncate(TOP_CONNECTIONS);
    }
    entries.sort_unstable_by_key(|e| std::cmp::Reverse(rank(e.1)));
    entries
        .into_iter()
        .map(|(k, e)| ActiveConnection {
            src_ip: k.src_ip.to_string(),
            dst_ip: k.dst_ip.to_string(),
            src_port: k.src_port,
            dst_port: k.dst_port,
            proto: k.proto,
            proto_name: proto_name(k.proto),
            direction: e.direction,
            bytes: e.bytes,
            packets: e.packets,
            flows: e.flows,
            first_seen: e.first_seen,
            last_seen: e.last_seen,
            recent_bytes: e.recent_bytes,
            src_geo: geo.lookup_opt(k.src_ip),
            dst_geo: geo.lookup_opt(k.dst_ip),
        })
        .collect()
}
