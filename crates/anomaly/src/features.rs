//! Merkmale je internem Host und Zeitfenster.
//!
//! Jeder Flow wird dem internen Host zugeordnet, der ihn verursacht: bei `out` und `internal` der Quelle, bei `in` dem
//! Ziel. Gezählt werden Volumen, Flows, verschiedene Gegenstellen, Dienste und Länder, dazu die Rohdaten der festen
//! Regeln (fehlgeschlagene TCP-Verbindungsversuche, DNS an externe Resolver).

use geo::GeoLookup;
use model::{Direction, FlowRecord, LocalNetworks};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const FEATURES: usize = 7;
pub const UP: usize = 0;
pub const DOWN: usize = 1;
pub const FLOWS: usize = 2;
pub const EXT_PEERS: usize = 3;
pub const INT_PEERS: usize = 4;
pub const PORTS: usize = 5;
pub const COUNTRIES: usize = 6;

/// Anzeigenamen der Merkmale (Reihenfolge wie die Indizes oben).
pub const NAMES: [&str; FEATURES] = ["upload", "download", "flows", "externe ziele", "interne ziele", "ports", "länder"];

/// Merkmale, deren Wert eine Datenmenge in Byte ist (für die Anzeige).
pub fn is_bytes(feature: usize) -> bool {
    feature == UP || feature == DOWN
}

/// Obergrenze je Menge, damit ein Scan über viele Adressen den Speicher nicht sprengt. Mehr braucht keine Schwelle.
const SET_CAP: usize = 50_000;

/// Zähler eines Hosts in einem Fenster.
#[derive(Debug, Default)]
pub struct HostWindow {
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Flows, die der Host selbst sendet (`out` und `internal`)
    pub flows: u64,
    pub ext_peers: HashSet<IpAddr>,
    pub int_peers: HashSet<IpAddr>,
    /// Dienste: jeweils der kleinere der beiden Ports, wie in Top Ports und Sankey
    pub ports: HashSet<u16>,
    /// Ländercode → hochgeladene Bytes
    pub countries: HashMap<String, u64>,
    /// Fehlgeschlagene TCP-Verbindungsversuche (SYN ohne ACK): Ziel und Port
    pub probes: HashSet<(IpAddr, u16)>,
    /// DNS (53, 853) an nicht erlaubte externe Resolver: Resolver → Flows
    pub dns: HashMap<IpAddr, u64>,
}

impl HostWindow {
    /// Rohwerte der Merkmale.
    pub fn values(&self) -> [f64; FEATURES] {
        let mut v = [0.0; FEATURES];
        v[UP] = self.bytes_up as f64;
        v[DOWN] = self.bytes_down as f64;
        v[FLOWS] = self.flows as f64;
        v[EXT_PEERS] = self.ext_peers.len() as f64;
        v[INT_PEERS] = self.int_peers.len() as f64;
        v[PORTS] = self.ports.len() as f64;
        v[COUNTRIES] = self.countries.len() as f64;
        v
    }

    /// Anteil des Uploads am Gesamtvolumen (0 … 1).
    pub fn upload_share(&self) -> f64 {
        let total = self.bytes_up + self.bytes_down;
        if total == 0 { 0.0 } else { self.bytes_up as f64 / total as f64 }
    }
}

/// Welche Hosts ausgewertet werden und welche externen Resolver erlaubt sind.
pub struct Filters {
    pub ignore: LocalNetworks,
    pub dns_servers: LocalNetworks,
}

/// Alle Hosts eines Zeitfensters.
pub struct Window {
    pub start_ms: i64,
    /// `true`, wenn das Fenster erst nach seinem Beginn angefangen wurde (Programmstart) – die Werte sind dann zu klein
    /// und fließen nicht in Baseline und Statistik ein.
    pub partial: bool,
    pub hosts: HashMap<IpAddr, HostWindow>,
    countries: HashMap<IpAddr, Option<String>>,
}

impl Window {
    pub fn new(start_ms: i64, partial: bool) -> Self {
        Self { start_ms, partial, hosts: HashMap::new(), countries: HashMap::new() }
    }

    pub fn add(&mut self, flow: &FlowRecord, filters: &Filters, geo: &GeoLookup) {
        let (host, peer) = match flow.direction {
            Direction::Out | Direction::Internal => (flow.src_ip, flow.dst_ip),
            Direction::In => (flow.dst_ip, flow.src_ip),
            Direction::External => return,
        };
        if filters.ignore.contains(host) {
            return;
        }
        let h = self.hosts.entry(host).or_default();
        if flow.direction == Direction::In {
            h.bytes_down = h.bytes_down.saturating_add(flow.bytes);
            return;
        }
        h.flows += 1;
        if h.ports.len() < SET_CAP {
            h.ports.insert(flow.src_port.min(flow.dst_port));
        }
        // SYN ohne ACK: Verbindungsversuch, der nie zustande kam (typisch für Portscans)
        if flow.proto == 6 && flow.tcp_flags & 0x02 != 0 && flow.tcp_flags & 0x10 == 0 && h.probes.len() < SET_CAP {
            h.probes.insert((peer, flow.dst_port));
        }
        if flow.direction == Direction::Internal {
            if h.int_peers.len() < SET_CAP {
                h.int_peers.insert(peer);
            }
            return;
        }
        h.bytes_up = h.bytes_up.saturating_add(flow.bytes);
        if h.ext_peers.len() < SET_CAP {
            h.ext_peers.insert(peer);
        }
        if matches!(flow.proto, 6 | 17) && matches!(flow.dst_port, 53 | 853) && !filters.dns_servers.contains(peer) {
            *h.dns.entry(peer).or_default() += 1;
        }
        let cc = self.countries.entry(peer).or_insert_with(|| geo.lookup(peer).cc);
        if let Some(cc) = cc {
            *h.countries.entry(cc.clone()).or_default() += flow.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn flow(src: &str, dst: &str, src_port: u16, dst_port: u16, bytes: u64, flags: u8, direction: Direction) -> FlowRecord {
        FlowRecord {
            ts_ms: 0,
            start_ms: 0,
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port,
            dst_port,
            proto: 6,
            bytes,
            packets: 3,
            tcp_flags: flags,
            in_if: 0,
            out_if: 0,
            exporter: "192.0.2.1".parse().unwrap(),
            direction,
        }
    }

    #[test]
    fn flows_are_counted_for_the_internal_host() {
        let filters = Filters { ignore: LocalNetworks::parse(&["192.168.1.99"]).unwrap(), dns_servers: LocalNetworks::parse(&["9.9.9.9"]).unwrap() };
        let geo = GeoLookup::disabled();
        let mut w = Window::new(0, false);
        w.add(&flow("192.168.1.10", "203.0.113.5", 50000, 443, 1000, 0x1b, Direction::Out), &filters, &geo);
        w.add(&flow("203.0.113.5", "192.168.1.10", 443, 50000, 90_000, 0x1b, Direction::In), &filters, &geo);
        w.add(&flow("192.168.1.10", "192.168.1.20", 50001, 445, 500, 0x1b, Direction::Internal), &filters, &geo);
        w.add(&flow("192.168.1.10", "198.51.100.7", 50002, 22, 60, 0x02, Direction::Out), &filters, &geo);
        w.add(&flow("192.168.1.10", "8.8.8.8", 50003, 53, 80, 0, Direction::Out), &filters, &geo);
        w.add(&flow("192.168.1.10", "9.9.9.9", 50004, 53, 80, 0, Direction::Out), &filters, &geo);
        // ignorierter Host und Verkehr ohne internen Beteiligten zählen nicht
        w.add(&flow("192.168.1.99", "203.0.113.5", 50000, 443, 1000, 0x1b, Direction::Out), &filters, &geo);
        w.add(&flow("203.0.113.1", "203.0.113.2", 1, 2, 1000, 0, Direction::External), &filters, &geo);

        assert_eq!(w.hosts.len(), 1);
        let h = &w.hosts[&"192.168.1.10".parse().unwrap()];
        assert_eq!(h.values(), [1220.0, 90_000.0, 5.0, 4.0, 1.0, 4.0, 0.0]);
        assert_eq!(h.probes.len(), 1);
        assert_eq!(h.dns.len(), 1, "nur der nicht erlaubte Resolver");
        assert!((h.upload_share() - 1220.0 / 91_220.0).abs() < 1e-9);
    }
}
