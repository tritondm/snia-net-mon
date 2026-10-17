//! Beaconing: Ein Host meldet sich in (fast) gleichen Abständen beim selben externen Ziel – typisch für Schadsoftware,
//! die ihren Steuerserver (C2) nach neuen Befehlen fragt. Volumen und Ports sind dabei unauffällig, verräterisch ist nur
//! der Rhythmus.
//!
//! Je Paar (interner Host, externes Ziel, Port, Protokoll) merkt sich der [`Tracker`] die Startzeiten der Verbindungen
//! der letzten [`HISTORY_MS`] im Speicher. Nach jedem Fenster wird ausgewertet: genug Verbindungen über eine Mindestdauer,
//! Abstände mit kleiner Streuung (Median und MAD, robust gegen einzelne ausgefallene Meldungen) und ein Ziel, das nicht
//! viele interne Hosts nutzen (das wäre eher ein Update- oder Push-Dienst).

use model::LocalNetworks;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

/// So weit zurück werden Verbindungen je Paar aufgehoben (und ausgewertet).
pub const HISTORY_MS: i64 = 12 * 3_600_000;
/// Höchstens so viele Verbindungen je Paar (die neuesten).
const MAX_CONNS: usize = 512;
/// Höchstens so viele Paare gleichzeitig – schützt den Speicher bei sehr vielen Hosts.
const MAX_PAIRS: usize = 300_000;
/// Kürzere Abstände sind kein Beacon, sondern ein Verbindungsbündel (z. B. ein Browser, der eine Seite lädt).
const MIN_INTERVAL_MS: f64 = 10_000.0;

/// (interner Host, externes Ziel, Zielport, Protokoll)
pub type Key = (IpAddr, IpAddr, u16, u8);

/// Einstellungen und Ausnahmen (`anomaly.beacon*`).
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub enabled: bool,
    /// Mindestanzahl Verbindungen im Muster
    pub min_connections: usize,
    /// Mindestdauer des Musters in Minuten
    pub min_minutes: u64,
    /// Erlaubte typische Abweichung der Abstände vom Median (0.2 = 20 %)
    pub max_jitter: f64,
    /// Nutzen so viele interne Hosts dasselbe Ziel, gilt es als normaler Dienst
    pub max_hosts: usize,
    /// Ausnahmen: interne Hosts oder externe Ziele (IP oder CIDR)
    pub allow: LocalNetworks,
    /// Ausnahmen: Ziele in diesen autonomen Systemen (z. B. 8075 Microsoft)
    pub allow_asn: HashSet<u32>,
    /// Ausnahmen: Zielports (Standard 123, NTP)
    pub allow_ports: HashSet<u16>,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_connections: 20,
            min_minutes: 120,
            max_jitter: 0.2,
            max_hosts: 10,
            allow: LocalNetworks::none(),
            allow_asn: HashSet::new(),
            allow_ports: HashSet::from([123]),
        }
    }
}

/// Land und Netz eines Ziels (für die Meldung).
#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub cc: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

#[derive(Debug, Default)]
struct Pair {
    /// (Start der Verbindung in Unix-ms, Bytes der Anfrage), aufsteigend
    conns: VecDeque<(i64, u64)>,
    /// im letzten Fenster neue Verbindungen
    updated: bool,
}

/// Ein erkanntes Muster.
#[derive(Debug, Clone)]
pub struct Finding {
    pub key: Key,
    pub connections: usize,
    /// Median der Abstände in Sekunden
    pub interval_s: f64,
    /// typische Abweichung (MAD) relativ zum Median
    pub jitter: f64,
    pub median_bytes: u64,
    pub first_ms: i64,
    pub last_ms: i64,
    /// interne Hosts, die dasselbe Ziel nutzen
    pub hosts_for_peer: usize,
}

#[derive(Debug, Default)]
pub struct Tracker {
    pairs: HashMap<Key, Pair>,
    info: HashMap<IpAddr, PeerInfo>,
    full_warned: bool,
}

impl Tracker {
    pub fn pairs(&self) -> usize {
        self.pairs.len()
    }

    pub fn info(&self, peer: &IpAddr) -> Option<&PeerInfo> {
        self.info.get(peer)
    }

    /// Verbindungen eines Fensters übernehmen und Altes verwerfen.
    pub fn merge(&mut self, conns: HashMap<Key, Vec<(i64, u64)>>, info: HashMap<IpAddr, PeerInfo>, now: i64) {
        for pair in self.pairs.values_mut() {
            pair.updated = false;
        }
        for (key, mut list) in conns {
            if !self.pairs.contains_key(&key) && self.pairs.len() >= MAX_PAIRS {
                if !self.full_warned {
                    self.full_warned = true;
                    tracing::warn!(max = MAX_PAIRS, "Beaconing: zu viele Verbindungspaare – neue werden vorerst nicht beobachtet");
                }
                continue;
            }
            list.sort_unstable();
            let pair = self.pairs.entry(key).or_default();
            for (ts, bytes) in list {
                match pair.conns.back_mut() {
                    // dieselbe Verbindung in mehreren Flow-Datensätzen (Active Timeout): zusammenzählen
                    Some(last) if last.0 == ts => last.1 = last.1.saturating_add(bytes),
                    // verspätete Datensätze vor der letzten Verbindung ignorieren
                    Some(last) if ts < last.0 => {}
                    _ => pair.conns.push_back((ts, bytes)),
                }
                pair.updated = true;
            }
            while pair.conns.len() > MAX_CONNS {
                pair.conns.pop_front();
            }
        }
        for (peer, i) in info {
            self.info.insert(peer, i);
        }
        let cutoff = now - HISTORY_MS;
        self.pairs.retain(|_, p| {
            while p.conns.front().is_some_and(|c| c.0 < cutoff) {
                p.conns.pop_front();
            }
            !p.conns.is_empty()
        });
        if self.pairs.len() < MAX_PAIRS * 9 / 10 {
            self.full_warned = false;
        }
        let peers: HashSet<IpAddr> = self.pairs.keys().map(|k| k.1).collect();
        self.info.retain(|ip, _| peers.contains(ip));
    }

    /// Paare mit neuen Verbindungen auf ein regelmäßiges Muster prüfen.
    pub fn analyze(&self, cfg: &BeaconConfig) -> Vec<Finding> {
        // Wie viele interne Hosts nutzen jedes Ziel? Ein Ziel vieler Hosts ist eher ein gewöhnlicher Dienst.
        let mut hosts_per_peer: HashMap<IpAddr, HashSet<IpAddr>> = HashMap::new();
        for (host, peer, _, _) in self.pairs.keys() {
            hosts_per_peer.entry(*peer).or_default().insert(*host);
        }
        let mut found = Vec::new();
        for (key, pair) in &self.pairs {
            let n = pair.conns.len();
            if !pair.updated || n < cfg.min_connections.max(3) {
                continue;
            }
            let hosts_for_peer = hosts_per_peer.get(&key.1).map_or(0, HashSet::len);
            if hosts_for_peer >= cfg.max_hosts.max(1) {
                continue;
            }
            let first = pair.conns.front().map_or(0, |c| c.0);
            let last = pair.conns.back().map_or(0, |c| c.0);
            if last - first < cfg.min_minutes as i64 * 60_000 {
                continue;
            }
            let gaps: Vec<f64> = pair.conns.iter().zip(pair.conns.iter().skip(1)).map(|(a, b)| (b.0 - a.0) as f64).collect();
            let interval = median(&gaps);
            if interval < MIN_INTERVAL_MS {
                continue;
            }
            let deviations: Vec<f64> = gaps.iter().map(|g| (g - interval).abs()).collect();
            let jitter = median(&deviations) / interval;
            if jitter > cfg.max_jitter {
                continue;
            }
            let bytes: Vec<f64> = pair.conns.iter().map(|c| c.1 as f64).collect();
            found.push(Finding {
                key: *key,
                connections: n,
                interval_s: interval / 1000.0,
                jitter,
                median_bytes: median(&bytes) as u64,
                first_ms: first,
                last_ms: last,
                hosts_for_peer,
            });
        }
        found.sort_by_key(|f| (f.key.0, f.key.1, f.key.2));
        found
    }
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    if v.len() % 2 == 1 { v[mid] } else { (v[mid - 1] + v[mid]) / 2.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Verbindungen alle `every` ms mit Abweichung bis `jitter` ms, beginnend bei `start`.
    fn series(start: i64, count: usize, every: i64, jitter: i64) -> Vec<(i64, u64)> {
        let mut x = 0x2545_f491_u64;
        (0..count)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let off = if jitter > 0 { (x % (2 * jitter as u64 + 1)) as i64 - jitter } else { 0 };
                (start + i as i64 * every + off, 400 + (x % 50))
            })
            .collect()
    }

    fn cfg() -> BeaconConfig {
        BeaconConfig { max_hosts: 3, ..BeaconConfig::default() }
    }

    #[test]
    fn regular_connections_are_reported_bursty_ones_not() {
        let mut t = Tracker::default();
        let beacon: Key = (ip("10.0.1.5"), ip("198.51.100.7"), 443, 6);
        let browser: Key = (ip("10.0.1.6"), ip("203.0.113.9"), 443, 6);
        let mut conns = HashMap::new();
        // alle 60 s ± 5 s über 3 Stunden
        conns.insert(beacon, series(0, 180, 60_000, 5_000));
        // unregelmäßig: Bündel mit langen Pausen
        let mut bursty: Vec<(i64, u64)> = Vec::new();
        for b in 0..12 {
            for i in 0..5 {
                bursty.push((b * 900_000 + i * 2_000 + (b * b * 37_000) % 300_000, 5_000));
            }
        }
        conns.insert(browser, bursty);
        let now = 180 * 60_000;
        t.merge(conns, HashMap::new(), now);
        let found = t.analyze(&cfg());
        assert_eq!(found.len(), 1, "{found:?}");
        let f = &found[0];
        assert_eq!(f.key, beacon);
        assert!((f.interval_s - 60.0).abs() < 2.0, "{}", f.interval_s);
        assert!(f.jitter < 0.1, "{}", f.jitter);
        assert!((400..450).contains(&f.median_bytes));
    }

    #[test]
    fn short_patterns_popular_targets_and_stale_pairs_are_skipped() {
        let mut t = Tracker::default();
        let mut conns = HashMap::new();
        // nur 30 Minuten lang
        conns.insert((ip("10.0.1.5"), ip("198.51.100.7"), 443, 6), series(0, 30, 60_000, 0));
        // dasselbe Ziel bei drei Hosts (max_hosts = 3) – ein gewöhnlicher Dienst
        for h in 10..13 {
            conns.insert((ip(&format!("10.0.1.{h}")), ip("198.51.100.8"), 443, 6), series(0, 200, 60_000, 0));
        }
        t.merge(conns, HashMap::new(), 200 * 60_000);
        assert!(t.analyze(&cfg()).is_empty());

        // ohne neue Verbindungen im nächsten Fenster wird nichts erneut gemeldet
        let mut t = Tracker::default();
        let key = (ip("10.0.1.5"), ip("198.51.100.7"), 443, 6);
        t.merge(HashMap::from([(key, series(0, 200, 60_000, 0))]), HashMap::new(), 200 * 60_000);
        assert_eq!(t.analyze(&cfg()).len(), 1);
        t.merge(HashMap::new(), HashMap::new(), 210 * 60_000);
        assert!(t.analyze(&cfg()).is_empty());
    }

    #[test]
    fn duplicates_are_merged_and_old_connections_dropped() {
        let mut t = Tracker::default();
        let key = (ip("10.0.1.5"), ip("198.51.100.7"), 443, 6);
        t.merge(HashMap::from([(key, vec![(1_000, 100), (1_000, 50), (61_000, 100)])]), HashMap::new(), 61_000);
        assert_eq!(t.pairs[&key].conns, VecDeque::from([(1_000, 150), (61_000, 100)]));
        t.merge(HashMap::new(), HashMap::new(), 61_000 + HISTORY_MS);
        assert_eq!(t.pairs[&key].conns.len(), 1);
        t.merge(HashMap::new(), HashMap::new(), 62_000 + HISTORY_MS);
        assert_eq!(t.pairs(), 0);
    }
}
