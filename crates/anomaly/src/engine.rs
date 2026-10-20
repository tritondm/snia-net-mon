//! Auswertung eines abgeschlossenen Fensters: Statistik gegen die Baseline, Isolation Forest, feste Regeln, Speichern.

use crate::AnomalyConfig;
use crate::baseline::{Baselines, SlotKind};
use crate::beacon::{self, Finding, Tracker};
use crate::features::{FEATURES, HostWindow, NAMES, PolicyHit, Window, is_bytes};
use crate::forest::{self, Forest, Rng, SHARE, TIME, Vector};
use crate::store::{Bucket, Counts, Event, EventFilter, EventRow, Kind, Severity, Store};
use jiff::tz::TimeZone;
use model::{cidr_range, ip_from_bytes, ip_to_bytes};
use serde::Serialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;
/// Wiederholt sich eine Auffälligkeit desselben Hosts innerhalb dieser Zeit, wird die bestehende verlängert.
const MERGE_GAP_MS: i64 = HOUR_MS;
/// So viele Vektoren je Fenster (zufällig gewählt) werden fürs Training aufgehoben.
const VECTORS_PER_WINDOW: usize = 100;
/// So viele Ziel-IPs speichert eine Meldung (Portscan, Netz-Regel) als Auszug
const SAMPLE_IPS: usize = 50;
/// Mindestzahl an Trainingsvektoren für den Isolation Forest.
pub const MIN_TRAIN: usize = 1000;

/// Netzgruppen: eigene Bereiche aus `anomaly.groups` (der engste gewinnt), sonst das Subnetz mit der eingestellten
/// Präfixlänge.
pub(crate) struct Groups {
    explicit: Vec<(u128, u128, String)>,
    v4: u8,
    v6: u8,
}

impl Groups {
    pub fn new(list: &[String], v4: u8, v6: u8) -> Result<Self, String> {
        let mut explicit = list
            .iter()
            .map(|entry| {
                let entry = entry.trim();
                let (lo, hi) = cidr_range(entry).ok_or_else(|| format!("ungültiges Netz: {entry:?}"))?;
                Ok((u128::from_be_bytes(lo), u128::from_be_bytes(hi), entry.to_string()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        explicit.sort_by_key(|(lo, hi, _)| hi - lo);
        Ok(Self { explicit, v4: v4.clamp(8, 32), v6: v6.clamp(16, 128) })
    }

    pub fn of(&self, ip: IpAddr) -> String {
        let value = u128::from_be_bytes(ip_to_bytes(ip));
        if let Some((_, _, name)) = self.explicit.iter().find(|(lo, hi, _)| value >= *lo && value <= *hi) {
            return name.clone();
        }
        let prefix = if ip.is_ipv4() { self.v4 } else { self.v6 };
        match cidr_range(&format!("{ip}/{prefix}")) {
            Some((lo, _)) => format!("{}/{prefix}", ip_from_bytes(&lo)),
            None => ip.to_string(),
        }
    }
}

/// Lage eines Zeitpunkts in der Woche (Ortszeit).
struct LocalTime {
    /// Wochentag (Montag = 0) × 24 + Stunde
    week_slot: u16,
    hour: f64,
    weekend: bool,
}

fn local_time(tz: &TimeZone, ms: i64) -> LocalTime {
    let Ok(ts) = jiff::Timestamp::from_millisecond(ms) else {
        return LocalTime { week_slot: 0, hour: 0.0, weekend: false };
    };
    let z = ts.to_zoned(tz.clone());
    let day = z.weekday().to_monday_zero_offset() as u16;
    LocalTime { week_slot: day * 24 + z.hour() as u16, hour: z.hour() as f64 + z.minute() as f64 / 60.0, weekend: day >= 5 }
}

struct Model {
    forest: Forest,
    /// wirksame Schwelle: `ml_threshold`, mindestens aber das 99,9-%-Quantil der Trainings-Scores
    threshold: f64,
    quantiles: forest::Quantiles,
    median: Vector,
    mad: Vector,
    trained_ms: i64,
    vectors: usize,
}

struct Open {
    id: i64,
    last_ts: i64,
    score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindowInfo {
    pub start_ms: i64,
    pub end_ms: i64,
    pub hosts: usize,
    /// Fenster nach dem Programmstart begonnen – nur Regeln, keine Statistik
    pub partial: bool,
    pub events: usize,
}

#[derive(Debug, Serialize)]
pub struct MlStatus {
    pub enabled: bool,
    /// eingestellte Mindestschwelle
    pub threshold: f64,
    /// wirksame Schwelle des aktuellen Modells
    pub effective_threshold: Option<f64>,
    /// Score-Verteilung auf den Trainingsdaten
    pub quantiles: Option<forest::Quantiles>,
    pub trained_ms: Option<i64>,
    pub trained_vectors: usize,
    pub stored_vectors: u64,
    pub min_vectors: usize,
    pub trees: usize,
    pub training_days: u64,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub window_minutes: u64,
    pub learning_days: u64,
    /// Beginn der Lernphase (erster Start mit Anomalie-Erkennung)
    pub started_ms: i64,
    pub learning: bool,
    pub timezone: String,
    pub groups: usize,
    /// Hosts mit eigenem Profil (feste Adressen)
    pub host_profiles: usize,
    pub z_threshold: f64,
    pub last_window: Option<WindowInfo>,
    pub ml: MlStatus,
    pub counts_24h: Counts,
    pub mail: bool,
    /// Anzahl Netz-Regeln und Zonen
    pub policy_rules: usize,
    pub policy_zones: usize,
    pub beacon: bool,
    /// beobachtete Verbindungspaare (Host, Ziel, Port)
    pub beacon_pairs: usize,
}

pub(crate) struct Engine {
    cfg: AnomalyConfig,
    tz: TimeZone,
    groups: Groups,
    store: Store,
    baselines: Baselines,
    countries: HashMap<String, HashSet<String>>,
    model: Option<Model>,
    started_ms: i64,
    open: HashMap<(String, Kind, String), Open>,
    last_window: Option<WindowInfo>,
    last_prune_ms: i64,
    last_train_attempt_ms: i64,
    rng: Rng,
    beacons: Tracker,
}

impl Engine {
    pub fn open(cfg: AnomalyConfig, now: i64) -> Result<Self, crate::Error> {
        let tz = match cfg.timezone.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            Some(name) => TimeZone::get(name).map_err(|e| crate::Error::Config(format!("anomaly.timezone {name:?}: {e}")))?,
            None => TimeZone::system(),
        };
        let groups = Groups::new(&cfg.groups, cfg.group_prefix_v4, cfg.group_prefix_v6).map_err(|e| crate::Error::Config(format!("anomaly.groups: {e}")))?;
        let store = Store::open(&cfg.db_path, cfg.secure_delete)?;
        let started_ms = match store.meta("started_ms")? {
            Some(ms) => ms,
            None => {
                store.set_meta("started_ms", now)?;
                now
            }
        };
        let baselines = Baselines::from_profiles(store.load_baselines()?);
        let countries = store.load_countries()?;
        Ok(Self {
            cfg,
            tz,
            groups,
            store,
            baselines,
            countries,
            model: None,
            started_ms,
            open: HashMap::new(),
            last_window: None,
            last_prune_ms: 0,
            last_train_attempt_ms: i64::MIN / 2,
            rng: Rng::new(now as u64 ^ 0x5eed_a90a),
            beacons: Tracker::default(),
        })
    }

    pub fn timezone_name(&self) -> String {
        self.tz.iana_name().unwrap_or("UTC").to_string()
    }

    fn learned(&self, now: i64) -> bool {
        now - self.started_ms >= self.cfg.learning_days as i64 * DAY_MS
    }

    fn window_ms(&self) -> i64 {
        self.cfg.window.as_millis() as i64
    }

    /// Fenster auswerten. Liefert die **neu angelegten** Auffälligkeiten (verlängerte nicht) – für den Mailversand.
    pub fn finish_window(&mut self, window: Window, now: i64) -> rusqlite::Result<Vec<Event>> {
        let end = window.start_ms + self.window_ms();
        let lt = local_time(&self.tz, window.start_ms);
        let learned = self.learned(now);
        let mut found = Vec::new();
        let mut vectors = Vec::new();

        for (ip, h) in &window.hosts {
            let group = self.groups.of(*ip);
            let host = ip.to_string();
            if !window.partial {
                let raw = h.values();
                let log = raw.map(f64::ln_1p);
                let mut hits = Vec::new();
                let mut slot = None;
                let host_key = (self.cfg.host_profiles && !self.cfg.dynamic_networks.contains(*ip)).then_some(host.as_str());
                if learned && let Some((kind, profile)) = self.baselines.reference(&group, host_key, lt.week_slot) {
                    slot = Some(kind);
                    for f in 0..FEATURES {
                        let z = profile[f].z(log[f]);
                        if z >= self.cfg.z_threshold && raw[f] >= self.cfg.minimums[f] {
                            hits.push(Hit { feature: f, value: raw[f], typical: profile[f].mean.exp_m1().max(0.0), z });
                        }
                    }
                }
                self.baselines.update(&group, host_key, lt.week_slot, &log);
                let v = forest::vector(&log, h, lt.hour, lt.weekend);
                let ml = self.model.as_ref().map(|m| (m.forest.score(&v), m));
                if !hits.is_empty() {
                    found.push(stat_event(end, &host, &group, hits, slot, ml.map(|(s, m)| (s, m.threshold)), &self.cfg));
                } else if let Some((score, model)) = ml.filter(|(s, m)| *s >= m.threshold)
                    && let Some(event) = ml_event(end, &host, &group, score, &v, model, slot)
                {
                    found.push(event);
                }
                vectors.push(v);
            }
            if self.cfg.scan_threshold > 0 && h.probes.len() >= self.cfg.scan_threshold {
                found.push(scan_event(end, &host, &group, h));
            }
            if self.cfg.dns_rule && !h.dns.is_empty() {
                found.push(dns_event(end, &host, &group, h));
            }
            for (cc, bytes) in &h.countries {
                if self.countries.entry(group.clone()).or_default().insert(cc.clone()) {
                    self.store.add_country(&group, cc, end)?;
                    if learned && self.cfg.new_country {
                        found.push(Event {
                            ts: end,
                            host: host.clone(),
                            group: group.clone(),
                            kind: Kind::Country,
                            tag: cc.clone(),
                            severity: Severity::Info,
                            score: *bytes as f64,
                            title: format!("erste verbindung der gruppe {group} nach {cc} ({} hochgeladen)", fmt_bytes(*bytes as f64)),
                            detail: json!({ "cc": cc, "bytes": bytes }),
                        });
                    }
                }
            }
        }

        if self.cfg.beacon.enabled {
            let peers: HashMap<IpAddr, beacon::PeerInfo> =
                window.beacons.keys().filter_map(|k| window.peers.get(&k.1).map(|i| (k.1, i.clone()))).collect();
            self.beacons.merge(window.beacons, peers, now);
            for f in self.beacons.analyze(&self.cfg.beacon) {
                let info = self.beacons.info(&f.key.1).cloned().unwrap_or_default();
                found.push(beacon_event(end, &self.groups.of(f.key.0), &f, &info));
            }
        }

        let mut hits: Vec<_> = window.policy.iter().collect();
        hits.sort_by_key(|((rule, host), _)| (*rule, *host));
        for ((rule, host), hit) in hits {
            if let Some(rule) = self.cfg.policy.rules.get(*rule) {
                found.push(policy_event(end, &host.to_string(), &self.groups.of(*host), rule, hit));
            }
        }

        self.store.save_baselines(&self.baselines.take_dirty())?;
        if self.cfg.ml && !vectors.is_empty() {
            // zufällige Auswahl, damit das Training alle Gruppen und Tageszeiten sieht
            for i in 0..vectors.len().min(VECTORS_PER_WINDOW) {
                let j = i + self.rng.below(vectors.len() - i);
                vectors.swap(i, j);
            }
            vectors.truncate(VECTORS_PER_WINDOW);
            self.store.add_vectors(end, &vectors)?;
        }
        let mut created = Vec::new();
        for event in found {
            if self.record(&event)? {
                created.push(event);
            }
        }
        self.last_window = Some(WindowInfo { start_ms: window.start_ms, end_ms: end, hosts: window.hosts.len(), partial: window.partial, events: created.len() });
        self.maybe_train(now)?;
        if now - self.last_prune_ms >= HOUR_MS {
            self.last_prune_ms = now;
            let (v, e) = self.store.prune(now - self.cfg.ml_training_days as i64 * DAY_MS, now - self.cfg.event_retention_days as i64 * DAY_MS)?;
            if v + e > 0 {
                tracing::debug!(vectors = v, events = e, "Anomalie-Erkennung: alte Daten gelöscht");
            }
            self.open.retain(|_, o| now - o.last_ts <= MERGE_GAP_MS + self.cfg.window.as_millis() as i64);
        }
        Ok(created)
    }

    /// Auffälligkeit speichern oder eine laufende desselben Hosts verlängern. `true` = neu angelegt.
    fn record(&mut self, event: &Event) -> rusqlite::Result<bool> {
        let key = (event.host.clone(), event.kind, event.tag.clone());
        if event.kind != Kind::Country
            && let Some(open) = self.open.get_mut(&key)
            && event.ts - open.last_ts <= MERGE_GAP_MS
        {
            let stronger = event.score > open.score;
            self.store.extend_event(open.id, event, stronger)?;
            open.last_ts = event.ts;
            open.score = open.score.max(event.score);
            return Ok(false);
        }
        let id = self.store.insert_event(event)?;
        self.open.insert(key, Open { id, last_ts: event.ts, score: event.score });
        Ok(true)
    }

    /// Isolation Forest täglich neu trainieren (mit den Vektoren der letzten `ml_training_days`). Reichen die Daten noch
    /// nicht, wird es stündlich erneut versucht.
    fn maybe_train(&mut self, now: i64) -> rusqlite::Result<()> {
        if !self.cfg.ml || !self.learned(now) {
            return Ok(());
        }
        if self.model.as_ref().is_some_and(|m| now - m.trained_ms < DAY_MS) || now - self.last_train_attempt_ms < HOUR_MS {
            return Ok(());
        }
        self.last_train_attempt_ms = now;
        let data = self.store.vectors(now - self.cfg.ml_training_days as i64 * DAY_MS)?;
        if data.len() < MIN_TRAIN {
            tracing::debug!(vectors = data.len(), needed = MIN_TRAIN, "Isolation Forest: noch zu wenige Trainingsdaten");
            return Ok(());
        }
        let started = std::time::Instant::now();
        if let Some(forest) = Forest::train(&data, forest::TREES, forest::SAMPLE, &mut self.rng) {
            let (median, mad) = forest::median_mad(&data);
            let quantiles = forest::score_quantiles(&forest, &data);
            let threshold = self.cfg.ml_threshold.max(quantiles.p999);
            tracing::info!(vectors = data.len(), threshold, p50 = quantiles.p50, ms = started.elapsed().as_millis() as u64, "Isolation Forest trainiert");
            self.model = Some(Model { forest, threshold, quantiles, median, mad, trained_ms: now, vectors: data.len() });
        }
        Ok(())
    }

    pub fn events(&self, filter: &EventFilter) -> rusqlite::Result<Vec<EventRow>> {
        self.store.events(filter)
    }

    pub fn timeline(&self, filter: &EventFilter, now: i64) -> rusqlite::Result<Vec<Bucket>> {
        self.store.timeline(filter, now)
    }

    pub fn status(&self, now: i64) -> rusqlite::Result<Status> {
        Ok(Status {
            window_minutes: self.cfg.window.as_secs() / 60,
            learning_days: self.cfg.learning_days,
            started_ms: self.started_ms,
            learning: !self.learned(now),
            timezone: self.timezone_name(),
            groups: self.baselines.groups(),
            host_profiles: self.baselines.hosts(),
            z_threshold: self.cfg.z_threshold,
            last_window: self.last_window.clone(),
            ml: MlStatus {
                enabled: self.cfg.ml,
                threshold: self.cfg.ml_threshold,
                effective_threshold: self.model.as_ref().map(|m| m.threshold),
                quantiles: self.model.as_ref().map(|m| m.quantiles),
                trained_ms: self.model.as_ref().map(|m| m.trained_ms),
                trained_vectors: self.model.as_ref().map_or(0, |m| m.vectors),
                stored_vectors: self.store.vector_count()?,
                min_vectors: MIN_TRAIN,
                trees: forest::TREES,
                training_days: self.cfg.ml_training_days,
            },
            counts_24h: self.store.counts(now - DAY_MS)?,
            mail: self.cfg.mail,
            policy_rules: self.cfg.policy.rules.len(),
            policy_zones: self.cfg.policy.zones,
            beacon: self.cfg.beacon.enabled,
            beacon_pairs: self.beacons.pairs(),
        })
    }
}

/// Ein Merkmal über der Schwelle.
struct Hit {
    feature: usize,
    value: f64,
    typical: f64,
    z: f64,
}

/// `ml`: Score und wirksame Schwelle des Isolation Forest (falls trainiert).
fn stat_event(ts: i64, host: &str, group: &str, mut hits: Vec<Hit>, slot: Option<SlotKind>, ml: Option<(f64, f64)>, cfg: &AnomalyConfig) -> Event {
    hits.sort_by(|a, b| b.z.total_cmp(&a.z));
    let top = &hits[0];
    let more = if hits.len() > 1 { format!(" · +{} weitere", hits.len() - 1) } else { String::new() };
    let title = format!(
        "{} {} statt typisch {} ({}×){more}",
        NAMES[top.feature],
        fmt_value(top.feature, top.value),
        fmt_value(top.feature, top.typical),
        fmt_factor((top.value + 1.0) / (top.typical + 1.0))
    );
    let ml_agrees = ml.is_some_and(|(score, threshold)| score >= threshold);
    let severity = if ml_agrees || top.z >= 2.0 * cfg.z_threshold { Severity::High } else { Severity::Warn };
    Event {
        ts,
        host: host.into(),
        group: group.into(),
        kind: Kind::Stat,
        tag: String::new(),
        severity,
        score: top.z,
        title,
        detail: json!({
            "features": hits.iter().map(|h| json!({
                "name": NAMES[h.feature], "value": h.value, "typical": h.typical, "z": round2(h.z), "bytes": is_bytes(h.feature),
            })).collect::<Vec<_>>(),
            "slot": slot.map(SlotKind::name),
            "ml_score": ml.map(|(score, _)| round2(score)),
            "ml_agrees": ml_agrees,
        }),
    }
}

/// ML-Treffer als Auffälligkeit – außer der Host war nur *ruhiger* als üblich (alle auffälligen Merkmale unter dem
/// Typischen): Das ist für die Sicherheit uninteressant.
fn ml_event(ts: i64, host: &str, group: &str, score: f64, v: &Vector, model: &Model, slot: Option<SlotKind>) -> Option<Event> {
    let deviations = explain(v, model);
    if !deviations.is_empty() && deviations.iter().all(|d| d.1 < d.2) {
        return None;
    }
    let names: Vec<&str> = deviations.iter().map(|d| d.0).collect();
    let reason = if names.is_empty() { "kombination aus uhrzeit und werten".to_string() } else { format!("auffällig: {}", names.join(", ")) };
    Some(Event {
        ts,
        host: host.into(),
        group: group.into(),
        kind: Kind::Ml,
        tag: String::new(),
        severity: Severity::Info,
        score,
        title: format!("ungewöhnliches gesamtmuster (ml-score {score:.2}) – {reason}"),
        detail: json!({
            "ml_score": round2(score),
            "deviations": deviations.iter().map(|(name, value, typical, kind)| json!({
                "name": name, "value": value, "typical": typical, "bytes": *kind == "bytes", "percent": *kind == "percent",
            })).collect::<Vec<_>>(),
            "slot": slot.map(SlotKind::name),
        }),
    })
}

/// Die bis zu drei Merkmale, die am stärksten vom Median der Trainingsdaten abweichen (mehr als 2 MAD-Einheiten):
/// (Name, Wert, typischer Wert, Einheit).
fn explain(v: &Vector, m: &Model) -> Vec<(&'static str, f64, f64, &'static str)> {
    let mut devs: Vec<(usize, f64)> = (0..TIME)
        .map(|d| {
            let floor = if d == SHARE { 0.1 } else { crate::baseline::MIN_STD };
            (d, (v[d] - m.median[d]).abs() / (m.mad[d] * 1.4826).max(floor))
        })
        .filter(|(_, dev)| *dev > 2.0)
        .collect();
    devs.sort_by(|a, b| b.1.total_cmp(&a.1));
    devs.truncate(3);
    devs.into_iter()
        .map(|(d, _)| {
            if d == SHARE {
                ("upload-anteil", v[d], m.median[d], "percent")
            } else {
                (NAMES[d], v[d].exp_m1().max(0.0), m.median[d].exp_m1().max(0.0), if is_bytes(d) { "bytes" } else { "count" })
            }
        })
        .collect()
}

fn scan_event(ts: i64, host: &str, group: &str, h: &HostWindow) -> Event {
    let hosts: HashSet<IpAddr> = h.probes.iter().map(|(ip, _)| *ip).collect();
    let mut ports: Vec<u16> = h.probes.iter().map(|(_, p)| *p).collect::<HashSet<_>>().into_iter().collect();
    ports.sort_unstable();
    let mut sample_hosts: Vec<String> = hosts.iter().map(IpAddr::to_string).collect();
    sample_hosts.sort();
    sample_hosts.truncate(SAMPLE_IPS);
    let attempts = h.probes.len();
    Event {
        ts,
        host: host.into(),
        group: group.into(),
        kind: Kind::Scan,
        tag: String::new(),
        severity: Severity::High,
        score: attempts as f64,
        title: format!("portscan: {attempts} fehlgeschlagene verbindungsversuche zu {} hosts auf {} ports", hosts.len(), ports.len()),
        detail: json!({
            "attempts": attempts,
            "hosts": hosts.len(),
            "ports": ports.len(),
            "sample_ports": ports.iter().take(20).collect::<Vec<_>>(),
            "sample_hosts": sample_hosts,
        }),
    }
}

fn dns_event(ts: i64, host: &str, group: &str, h: &HostWindow) -> Event {
    let mut resolvers: Vec<(IpAddr, u64)> = h.dns.iter().map(|(ip, n)| (*ip, *n)).collect();
    resolvers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let total: u64 = resolvers.iter().map(|r| r.1).sum();
    let more = if resolvers.len() > 1 { format!(" · +{} weitere", resolvers.len() - 1) } else { String::new() };
    Event {
        ts,
        host: host.into(),
        group: group.into(),
        kind: Kind::Dns,
        tag: String::new(),
        severity: Severity::Warn,
        score: total as f64,
        title: format!("dns an externen resolver {} ({} flows){more}", resolvers[0].0, resolvers[0].1),
        detail: json!({
            "resolvers": resolvers.iter().take(20).map(|(ip, n)| json!({ "ip": ip.to_string(), "flows": n })).collect::<Vec<_>>(),
            "flows": total,
        }),
    }
}

fn policy_event(ts: i64, host: &str, group: &str, rule: &crate::policy::Rule, hit: &PolicyHit) -> Event {
    let mut ports: Vec<u16> = hit.ports.iter().copied().collect();
    ports.sort_unstable();
    let mut peers: Vec<String> = hit.peers.iter().map(IpAddr::to_string).collect();
    peers.sort();
    let port_text = match ports.len() {
        0 => String::new(),
        1..=5 => format!(", ports {}", ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
        n => format!(", {n} ports"),
    };
    let peer_text = if peers.len() == 1 { peers[0].clone() } else { format!("{} zielen", peers.len()) };
    Event {
        ts,
        host: host.into(),
        group: group.into(),
        kind: Kind::Policy,
        tag: rule.name.clone(),
        severity: rule.severity,
        score: hit.flows as f64,
        title: format!("netz-regel {}: {} verbindungen zu {peer_text}{port_text}", rule.name, hit.flows),
        detail: json!({
            "rule": rule.name,
            "from": rule.from,
            "to": rule.to,
            "flows": hit.flows,
            "bytes": hit.bytes,
            "peers": hit.peers.len(),
            "sample_peers": peers.iter().take(SAMPLE_IPS).collect::<Vec<_>>(),
            "ports": ports.iter().take(50).collect::<Vec<_>>(),
        }),
    }
}

fn beacon_event(ts: i64, group: &str, f: &Finding, info: &beacon::PeerInfo) -> Event {
    let (host, peer, port, proto) = f.key;
    let proto_name = if proto == 17 { "udp" } else { "tcp" };
    let minutes = (f.last_ms - f.first_ms) / 60_000;
    let span = if minutes >= 120 { format!("{} h", minutes / 60) } else { format!("{minutes} min") };
    let place = match (&info.cc, &info.org) {
        (Some(cc), Some(org)) => format!(" ({cc}, {org})"),
        (Some(cc), None) => format!(" ({cc})"),
        (None, Some(org)) => format!(" ({org})"),
        (None, None) => String::new(),
    };
    Event {
        ts,
        host: host.to_string(),
        group: group.into(),
        kind: Kind::Beacon,
        tag: format!("{peer}:{port}/{proto_name}"),
        // nur ein Hinweis zum Nachsehen: regelmäßige Verbindungen haben oft harmlose Gründe (geht nie per Mail raus)
        severity: Severity::Info,
        score: f.connections as f64,
        title: format!(
            "beaconing zu {peer}:{port}{place}: {} verbindungen, alle {} ± {:.0} %, je ~{}, seit {span}",
            f.connections,
            fmt_interval(f.interval_s),
            f.jitter * 100.0,
            fmt_bytes(f.median_bytes as f64)
        ),
        detail: json!({
            "peer": peer.to_string(),
            "port": port,
            "proto": proto_name,
            "cc": info.cc,
            "asn": info.asn,
            "org": info.org,
            "connections": f.connections,
            "interval_s": round2(f.interval_s),
            "jitter": round2(f.jitter),
            "median_bytes": f.median_bytes,
            "first_ms": f.first_ms,
            "last_ms": f.last_ms,
            "fleet_hosts": f.fleet_hosts,
        }),
    }
}

fn fmt_interval(secs: f64) -> String {
    if secs >= 90.0 { format!("{:.1} min", secs / 60.0) } else { format!("{secs:.0} s") }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn fmt_factor(f: f64) -> String {
    if f >= 10.0 { format!("{f:.0}") } else { format!("{f:.1}") }
}

fn fmt_value(feature: usize, value: f64) -> String {
    if is_bytes(feature) { fmt_bytes(value) } else { format!("{value:.0}") }
}

pub(crate) fn fmt_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{value:.0} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::Filters;
    use model::{Direction, FlowRecord};

    const MIB: u64 = 1024 * 1024;

    fn config(name: &str) -> AnomalyConfig {
        let dir = std::env::temp_dir().join(format!("snm-anomaly-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        AnomalyConfig { db_path: dir.join("anomaly.db"), learning_days: 0, timezone: Some("UTC".into()), ..AnomalyConfig::default() }
    }

    fn flow(src: &str, dst: &str, dst_port: u16, bytes: u64, flags: u8, direction: Direction) -> FlowRecord {
        FlowRecord {
            ts_ms: 0,
            start_ms: 0,
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port: 50000,
            dst_port,
            proto: 6,
            bytes,
            packets: 10,
            tcp_flags: flags,
            in_if: 0,
            out_if: 0,
            exporter: "192.0.2.1".parse().unwrap(),
            direction,
        }
    }

    fn filters() -> Filters {
        Filters::default()
    }

    /// Normaler Verkehr: 30 Clients in 10.0.1.0/24, jeder ein paar MiB zu wenigen Servern.
    fn normal_window(start: i64, seed: u64) -> Window {
        let geo = geo::GeoLookup::disabled();
        let mut rng = Rng::new(seed);
        let mut w = Window::new(start, false);
        for c in 0..30 {
            let host = format!("10.0.1.{}", c + 10);
            for s in 0..(3 + rng.below(4)) {
                let server = format!("203.0.113.{}", s + 1);
                w.add(&flow(&host, &server, 443, (1 + rng.below(4) as u64) * MIB / 4, 0x1b, Direction::Out), &filters(), &geo);
                w.add(&flow(&server, &host, 50000, (2 + rng.below(8) as u64) * MIB, 0x1b, Direction::In), &filters(), &geo);
            }
        }
        w
    }

    #[test]
    fn groups_by_subnet_or_explicit_range() {
        let g = Groups::new(&["10.0.1.0/24".into(), "10.0.1.5".into()], 24, 64).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(g.of(ip("10.0.1.5")), "10.0.1.5");
        assert_eq!(g.of(ip("10.0.1.6")), "10.0.1.0/24");
        assert_eq!(g.of(ip("10.0.7.9")), "10.0.7.0/24");
        assert_eq!(g.of(ip("2001:db8:1:2:3::4")), "2001:db8:1:2::/64");
        assert!(Groups::new(&["kein netz".into()], 24, 64).is_err());
    }

    #[test]
    fn week_slot_uses_local_time() {
        // 2026-10-19 ist ein Montag; 07:30 UTC = 09:30 in Wien (Sommerzeit endet erst am 25.10.)
        let ms = jiff::Timestamp::from_second(1_792_395_000).unwrap().as_millisecond();
        let vienna = local_time(&TimeZone::get("Europe/Vienna").unwrap(), ms);
        assert_eq!((vienna.week_slot, vienna.weekend), (9, false));
        assert!((vienna.hour - 9.5).abs() < 1e-9);
        let sunday = local_time(&TimeZone::UTC, ms - DAY_MS);
        assert_eq!((sunday.week_slot, sunday.weekend), (6 * 24 + 7, true));
    }

    #[test]
    fn learns_baseline_then_reports_upload_spike_scan_and_dns() {
        let cfg = config("spike");
        let path = cfg.db_path.clone();
        let mut engine = Engine::open(cfg, 0).unwrap();
        let window = 600_000;
        // Montag, 00:00 UTC
        let t0 = 1_792_368_000_000;
        let mut now = t0;
        for i in 0..40 {
            now = t0 + i * window;
            let created = engine.finish_window(normal_window(now, i as u64), now + window).unwrap();
            assert!(created.is_empty(), "Fenster {i} meldet {created:?}");
        }
        assert!(engine.model.is_some(), "Isolation Forest sollte trainiert sein");

        let start = now + window;
        let geo = geo::GeoLookup::disabled();
        let mut w = normal_window(start, 99);
        // 10.0.1.10 lädt 2 GiB hoch
        w.add(&flow("10.0.1.10", "198.51.100.9", 443, 2048 * MIB, 0x1b, Direction::Out), &filters(), &geo);
        // 10.0.1.11 scannt das LAN: SYN ohne ACK an 150 Ziele
        for i in 0..150u16 {
            w.add(&flow("10.0.1.11", &format!("10.0.2.{}", i % 250), 22, 60, 0x02, Direction::Internal), &filters(), &geo);
        }
        // 10.0.1.12 fragt einen externen Resolver
        w.add(&flow("10.0.1.12", "8.8.8.8", 53, 80, 0, Direction::Out), &filters(), &geo);
        let created = engine.finish_window(w, start + window).unwrap();

        let by = |host: &str, kind: Kind| created.iter().find(|e| e.host == host && e.kind == kind);
        let upload = by("10.0.1.10", Kind::Stat).expect("Upload-Spitze erwartet");
        assert!(upload.title.starts_with("upload 2.0 GiB statt typisch"), "{}", upload.title);
        assert_eq!(upload.group, "10.0.1.0/24");
        assert!(upload.detail["ml_score"].as_f64().is_some(), "zweite Meinung fehlt: {}", upload.detail);
        let scan = by("10.0.1.11", Kind::Scan).expect("Portscan erwartet");
        assert_eq!((scan.severity, scan.detail["hosts"].as_u64()), (Severity::High, Some(150)));
        assert!(by("10.0.1.12", Kind::Dns).is_some());

        // Dieselbe Spitze im nächsten Fenster verlängert die bestehende Auffälligkeit
        let start = start + window;
        let mut w = normal_window(start, 100);
        w.add(&flow("10.0.1.10", "198.51.100.9", 443, 2048 * MIB, 0x1b, Direction::Out), &filters(), &geo);
        let created = engine.finish_window(w, start + window).unwrap();
        assert!(by_kind(&created, Kind::Stat).is_none(), "keine neue Zeile: {created:?}");
        let rows = engine.events(&EventFilter { kind: Some("stat".into()), host: Some("10.0.1.10".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 2);

        let status = engine.status(start + window).unwrap();
        assert!(!status.learning);
        assert_eq!(status.groups, 1);
        assert!(status.ml.trained_ms.is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn policy_violations_are_reported_per_rule_and_merged() {
        use crate::policy::{Action, Policy, RuleConfig, ZoneConfig};
        let zone = |name: &str, net: &str| ZoneConfig { name: name.into(), networks: vec![net.into()] };
        let rule = |from: &str, to: &str, severity: &str| RuleConfig {
            name: String::new(),
            from: from.into(),
            to: to.into(),
            ports: vec![],
            action: Action::Alert,
            severity: severity.into(),
        };
        let policy = Policy::new(
            &[zone("schueler", "10.20.0.0/22"), zone("verwaltung", "10.0.5.0/24"), zone("server", "10.0.10.0/28")],
            &[rule("schueler", "verwaltung", "high"), rule("schueler", "server", "warn")],
        )
        .unwrap();
        let cfg = AnomalyConfig { learning_days: 7, policy: policy.clone(), ..config("policy") };
        let path = cfg.db_path.clone();
        let mut engine = Engine::open(cfg, 0).unwrap();
        let filters = Filters { policy, ..Filters::default() };
        let geo = geo::GeoLookup::disabled();
        let window = |start: i64| {
            let mut w = Window::new(start, false);
            for port in [445, 3389] {
                w.add(&flow("10.20.1.5", "10.0.5.7", port, 500, 0x1b, Direction::Internal), &filters, &geo);
            }
            // Antwort der Verwaltung zählt nicht
            w.add(&FlowRecord { src_port: 445, dst_port: 50000, ..flow("10.0.5.7", "10.20.1.5", 0, 9000, 0x1b, Direction::Internal) }, &filters, &geo);
            w.add(&flow("10.20.1.5", "10.0.10.2", 22, 500, 0x1b, Direction::Internal), &filters, &geo);
            w
        };
        let created = engine.finish_window(window(0), 600_000).unwrap();
        let policy: Vec<&Event> = created.iter().filter(|e| e.kind == Kind::Policy).collect();
        assert_eq!(policy.len(), 2, "eine Meldung je Regel, auch während der Lernphase: {created:?}");
        assert_eq!(policy[0].title, "netz-regel schueler → verwaltung: 2 verbindungen zu 10.0.5.7, ports 445, 3389");
        assert_eq!((policy[0].severity, policy[0].host.as_str(), policy[0].group.as_str()), (Severity::High, "10.20.1.5", "10.20.1.0/24"));
        assert_eq!(policy[1].severity, Severity::Warn);
        // nächstes Fenster: beide Zeilen werden verlängert, nicht neu angelegt
        let created = engine.finish_window(window(600_000), 1_200_000).unwrap();
        assert!(created.iter().all(|e| e.kind != Kind::Policy));
        let rows = engine.events(&EventFilter { kind: Some("policy".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.iter().map(|r| r.count).collect::<Vec<_>>(), vec![2, 2]);
        assert_eq!(engine.status(1_200_000).unwrap().policy_rules, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn regular_connections_to_one_target_are_reported_as_beaconing() {
        let cfg = AnomalyConfig { learning_days: 7, ..config("beacon") };
        let path = cfg.db_path.clone();
        let mut engine = Engine::open(cfg, 0).unwrap();
        let geo = geo::GeoLookup::disabled();
        let window = 600_000;
        let mut beacons = Vec::new();
        // 3 Stunden lang alle 60 s eine kleine Verbindung, dazu gewöhnlicher Verkehr
        for i in 0..18 {
            let start = i * window;
            let mut w = normal_window(start, i as u64);
            for k in 0..10 {
                let t = start + k * 60_000 + (k * 7_919) % 3_000;
                let f = FlowRecord { start_ms: t, ts_ms: t, src_port: 40_000 + k as u16, ..flow("10.0.1.20", "198.51.100.66", 443, 420, 0x1b, Direction::Out) };
                w.add(&f, &Filters::default(), &geo);
            }
            beacons.extend(engine.finish_window(w, start + window).unwrap().into_iter().filter(|e| e.kind == Kind::Beacon));
        }
        assert_eq!(beacons.len(), 1, "einmal angelegt, danach verlängert: {beacons:?}");
        let b = &beacons[0];
        assert_eq!((b.host.as_str(), b.severity, b.tag.as_str()), ("10.0.1.20", Severity::Info, "198.51.100.66:443/tcp"));
        assert!(b.title.starts_with("beaconing zu 198.51.100.66:443: "), "{}", b.title);
        assert!((b.detail["interval_s"].as_f64().unwrap() - 60.0).abs() < 3.0, "{}", b.detail);
        // die normalen Clients sprechen mit wenigen gemeinsamen Servern in Bündeln – keine Meldung
        let rows = engine.events(&EventFilter { kind: Some("beacon".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].count > 1);
        assert!(engine.status(18 * window).unwrap().beacon_pairs > 0);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    fn by_kind(events: &[Event], kind: Kind) -> Option<&Event> {
        events.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn nothing_is_reported_while_learning_except_rules() {
        let cfg = AnomalyConfig { learning_days: 7, ..config("learning") };
        let path = cfg.db_path.clone();
        let mut engine = Engine::open(cfg, 0).unwrap();
        let mut w = Window::new(0, false);
        let host = w.hosts.entry("10.0.1.10".parse().unwrap()).or_default();
        host.bytes_up = 50 * 1024 * MIB;
        host.countries.insert("CN".into(), 5 * MIB);
        host.dns.insert("8.8.8.8".parse().unwrap(), 3);
        let created = engine.finish_window(w, 600_000).unwrap();
        assert_eq!(created.iter().map(|e| e.kind).collect::<Vec<_>>(), vec![Kind::Dns]);
        // Land wurde trotzdem gelernt
        assert!(engine.countries["10.0.1.0/24"].contains("CN"));
        assert!(engine.status(600_000).unwrap().learning);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
