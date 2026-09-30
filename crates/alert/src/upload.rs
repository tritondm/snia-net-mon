//! Upload-Alarm: summiert den ausgehenden Verkehr (Richtung `out`, intern → extern) je Verbindung (5-Tupel) über alle
//! ihre Flows. softflowd meldet eine lange Verbindung mehrfach (je `maxlife`), deshalb zählt die Summe, nicht der
//! einzelne Flow. Überschreitet eine Verbindung die Schwelle, geht **eine** Mail an die Admins. Ohne neue Flows seit
//! `session_idle` gilt die Verbindung als beendet und wird vergessen.

use crate::mail::Mailer;
use geo::GeoLookup;
use model::{Direction, FlowKey, FlowRecord, fmt_utc, now_ms, proto_name};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone)]
pub struct UploadAlertConfig {
    pub threshold_bytes: u64,
    pub session_idle: Duration,
    /// Obergrenze gegen Mail-Fluten (z. B. wenn ein Backup viele parallele Verbindungen öffnet)
    pub max_mails_per_hour: u32,
}

/// Eine Verbindung, die die Schwelle überschritten hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadAlert {
    pub key: FlowKey,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

struct Session {
    bytes: u64,
    packets: u64,
    flows: u64,
    first_seen: i64,
    last_seen: i64,
    alerted: bool,
}

/// Zustand der Erkennung – ohne I/O, damit testbar.
pub struct UploadTracker {
    threshold: u64,
    idle_ms: i64,
    sessions: HashMap<FlowKey, Session>,
}

impl UploadTracker {
    pub fn new(threshold_bytes: u64, session_idle: Duration) -> Self {
        Self { threshold: threshold_bytes.max(1), idle_ms: session_idle.as_millis() as i64, sessions: HashMap::new() }
    }

    /// Flow einrechnen. Liefert einen Alarm, sobald die Verbindung die Schwelle zum ersten Mal überschreitet.
    pub fn add(&mut self, flow: &FlowRecord) -> Option<UploadAlert> {
        if flow.direction != Direction::Out {
            return None;
        }
        let session = self.sessions.entry(flow.key()).or_insert(Session {
            bytes: 0,
            packets: 0,
            flows: 0,
            first_seen: flow.start_ms,
            last_seen: flow.ts_ms,
            alerted: false,
        });
        session.bytes = session.bytes.saturating_add(flow.bytes);
        session.packets = session.packets.saturating_add(flow.packets);
        session.flows += 1;
        session.first_seen = session.first_seen.min(flow.start_ms);
        session.last_seen = session.last_seen.max(flow.ts_ms);
        if session.alerted || session.bytes < self.threshold {
            return None;
        }
        session.alerted = true;
        Some(UploadAlert {
            key: flow.key(),
            bytes: session.bytes,
            packets: session.packets,
            flows: session.flows,
            first_seen: session.first_seen,
            last_seen: session.last_seen,
        })
    }

    /// Verbindungen ohne Flows seit `session_idle` vergessen.
    pub fn expire(&mut self, now_ms: i64) {
        self.sessions.retain(|_, s| now_ms - s.last_seen <= self.idle_ms);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Erkennung als Task starten. Ohne `mailer` werden Alarme nur protokolliert.
pub fn spawn_upload_watch(
    config: UploadAlertConfig,
    mut rx: mpsc::Receiver<Arc<Vec<FlowRecord>>>,
    geo: Arc<GeoLookup>,
    mailer: Option<Mailer>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tracker = UploadTracker::new(config.threshold_bytes, config.session_idle);
        let mut sweep = tokio::time::interval(Duration::from_secs(30));
        let mut sent: VecDeque<i64> = VecDeque::new();
        loop {
            tokio::select! {
                batch = rx.recv() => {
                    let Some(batch) = batch else { return };
                    for flow in batch.iter() {
                        if let Some(alert) = tracker.add(flow) {
                            notify(&alert, &config, &geo, mailer.as_ref(), &mut sent);
                        }
                    }
                }
                _ = sweep.tick() => tracker.expire(now_ms()),
                _ = shutdown.changed() => if *shutdown.borrow() { return },
            }
        }
    })
}

fn notify(alert: &UploadAlert, config: &UploadAlertConfig, geo: &GeoLookup, mailer: Option<&Mailer>, sent: &mut VecDeque<i64>) {
    let k = &alert.key;
    tracing::warn!(
        src = %k.src_ip, dst = %k.dst_ip, dst_port = k.dst_port, proto = proto_name(k.proto), bytes = alert.bytes,
        "Upload-Alarm: Verbindung über der Schwelle"
    );
    let Some(mailer) = mailer else { return };
    let now = now_ms();
    while sent.front().is_some_and(|&t| now - t > 3_600_000) {
        sent.pop_front();
    }
    if sent.len() >= config.max_mails_per_hour as usize {
        tracing::warn!(limit = config.max_mails_per_hour, "Mail-Limit pro Stunde erreicht – Upload-Alarm nur im Log");
        return;
    }
    sent.push_back(now);
    let (subject, body) = render(alert, config.threshold_bytes, geo);
    let mailer = mailer.clone();
    tokio::spawn(async move {
        match mailer.send(&subject, &body).await {
            Ok(()) => tracing::info!(to = %mailer.recipients(), "Upload-Alarm per Mail gesendet"),
            Err(err) => tracing::error!(%err, "Upload-Alarm: Mail konnte nicht gesendet werden"),
        }
    });
}

/// Betreff und Text der Alarm-Mail.
pub fn render(alert: &UploadAlert, threshold: u64, geo: &GeoLookup) -> (String, String) {
    let k = &alert.key;
    let peer = geo.lookup(k.dst_ip);
    let peer_text = [peer.country.clone().or(peer.cc.clone()), peer.asn.map(|asn| format!("AS{asn} {}", peer.org.clone().unwrap_or_default()).trim().to_string())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    let peer_suffix = if peer_text.is_empty() { String::new() } else { format!(" ({peer_text})") };
    let secs = ((alert.last_seen - alert.first_seen) / 1000).max(1);
    let duration = format!("{} min {} s", secs / 60, secs % 60);
    let rate = format!("{:.1} Mbit/s", alert.bytes as f64 * 8.0 / secs as f64 / 1e6);
    let service = match k.proto {
        6 | 17 | 132 => format!("{}/{}", proto_name(k.proto), k.dst_port),
        _ => proto_name(k.proto).to_string(),
    };
    let subject = format!("[snia-net-mon] Upload {} von {} nach {}{peer_suffix}", fmt_bytes(alert.bytes), k.src_ip, k.dst_ip);
    let body = format!(
        "Eine einzelne Verbindung hat mehr als {threshold} nach extern hochgeladen.\n\
         \n\
         Quelle (intern):  {src}:{sport}\n\
         Ziel:             {dst}:{dport}{peer_suffix}\n\
         Dienst:           {service}\n\
         Hochgeladen:      {bytes} ({raw} Byte, {packets} Pakete, {flows} Flows)\n\
         Beginn:           {first}\n\
         Zuletzt gesehen:  {last}\n\
         Dauer:            {duration}\n\
         ø Rate:           {rate}\n\
         \n\
         Die Verbindung läuft eventuell noch weiter; sie wird nur einmal gemeldet.\n\
         Details in der Web-UI unter Flows, Suche nach {src}.\n",
        threshold = fmt_bytes(threshold),
        src = k.src_ip,
        sport = k.src_port,
        dst = k.dst_ip,
        dport = k.dst_port,
        bytes = fmt_bytes(alert.bytes),
        raw = alert.bytes,
        packets = alert.packets,
        flows = alert.flows,
        first = fmt_utc(alert.first_seen),
        last = fmt_utc(alert.last_seen),
    );
    (subject, body)
}

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.2} {}", UNITS[unit]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn flow(ts_ms: i64, src_port: u16, bytes: u64, direction: Direction) -> FlowRecord {
        FlowRecord {
            ts_ms,
            start_ms: ts_ms - 60_000,
            src_ip: "192.168.1.10".parse().unwrap(),
            dst_ip: "203.0.113.5".parse().unwrap(),
            src_port,
            dst_port: 443,
            proto: 6,
            bytes,
            packets: bytes / 1400,
            tcp_flags: 0,
            in_if: 0,
            out_if: 0,
            exporter: "192.0.2.1".parse().unwrap(),
            direction,
        }
    }

    #[test]
    fn alerts_once_per_connection_when_sum_of_flows_crosses_threshold() {
        let mut tracker = UploadTracker::new(GIB, Duration::from_secs(600));
        let t = 1_000_000_000;
        assert_eq!(tracker.add(&flow(t, 50000, 400 * 1024 * 1024, Direction::Out)), None);
        // Download und andere Verbindungen zählen nicht mit
        assert_eq!(tracker.add(&flow(t, 50000, 2 * GIB, Direction::In)), None);
        assert_eq!(tracker.add(&flow(t, 50001, 700 * 1024 * 1024, Direction::Out)), None);
        assert_eq!(tracker.add(&flow(t + 60_000, 50000, 400 * 1024 * 1024, Direction::Out)), None);
        let alert = tracker.add(&flow(t + 120_000, 50000, 300 * 1024 * 1024, Direction::Out)).expect("Alarm erwartet");
        assert_eq!((alert.bytes, alert.flows, alert.first_seen, alert.last_seen), (1100 * 1024 * 1024, 3, t - 60_000, t + 120_000));
        // kein zweiter Alarm für dieselbe Verbindung
        assert_eq!(tracker.add(&flow(t + 180_000, 50000, GIB, Direction::Out)), None);

        // Nach der Leerlaufzeit ist die Verbindung vergessen und würde neu gezählt
        tracker.expire(t + 180_000 + 600_001);
        assert!(tracker.is_empty());
        assert!(tracker.add(&flow(t + 900_000, 50000, 2 * GIB, Direction::Out)).is_some());
    }

    #[test]
    fn mail_text_contains_the_essentials() {
        let alert = UploadAlert {
            key: flow(0, 50000, 0, Direction::Out).key(),
            bytes: 3 * GIB / 2,
            packets: 1_000_000,
            flows: 4,
            first_seen: 1_790_775_907_000,
            last_seen: 1_790_775_907_000 + 150_000,
        };
        let (subject, body) = render(&alert, GIB, &GeoLookup::disabled());
        assert_eq!(subject, "[snia-net-mon] Upload 1.50 GiB von 192.168.1.10 nach 203.0.113.5");
        for needle in ["mehr als 1.00 GiB", "192.168.1.10:50000", "203.0.113.5:443", "TCP/443", "2026-09-30 13:45:07 UTC", "2 min 30 s", "85.9 Mbit/s"] {
            assert!(body.contains(needle), "{needle:?} fehlt in:\n{body}");
        }
    }
}
