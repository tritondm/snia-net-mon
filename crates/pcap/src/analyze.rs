// analyze.rs
//
// Die eigentliche Analyse: liest eine Capture-Datei Record für Record, zählt die
// Kennzahlen und baut das JSON-Ergebnis. Pro Endpunkt (IP) kommen IN/OUT-Bytes,
// Pakete, Zeitfenster und die Geo-Infos (Land, ASN, Organisation) dazu.

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::net::IpAddr;

use indexmap::IndexMap;
use serde_json::{Value, json};

use crate::apps::{AppRules, DnsLearner};
use crate::dissect::{Frame, Kind4, dissect};
use crate::dns::parse_dns;
use crate::reader::CaptureReader;
use crate::tls::parse_sni;
use geo::GeoLookup;

/// Dienstname für bekannte Ziel-Ports.
fn port_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp",
        80 => "http",
        110 => "pop3",
        123 => "ntp",
        143 => "imap",
        443 => "https",
        465 => "smtps",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        8888 => "cassandra",
        9090 => "metrics",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        5000 => "docker",
        5001 => "docker-ui",
        _ => "custom",
    }
}

/// DNS-Standard-Ports – NICHT-standard-Ports dort gelten als verdächtig.
fn standard_dns_port(p: u16) -> bool {
    matches!(p, 53 | 5353 | 1900 | 2061 | 5300 | 5355)
}

/// HTTP-Standard-Ports – NICHT-standard-Ports dort gelten als verdächtig.
fn standard_http_port(p: u16) -> bool {
    matches!(p, 80 | 8080 | 3128 | 8443 | 8000)
}

/// Formatiert Bytes menschenlesbar (1 Nachkommastelle).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.1} {}", v, UNITS[i])
}

/// Rundet auf `digits` Nachkommastellen (halte dich an Python-`round`).
fn round_to(x: f64, digits: i32) -> f64 {
    let m = 10f64.powi(digits);
    (x * m).round() / m
}

/// UTC-Zeitstempel: "2024-01-01 12:00:00 UTC".
fn fmt_datetime(ts: f64) -> Option<String> {
    if ts.is_nan() || ts.is_infinite() || ts < 0.0 {
        return None;
    }
    let secs = ts.floor() as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);

    // Howard-Hinnant-Algorithmus: Days-from-Civil umgekehrt.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y, m, d, hh, mm, ss
    ))
}

/// Aggregationswerte eines Endpunkts (IP)).
#[derive(Default)]
struct EndpointAgg {
    out_bytes: u64,
    in_bytes: u64,
    out_pkts: u64,
    in_pkts: u64,
    first_ts: f64,
    last_ts: f64,
}

/// Kanonischer Flow-Schlüssel (Protokoll + sortierte Socket-Paare), damit
/// Hin- und Rückrichtung demselben Flow zugeschlagen werden.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FlowKey {
    proto: u8,
    ip1: IpAddr,
    p1: u16,
    ip2: IpAddr,
    p2: u16,
}

fn flow_key(proto: u8, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> FlowKey {
    let (a, b) = if (src, sport) <= (dst, dport) {
        ((src, sport), (dst, dport))
    } else {
        ((dst, dport), (src, sport))
    };
    FlowKey {
        proto,
        ip1: a.0,
        p1: a.1,
        ip2: b.0,
        p2: b.1,
    }
}

/// Aggregationswerte einer erkannten App.
#[derive(Default)]
struct AppAgg {
    packets: u64,
    bytes: u64,
    /// DNS-Queries, die der App-Regel entsprechen
    queries: u64,
    /// Wie oft wurde über das jeweilige Signal klassifiziert?
    sni: u64,
    dns: u64,
    http: u64,
    ip: u64,
    /// Beobachtete Domains (DNS, SNI, HTTP)
    domains: BTreeSet<String>,
}

/// Stabile Top-N: sortiert nach `get` absteigend, gleiche Werte bleiben in
/// Einfüge-Reihenfolge (so wie Python `Counter.most_common()`).
fn top_n<K: Clone>(map: &IndexMap<K, u64>, n: usize) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by_key(|(_, c)| Reverse(*c));
    v.truncate(n);
    v
}

// --------------------------------------------------------------------------
// Haupt-Einstieg
// --------------------------------------------------------------------------

/// Analysiert eine Capture-Datei (PCAP oder pcapng) und baut das JSON-Ergebnis.
pub fn analyze<R: Read>(
    input: R,
    filename: &str,
    geo: &GeoLookup,
    apps: &AppRules,
) -> Result<Value, String> {
    let mut rd = CaptureReader::new(input)?;

    // ---- Zähler ----
    let mut packet_count: u64 = 0;
    let mut byte_total: u64 = 0;
    let mut start_ts: Option<f64> = None;
    let mut end_ts: f64 = 0.0;
    let mut ts_list: Vec<f64> = Vec::new();

    // proto_count: (Pakete, Bytes) in Einfüge-Reihenfolge der Kategorien
    let mut proto_count: IndexMap<String, (u64, u64)> = IndexMap::new();

    let mut ip_bytes: IndexMap<String, u64> = IndexMap::new();
    let mut ip_pkts: IndexMap<String, u64> = IndexMap::new();
    let mut endpoints: HashMap<String, EndpointAgg> = HashMap::new();

    let mut port_counter: IndexMap<String, u64> = IndexMap::new();
    let mut port_bytes: IndexMap<String, u64> = IndexMap::new();
    let mut port_src: HashMap<String, &'static str> = HashMap::new();

    let mut flow_bytes: IndexMap<String, u64> = IndexMap::new();
    let mut flow_pkts: IndexMap<String, u64> = IndexMap::new();

    let mut dns_queries: IndexMap<String, u64> = IndexMap::new();
    let mut dns_resolved: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut dns_nxdomain: IndexMap<String, u64> = IndexMap::new();
    let mut dns_port_anomaly: u64 = 0;

    let mut http_hosts: IndexMap<String, u64> = IndexMap::new();
    let mut http_urls: IndexMap<String, u64> = IndexMap::new();
    let mut http_methods: IndexMap<String, u64> = IndexMap::new();
    let mut http_port_anomaly: u64 = 0;

    let mut syn: u64 = 0;
    let mut rst: u64 = 0;
    let mut fin: u64 = 0;
    let mut src_ports: HashMap<String, HashSet<u16>> = HashMap::new();

    // ---- App-Klassifikation ----
    let mut dns_learner = DnsLearner::new();
    let mut flow_app: HashMap<FlowKey, String> = HashMap::new();
    let mut app_agg: IndexMap<String, AppAgg> = IndexMap::new();

    while let Some(rec) = rd.next_record() {
        let rec = rec?;
        let ts = rec.ts;
        let data = rec.data;

        let length = data.len() as u64;
        packet_count += 1;
        byte_total += length;
        if start_ts.is_none() {
            start_ts = Some(ts);
        }
        end_ts = ts;
        ts_list.push(ts);

        let frame = rec.linktype.and_then(|lt| dissect(data, lt));
        match frame {
            None => {
                // Unbekannter Frame-Typ: als "Andere" zählen (wie scapy)
                bump_proto(&mut proto_count, "Andere", length);
            }
            Some(Frame::Arp) => {
                bump_proto(&mut proto_count, "ARP", length);
            }
            Some(Frame::Ip(ip)) => {
                // Kategorien sind gegenseitig exklusiv (sie summieren sich auf 100%).
                // Wichtig: scapy rechnet ICMPv6 NICHT als "ICMP" – nur das IPv4-ICMP
                // (Protokoll 1) ist die ICMP-Schicht. ICMPv6 landet bei "IPv6".
                let is_v6 = matches!(ip.src, IpAddr::V6(_));
                let cat = match (ip.kind4, is_v6) {
                    (Kind4::Tcp, _) => "TCP",
                    (Kind4::Udp, _) => "UDP",
                    (Kind4::Icmp, false) => "ICMP",
                    (_, true) => "IPv6",
                    (_, false) => "IPv4",
                };
                bump_proto(&mut proto_count, cat, length);
                if is_v6 {
                    bump_proto(&mut proto_count, "_v6", length);
                } else {
                    bump_proto(&mut proto_count, "_v4", length);
                }

                let s = ip.src.to_string();
                let d = ip.dst.to_string();
                let dport = ip.dport;

                // ---- nach Quelle (Bytes) ----
                *ip_bytes.entry(s.clone()).or_insert(0) += length;
                *ip_pkts.entry(s.clone()).or_insert(0) += 1;

                // ---- Endpunkt-Aggregat: "out" = als Quelle, "in" = als Ziel ----
                let e_s = endpoints.entry(s.clone()).or_default();
                e_s.out_bytes += length;
                e_s.out_pkts += 1;
                e_s.first_ts = if e_s.first_ts == 0.0 {
                    ts
                } else {
                    e_s.first_ts
                };
                e_s.last_ts = ts;
                let e_d = endpoints.entry(d.clone()).or_default();
                e_d.in_bytes += length;
                e_d.in_pkts += 1;
                e_d.first_ts = if e_d.first_ts == 0.0 {
                    ts
                } else {
                    e_d.first_ts
                };
                e_d.last_ts = ts;

                // ---- Ziel-Ports ----
                if let Some(dp) = dport
                    && dp != 0
                {
                    let key = dp.to_string();
                    *port_counter.entry(key.clone()).or_insert(0) += 1;
                    *port_bytes.entry(key.clone()).or_insert(0) += length;
                    port_src
                        .entry(key.clone())
                        .or_insert_with(|| if ip.kind4 == Kind4::Tcp { "tcp" } else { "udp" });

                    // Quellen-Port-Tracking für Scan-Erkennung
                    if s != "0.0.0.0" && s != "::" {
                        src_ports.entry(s.clone()).or_default().insert(dp);
                    }

                    // ---- Flow-Schlüssel ----
                    let fkey = format!("{}->{}:{}", s, d, dp);
                    *flow_bytes.entry(fkey.clone()).or_insert(0) += length;
                    *flow_pkts.entry(fkey).or_insert(0) += 1;
                }

                // ---- TCP-Flags ----
                if let Some(fl) = ip.flags {
                    if fl & 0x02 != 0 {
                        syn += 1;
                    }
                    if fl & 0x04 != 0 {
                        rst += 1;
                    }
                    if fl & 0x01 != 0 {
                        fin += 1;
                    }
                }

                // ---- DNS ----
                if (ip.kind4 == Kind4::Tcp || ip.kind4 == Kind4::Udp)
                    && let Some(dinfo) = parse_dns(&ip.payload)
                    && let Some(name) = dinfo.name
                {
                    if !dinfo.qr {
                        // Query zählt zusätzlich für die App, deren
                        // Regeln auf die Domain passen.
                        if let Some(app) = apps.classify_domain(&name) {
                            let ag = app_agg.entry(app).or_default();
                            ag.queries += 1;
                            ag.domains.insert(name.clone());
                        }
                        *dns_queries.entry(name).or_insert(0) += 1;
                        if let Some(dp) = dport
                            && !standard_dns_port(dp)
                            && !d.starts_with("224.")
                            && !d.starts_with("ff")
                            && !d.contains(':')
                        {
                            dns_port_anomaly += 1;
                        }
                    } else {
                        for a in &dinfo.a_answers {
                            dns_resolved
                                .entry(name.clone())
                                .or_default()
                                .insert(a.to_string());
                        }
                        // DNS-Learning: aufgelöste IPs -> App, damit
                        // auch QUIC/UDP-443-Verkehr zugeordnet werden kann.
                        if let Some(app) = dns_learner.learn(apps, name.as_str(), &dinfo.a_answers)
                        {
                            let ag = app_agg.entry(app).or_default();
                            for _ in &dinfo.a_answers {
                                ag.domains.insert(name.clone());
                            }
                        }
                        if dinfo.nxdomain {
                            *dns_nxdomain.entry(name.clone()).or_insert(0) += 1;
                        }
                    }
                }

                // ---- HTTP (nur TCP-Nutzdaten) ----
                let http_host = if ip.kind4 == Kind4::Tcp && !ip.payload.is_empty() {
                    handle_http(
                        &ip.payload,
                        dport,
                        &mut http_methods,
                        &mut http_hosts,
                        &mut http_urls,
                        &mut http_port_anomaly,
                    )
                } else {
                    None
                };

                // ---- App-Zuordnung (Verkehr nach Anwendung) ----
                let proto8 = match ip.kind4 {
                    Kind4::Tcp => 6u8,
                    Kind4::Udp => 17u8,
                    _ => 0,
                };
                if proto8 != 0
                    && let (Some(sp), Some(dp)) = (ip.sport, ip.dport)
                    && dp != 0
                {
                    let key = flow_key(proto8, ip.src, ip.dst, sp, dp);
                    if let Some(existing) = flow_app.get(&key) {
                        // Bereits klassifizierter Flow: Bytes anhäufen.
                        let ag = app_agg.entry(existing.clone()).or_default();
                        ag.packets += 1;
                        ag.bytes += length;
                    } else {
                        let mut found: Option<(String, &'static str)> = None;
                        let mut seen_domain: Option<String> = None;
                        // 1) TLS-SNI (bester Direkt-Trigger)
                        if ip.kind4 == Kind4::Tcp
                            && !ip.payload.is_empty()
                            && let Some(sni) = parse_sni(&ip.payload)
                            && let Some(a) = apps.classify_domain(&sni)
                        {
                            found = Some((a, "sni"));
                            seen_domain = Some(sni);
                        }
                        // 2) DNS-Learning: Ziel-IP wurde für eine App aufgelöst
                        if found.is_none()
                            && let Some(a) = dns_learner.app_for_ip(&d)
                        {
                            found = Some((a.to_string(), "dns"));
                            seen_domain = dns_learner.domain_for_ip(&d).map(|s| s.to_string());
                        }
                        // 3) HTTP-Host
                        if found.is_none()
                            && let Some(h) = &http_host
                            && let Some(a) = apps.classify_domain(h)
                        {
                            found = Some((a, "http"));
                            seen_domain = Some(h.clone());
                        }
                        // 4) IP-Präfix-Regeln
                        if found.is_none()
                            && let Some(a) = apps.classify_ip(&ip.dst)
                        {
                            found = Some((a, "ip"));
                        }
                        if let Some((app, signal)) = found {
                            let ag = app_agg.entry(app.clone()).or_default();
                            ag.packets += 1;
                            ag.bytes += length;
                            match signal {
                                "sni" => ag.sni += 1,
                                "dns" => ag.dns += 1,
                                "http" => ag.http += 1,
                                _ => ag.ip += 1,
                            }
                            if let Some(dom) = seen_domain {
                                ag.domains.insert(dom);
                            }
                            flow_app.insert(key, app);
                        }
                    }
                }
            }
        }
    }

    let duration = match start_ts {
        Some(s) => end_ts - s,
        None => 0.0,
    };

    Ok(build_summary(
        filename,
        packet_count,
        byte_total,
        start_ts,
        end_ts,
        duration,
        &ts_list,
        &proto_count,
        &ip_bytes,
        &ip_pkts,
        &endpoints,
        &port_counter,
        &port_bytes,
        &port_src,
        &flow_bytes,
        &flow_pkts,
        &dns_queries,
        &dns_resolved,
        &dns_nxdomain,
        dns_port_anomaly,
        &http_hosts,
        &http_urls,
        &http_methods,
        http_port_anomaly,
        syn,
        rst,
        fin,
        &src_ports,
        geo,
        apps,
        &app_agg,
        &dns_learner,
    ))
}

/// Erhöht einen Protokoll-Zähler (erstes Auftreten legt die Reihenfolge fest).
fn bump_proto(map: &mut IndexMap<String, (u64, u64)>, name: &str, bytes: u64) {
    let e = map.entry(name.to_string()).or_insert((0, 0));
    e.0 += 1;
    e.1 += bytes;
}

/// HTTP-Analyse pro Paket (Anfragezeile + Host-Header).
/// Liefert den erkannten Host zurück (für die App-Klassifikation).
fn handle_http(
    payload: &[u8],
    dport: Option<u16>,
    methods: &mut IndexMap<String, u64>,
    hosts: &mut IndexMap<String, u64>,
    urls: &mut IndexMap<String, u64>,
    anomaly: &mut u64,
) -> Option<String> {
    const TYPES: [&str; 7] = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"];

    // erste Zeile = alles bis zum ersten \r\n (bzw. der ganze Payload)
    let fl_end = payload
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(payload.len());
    let first_line = String::from_utf8_lossy(&payload[..fl_end]);
    let parts: Vec<&str> = first_line.split(' ').collect();
    let method = parts.first().copied().unwrap_or("");
    if !TYPES.contains(&method) || parts.len() < 2 {
        return None;
    }
    let url_part = parts[1];

    *methods.entry(method.to_string()).or_insert(0) += 1;

    // Host-Header suchen (erste Zeile, die mit "host:" beginnt)
    let mut host: Option<String> = None;
    for line in payload.split(|&b| b == b'\n') {
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let value = &line[5..];
            let trimmed = String::from_utf8_lossy(value).trim().to_string();
            let h = trimmed.split(':').next().unwrap_or("").to_lowercase();
            host = if h.is_empty() { None } else { Some(h) };
            break;
        }
    }

    match &host {
        Some(h) => {
            *hosts.entry(h.clone()).or_insert(0) += 1;
            let url = if url_part != "/" { url_part } else { "/" };
            *urls
                .entry(format!("{}{}", h, url).to_lowercase())
                .or_insert(0) += 1;
        }
        None => {
            *urls.entry(url_part.to_lowercase()).or_insert(0) += 1;
        }
    }

    if let Some(dp) = dport
        && !standard_http_port(dp)
    {
        *anomaly += 1;
    }
    host
}

// --------------------------------------------------------------------------
// Ergebnis-Erzeugung als JSON
// --------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_summary(
    filename: &str,
    packet_count: u64,
    byte_total: u64,
    start_ts: Option<f64>,
    end_ts: f64,
    duration: f64,
    ts_list: &[f64],
    proto_count: &IndexMap<String, (u64, u64)>,
    ip_bytes: &IndexMap<String, u64>,
    ip_pkts: &IndexMap<String, u64>,
    endpoints: &HashMap<String, EndpointAgg>,
    port_counter: &IndexMap<String, u64>,
    port_bytes: &IndexMap<String, u64>,
    port_src: &HashMap<String, &'static str>,
    flow_bytes: &IndexMap<String, u64>,
    flow_pkts: &IndexMap<String, u64>,
    dns_queries: &IndexMap<String, u64>,
    dns_resolved: &HashMap<String, BTreeSet<String>>,
    dns_nxdomain: &IndexMap<String, u64>,
    dns_port_anomaly: u64,
    http_hosts: &IndexMap<String, u64>,
    http_urls: &IndexMap<String, u64>,
    http_methods: &IndexMap<String, u64>,
    http_port_anomaly: u64,
    syn: u64,
    rst: u64,
    fin: u64,
    src_ports: &HashMap<String, HashSet<u16>>,
    geo: &GeoLookup,
    apps: &AppRules,
    app_agg: &IndexMap<String, AppAgg>,
    dns_learner: &DnsLearner,
) -> Value {
    let total = packet_count.max(1);

    // ---- Protokoll-Liste (EXklusive _v4/_v6-Hilfszähler) ----
    let mut protos: Vec<(&str, u64, u64)> = proto_count
        .iter()
        .filter(|(k, _)| !k.starts_with('_'))
        .map(|(k, (c, b))| (k.as_str(), *c, *b))
        .collect();
    protos.sort_by_key(|p| Reverse(p.1));

    let top_ips: Vec<Value> = top_n(ip_bytes, 12)
        .into_iter()
        .map(|(ip, b)| {
            json!({
                "src": ip,
                "bytes": b,
                "bytes_human": human_bytes(b),
                "pkts": ip_pkts.get(&ip).copied().unwrap_or(0),
            })
        })
        .collect();

    let top_ports: Vec<Value> = top_n(port_counter, 15)
        .into_iter()
        .map(|(p, c)| {
            let num = p.parse::<u16>().unwrap_or(0);
            json!({
                "port": p,
                "name": port_name(num),
                "protocol": port_src.get(&p).copied().unwrap_or("-"),
                "pkts": c,
                "bytes": port_bytes.get(&p).copied().unwrap_or(0),
                "bytes_human": human_bytes(port_bytes.get(&p).copied().unwrap_or(0)),
            })
        })
        .collect();

    let top_flows: Vec<Value> = top_n(flow_bytes, 15)
        .into_iter()
        .map(|(f, b)| {
            json!({
                "src_dst_dstport": f,
                "bytes": b,
                "bytes_human": human_bytes(b),
                "pkts": flow_pkts.get(&f).copied().unwrap_or(0),
            })
        })
        .collect();

    // ---- DNS ----
    let dns_queries_total: u64 = dns_queries.values().sum();
    let dns_nx_total: u64 = dns_nxdomain.values().sum();
    let top_queries: Vec<Value> = top_n(dns_queries, 15)
        .into_iter()
        .map(|(d, c)| {
            let resolved: Vec<String> = dns_resolved
                .get(&d)
                .map(|s| s.iter().take(4).cloned().collect())
                .unwrap_or_default();
            json!({ "domain": d, "count": c, "resolved": resolved })
        })
        .collect();

    // ---- HTTP ----
    let http_total: u64 = http_methods.values().sum();
    let top_hosts: Vec<Value> = top_n(http_hosts, 10)
        .into_iter()
        .map(|(h, c)| json!({ "host": h, "count": c }))
        .collect();
    let top_urls: Vec<Value> = top_n(http_urls, 15)
        .into_iter()
        .map(|(u, c)| json!({ "url": u, "count": c }))
        .collect();

    // ---- Timeline ----
    let mut timeline_norm: Vec<Value> = Vec::new();
    if let Some(start) = start_ts
        && duration > 0.0
    {
        let bucket_count = if duration >= 60.0 {
            (duration as usize).clamp(12, 48)
        } else if duration >= 6.0 {
            (duration as usize).min(48)
        } else {
            ((duration * 60.0) as usize).max(1)
        };
        let bucket_size = duration / bucket_count as f64;
        let mut buckets: Vec<u64> = vec![0; bucket_count];
        for ts in ts_list {
            let idx = (((ts - start) / bucket_size) as usize).min(bucket_count - 1);
            buckets[idx] += 1;
        }
        let max_t = buckets.iter().copied().max().unwrap_or(1).max(1);
        for (i, count) in buckets.iter().enumerate() {
            let pct = *count as f64 / max_t as f64 * 100.0;
            let ts_at = round_to(start + i as f64 * bucket_size, 3);
            timeline_norm.push(json!([pct, ts_at]));
        }
    }
    let seconds_per_bucket = round_to(duration / timeline_norm.len().max(1) as f64, 3);

    // ---- Bedrohungen (Heuristiken) ----
    let mut threats: Vec<(&str, String, String)> = Vec::new();
    if syn > (packet_count as f64 * 0.02) as u64 && syn > 100 {
        threats.push((
            "medium",
            format!(
                "Hoher SYN-Anteil: {} SYN / {} Pakete ({}%)",
                syn,
                packet_count,
                syn * 100 / packet_count.max(1)
            ),
            "Möglicher SYN-Scan oder SYN-Flood.".to_string(),
        ));
    }
    if rst > (packet_count as f64 * 0.08) as u64 {
        threats.push((
            "medium",
            format!(
                "Hoher RST-Anteil: {} RST-Pakete ({}%)",
                rst,
                rst * 100 / packet_count.max(1)
            ),
            "Viele abgelehnte Verbindungen – möglicher Port-Scan.".to_string(),
        ));
    }
    {
        let mut nx: Vec<(&str, u64)> = dns_nxdomain.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        nx.sort_by_key(|(_, c)| Reverse(*c));
        for (name, count) in nx.into_iter().take(8) {
            if count >= 3 {
                threats.push((
                    "high",
                    format!("DNS NXDOMAIN x{}: {}", count, name),
                    "Wiederholte nicht-auflösbare Domain – mögliche DNS-Tunneling oder DGA-Domain."
                        .to_string(),
                ));
            }
        }
    }
    {
        let mut scans: Vec<(&str, usize)> = src_ports
            .iter()
            .filter(|(_, ps)| ps.len() >= 30)
            .map(|(ip, ps)| (ip.as_str(), ps.len()))
            .collect();
        scans.sort_by_key(|(_, n)| Reverse(*n));
        for (src, nports) in scans.into_iter().take(8) {
            threats.push(("high", format!("Möglicher Port-Scan: {} -> {} Ziel-Ports", src, nports), format!("Quelle {} hat {} verschiedene Ziel-Ports kontaktiert – typisches Portscanner-Verhalten.", src, nports)));
        }
    }
    if dns_port_anomaly > 50 {
        threats.push((
            "high",
            format!(
                "{} DNS-Meldungen auf Nicht-Standard-Ports",
                dns_port_anomaly
            ),
            "DNS auf Ports != 53 – möglicher C2-Kanal.".to_string(),
        ));
    }
    if http_port_anomaly > 50 {
        threats.push((
            "medium",
            format!(
                "{} HTTP-Meldungen auf Nicht-Standard-Ports",
                http_port_anomaly
            ),
            "HTTP auf Nicht-Standard-Ports – mögliche Tunneling/Reverse-Proxy.".to_string(),
        ));
    }
    let order = |sev: &str| match sev {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    };
    threats.sort_by_key(|(s, _, _)| order(s));
    let threats_json: Vec<Value> = threats
        .into_iter()
        .map(|(sev, title, detail)| json!({ "severity": sev, "title": title, "detail": detail }))
        .collect();

    // ---- Endpunkte mit Geo (IN/OUT, Größe, Zeitfenster, ASN, Land) ----
    let mut eps: Vec<(&String, &EndpointAgg)> = endpoints.iter().collect();
    eps.sort_by(|a, b| {
        let ka = a.1.out_bytes + a.1.in_bytes;
        let kb = b.1.out_bytes + b.1.in_bytes;
        kb.cmp(&ka)
    });
    let endpoints_json: Vec<Value> = eps
        .into_iter()
        .take(20)
        .map(|(ip, e)| {
            let parsed = ip.parse::<IpAddr>().ok();
            let app = dns_learner
                .app_for_ip(ip)
                .map(|a| a.to_string())
                .or_else(|| parsed.as_ref().and_then(|p| apps.classify_ip(p)));
            let app_label = app.as_deref().map(|a| apps.label(a).to_string());
            json!({
                "ip": ip,
                "app": app,
                "app_label": app_label,
                "out_bytes": e.out_bytes,
                "in_bytes": e.in_bytes,
                "out_bytes_human": human_bytes(e.out_bytes),
                "in_bytes_human": human_bytes(e.in_bytes),
                "total_bytes": e.out_bytes + e.in_bytes,
                "total_bytes_human": human_bytes(e.out_bytes + e.in_bytes),
                "out_packets": e.out_pkts,
                "in_packets": e.in_pkts,
                "first_ts": fmt_datetime(e.first_ts),
                "last_ts": fmt_datetime(e.last_ts),
                "first_ms": (e.first_ts * 1000.0) as i64,
                "last_ms": (e.last_ts * 1000.0) as i64,
                "geo": parsed.and_then(|p| geo.lookup_opt(p)),
            })
        })
        .collect();

    // ---- Verkehr nach Anwendung ----
    let ip_total_bytes: u64 = ip_bytes.values().sum();
    let identified_bytes: u64 = app_agg.values().map(|a| a.bytes).sum();
    let identified_packets: u64 = app_agg.values().map(|a| a.packets).sum();
    let identified_pct = if ip_total_bytes > 0 {
        round_to(identified_bytes as f64 * 100.0 / ip_total_bytes as f64, 1)
    } else {
        0.0
    };

    let mut app_rows: Vec<(&String, &AppAgg)> = app_agg.iter().collect();
    app_rows.sort_by_key(|(_, a)| Reverse(a.bytes));
    let apps_json: Vec<Value> = app_rows
        .into_iter()
        .map(|(app, a)| {
            json!({
                "app": app,
                "label": apps.label(app),
                "packets": a.packets,
                "bytes": a.bytes,
                "bytes_human": human_bytes(a.bytes),
                "pct": if identified_bytes > 0 {
                    round_to(a.bytes as f64 * 100.0 / identified_bytes as f64, 1)
                } else {
                    0.0
                },
                "signals": {
                    "sni": a.sni,
                    "dns": a.dns,
                    "http": a.http,
                    "ip": a.ip,
                },
                "queries": a.queries,
                "domains": a.domains.iter().take(8).cloned().collect::<Vec<_>>(),
            })
        })
        .collect();

    let duration_human = if duration < 3600.0 {
        format!("{:.1}s", duration)
    } else {
        format!("{:.2}h", duration / 3600.0)
    };

    json!({
        "filename": filename,
        "total": {
            "packets": packet_count,
            "bytes": byte_total,
            "bytes_human": human_bytes(byte_total),
            "duration_sec": round_to(duration, 3),
            "duration_human": duration_human,
            "start": start_ts.and_then(fmt_datetime),
            "start_ms": start_ts.map(|t| (t * 1000.0) as i64),
            "end_ms": start_ts.map(|_| (end_ts * 1000.0) as i64),
            "end": if start_ts.is_some() { fmt_datetime(end_ts) } else { None },
            "pps": if duration > 0.0 { round_to(packet_count as f64 / duration, 1) } else { 0.0 },
            "mbps": if duration > 0.0 { format!("{:.2} Mbps", byte_total as f64 * 8.0 / duration / 1e6) } else { "0".to_string() },
        },
        "protocols": protos.iter().map(|(name, c, b)| json!({
            "name": name,
            "packets": c,
            "bytes": b,
            "bytes_human": human_bytes(*b),
            "pct": round_to(*c as f64 * 100.0 / total as f64, 1),
        })).collect::<Vec<_>>(),
        "protocol_split": {
            "IPv4": proto_count.get("_v4").map(|(c, _)| c).copied().unwrap_or(0),
            "IPv6": proto_count.get("_v6").map(|(c, _)| c).copied().unwrap_or(0),
        },
        "protocol_pct": {
            "IPv4": round_to(proto_count.get("IPv4").map(|(c, _)| *c).unwrap_or(0) as f64 * 100.0 / total as f64, 1),
            "IPv6": round_to(proto_count.get("IPv6").map(|(c, _)| *c).unwrap_or(0) as f64 * 100.0 / total as f64, 1),
        },
        "top_ips": top_ips,
        "top_ports": top_ports,
        "top_flows": top_flows,
        "dns": {
            "queries_total": dns_queries_total,
            "unique_domains": dns_queries.len(),
            "top_queries": top_queries,
            "nxdomain_total": dns_nx_total,
        },
        "http": {
            "requests_total": http_total,
            "methods": json!(http_methods),
            "top_hosts": top_hosts,
            "top_urls": top_urls,
        },
        "tcp": { "syn": syn, "rst": rst, "fin": fin },
        "threats": threats_json,
        "timeline": { "values": timeline_norm, "seconds_per_bucket": seconds_per_bucket },
        "endpoints": endpoints_json,
        "apps": {
            "identified_pct": identified_pct,
            "total": {
                "packets": identified_packets,
                "bytes": identified_bytes,
                "bytes_human": human_bytes(identified_bytes),
            },
            "top": apps_json,
        },
    })
}
