//! Synthetische NetFlow-v9-/IPFIX-Pakete: Encoder und ein einfaches Verkehrsmodell.
//!
//! Wird von den Parser-Tests (Roundtrip) und vom Demo-Generator `flowgen` benutzt, damit sich die komplette Pipeline
//! ohne echte pfSense testen lässt. Die erzeugten Pakete sind standardkonform und werden über echtes UDP verschickt.

use model::FlowRecord;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    NetflowV9,
    Ipfix,
}

const TEMPLATE_V4: u16 = 256;
const TEMPLATE_V6: u16 = 257;
/// Private Enterprise Number für das Test-Feld mit variabler Länge (nur IPFIX), prüft Enterprise- und Varlen-Parsing.
const TEST_PEN: u32 = 29305;

/// (Feld-ID, Länge) – NetFlow v9 wie softflowd: Zähler mit 4 Byte, Zeiten als Uptime.
const V9_FIELDS: &[(u16, u16)] = &[(1, 4), (2, 4), (4, 1), (6, 1), (7, 2), (0, 0), (10, 2), (11, 2), (0, 0), (14, 2), (21, 4), (22, 4)];
/// IPFIX: 64-Bit-Zähler und absolute Millisekunden-Zeitstempel.
const IPFIX_FIELDS: &[(u16, u16)] = &[(1, 8), (2, 8), (4, 1), (6, 2), (7, 2), (0, 0), (10, 4), (11, 2), (0, 0), (14, 4), (153, 8), (152, 8)];

pub struct Encoder {
    format: Format,
    source_id: u32,
    sequence: u32,
}

impl Encoder {
    pub fn new(format: Format, source_id: u32) -> Self {
        Self { format, source_id, sequence: 0 }
    }

    /// Ein Export-Paket mit den gegebenen Flows erzeugen (optional inklusive Templates).
    pub fn encode(&mut self, flows: &[FlowRecord], export_secs: u32, include_templates: bool) -> Vec<u8> {
        let v4: Vec<&FlowRecord> = flows.iter().filter(|f| f.src_ip.is_ipv4() && f.dst_ip.is_ipv4()).collect();
        let v6: Vec<&FlowRecord> = flows.iter().filter(|f| !(f.src_ip.is_ipv4() && f.dst_ip.is_ipv4())).collect();
        match self.format {
            Format::NetflowV9 => self.encode_v9(&v4, &v6, export_secs, include_templates),
            Format::Ipfix => self.encode_ipfix(&v4, &v6, export_secs, include_templates),
        }
    }

    fn encode_v9(&mut self, v4: &[&FlowRecord], v6: &[&FlowRecord], export_secs: u32, include_templates: bool) -> Vec<u8> {
        // Exporter "läuft" seit einem Tag – Uptime-Zeitstempel sind relativ dazu
        let uptime_ms: u32 = 86_400_000;
        let boot_ms = export_secs as i64 * 1000 - uptime_ms as i64;
        let mut p = Vec::with_capacity(1400);
        let mut record_count: u16 = 0;
        p.extend_from_slice(&9u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // count, wird unten gesetzt
        p.extend_from_slice(&uptime_ms.to_be_bytes());
        p.extend_from_slice(&export_secs.to_be_bytes());
        p.extend_from_slice(&self.sequence.to_be_bytes());
        p.extend_from_slice(&self.source_id.to_be_bytes());
        self.sequence = self.sequence.wrapping_add(1);

        if include_templates {
            let start = begin_set(&mut p, 0);
            for (id, is_v6) in [(TEMPLATE_V4, false), (TEMPLATE_V6, true)] {
                p.extend_from_slice(&id.to_be_bytes());
                p.extend_from_slice(&(V9_FIELDS.len() as u16).to_be_bytes());
                for &(field, len) in resolve_fields(V9_FIELDS, is_v6).iter() {
                    p.extend_from_slice(&field.to_be_bytes());
                    p.extend_from_slice(&len.to_be_bytes());
                }
                record_count += 1;
            }
            end_set(&mut p, start, 4);
        }

        for (id, flows, is_v6) in [(TEMPLATE_V4, v4, false), (TEMPLATE_V6, v6, true)] {
            if flows.is_empty() {
                continue;
            }
            let start = begin_set(&mut p, id);
            for flow in flows {
                for &(field, len) in resolve_fields(V9_FIELDS, is_v6).iter() {
                    let value = match field {
                        21 => (flow.ts_ms - boot_ms).max(0) as u64,
                        22 => (flow.start_ms - boot_ms).max(0) as u64,
                        _ => common_value(flow, field),
                    };
                    put_field(&mut p, field, len, value, flow);
                }
                record_count += 1;
            }
            end_set(&mut p, start, 4);
        }
        p[2..4].copy_from_slice(&record_count.to_be_bytes());
        p
    }

    fn encode_ipfix(&mut self, v4: &[&FlowRecord], v6: &[&FlowRecord], export_secs: u32, include_templates: bool) -> Vec<u8> {
        let mut p = Vec::with_capacity(1400);
        p.extend_from_slice(&10u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // Länge, wird unten gesetzt
        p.extend_from_slice(&export_secs.to_be_bytes());
        p.extend_from_slice(&self.sequence.to_be_bytes());
        p.extend_from_slice(&self.source_id.to_be_bytes());

        if include_templates {
            let start = begin_set(&mut p, 2);
            for (id, is_v6) in [(TEMPLATE_V4, false), (TEMPLATE_V6, true)] {
                p.extend_from_slice(&id.to_be_bytes());
                p.extend_from_slice(&(IPFIX_FIELDS.len() as u16 + 1).to_be_bytes());
                for &(field, len) in resolve_fields(IPFIX_FIELDS, is_v6).iter() {
                    p.extend_from_slice(&field.to_be_bytes());
                    p.extend_from_slice(&len.to_be_bytes());
                }
                // Enterprise-Feld mit variabler Länge
                p.extend_from_slice(&(0x8000u16 | 1).to_be_bytes());
                p.extend_from_slice(&0xFFFFu16.to_be_bytes());
                p.extend_from_slice(&TEST_PEN.to_be_bytes());
            }
            end_set(&mut p, start, 1);
        }

        let mut data_records = 0u32;
        for (id, flows, is_v6) in [(TEMPLATE_V4, v4, false), (TEMPLATE_V6, v6, true)] {
            if flows.is_empty() {
                continue;
            }
            let start = begin_set(&mut p, id);
            for flow in flows {
                for &(field, len) in resolve_fields(IPFIX_FIELDS, is_v6).iter() {
                    let value = match field {
                        152 => flow.start_ms as u64,
                        153 => flow.ts_ms as u64,
                        _ => common_value(flow, field),
                    };
                    put_field(&mut p, field, len, value, flow);
                }
                p.push(3);
                p.extend_from_slice(b"snm");
                data_records += 1;
            }
            end_set(&mut p, start, 1);
        }
        self.sequence = self.sequence.wrapping_add(data_records);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }
}

/// Platzhalter (0, 0) in den Feldlisten durch die IPv4- bzw. IPv6-Adressfelder ersetzen.
fn resolve_fields(fields: &[(u16, u16)], is_v6: bool) -> Vec<(u16, u16)> {
    let mut address_slot = 0;
    fields
        .iter()
        .map(|&(id, len)| {
            if id != 0 {
                return (id, len);
            }
            address_slot += 1;
            match (address_slot, is_v6) {
                (1, false) => (8, 4),
                (1, true) => (27, 16),
                (_, false) => (12, 4),
                (_, true) => (28, 16),
            }
        })
        .collect()
}

fn common_value(flow: &FlowRecord, field: u16) -> u64 {
    match field {
        1 => flow.bytes,
        2 => flow.packets,
        4 => flow.proto as u64,
        6 => flow.tcp_flags as u64,
        7 => flow.src_port as u64,
        10 => flow.in_if as u64,
        11 => flow.dst_port as u64,
        14 => flow.out_if as u64,
        _ => 0,
    }
}

fn put_field(p: &mut Vec<u8>, field: u16, len: u16, value: u64, flow: &FlowRecord) {
    match field {
        8 | 27 => put_ip(p, flow.src_ip),
        12 | 28 => put_ip(p, flow.dst_ip),
        _ => {
            let bytes = value.to_be_bytes();
            p.extend_from_slice(&bytes[8 - len as usize..]);
        }
    }
}

fn put_ip(p: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => p.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => p.extend_from_slice(&v6.octets()),
    }
}

fn begin_set(p: &mut Vec<u8>, id: u16) -> usize {
    let start = p.len();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    start
}

/// Set-Länge eintragen; `align` = Padding auf ein Vielfaches (NetFlow v9: 4 Byte).
fn end_set(p: &mut Vec<u8>, start: usize, align: usize) {
    while !(p.len() - start).is_multiple_of(align) {
        p.push(0);
    }
    let len = (p.len() - start) as u16;
    p[start + 2..start + 4].copy_from_slice(&len.to_be_bytes());
}

/// Kleiner, schneller Pseudo-Zufallsgenerator (xorshift64*) – für Demo-Verkehr völlig ausreichend.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// Pareto-ähnlich verteilte Größe: viele kleine, wenige sehr große Werte (typisch für Netzwerkverkehr).
    pub fn heavy_tail(&mut self, min: u64, max: u64) -> u64 {
        let u = (self.below(1_000_000) as f64 + 1.0) / 1_000_001.0;
        let value = min as f64 / u.powf(1.0 / 1.2);
        (value as u64).clamp(min, max)
    }
}

struct Service {
    port: u16,
    proto: u8,
    servers: &'static [&'static str],
    weight: u64,
    max_bytes: u64,
}

const SERVICES: &[Service] = &[
    Service { port: 443, proto: 6, servers: &["142.250.185.78", "151.101.1.140", "104.16.132.229", "13.107.42.14", "2a00:1450:4001:82b::200e", "2606:4700::6810:84e5"], weight: 40, max_bytes: 400_000_000 },
    Service { port: 443, proto: 17, servers: &["142.250.185.78", "157.240.17.35", "2a03:2880:f12d:83:face:b00c:0:25de"], weight: 12, max_bytes: 200_000_000 },
    Service { port: 53, proto: 17, servers: &["1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"], weight: 20, max_bytes: 2_000 },
    Service { port: 80, proto: 6, servers: &["93.184.215.14", "199.232.82.132"], weight: 5, max_bytes: 30_000_000 },
    Service { port: 123, proto: 17, servers: &["162.159.200.1", "91.189.94.4"], weight: 3, max_bytes: 400 },
    Service { port: 22, proto: 6, servers: &["140.82.121.4", "192.168.10.5"], weight: 3, max_bytes: 50_000_000 },
    Service { port: 993, proto: 6, servers: &["52.97.146.162"], weight: 3, max_bytes: 5_000_000 },
    Service { port: 445, proto: 6, servers: &["192.168.10.20"], weight: 4, max_bytes: 800_000_000 },
    Service { port: 51820, proto: 17, servers: &["185.213.154.66"], weight: 2, max_bytes: 100_000_000 },
    Service { port: 3478, proto: 17, servers: &["74.125.250.129"], weight: 3, max_bytes: 60_000_000 },
    Service { port: 0, proto: 1, servers: &["8.8.8.8", "192.168.10.1"], weight: 2, max_bytes: 2_000 },
];

/// Erzeugt plausiblen Firewall-Verkehr: einige LAN-Clients (einzelne davon "Vielnutzer"), typische Internetdienste,
/// etwas internes SMB/SSH sowie gelegentliche eingehende Scans auf einen per Port-Forwarding erreichbaren Server.
/// Wie softflowd entstehen pro Verbindung zwei Flows: Anfrage (Client → Server) und Antwort (Server → Client).
pub struct TrafficModel {
    rng: Rng,
    clients_v4: Vec<IpAddr>,
    clients_v6: Vec<IpAddr>,
    exporter: IpAddr,
    /// Antwort-Flow der zuletzt erzeugten Verbindung, wird als nächster Flow ausgegeben.
    pending: Option<FlowRecord>,
}

impl TrafficModel {
    pub fn new(seed: u64) -> Self {
        let clients_v4 = (10..40u8).map(|i| IpAddr::V4(Ipv4Addr::new(192, 168, 1, i))).collect();
        let clients_v6 = (0x10..0x18u16)
            .map(|i| IpAddr::V6(Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 0x1, 0, 0, 0, i)))
            .collect();
        Self { rng: Rng::new(seed), clients_v4, clients_v6, exporter: IpAddr::V4(Ipv4Addr::UNSPECIFIED), pending: None }
    }

    pub fn next_flows(&mut self, count: usize, now_ms: i64) -> Vec<FlowRecord> {
        (0..count).map(|_| self.next_flow(now_ms)).collect()
    }

    fn next_flow(&mut self, now_ms: i64) -> FlowRecord {
        if let Some(response) = self.pending.take() {
            return response;
        }
        // ~3 % eingehende Verbindungsversuche (Scanner) auf einen per Port-Forwarding erreichbaren Server
        if self.rng.below(100) < 3 {
            let scanner = IpAddr::V4(Ipv4Addr::new(45, 146, 164, self.rng.below(250) as u8 + 1));
            let port = *self.rng.pick(&[22u16, 23, 3389, 445, 8080, 5900, 1433]);
            let src_port = self.ephemeral();
            return self.flow(scanner, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), src_port, port, 6, 60, 1, 0x02, now_ms);
        }
        let total_weight: u64 = SERVICES.iter().map(|s| s.weight).sum();
        let mut roll = self.rng.below(total_weight);
        let service = SERVICES
            .iter()
            .find(|s| {
                if roll < s.weight {
                    true
                } else {
                    roll -= s.weight;
                    false
                }
            })
            .unwrap_or(&SERVICES[0]);
        let server: IpAddr = self.rng.pick(service.servers).parse().expect("gültige Server-IP");
        let client = if server.is_ipv6() {
            *self.rng.pick(&self.clients_v6)
        } else {
            // Die ersten drei Clients erzeugen deutlich mehr Verkehr (Top Talker)
            let idx = if self.rng.below(3) == 0 { self.rng.below(3) } else { self.rng.below(self.clients_v4.len() as u64) };
            self.clients_v4[idx as usize]
        };
        // Mindestgröße je Dienst: ein HTTPS-Flow hat realistisch eher KB als Bytes
        let bytes = self.rng.heavy_tail((service.max_bytes / 20_000).max(64), service.max_bytes);
        // Anteil, den der Client selbst sendet: Web/Streaming fast nur Download, SSH/SMB/Videocalls symmetrischer
        let upload_percent: u64 = match (service.proto, service.port) {
            (6, 443) | (17, 443) | (6, 80) => 4 + self.rng.below(6),
            (6, 993) => 15,
            (6, 22) | (6, 445) | (17, 3478) => 30 + self.rng.below(50),
            (17, 51820) => 25,
            _ => 50,
        };
        let request_bytes = (bytes * upload_percent / 100).max(60);
        let flags = if service.proto == 6 { 0x1b } else { 0 };
        let (src_port, dst_port) = if service.proto == 1 { (0, 0x0800) } else { (self.ephemeral(), service.port) };
        let request = self.flow(client, server, src_port, dst_port, service.proto, request_bytes, (request_bytes / 700).max(1), flags, now_ms);
        let reply_port = if service.proto == 1 { 0 } else { dst_port };
        let mut response = self.flow(server, client, reply_port, src_port, service.proto, bytes, (bytes / 1300).max(1), flags, now_ms);
        response.start_ms = request.start_ms;
        self.pending = Some(response);
        request
    }

    fn ephemeral(&mut self) -> u16 {
        49152 + self.rng.below(16383) as u16
    }

    #[allow(clippy::too_many_arguments)]
    fn flow(&mut self, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, proto: u8, bytes: u64, packets: u64, tcp_flags: u8, now_ms: i64) -> FlowRecord {
        let duration = self.rng.below(60_000) as i64;
        FlowRecord {
            ts_ms: now_ms,
            start_ms: now_ms - duration,
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            proto,
            bytes,
            packets,
            tcp_flags,
            in_if: 1,
            out_if: 2,
            exporter: self.exporter,
            direction: Default::default(),
        }
    }
}
