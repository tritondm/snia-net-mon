//! Parser für NetFlow v9 (RFC 3954) und IPFIX (RFC 7011).
//!
//! Beide Formate sind template-basiert: Der Exporter schickt zuerst Templates (Feldliste + Längen), danach Daten-Records,
//! die sich nur mit dem passenden Template dekodieren lassen. Templates werden pro Exporter-IP, Source-ID bzw.
//! Observation Domain und Template-ID gecacht. Ein Template wird beim Empfang einmal in einen "Dekodierplan"
//! übersetzt, damit das Parsen der (sehr viel häufigeren) Daten-Records ohne Nachschlagen und ohne Allokationen auskommt.

use model::FlowRecord;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

const VARIABLE_LENGTH: u16 = 0xFFFF;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("Paket zu kurz ({0} Bytes)")]
    TooShort(usize),
    #[error("nicht unterstützte Version {0}")]
    UnsupportedVersion(u16),
    #[error("ungültige Set-/FlowSet-Länge {0}")]
    BadSetLength(usize),
    #[error("ungültiges Template")]
    BadTemplate,
}

/// Bedeutung eines Template-Feldes (IANA Information Elements; die NetFlow-v9-Feldtypen 1–127 sind identisch nummeriert).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Bytes,
    Packets,
    Proto,
    TcpFlags,
    SrcPort,
    DstPort,
    SrcV4,
    DstV4,
    SrcV6,
    DstV6,
    InIf,
    OutIf,
    /// flowEndSysUpTime / LAST_SWITCHED (ms seit Systemstart)
    LastUptime,
    /// flowStartSysUpTime / FIRST_SWITCHED
    FirstUptime,
    StartSec,
    EndSec,
    StartMs,
    EndMs,
    /// systemInitTimeMilliseconds (IPFIX)
    SysInitMs,
    Skip,
}

impl FieldKind {
    fn from_ie(enterprise: u32, id: u16) -> Self {
        if enterprise != 0 {
            return FieldKind::Skip;
        }
        match id {
            1 | 85 => FieldKind::Bytes,   // octetDeltaCount / octetTotalCount
            2 | 86 => FieldKind::Packets, // packetDeltaCount / packetTotalCount
            4 => FieldKind::Proto,
            6 => FieldKind::TcpFlags,
            7 => FieldKind::SrcPort,
            8 => FieldKind::SrcV4,
            10 => FieldKind::InIf,
            11 => FieldKind::DstPort,
            12 => FieldKind::DstV4,
            14 => FieldKind::OutIf,
            21 => FieldKind::LastUptime,
            22 => FieldKind::FirstUptime,
            27 => FieldKind::SrcV6,
            28 => FieldKind::DstV6,
            150 => FieldKind::StartSec,
            151 => FieldKind::EndSec,
            152 => FieldKind::StartMs,
            153 => FieldKind::EndMs,
            160 => FieldKind::SysInitMs,
            _ => FieldKind::Skip,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Field {
    kind: FieldKind,
    len: u16,
}

/// Übersetztes Template ("Dekodierplan").
#[derive(Debug, Clone)]
struct Template {
    fields: Vec<Field>,
    /// Summe der festen Feldlängen (ohne variable Felder) – Mindestgröße eines Records.
    min_len: usize,
    has_variable: bool,
    /// Options-Templates liefern keine Flows; ihre Records werden nur übersprungen.
    is_options: bool,
}

impl Template {
    fn new(fields: Vec<Field>, is_options: bool) -> Result<Self, ParseError> {
        if fields.is_empty() {
            return Err(ParseError::BadTemplate);
        }
        let has_variable = fields.iter().any(|f| f.len == VARIABLE_LENGTH);
        let min_len: usize = fields.iter().filter(|f| f.len != VARIABLE_LENGTH).map(|f| f.len as usize).sum();
        if min_len == 0 && !has_variable {
            return Err(ParseError::BadTemplate);
        }
        Ok(Self { fields, min_len, has_variable, is_options })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TemplateKey {
    exporter: IpAddr,
    /// NetFlow v9: Source ID, IPFIX: Observation Domain ID
    domain: u32,
    template_id: u16,
    version: u16,
}

/// Header-Werte, die zur Zeitumrechnung gebraucht werden.
#[derive(Debug, Clone, Copy)]
struct HeaderTime {
    /// Exportzeit in Unix-Millisekunden.
    export_ms: i64,
    /// NetFlow v9: Uptime des Exporters in ms zum Exportzeitpunkt.
    sys_uptime_ms: Option<i64>,
}

/// Ergebnis eines Paketes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParseStats {
    pub flows: usize,
    /// Daten-Sets, für die (noch) kein Template bekannt war – typisch direkt nach dem Start, bis der Exporter
    /// seine Templates erneut sendet (softflowd: alle 16 Pakete bzw. per `-t`).
    pub missing_template_sets: usize,
}

/// Zustandsbehafteter Parser. Jeder Collector-Worker besitzt einen eigenen Parser (kein Locking); dank `SO_REUSEPORT`
/// landen Pakete eines Exporters immer beim selben Worker, sodass dessen Template-Cache vollständig ist.
#[derive(Debug, Default)]
pub struct Parser {
    templates: HashMap<TemplateKey, Template>,
}

impl Parser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Ein UDP-Paket parsen und alle enthaltenen Flows an `out` anhängen.
    pub fn parse(&mut self, exporter: IpAddr, packet: &[u8], out: &mut Vec<FlowRecord>) -> Result<ParseStats, ParseError> {
        if packet.len() < 2 {
            return Err(ParseError::TooShort(packet.len()));
        }
        match u16::from_be_bytes([packet[0], packet[1]]) {
            9 => self.parse_v9(exporter, packet, out),
            10 => self.parse_ipfix(exporter, packet, out),
            other => Err(ParseError::UnsupportedVersion(other)),
        }
    }

    fn parse_v9(&mut self, exporter: IpAddr, packet: &[u8], out: &mut Vec<FlowRecord>) -> Result<ParseStats, ParseError> {
        const HEADER: usize = 20;
        if packet.len() < HEADER {
            return Err(ParseError::TooShort(packet.len()));
        }
        let sys_uptime = be_u32(&packet[4..8]) as i64;
        let unix_secs = be_u32(&packet[8..12]) as i64;
        let source_id = be_u32(&packet[16..20]);
        let time = HeaderTime { export_ms: unix_secs * 1000, sys_uptime_ms: Some(sys_uptime) };

        let mut stats = ParseStats::default();
        let mut offset = HEADER;
        while offset + 4 <= packet.len() {
            let set_id = be_u16(&packet[offset..]);
            let set_len = be_u16(&packet[offset + 2..]) as usize;
            if set_len < 4 || offset + set_len > packet.len() {
                return Err(ParseError::BadSetLength(set_len));
            }
            let body = &packet[offset + 4..offset + set_len];
            match set_id {
                0 => self.v9_templates(exporter, source_id, body)?,
                1 => self.v9_options_templates(exporter, source_id, body)?,
                2..=255 => {} // reserviert
                template_id => {
                    let key = TemplateKey { exporter, domain: source_id, template_id, version: 9 };
                    match self.templates.get(&key) {
                        Some(template) => stats.flows += decode_records(template, body, exporter, time, out),
                        None => stats.missing_template_sets += 1,
                    }
                }
            }
            offset += set_len;
        }
        Ok(stats)
    }

    fn v9_templates(&mut self, exporter: IpAddr, source_id: u32, mut body: &[u8]) -> Result<(), ParseError> {
        while body.len() >= 4 {
            let template_id = be_u16(body);
            let count = be_u16(&body[2..]) as usize;
            let needed = 4 + count * 4;
            if template_id < 256 || body.len() < needed {
                return Err(ParseError::BadTemplate);
            }
            let fields = body[4..needed]
                .as_chunks::<4>().0.iter()
                .map(|c| Field { kind: FieldKind::from_ie(0, be_u16(c)), len: be_u16(&c[2..]) })
                .collect::<Vec<_>>();
            // NetFlow v9 kennt keine variablen Längen – 0xFFFF wäre hier ein Fehler des Exporters
            if fields.iter().any(|f| f.len == VARIABLE_LENGTH) {
                return Err(ParseError::BadTemplate);
            }
            let key = TemplateKey { exporter, domain: source_id, template_id, version: 9 };
            self.templates.insert(key, Template::new(fields, false)?);
            body = &body[needed..];
        }
        Ok(())
    }

    fn v9_options_templates(&mut self, exporter: IpAddr, source_id: u32, mut body: &[u8]) -> Result<(), ParseError> {
        while body.len() >= 6 {
            let template_id = be_u16(body);
            let scope_len = be_u16(&body[2..]) as usize;
            let option_len = be_u16(&body[4..]) as usize;
            let needed = 6 + scope_len + option_len;
            if template_id < 256 || body.len() < needed || !(scope_len + option_len).is_multiple_of(4) {
                return Err(ParseError::BadTemplate);
            }
            let fields = body[6..needed]
                .as_chunks::<4>().0.iter()
                .map(|c| Field { kind: FieldKind::Skip, len: be_u16(&c[2..]) })
                .collect::<Vec<_>>();
            let key = TemplateKey { exporter, domain: source_id, template_id, version: 9 };
            self.templates.insert(key, Template::new(fields, true)?);
            body = &body[needed..];
            // Rest < 6 Bytes ist Padding
        }
        Ok(())
    }

    fn parse_ipfix(&mut self, exporter: IpAddr, packet: &[u8], out: &mut Vec<FlowRecord>) -> Result<ParseStats, ParseError> {
        const HEADER: usize = 16;
        if packet.len() < HEADER {
            return Err(ParseError::TooShort(packet.len()));
        }
        let message_len = be_u16(&packet[2..]) as usize;
        if message_len < HEADER || message_len > packet.len() {
            return Err(ParseError::BadSetLength(message_len));
        }
        let packet = &packet[..message_len];
        let export_secs = be_u32(&packet[4..8]) as i64;
        let domain = be_u32(&packet[12..16]);
        let time = HeaderTime { export_ms: export_secs * 1000, sys_uptime_ms: None };

        let mut stats = ParseStats::default();
        let mut offset = HEADER;
        while offset + 4 <= packet.len() {
            let set_id = be_u16(&packet[offset..]);
            let set_len = be_u16(&packet[offset + 2..]) as usize;
            if set_len < 4 || offset + set_len > packet.len() {
                return Err(ParseError::BadSetLength(set_len));
            }
            let body = &packet[offset + 4..offset + set_len];
            match set_id {
                2 => self.ipfix_templates(exporter, domain, body, false)?,
                3 => self.ipfix_templates(exporter, domain, body, true)?,
                4..=255 | 0 | 1 => {} // reserviert
                template_id => {
                    let key = TemplateKey { exporter, domain, template_id, version: 10 };
                    match self.templates.get(&key) {
                        Some(template) => stats.flows += decode_records(template, body, exporter, time, out),
                        None => stats.missing_template_sets += 1,
                    }
                }
            }
            offset += set_len;
        }
        Ok(stats)
    }

    fn ipfix_templates(&mut self, exporter: IpAddr, domain: u32, mut body: &[u8], options: bool) -> Result<(), ParseError> {
        let header_len = if options { 6 } else { 4 };
        while body.len() >= header_len {
            let template_id = be_u16(body);
            let count = be_u16(&body[2..]) as usize;
            let key = TemplateKey { exporter, domain, template_id, version: 10 };
            if template_id < 256 {
                return Err(ParseError::BadTemplate);
            }
            if count == 0 {
                // Template Withdrawal (RFC 7011, 8.1)
                self.templates.remove(&key);
                body = &body[4..];
                continue;
            }
            let mut pos = header_len;
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                if body.len() < pos + 4 {
                    return Err(ParseError::BadTemplate);
                }
                let raw_id = be_u16(&body[pos..]);
                let len = be_u16(&body[pos + 2..]);
                pos += 4;
                let enterprise = if raw_id & 0x8000 != 0 {
                    if body.len() < pos + 4 {
                        return Err(ParseError::BadTemplate);
                    }
                    let e = be_u32(&body[pos..]);
                    pos += 4;
                    e
                } else {
                    0
                };
                let kind = if options { FieldKind::Skip } else { FieldKind::from_ie(enterprise, raw_id & 0x7FFF) };
                fields.push(Field { kind, len });
            }
            self.templates.insert(key, Template::new(fields, options)?);
            body = &body[pos..];
        }
        Ok(())
    }
}

/// Alle Records eines Daten-Sets dekodieren. Rückgabe: Anzahl erzeugter Flows.
fn decode_records(template: &Template, mut body: &[u8], exporter: IpAddr, time: HeaderTime, out: &mut Vec<FlowRecord>) -> usize {
    let mut produced = 0;
    // Weniger als ein Mindest-Record übrig = Padding am Set-Ende
    while body.len() >= template.min_len.max(1) {
        let Some((record, used)) = decode_record(template, body, exporter, time) else {
            break;
        };
        body = &body[used..];
        if let Some(record) = record {
            out.push(record);
            produced += 1;
        }
        if used == 0 {
            break;
        }
        if !template.has_variable && body.len() < template.min_len {
            break;
        }
    }
    produced
}

/// Einen Record dekodieren. Rückgabe: (Flow – `None` bei Options-Records oder Records ohne IP-Adressen, verbrauchte Bytes).
fn decode_record(template: &Template, data: &[u8], exporter: IpAddr, time: HeaderTime) -> Option<(Option<FlowRecord>, usize)> {
    let mut pos = 0usize;
    let mut r = RawFlow::default();
    for field in &template.fields {
        let len = if field.len == VARIABLE_LENGTH {
            // RFC 7011, 7: 1 Byte Länge, bei 255 folgen 2 Bytes Länge
            let first = *data.get(pos)? as usize;
            pos += 1;
            if first == 255 {
                let long = be_u16(data.get(pos..pos + 2)?) as usize;
                pos += 2;
                long
            } else {
                first
            }
        } else {
            field.len as usize
        };
        let value = data.get(pos..pos + len)?;
        pos += len;
        if template.is_options {
            continue;
        }
        match field.kind {
            FieldKind::Skip => {}
            FieldKind::Bytes => r.bytes = be_uint(value),
            FieldKind::Packets => r.packets = be_uint(value),
            FieldKind::Proto => r.proto = be_uint(value) as u8,
            FieldKind::TcpFlags => r.tcp_flags = be_uint(value) as u8, // IPFIX: 2 Byte, relevant ist das untere Byte
            FieldKind::SrcPort => r.src_port = be_uint(value) as u16,
            FieldKind::DstPort => r.dst_port = be_uint(value) as u16,
            FieldKind::InIf => r.in_if = be_uint(value) as u32,
            FieldKind::OutIf => r.out_if = be_uint(value) as u32,
            FieldKind::SrcV4 => r.src = ipv4(value).or(r.src),
            FieldKind::DstV4 => r.dst = ipv4(value).or(r.dst),
            FieldKind::SrcV6 => r.src = ipv6(value).or(r.src),
            FieldKind::DstV6 => r.dst = ipv6(value).or(r.dst),
            FieldKind::FirstUptime => r.first_uptime = Some(be_uint(value) as i64),
            FieldKind::LastUptime => r.last_uptime = Some(be_uint(value) as i64),
            FieldKind::StartSec => r.start_ms = Some(be_uint(value) as i64 * 1000),
            FieldKind::EndSec => r.end_ms = Some(be_uint(value) as i64 * 1000),
            FieldKind::StartMs => r.start_ms = Some(be_uint(value) as i64),
            FieldKind::EndMs => r.end_ms = Some(be_uint(value) as i64),
            FieldKind::SysInitMs => r.sys_init_ms = Some(be_uint(value) as i64),
        }
    }
    if template.is_options {
        return Some((None, pos));
    }
    Some((r.finish(exporter, time), pos))
}

#[derive(Default)]
struct RawFlow {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    tcp_flags: u8,
    bytes: u64,
    packets: u64,
    in_if: u32,
    out_if: u32,
    first_uptime: Option<i64>,
    last_uptime: Option<i64>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    sys_init_ms: Option<i64>,
}

impl RawFlow {
    fn finish(self, exporter: IpAddr, time: HeaderTime) -> Option<FlowRecord> {
        let (src_ip, dst_ip) = (self.src?, self.dst?);
        // Uptime-Werte in absolute Zeit umrechnen: v9 über (Exportzeit − Uptime), IPFIX über systemInitTimeMilliseconds
        let boot_ms = match (time.sys_uptime_ms, self.sys_init_ms) {
            (_, Some(init)) => Some(init),
            (Some(uptime), None) => Some(time.export_ms - uptime),
            (None, None) => None,
        };
        let from_uptime = |uptime: Option<i64>| uptime.zip(boot_ms).map(|(u, boot)| boot + u);
        let ts_ms = self.end_ms.or_else(|| from_uptime(self.last_uptime)).unwrap_or(time.export_ms);
        let start_ms = self.start_ms.or_else(|| from_uptime(self.first_uptime)).unwrap_or(ts_ms).min(ts_ms);
        Some(FlowRecord {
            ts_ms,
            start_ms,
            src_ip,
            dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
            bytes: self.bytes,
            packets: self.packets,
            tcp_flags: self.tcp_flags,
            in_if: self.in_if,
            out_if: self.out_if,
            exporter,
            direction: Default::default(),
        })
    }
}

#[inline]
fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Vorzeichenlose Big-Endian-Zahl mit 1–8 Byte (IPFIX "reduced-size encoding"). Längere Werte: die letzten 8 Byte.
#[inline]
fn be_uint(b: &[u8]) -> u64 {
    let b = if b.len() > 8 { &b[b.len() - 8..] } else { b };
    b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
}

#[inline]
fn ipv4(b: &[u8]) -> Option<IpAddr> {
    <[u8; 4]>::try_from(b).ok().map(|o| IpAddr::V4(Ipv4Addr::from(o)))
}

#[inline]
fn ipv6(b: &[u8]) -> Option<IpAddr> {
    <[u8; 16]>::try_from(b).ok().map(|o| IpAddr::V6(Ipv6Addr::from(o)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth::{self, Format};

    fn sample_flows() -> Vec<FlowRecord> {
        let exporter: IpAddr = "192.0.2.1".parse().unwrap();
        vec![
            FlowRecord {
                ts_ms: 1_758_800_000_000,
                start_ms: 1_758_799_990_000,
                src_ip: "192.168.1.20".parse().unwrap(),
                dst_ip: "1.1.1.1".parse().unwrap(),
                src_port: 51514,
                dst_port: 443,
                proto: 6,
                bytes: 123_456,
                packets: 120,
                tcp_flags: 0x1b,
                in_if: 1,
                out_if: 2,
                exporter,
                direction: Default::default(),
            },
            FlowRecord {
                ts_ms: 1_758_800_001_000,
                start_ms: 1_758_800_000_500,
                src_ip: "2001:db8::10".parse().unwrap(),
                dst_ip: "2a00:1450:4001::200e".parse().unwrap(),
                src_port: 40000,
                dst_port: 53,
                proto: 17,
                bytes: 90,
                packets: 1,
                tcp_flags: 0,
                in_if: 1,
                out_if: 2,
                exporter,
                direction: Default::default(),
            },
        ]
    }

    fn roundtrip(format: Format) {
        let flows = sample_flows();
        let exporter = flows[0].exporter;
        let mut encoder = synth::Encoder::new(format, 42);
        let packet = encoder.encode(&flows, 1_758_800_002, true);
        let mut parser = Parser::new();
        let mut out = Vec::new();
        let stats = parser.parse(exporter, &packet, &mut out).unwrap();
        assert_eq!(stats.flows, 2);
        assert_eq!(out, flows);
    }

    #[test]
    fn netflow_v9_roundtrip() {
        roundtrip(Format::NetflowV9);
    }

    #[test]
    fn ipfix_roundtrip_with_enterprise_and_variable_fields() {
        roundtrip(Format::Ipfix);
    }

    #[test]
    fn data_without_template_is_counted_not_parsed() {
        let flows = sample_flows();
        let mut encoder = synth::Encoder::new(Format::NetflowV9, 1);
        let packet = encoder.encode(&flows, 1_758_800_002, false);
        let mut out = Vec::new();
        let stats = Parser::new().parse(flows[0].exporter, &packet, &mut out).unwrap();
        assert_eq!(stats.flows, 0);
        assert_eq!(stats.missing_template_sets, 2);
    }

    #[test]
    fn templates_are_isolated_per_exporter() {
        let flows = sample_flows();
        let mut encoder = synth::Encoder::new(Format::Ipfix, 1);
        let mut parser = Parser::new();
        let mut out = Vec::new();
        parser.parse(flows[0].exporter, &encoder.encode(&flows, 1, true), &mut out).unwrap();
        let other: IpAddr = "198.51.100.7".parse().unwrap();
        let stats = parser.parse(other, &encoder.encode(&flows, 1, false), &mut out).unwrap();
        assert_eq!(stats.flows, 0);
        assert_eq!(stats.missing_template_sets, 2);
    }

    #[test]
    fn garbage_never_panics() {
        let mut parser = Parser::new();
        let mut out = Vec::new();
        let flows = sample_flows();
        let packet = synth::Encoder::new(Format::Ipfix, 7).encode(&flows, 1, true);
        // Jede Kürzung und jedes gekippte Byte muss sauber als Fehler oder Teilergebnis enden
        for cut in 0..packet.len() {
            let _ = parser.parse(flows[0].exporter, &packet[..cut], &mut out);
        }
        for i in 0..packet.len() {
            let mut broken = packet.clone();
            broken[i] ^= 0xA5;
            let _ = parser.parse(flows[0].exporter, &broken, &mut out);
        }
        assert_eq!(Parser::new().parse(flows[0].exporter, &[0, 5, 0, 0], &mut out), Err(ParseError::UnsupportedVersion(5)));
    }
}
