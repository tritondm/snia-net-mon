//! Minimaler PCAP-Leser/-Schreiber für die Paketvorschau im Frontend.
//!
//! Unterstützt das klassische libpcap-Format (µs und ns, beide Byte-Reihenfolgen) mit den Link-Typen, die auf einer
//! pfSense vorkommen: Ethernet (inkl. VLAN/QinQ), BSD-Loopback/NULL (lo0, enc0, tun), Raw IP, Linux SLL und pflog.
//! Eine noch wachsende Datei (laufender Trace) wird bis zum letzten vollständigen Paket gelesen.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize)]
pub struct PacketSummary {
    pub index: usize,
    /// Zeitstempel in Unix-Mikrosekunden.
    pub ts_us: i64,
    pub len: u32,
    pub caplen: u32,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub proto: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub summary: String,
    /// Die ersten 64 Byte als Hex-Dump (für die Detailansicht).
    pub hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketPage {
    pub total: usize,
    pub offset: usize,
    pub link_type: u32,
    pub packets: Vec<PacketSummary>,
}

struct Header {
    big_endian: bool,
    nanos: bool,
    link_type: u32,
}

fn parse_header(data: &[u8]) -> Result<Header, String> {
    if data.len() < 24 {
        return Err("Datei enthält noch keinen vollständigen PCAP-Header".into());
    }
    let magic = [data[0], data[1], data[2], data[3]];
    let (big_endian, nanos) = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        _ => return Err("kein PCAP-Format (pcapng wird nicht unterstützt)".into()),
    };
    let link_type = read_u32(&data[20..24], big_endian) & 0x0fff_ffff;
    Ok(Header { big_endian, nanos, link_type })
}

/// Pakete ab `offset` zusammenfassen; `total` zählt alle vollständigen Pakete der Datei.
pub fn summarize(data: &[u8], offset: usize, limit: usize) -> Result<PacketPage, String> {
    let header = parse_header(data)?;
    let mut pos = 24;
    let mut index = 0;
    let mut packets = Vec::new();
    while pos + 16 <= data.len() {
        let secs = read_u32(&data[pos..], header.big_endian) as i64;
        let frac = read_u32(&data[pos + 4..], header.big_endian) as i64;
        let caplen = read_u32(&data[pos + 8..], header.big_endian);
        let len = read_u32(&data[pos + 12..], header.big_endian);
        let start = pos + 16;
        let end = start + caplen as usize;
        if caplen > 262_144 * 4 || end > data.len() {
            break; // unvollständig (Datei wächst noch) oder beschädigt
        }
        if index >= offset && packets.len() < limit {
            let frame = &data[start..end];
            let ts_us = secs * 1_000_000 + if header.nanos { frac / 1000 } else { frac };
            packets.push(describe(index, ts_us, len, caplen, header.link_type, frame));
        }
        index += 1;
        pos = end;
    }
    Ok(PacketPage { total: index, offset, link_type: header.link_type, packets })
}

fn describe(index: usize, ts_us: i64, len: u32, caplen: u32, link_type: u32, frame: &[u8]) -> PacketSummary {
    let mut p = PacketSummary {
        index,
        ts_us,
        len,
        caplen,
        src: None,
        dst: None,
        proto: "?".into(),
        src_port: None,
        dst_port: None,
        summary: String::new(),
        hex: frame.iter().take(64).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
    };
    match layer3(link_type, frame) {
        Some(L3::V4(ip)) => decode_ipv4(ip, &mut p),
        Some(L3::V6(ip)) => decode_ipv6(ip, &mut p),
        Some(L3::Arp(arp)) => {
            p.proto = "ARP".into();
            p.summary = if arp.len() >= 28 {
                let target = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
                let sender = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
                match u16::from_be_bytes([arp[6], arp[7]]) {
                    1 => format!("ARP who-has {target} tell {sender}"),
                    2 => format!("ARP reply {sender} is-at {}", mac(&arp[8..14])),
                    op => format!("ARP op {op}"),
                }
            } else {
                "ARP (gekürzt)".into()
            };
        }
        Some(L3::Other(ethertype)) => {
            p.proto = format!("0x{ethertype:04x}");
            p.summary = format!("Ethertype 0x{ethertype:04x}, {len} Bytes");
        }
        None => p.summary = format!("Link-Typ {link_type}, {len} Bytes"),
    }
    p
}

enum L3<'a> {
    V4(&'a [u8]),
    V6(&'a [u8]),
    Arp(&'a [u8]),
    Other(u16),
}

fn layer3(link_type: u32, frame: &[u8]) -> Option<L3<'_>> {
    match link_type {
        1 => {
            // Ethernet, VLAN-Tags überspringen
            let mut pos = 12;
            let mut ethertype = u16::from_be_bytes([*frame.get(pos)?, *frame.get(pos + 1)?]);
            while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                pos += 4;
                ethertype = u16::from_be_bytes([*frame.get(pos)?, *frame.get(pos + 1)?]);
            }
            let payload = frame.get(pos + 2..)?;
            Some(match ethertype {
                0x0800 => L3::V4(payload),
                0x86dd => L3::V6(payload),
                0x0806 => L3::Arp(payload),
                other => L3::Other(other),
            })
        }
        0 | 108 => {
            // BSD-Loopback: 4 Byte Adressfamilie (NULL: Host-Byte-Order, LOOP: Network-Byte-Order)
            let family = frame.get(..4)?;
            let af = u32::from_le_bytes(family.try_into().ok()?).min(u32::from_be_bytes(family.try_into().ok()?));
            by_family(af, frame.get(4..)?)
        }
        117 => {
            // pflog: Header-Länge im ersten Byte, auf 4 Byte ausgerichtet; Adressfamilie im zweiten Byte
            let hdr = (*frame.first()? as usize).div_ceil(4) * 4;
            by_family(*frame.get(1)? as u32, frame.get(hdr..)?)
        }
        113 => {
            // Linux cooked capture
            let proto = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
            let payload = frame.get(16..)?;
            Some(match proto {
                0x0800 => L3::V4(payload),
                0x86dd => L3::V6(payload),
                other => L3::Other(other),
            })
        }
        12 | 14 | 101 => match frame.first()? >> 4 {
            4 => Some(L3::V4(frame)),
            6 => Some(L3::V6(frame)),
            _ => None,
        },
        _ => None,
    }
}

fn by_family(af: u32, payload: &[u8]) -> Option<L3<'_>> {
    match af {
        2 => Some(L3::V4(payload)),
        10 | 24 | 28 | 30 => Some(L3::V6(payload)),
        _ => None,
    }
}

fn decode_ipv4(ip: &[u8], p: &mut PacketSummary) {
    if ip.len() < 20 {
        p.summary = "IPv4 (gekürzt)".into();
        return;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    let fragment_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let payload = if fragment_offset == 0 { ip.get(ihl..).unwrap_or(&[]) } else { &[] };
    decode_l4(ip[9], src, dst, payload, ip[8], p);
}

fn decode_ipv6(ip: &[u8], p: &mut PacketSummary) {
    if ip.len() < 40 {
        p.summary = "IPv6 (gekürzt)".into();
        return;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).expect("16 Byte")));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).expect("16 Byte")));
    let mut next = ip[6];
    let mut pos = 40;
    // Einfache Extension-Header (Hop-by-Hop, Routing, Destination Options) überspringen
    while matches!(next, 0 | 43 | 60) && pos + 8 <= ip.len() {
        next = ip[pos];
        pos += (ip[pos + 1] as usize + 1) * 8;
    }
    decode_l4(next, src, dst, ip.get(pos..).unwrap_or(&[]), ip[7], p);
}

fn decode_l4(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8], ttl: u8, p: &mut PacketSummary) {
    p.src = Some(src.to_string());
    p.dst = Some(dst.to_string());
    p.proto = model::proto_name(proto).to_string();
    let ports = (l4.len() >= 4).then(|| (u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]])));
    let fmt_ep = |ip: IpAddr, port: u16| match ip {
        IpAddr::V6(_) => format!("[{ip}]:{port}"),
        IpAddr::V4(_) => format!("{ip}:{port}"),
    };
    match (proto, ports) {
        (6, Some((sp, dp))) => {
            p.src_port = Some(sp);
            p.dst_port = Some(dp);
            let flags = l4.get(13).copied().unwrap_or(0);
            let data_offset = l4.get(12).map(|b| (b >> 4) as usize * 4).unwrap_or(20);
            let payload = l4.len().saturating_sub(data_offset);
            p.summary = format!("{} → {} [{}] ttl={ttl} len={payload}", fmt_ep(src, sp), fmt_ep(dst, dp), tcp_flags(flags));
        }
        (17, Some((sp, dp))) => {
            p.src_port = Some(sp);
            p.dst_port = Some(dp);
            let app = match (sp, dp) {
                (53, _) | (_, 53) => " DNS",
                (123, _) | (_, 123) => " NTP",
                (67 | 68, _) | (_, 67 | 68) => " DHCP",
                (443, _) | (_, 443) => " QUIC",
                (51820, _) | (_, 51820) => " WireGuard",
                _ => "",
            };
            p.summary = format!("{} → {}{app} len={}", fmt_ep(src, sp), fmt_ep(dst, dp), l4.len().saturating_sub(8));
        }
        (1 | 58, _) if !l4.is_empty() => {
            let kind = match (proto, l4[0]) {
                (1, 8) | (58, 128) => "echo request",
                (1, 0) | (58, 129) => "echo reply",
                (1, 3) | (58, 1) => "unreachable",
                (1, 11) | (58, 3) => "time exceeded",
                (58, 135) => "neighbor solicitation",
                (58, 136) => "neighbor advertisement",
                _ => "",
            };
            p.summary = format!("{src} → {dst} {} type={} {kind}", p.proto, l4[0]);
        }
        _ => p.summary = format!("{src} → {dst} {} (Protokoll {proto})", p.proto),
    }
}

fn tcp_flags(flags: u8) -> String {
    let names = [(0x02, 'S'), (0x01, 'F'), (0x04, 'R'), (0x08, 'P'), (0x20, 'U'), (0x10, '.')];
    let s: String = names.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, c)| *c).collect();
    if s.is_empty() { "none".into() } else { s }
}

fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn read_u32(b: &[u8], big_endian: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
}

// ---------------------------------------------------------------------------------------------- Schreiben (Mock-Backend)

/// PCAP-Dateikopf (Little Endian, Mikrosekunden).
pub fn global_header(link_type: u32, snaplen: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&snaplen.to_le_bytes());
    h.extend_from_slice(&link_type.to_le_bytes());
    h
}

pub fn record(ts_us: i64, frame: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + frame.len());
    r.extend_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    r.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    r.extend_from_slice(frame);
    r
}

/// Plausibles Ethernet/IPv4-Paket (TCP oder UDP) mit gültigen Prüfsummen, abgeleitet aus einer Zufallszahl.
pub fn synthetic_packet(rand: u64) -> Vec<u8> {
    const SERVERS: [[u8; 4]; 5] = [[1, 1, 1, 1], [142, 250, 185, 78], [151, 101, 1, 140], [9, 9, 9, 9], [140, 82, 121, 4]];
    let client = [192, 168, 1, 10 + (rand % 20) as u8];
    let server = SERVERS[(rand >> 8) as usize % SERVERS.len()];
    let udp = server[0] == 1 || server[0] == 9;
    let (sport, dport) = (49152 + (rand >> 16) as u16 % 16000, if udp { 53 } else { 443 });
    let outbound = rand >> 40 & 1 == 0;
    let (src, dst, sp, dp) = if outbound { (client, server, sport, dport) } else { (server, client, dport, sport) };
    let payload_len = if udp { 40 + (rand >> 32) as usize % 60 } else { [0usize, 0, 517, 1360][(rand >> 44) as usize % 4] };

    let mut l4 = Vec::new();
    l4.extend_from_slice(&sp.to_be_bytes());
    l4.extend_from_slice(&dp.to_be_bytes());
    if udp {
        l4.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        l4.extend_from_slice(&0u16.to_be_bytes());
    } else {
        l4.extend_from_slice(&((rand >> 3) as u32).to_be_bytes()); // seq
        l4.extend_from_slice(&((rand >> 11) as u32).to_be_bytes()); // ack
        l4.push(5 << 4);
        l4.push(if payload_len == 0 { [0x02, 0x12, 0x10, 0x11][(rand >> 50) as usize % 4] } else { 0x18 });
        l4.extend_from_slice(&64240u16.to_be_bytes());
        l4.extend_from_slice(&[0, 0, 0, 0]); // Prüfsumme, Urgent
    }
    l4.extend((0..payload_len).map(|i| (i as u8).wrapping_mul(31)));
    let proto = if udp { 17 } else { 6 };
    let checksum = transport_checksum(&src, &dst, proto, &l4);
    let at = if udp { 6 } else { 16 };
    l4[at..at + 2].copy_from_slice(&checksum.to_be_bytes());

    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    ip[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&((rand >> 20) as u16).to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let hc = ones_complement(&ip);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());

    let mut frame = vec![0x00, 0x0d, 0xb9, 0x01, 0x02, 0x03, 0x3c, 0x22, 0xfb, 0x10, 0x20, 0x30, 0x08, 0x00];
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&l4);
    frame
}

fn transport_checksum(src: &[u8; 4], dst: &[u8; 4], proto: u8, l4: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + l4.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(l4);
    ones_complement(&pseudo)
}

fn ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_partial_file() {
        let mut file = global_header(1, 262_144);
        for i in 0..5u64 {
            file.extend(record(1_700_000_000_000_000 + i as i64, &synthetic_packet(i * 7919 + 1)));
        }
        let page = summarize(&file, 1, 2).unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(page.packets.len(), 2);
        assert_eq!(page.packets[0].index, 1);
        assert!(page.packets[0].src.as_deref().unwrap().contains('.'));
        // Angeschnittenes letztes Paket (laufender Trace) wird ignoriert, nicht als Fehler gemeldet
        let cut = &file[..file.len() - 5];
        assert_eq!(summarize(cut, 0, 100).unwrap().total, 4);
        assert!(summarize(&file[..10], 0, 10).is_err());
    }

    #[test]
    fn ip_header_checksum_is_valid() {
        let frame = synthetic_packet(12345);
        assert_eq!(ones_complement(&frame[14..34]), 0);
    }
}
