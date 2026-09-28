// dissect.rs
//
// Frame-Zergliederung: nimmt die rohen Nutzdaten eines PCAP-Records und zieht
// daraus – je nach Linktype – die interessanten Felder heraus:
//   - Ethernet II (+ 802.1Q-VLAN-Tags), ARP
//   - IPv4 / IPv6 mit TCP, UDP, ICMP als L4
//
// Ziel ist es, NUR die Felder zu lesen, die für die Analyse gebraucht werden
// (Adressen, Ports, Flags, L4-Payload). Keine Checksummen, kaum Allocs –
// deshalb "pfeil schnell".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::reader::LinkType;

/// Kategorie des L4-Protokolls (so wie scapys `TCP in pkt`-Prüfungen).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind4 {
    Tcp,
    Udp,
    Icmp,
    /// z. B. IPv4/IPv6 ohne L4 oder unbekanntes Protokoll.
    Other,
}

/// Das Ergebnis der IP-Zergliederung eines Pakets.
#[derive(Clone, Debug)]
pub struct IpInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub kind4: Kind4,
    /// Quell-Port – nur bei TCP/UDP.
    pub sport: Option<u16>,
    /// Ziel-Port – nur bei TCP/UDP.
    pub dport: Option<u16>,
    /// Die L4-Nutzdaten (z. B. DNS-/HTTP-Bytes). Leer, wenn keine vorhanden.
    pub payload: Vec<u8>,
    /// TCP-Flags-Byte (8 Bit), nur bei TCP gesetzt – für SYN/RST/FIN-Zählung.
    pub flags: Option<u8>,
}

/// Ergebnis der Frame-Zergliederung.
#[derive(Debug)]
pub enum Frame {
    /// ARP (EtherType 0x0806) – wird nur gezählt, nicht weiter zerlegt.
    Arp,
    /// Paket mit IP-Schicht.
    Ip(IpInfo),
}

#[inline]
fn u16_be(bytes: &[u8], i: usize) -> Option<u16> {
    let b = bytes.get(i..i + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

// --------------------------------------------------------------------------
// Einstieg pro Linktype
// --------------------------------------------------------------------------

/// Zerlegt einen rohen Frame. None = Frame ist für die Analyse uninteressant
/// (z. B. unbekannter EtherType, Truncation, nicht unterstütztes Format).
pub fn dissect(data: &[u8], linktype: LinkType) -> Option<Frame> {
    match linktype {
        LinkType::Ethernet => ethernet(data),
        LinkType::RawIp => raw_ip(data),
        LinkType::LinuxSll => linux_sll(data),
        LinkType::LinuxSll2 => linux_sll2(data),
        // BSD-Loopback/-Tunnel: 4 Byte Adressfamilie (Byte-Reihenfolge je nach System) – danach IP
        LinkType::Null | LinkType::Loop => raw_ip(data.get(4..)?),
        // pfSense/OpenBSD pflog: Kopflänge im ersten Byte, auf 4 Byte aufgerundet
        LinkType::Pflog => raw_ip(data.get((*data.first()? as usize + 3) & !3..)?),
    }
}

// --------------------------------------------------------------------------
// Ethernet II (+ VLAN-Tags)
// --------------------------------------------------------------------------

fn ethernet(data: &[u8]) -> Option<Frame> {
    if data.len() < 14 {
        return None;
    }
    // dst(6) src(6) EtherType(2) – danach folgen VLAN-Tags
    let mut i = 12;
    loop {
        let et = u16_be(data, i)?;
        match et {
            // 802.1Q / 802.1ad / Q-in-Q: TCI(2) + nächster Typ(2) überspringen
            0x8100 | 0x88a8 | 0x9100 => {
                i += 4;
                continue;
            }
            0x0800 => return ipv4(data.get(i + 2..)?),
            0x86dd => return ipv6(data.get(i + 2..)?),
            0x0806 => return Some(Frame::Arp),
            _ => return None,
        }
    }
}

// --------------------------------------------------------------------------
// Roh-IP (DLT 101) und Linux SLL (DLT 113)
// --------------------------------------------------------------------------

fn raw_ip(data: &[u8]) -> Option<Frame> {
    match data.first()? >> 4 {
        4 => ipv4(data),
        6 => ipv6(data),
        _ => None,
    }
}

fn linux_sll(data: &[u8]) -> Option<Frame> {
    if data.len() < 16 {
        return None;
    }
    // SLL-Kopf (16 Byte); auf Offset 14 steht der Protokolltyp (wie EtherType)
    match u16_be(data, 14)? {
        0x0800 => ipv4(data.get(16..)?),
        0x86dd => ipv6(data.get(16..)?),
        0x0806 => Some(Frame::Arp),
        _ => None,
    }
}

fn linux_sll2(data: &[u8]) -> Option<Frame> {
    // SLL2-Kopf (20 Byte); Protokolltyp steht ganz vorne
    match u16_be(data, 0)? {
        0x0800 => ipv4(data.get(20..)?),
        0x86dd => ipv6(data.get(20..)?),
        0x0806 => Some(Frame::Arp),
        _ => None,
    }
}

// --------------------------------------------------------------------------
// IPv4
// --------------------------------------------------------------------------

fn ipv4(data: &[u8]) -> Option<Frame> {
    if data.len() < 20 {
        return None;
    }
    if data[0] >> 4 != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let proto = data[9];
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    // Folgefragmente enthalten keinen L4-Kopf – sonst würden Nutzdaten als Ports gelesen
    if u16_be(data, 6)? & 0x1fff != 0 {
        return Some(Frame::Ip(build_ip(src, dst, 0xff, &[])));
    }
    Some(Frame::Ip(build_ip(src, dst, proto, &data[ihl..])))
}

// --------------------------------------------------------------------------
// IPv6 (inkl. der häufigsten Extension-Header)
// --------------------------------------------------------------------------

fn ipv6(data: &[u8]) -> Option<Frame> {
    if data.len() < 40 {
        return None;
    }
    if data[0] >> 4 != 6 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);

    // Extension-Header überspringen (nur deren Länge kennen wir ohne
    // Argumentanalyse). Abbruch bei ESP (50 – verschlüsselt) und No-Next (59).
    let mut proto = data[6];
    let mut off = 40usize;
    loop {
        match proto {
            0 | 43 | 60 | 135 => {
                // Hop-by-hop, Routing, Destination-Options, Mobility:
                // Byte 0 = nächstes Protokoll, Byte 1 = Länge in 8-Byte-Einheiten
                let nh = *data.get(off)?;
                let hdr_len = (*data.get(off + 1)? as usize + 1) * 8;
                if data.len() < off + hdr_len {
                    return None;
                }
                proto = nh;
                off += hdr_len;
            }
            44 => {
                // Fragment-Header: 8 Byte; Offset in Byte 2/3 (>>3 = "offset in 8-byte units")
                // Ein Fragment mit Offset > 0 enthält kein verwertbares L4 mehr.
                let nh = *data.get(off)?;
                let frag_off = ((u16_be(data, off + 2)? & 0xfff8) >> 3) as u32;
                if frag_off != 0 {
                    return Some(Frame::Ip(IpInfo {
                        src: IpAddr::V6(src),
                        dst: IpAddr::V6(dst),
                        kind4: Kind4::Other,
                        sport: None,
                        dport: None,
                        payload: Vec::new(),
                        flags: None,
                    }));
                }
                proto = nh;
                off += 8;
            }
            _ => break,
        }
        if off > data.len() {
            return None;
        }
    }

    let rest = data.get(off..)?;
    Some(Frame::Ip(build_ip(
        IpAddr::V6(src),
        IpAddr::V6(dst),
        proto,
        rest,
    )))
}

// --------------------------------------------------------------------------
// L4
// --------------------------------------------------------------------------

/// Ordnet eine IP-Protokollnummer ihrer Kategorie zu.
fn kind4(proto: u8) -> Kind4 {
    match proto {
        6 => Kind4::Tcp,
        17 => Kind4::Udp,
        1 | 58 => Kind4::Icmp,
        _ => Kind4::Other,
    }
}

impl IpInfo {
    /// Setzt Ports und Nutzdaten für TCP/UDP/ICMP – wird unten von `l4_payload`
    /// verwendet, damit die IPv4-/IPv6-Pfade nicht dupliziert werden.
    fn fill_l4(&mut self, proto: u8, rest: &[u8]) {
        match (self.kind4, proto) {
            (Kind4::Tcp, 6) => {
                if rest.len() < 20 {
                    self.kind4 = Kind4::Other;
                    return;
                }
                self.sport = Some(u16_be(rest, 0).unwrap_or(0));
                self.dport = Some(u16_be(rest, 2).unwrap_or(0));
                // Flags: das zweite Byte nach der Sequenznummer.
                self.flags = Some(rest[13]);
                // Daten-Offset = oberes Halbbyte; bei unplausiblem Wert hinter die 20-Byte-Basis blicken
                let data_off = (rest[12] >> 4) as usize * 4;
                let start = if (20..=rest.len()).contains(&data_off) {
                    data_off
                } else {
                    20
                };
                self.payload = rest.get(start..).unwrap_or(&[]).to_vec();
            }
            (Kind4::Udp, 17) => {
                if rest.len() < 8 {
                    self.kind4 = Kind4::Other;
                    return;
                }
                self.sport = Some(u16_be(rest, 0).unwrap_or(0));
                self.dport = Some(u16_be(rest, 2).unwrap_or(0));
                let udp_len = u16_be(rest, 4).unwrap_or(0) as usize;
                let end = udp_len.min(rest.len());
                self.payload = rest.get(8..end).unwrap_or(&[]).to_vec();
            }
            (Kind4::Icmp, _) => {
                self.payload = rest.to_vec();
            }
            _ => {}
        }
    }
}

/// Erzeugt das IpInfo-Ergebnis und befüllt Ports + Nutzdaten anhand von `proto`.
fn build_ip(src: IpAddr, dst: IpAddr, proto: u8, rest: &[u8]) -> IpInfo {
    let kind4 = kind4(proto);
    let mut info = IpInfo {
        src,
        dst,
        kind4,
        sport: None,
        dport: None,
        payload: Vec::new(),
        flags: None,
    };
    info.fill_l4(proto, rest);
    info
}
