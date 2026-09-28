// dns.rs
//
// Minimaler DNS-Parser: reicht aus, um Requests und Antworten so auszuwerten,
// wie es die scapy-Baseline tut:
//   - Name der Anfrage (erste Question)
//   - Request oder Response?
//   - A-Records (Typ 1) in Antworten  -> aufgelöste IPs
//   - RCODE 3 (NXDOMAIN)               -> Domain existiert nicht
//
// Es wird bewusst nur der DNS-Header + Question/Answer-Abschnitt gelesen.
// Kompression (Name-Pointer) wird verstanden, weil Antworten sie nutzen.

use std::net::Ipv4Addr;

/// Das Ergebnis einer DNS-Schicht-Auswertung.
pub struct DnsInfo {
    /// Name der ersten Question (ohne abschließenden Punkt).
    pub name: Option<String>,
    /// true = DNS-Antwort (QR-Flag), false = Anfrage.
    pub qr: bool,
    /// Aufgelöste A-Records.
    pub a_answers: Vec<Ipv4Addr>,
    /// Antwort mit RCODE 3: Domain existiert nicht.
    pub nxdomain: bool,
}

/// Liest ein u16 big-endian aus einem Slice.
fn u16_be(bytes: &[u8], i: usize) -> Option<u16> {
    let b = bytes.get(i..i + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Liest einen (komprimierten) Domain-Namen ab `start`.
///
/// Liefert (Name, verbrauchte Bytes ab `start` fürs Weiterschalten). Pointer
/// springen per RFC 1035 innerhalb des Pakets; der verbrauchte Zähler zählt
/// nur den Pfad, auf dem der Parser weiterläuft.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut consumed = 0usize;
    let mut jumped = false;

    for _ in 0..128 {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        if b == 0 {
            if !jumped {
                consumed += 1;
            }
            return Some((name, consumed));
        }
        if b & 0xc0 == 0xc0 {
            // Kompressions-Pointer: 14 Bit Offset innerhalb des Pakets.
            if pos + 1 >= buf.len() {
                return None;
            }
            let off = (((b & 0x3f) as usize) << 8) | buf[pos + 1] as usize;
            if !jumped {
                consumed += 2;
            }
            pos = off;
            jumped = true;
            continue;
        }
        let len = b as usize;
        if pos + 1 + len > buf.len() {
            return None;
        }
        let label = &buf[pos + 1..pos + 1 + len];
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        consumed += 1 + len;
        pos += 1 + len;
    }
    None
}

/// Versucht, `payload` als DNS zu parsen.
///
/// Bei DNS über TCP steht ein 2-Byte-Längen-Präfix davor; beide Varianten
/// werden versucht (Abfolge: erst ohne, dann mit Präfix).
pub fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    parse_dns_buf(payload).or_else(|| {
        if payload.len() >= 2 {
            let len = u16_be(payload, 0)? as usize;
            parse_dns_buf(payload.get(2..2 + len)?)
        } else {
            None
        }
    })
}

/// Parser-Variante ohne Längen-Präfix.
fn parse_dns_buf(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16_be(payload, 2)?;
    let qd = u16_be(payload, 4)? as usize;
    let an = u16_be(payload, 6)? as usize;
    if qd == 0 && an == 0 {
        // kein DNS-Inhalt (oder leere Section) – ignorieren
        return None;
    }

    let qr = flags & 0x8000 != 0;
    let mut pos = 12usize;

    // Questions: nur den Namen der ersten brauchen wir, Rest überspringen.
    let mut name = None;
    for q in 0..qd {
        let (n, used) = read_name(payload, pos)?;
        if q == 0 {
            name = Some(n);
        }
        pos += used + 4; // qtype(2) + qclass(2)
        if pos > payload.len() {
            return None;
        }
    }

    let mut a_answers = Vec::new();
    for _ in 0..an {
        // Name überspringen (kann hier ein Pointer sein).
        let (_, used) = read_name(payload, pos)?;
        pos += used;
        if pos + 10 > payload.len() {
            return None;
        }
        let rtype = u16_be(payload, pos)?;
        // Header-Teil nach dem Namen: type(2) class(2) ttl(4) + rdlen folgt
        let rdlen = u16_be(payload, pos + 8)? as usize;
        let rdata_start = pos + 10;
        if rdata_start + rdlen > payload.len() {
            return None;
        }
        match rtype {
            1 if rdlen == 4 => {
                let ip = payload.get(rdata_start..rdata_start + 4)?;
                a_answers.push(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
            }
            _ => {}
        }
        pos = rdata_start + rdlen;
    }

    Some(DnsInfo {
        name,
        qr,
        a_answers,
        nxdomain: qr && flags & 0x000f == 3,
    })
}
