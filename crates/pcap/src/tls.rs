// tls.rs
//
// Minimaler TLS-ClientHello-Parser: liest nur das SNI-Extension (server_name),
// um die Ziel-Domain einer TLS-Verbindung zu erkennen – ohne Entschlüsselung.
// Erwartet die TCP-Nutzdaten am Anfang einer Verbindung (ClientHello).

/// Extrahiert den Server-Name (SNI) aus einem TLS-Handshake-ClientHello.
/// None, wenn der Payload kein (vollständiges) ClientHello mit SNI enthält.
pub fn parse_sni(payload: &[u8]) -> Option<String> {
    // TLS-Record-Header: type(1) + version(2) + length(2)
    if payload.len() < 5 || payload[0] != 0x16 {
        return None; // kein Handshake-Record
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let hs = payload.get(5..5 + rec_len)?;
    if hs.len() < 4 || hs[0] != 0x01 {
        return None; // kein ClientHello
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    // body: legacy_version(2) + random(32), dann die Längenfelder
    let body = hs.get(4..4 + hs_len)?;
    let mut o = 34usize;

    // session_id: 1 Byte Länge
    let sid_len = *body.get(o)? as usize;
    o += 1 + sid_len;
    // cipher_suites: 2 Byte Länge
    let cs_len = u16::from_be_bytes([*body.get(o)?, *body.get(o + 1)?]) as usize;
    o += 2 + cs_len;
    // compression_methods: 1 Byte Länge
    let cm_len = *body.get(o)? as usize;
    o += 1 + cm_len;
    // extensions: 2 Byte Gesamtlänge
    if body.len() < o + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[o], body[o + 1]]) as usize;
    o += 2;
    let ext = body.get(o..o + ext_len)?;

    let mut e = 0usize;
    while e + 4 <= ext.len() {
        let etype = u16::from_be_bytes([ext[e], ext[e + 1]]);
        let elen = u16::from_be_bytes([ext[e + 2], ext[e + 3]]) as usize;
        e += 4;
        if e + elen > ext.len() {
            break;
        }
        if etype == 0 {
            // server_name
            if let Some(name) = parse_server_name(&ext[e..e + elen]) {
                return Some(name);
            }
        }
        e += elen;
    }
    None
}

/// server_name-Extension: Liste von ServerName-Einträgen, wir wollen Typ 0 (host_name).
fn parse_server_name(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = (2 + list_len).min(data.len());
    let mut p = 2usize;
    while p + 3 <= end {
        let ntype = data[p];
        let nlen = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
        p += 3;
        if p + nlen > end {
            break;
        }
        if ntype == 0 {
            let host = &data[p..p + nlen];
            if let Ok(s) = std::str::from_utf8(host) {
                let s = s.trim_end_matches('.');
                if !s.is_empty() {
                    return Some(s.to_ascii_lowercase());
                }
            }
        }
        p += nlen;
    }
    None
}
