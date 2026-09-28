//! Streamender Leser für Capture-Dateien: klassisches PCAP (µs- und ns-Zeitstempel, beide Byte-Reihenfolgen) und
//! pcapng (Section-, Interface-, Enhanced-/Simple-Packet-Blöcke, mehrere Interfaces mit eigenem Linktype).
//!
//! Pro Paket liefert der Leser Zeitstempel, Linktype und die rohen Frame-Daten. Der Puffer wird wiederverwendet –
//! keine Allokation pro Paket.

use std::io::{BufReader, ErrorKind, Read};

/// Linklayer-Typ eines Pakets – bestimmt, wie der Frame zerlegt wird.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// BSD-Loopback (DLT 0), z. B. `lo0` oder Tunnel-Interfaces auf der pfSense
    Null,
    /// Ethernet II (DLT 1)
    Ethernet,
    /// Rohes IP ohne L2-Kopf (DLT 101)
    RawIp,
    /// OpenBSD-Loopback (DLT 108)
    Loop,
    /// Linux "cooked" capture (DLT 113)
    LinuxSll,
    /// pf-Log (DLT 117), `tcpdump -i pflog0` auf der pfSense
    Pflog,
    /// Linux "cooked" capture v2 (DLT 276)
    LinuxSll2,
}

impl LinkType {
    fn from_dlt(dlt: u32) -> Option<Self> {
        Some(match dlt {
            0 => Self::Null,
            1 => Self::Ethernet,
            // 12 und 14 werden je nach System ebenfalls für rohes IP benutzt
            101 | 12 | 14 => Self::RawIp,
            108 => Self::Loop,
            113 => Self::LinuxSll,
            117 => Self::Pflog,
            276 => Self::LinuxSll2,
            _ => return None,
        })
    }
}

/// Ein Paket aus der Datei. `linktype` ist `None`, wenn das Interface einen nicht unterstützten Typ hat.
pub struct Record<'a> {
    /// Sekunden seit 1970 (mit Nachkommaanteil)
    pub ts: f64,
    pub linktype: Option<LinkType>,
    pub data: &'a [u8],
}

/// Obergrenze für einen einzelnen Block/Record – schützt vor defekten Längenangaben.
const MAX_BLOCK: usize = 64 * 1024 * 1024;

enum Format {
    Pcap {
        swapped: bool,
        nanos: bool,
        linktype: Option<LinkType>,
    },
    Pcapng {
        swapped: bool,
        interfaces: Vec<Interface>,
    },
}

#[derive(Clone, Copy)]
struct Interface {
    linktype: Option<LinkType>,
    /// Zeitstempel-Einheiten pro Sekunde (Standard 10^6)
    ticks_per_sec: f64,
}

pub struct CaptureReader<R: Read> {
    reader: BufReader<R>,
    format: Format,
    buf: Vec<u8>,
    /// Beginn und Länge der Paketdaten innerhalb von `buf` (pcapng-Blöcke haben einen Kopf davor)
    span: (usize, usize),
    last_ts: f64,
    finished: bool,
}

impl<R: Read> CaptureReader<R> {
    /// Datei-Kopf lesen und Format erkennen.
    pub fn new(inner: R) -> Result<Self, String> {
        let mut reader = BufReader::with_capacity(1 << 20, inner);
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| "Datei zu kurz – keine Capture-Datei".to_string())?;
        let format = match u32::from_le_bytes(magic) {
            0x0a0d0d0a => {
                // pcapng: Section Header Block – die Byte-Reihenfolge steht im Byte-Order-Magic danach
                let mut rest = [0u8; 8];
                reader
                    .read_exact(&mut rest)
                    .map_err(|_| "pcapng-Kopf unvollständig".to_string())?;
                let swapped = match u32::from_le_bytes(rest[4..8].try_into().unwrap()) {
                    0x1a2b3c4d => false,
                    0x4d3c2b1a => true,
                    _ => return Err("pcapng: ungültiges Byte-Order-Magic".into()),
                };
                let total = read_u32(&rest[0..4], swapped) as usize;
                if !(28..=MAX_BLOCK).contains(&total) || !total.is_multiple_of(4) {
                    return Err("pcapng: ungültige Blocklänge im Section Header".into());
                }
                skip(&mut reader, total - 12)?;
                Format::Pcapng {
                    swapped,
                    interfaces: Vec::new(),
                }
            }
            m @ (0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1) => {
                let swapped = m == 0xd4c3b2a1 || m == 0x4d3cb2a1;
                let nanos = m == 0xa1b23c4d || m == 0x4d3cb2a1;
                let mut hdr = [0u8; 20];
                reader
                    .read_exact(&mut hdr)
                    .map_err(|_| "PCAP-Kopf unvollständig".to_string())?;
                // Obere 16 Bit des Linktype-Felds können FCS-Informationen tragen
                let dlt = read_u32(&hdr[16..20], swapped) & 0xffff;
                let linktype = LinkType::from_dlt(dlt)
                    .ok_or_else(|| format!("nicht unterstützter Linktype {dlt}"))?;
                Format::Pcap {
                    swapped,
                    nanos,
                    linktype: Some(linktype),
                }
            }
            m => return Err(format!("keine PCAP/pcapng-Datei (Magic {m:#010x})")),
        };
        Ok(Self {
            reader,
            format,
            buf: Vec::with_capacity(65536),
            span: (0, 0),
            last_ts: 0.0,
            finished: false,
        })
    }

    /// Nächstes Paket; `None` am Dateiende. Ein abgeschnittenes letztes Paket (abgebrochener Mitschnitt) beendet das
    /// Lesen still – alles davor wird ausgewertet.
    pub fn next_record(&mut self) -> Option<Result<Record<'_>, String>> {
        if self.finished {
            return None;
        }
        let result = match self.format {
            Format::Pcap {
                swapped,
                nanos,
                linktype,
            } => self
                .next_pcap(swapped, nanos)
                .map(|r| r.map(|ts| (ts, linktype))),
            Format::Pcapng { .. } => self.next_pcapng(),
        };
        match result {
            Some(Ok((ts, linktype))) => {
                self.last_ts = ts;
                let (start, len) = self.span;
                Some(Ok(Record {
                    ts,
                    linktype,
                    data: &self.buf[start..start + len],
                }))
            }
            Some(Err(e)) => {
                self.finished = true;
                Some(Err(e))
            }
            None => {
                self.finished = true;
                None
            }
        }
    }

    fn next_pcap(&mut self, swapped: bool, nanos: bool) -> Option<Result<f64, String>> {
        let mut rec = [0u8; 16];
        if !read_or_eof(&mut self.reader, &mut rec)? {
            return None;
        }
        let sec = read_u32(&rec[0..4], swapped) as f64;
        let frac = read_u32(&rec[4..8], swapped) as f64;
        let incl = read_u32(&rec[8..12], swapped) as usize;
        if incl > MAX_BLOCK {
            return Some(Err(format!("Paketlänge {incl} unplausibel – Datei defekt")));
        }
        self.buf.resize(incl, 0);
        if !read_or_eof(&mut self.reader, &mut self.buf)? {
            return None;
        }
        self.span = (0, incl);
        Some(Ok(sec + frac / if nanos { 1e9 } else { 1e6 }))
    }

    fn next_pcapng(&mut self) -> Option<Result<(f64, Option<LinkType>), String>> {
        loop {
            let Format::Pcapng { swapped, .. } = self.format else {
                unreachable!()
            };
            let mut head = [0u8; 8];
            if !read_or_eof(&mut self.reader, &mut head)? {
                return None;
            }
            let block_type = read_u32(&head[0..4], swapped);
            let total = read_u32(&head[4..8], swapped) as usize;
            if block_type == 0x0a0d0d0a {
                // Neue Section: Byte-Reihenfolge kann wechseln, Interface-IDs beginnen neu
                return Some(self.new_section(total));
            }
            if !(12..=MAX_BLOCK).contains(&total) {
                return Some(Err(format!(
                    "pcapng: Blocklänge {total} unplausibel – Datei defekt"
                )));
            }
            // Blockinhalt + abschließende Längenangabe
            self.buf.resize(total - 8, 0);
            if !read_or_eof(&mut self.reader, &mut self.buf)? {
                return None;
            }
            let body_len = total - 12;
            let Format::Pcapng {
                swapped,
                interfaces,
            } = &mut self.format
            else {
                unreachable!()
            };
            let swapped = *swapped;
            let body = &self.buf[..body_len];
            match block_type {
                // Interface Description Block
                1 if body.len() >= 8 => {
                    let dlt = read_u16(&body[0..2], swapped) as u32;
                    let ticks_per_sec = tsresol(&body[8..], swapped).unwrap_or(1e6);
                    interfaces.push(Interface {
                        linktype: LinkType::from_dlt(dlt),
                        ticks_per_sec,
                    });
                }
                // Enhanced Packet Block
                6 if body.len() >= 20 => {
                    let iface = interfaces
                        .get(read_u32(&body[0..4], swapped) as usize)
                        .copied();
                    let ticks = ((read_u32(&body[4..8], swapped) as u64) << 32)
                        | read_u32(&body[8..12], swapped) as u64;
                    let caplen = (read_u32(&body[12..16], swapped) as usize).min(body.len() - 20);
                    let Some(iface) = iface else { continue };
                    self.span = (20, caplen);
                    return Some(Ok((ticks as f64 / iface.ticks_per_sec, iface.linktype)));
                }
                // Simple Packet Block: immer Interface 0, ohne Zeitstempel
                3 if body.len() >= 4 => {
                    let Some(iface) = interfaces.first().copied() else {
                        continue;
                    };
                    let caplen = (read_u32(&body[0..4], swapped) as usize).min(body.len() - 4);
                    self.span = (4, caplen);
                    return Some(Ok((self.last_ts, iface.linktype)));
                }
                // Veralteter Packet Block
                2 if body.len() >= 20 => {
                    let iface = interfaces
                        .get(read_u16(&body[0..2], swapped) as usize)
                        .copied();
                    let ticks = ((read_u32(&body[4..8], swapped) as u64) << 32)
                        | read_u32(&body[8..12], swapped) as u64;
                    let caplen = (read_u32(&body[12..16], swapped) as usize).min(body.len() - 20);
                    let Some(iface) = iface else { continue };
                    self.span = (20, caplen);
                    return Some(Ok((ticks as f64 / iface.ticks_per_sec, iface.linktype)));
                }
                // Statistiken, Name Resolution, Kommentare … überspringen
                _ => continue,
            }
        }
    }

    /// Weiteren Section Header Block lesen (die ersten 8 Byte sind schon gelesen); liefert danach das nächste Paket.
    fn new_section(&mut self, raw_total: usize) -> Result<(f64, Option<LinkType>), String> {
        let mut bom = [0u8; 4];
        self.reader
            .read_exact(&mut bom)
            .map_err(|_| "pcapng: Section Header unvollständig".to_string())?;
        let swapped = match u32::from_le_bytes(bom) {
            0x1a2b3c4d => false,
            0x4d3c2b1a => true,
            _ => return Err("pcapng: ungültiges Byte-Order-Magic".into()),
        };
        // Die Länge wurde vor dem Byte-Order-Magic mit der alten Reihenfolge gelesen
        let total = if swapped == matches!(self.format, Format::Pcapng { swapped: true, .. }) {
            raw_total
        } else {
            (raw_total as u32).swap_bytes() as usize
        };
        if !(28..=MAX_BLOCK).contains(&total) {
            return Err("pcapng: ungültige Blocklänge im Section Header".into());
        }
        skip(&mut self.reader, total - 12)?;
        self.format = Format::Pcapng {
            swapped,
            interfaces: Vec::new(),
        };
        match self.next_pcapng() {
            Some(result) => result,
            None => Err("pcapng: Section ohne Pakete am Dateiende".into()),
        }
    }
}

/// Option `if_tsresol` (Code 9) eines Interface Description Blocks auswerten.
fn tsresol(mut options: &[u8], swapped: bool) -> Option<f64> {
    while options.len() >= 4 {
        let code = read_u16(&options[0..2], swapped);
        let len = read_u16(&options[2..4], swapped) as usize;
        let value = options.get(4..4 + len)?;
        match code {
            0 => return None,
            9 if len >= 1 => {
                let v = value[0];
                let exp = (v & 0x7f) as i32;
                return Some(if v & 0x80 != 0 {
                    2f64.powi(exp)
                } else {
                    10f64.powi(exp)
                });
            }
            _ => {}
        }
        options = options.get(4 + len.div_ceil(4) * 4..)?;
    }
    None
}

fn read_u32(b: &[u8], swapped: bool) -> u32 {
    let raw: [u8; 4] = b[..4].try_into().unwrap();
    if swapped {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

fn read_u16(b: &[u8], swapped: bool) -> u16 {
    let raw: [u8; 2] = b[..2].try_into().unwrap();
    if swapped {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    }
}

/// `Some(true)` = gelesen, `Some(false)`/`None` = Dateiende (auch mitten im Record).
fn read_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Option<bool> {
    match reader.read_exact(buf) {
        Ok(()) => Some(true),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => None,
        Err(_) => None,
    }
}

fn skip<R: Read>(reader: &mut R, n: usize) -> Result<(), String> {
    let copied = std::io::copy(&mut reader.take(n as u64), &mut std::io::sink())
        .map_err(|e| e.to_string())?;
    if copied as usize == n {
        Ok(())
    } else {
        Err("Datei endet mitten im Kopf".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap_file(nanos: bool, packets: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let magic: u32 = if nanos { 0xa1b23c4d } else { 0xa1b2c3d4 };
        let mut out = Vec::new();
        out.extend(magic.to_le_bytes());
        out.extend(2u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.extend([0u8; 8]);
        out.extend(65535u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        for (sec, frac, data) in packets {
            out.extend(sec.to_le_bytes());
            out.extend(frac.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(*data);
        }
        out
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let total = (12 + padded) as u32;
        let mut out = Vec::new();
        out.extend(kind.to_le_bytes());
        out.extend(total.to_le_bytes());
        out.extend(body);
        out.resize(8 + padded, 0);
        out.extend(total.to_le_bytes());
        out
    }

    #[test]
    fn reads_classic_pcap_with_micro_and_nano_timestamps() {
        for nanos in [false, true] {
            let frac = if nanos { 500_000_000 } else { 500_000 };
            let file = pcap_file(nanos, &[(10, frac, b"abc"), (11, 0, b"de")]);
            let mut r = CaptureReader::new(&file[..]).unwrap();
            let first = r.next_record().unwrap().unwrap();
            assert_eq!(
                (first.ts, first.data, first.linktype),
                (10.5, &b"abc"[..], Some(LinkType::Ethernet))
            );
            assert_eq!(r.next_record().unwrap().unwrap().data, b"de");
            assert!(r.next_record().is_none());
        }
    }

    #[test]
    fn truncated_last_packet_ends_quietly() {
        let mut file = pcap_file(false, &[(1, 0, b"abcd")]);
        file.truncate(file.len() - 2);
        let mut r = CaptureReader::new(&file[..]).unwrap();
        assert!(r.next_record().is_none());
    }

    #[test]
    fn reads_pcapng_with_tsresol_and_multiple_interfaces() {
        let mut shb = Vec::new();
        shb.extend(0x1a2b3c4du32.to_le_bytes());
        shb.extend(1u16.to_le_bytes());
        shb.extend(0u16.to_le_bytes());
        shb.extend((-1i64).to_le_bytes());
        let mut file = block(0x0a0d0d0a, &shb);
        // Interface 0: Ethernet, Standardauflösung (µs)
        let mut idb0 = vec![1, 0, 0, 0];
        idb0.extend(65535u32.to_le_bytes());
        file.extend(block(1, &idb0));
        // Interface 1: rohes IP, Nanosekunden (if_tsresol = 9)
        let mut idb1 = vec![101, 0, 0, 0];
        idb1.extend(65535u32.to_le_bytes());
        idb1.extend([9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        file.extend(block(1, &idb1));
        let epb = |iface: u32, ticks: u64, data: &[u8]| {
            let mut b = Vec::new();
            b.extend(iface.to_le_bytes());
            b.extend(((ticks >> 32) as u32).to_le_bytes());
            b.extend((ticks as u32).to_le_bytes());
            b.extend((data.len() as u32).to_le_bytes());
            b.extend((data.len() as u32).to_le_bytes());
            b.extend(data);
            block(6, &b)
        };
        file.extend(epb(0, 2_000_000, b"hello"));
        file.extend(epb(1, 3_000_000_000, b"xyz"));
        let mut r = CaptureReader::new(&file[..]).unwrap();
        let a = r.next_record().unwrap().unwrap();
        assert_eq!(
            (a.ts, a.data, a.linktype),
            (2.0, &b"hello"[..], Some(LinkType::Ethernet))
        );
        let b = r.next_record().unwrap().unwrap();
        assert_eq!(
            (b.ts, b.data, b.linktype),
            (3.0, &b"xyz"[..], Some(LinkType::RawIp))
        );
        assert!(r.next_record().is_none());
    }

    #[test]
    fn rejects_other_files() {
        assert!(CaptureReader::new(&b"GIF89a......"[..]).is_err());
    }
}
