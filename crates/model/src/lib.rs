//! Gemeinsame Datentypen für alle Crates.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Harte Obergrenze der Live-Datenbank: Flows bleiben dort höchstens 72 Stunden. Danach werden sie gelöscht oder –
/// mit aktivierter Historie – in die Historien-Datenbank verschoben. Die Konfiguration kann den Wert nur verkleinern.
pub const MAX_RETENTION_HOURS: u64 = 72;

/// Ein normalisierter Flow-Datensatz – unabhängig davon, ob er aus NetFlow v9 oder IPFIX stammt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowRecord {
    /// Ende des Flows (Unix-Zeit in Millisekunden). Maßgeblich für Abfragen und Retention.
    pub ts_ms: i64,
    /// Beginn des Flows (Unix-Zeit in Millisekunden).
    pub start_ms: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP-Protokollnummer (6 = TCP, 17 = UDP, 1 = ICMP, …).
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
    pub tcp_flags: u8,
    pub in_if: u32,
    pub out_if: u32,
    /// Absender des Export-Pakets (Firewall, Router, Probe).
    pub exporter: IpAddr,
    /// Verkehrsrichtung relativ zu den internen Netzen (setzt der Collector, siehe [`LocalNetworks`]).
    pub direction: Direction,
}

impl FlowRecord {
    pub fn key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
        }
    }
}

/// 5-Tupel zur Identifikation einer Verbindung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

/// Richtung eines Flows aus Sicht des eigenen Netzes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Weder Quelle noch Ziel sind intern (z. B. Verkehr zwischen zwei öffentlichen Adressen).
    #[default]
    External = 0,
    /// Von extern nach intern (Download bzw. eingehende Verbindung).
    In = 1,
    /// Von intern nach extern (Upload bzw. ausgehende Verbindung).
    Out = 2,
    /// Zwischen internen Netzen (z. B. LAN ↔ VLAN).
    Internal = 3,
}

impl Direction {
    pub const ALL: [Direction; 4] = [Direction::In, Direction::Out, Direction::Internal, Direction::External];

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Direction::In,
            2 => Direction::Out,
            3 => Direction::Internal,
            _ => Direction::External,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
            Direction::Internal => "internal",
            Direction::External => "external",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == value.trim().to_ascii_lowercase())
    }
}

/// Liste von Netzen (CIDR). Dient für die internen Netze (LAN, VLANs, eigenes IPv6-Präfix, WAN-Adresse …) zur
/// Bestimmung der Richtung und für die vom Monitoring ausgenommenen Netze.
#[derive(Debug, Clone)]
pub struct LocalNetworks {
    ranges: Vec<(u128, u128)>,
}

impl LocalNetworks {
    /// Private und lokale Adressbereiche (RFC 1918, CGNAT, Link-Local, Loopback, IPv6-ULA).
    pub const DEFAULT: [&'static str; 8] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
    ];

    /// Liste aus CIDR-Angaben bauen; ungültige Einträge ergeben einen Fehler mit dem betroffenen Eintrag.
    pub fn parse<S: AsRef<str>>(list: &[S]) -> Result<Self, String> {
        let ranges = list
            .iter()
            .map(|entry| {
                let entry = entry.as_ref();
                cidr_range(entry)
                    .map(|(lo, hi)| (u128::from_be_bytes(lo), u128::from_be_bytes(hi)))
                    .ok_or_else(|| format!("ungültiges Netz: {entry:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { ranges })
    }

    /// Leere Liste (trifft keine Adresse).
    pub fn none() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let value = u128::from_be_bytes(ip_to_bytes(ip));
        self.ranges.iter().any(|&(lo, hi)| value >= lo && value <= hi)
    }

    pub fn classify(&self, src: IpAddr, dst: IpAddr) -> Direction {
        match (self.contains(src), self.contains(dst)) {
            (true, true) => Direction::Internal,
            (true, false) => Direction::Out,
            (false, true) => Direction::In,
            (false, false) => Direction::External,
        }
    }
}

impl Default for LocalNetworks {
    fn default() -> Self {
        Self::parse(&Self::DEFAULT).expect("Standardnetze sind gültig")
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Unix-ms als `2026-09-30 13:45:07 UTC`.
pub fn fmt_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s % 3600 / 60, s % 60)
}

/// Tage seit 1970-01-01 → (Jahr, Monat, Tag) im gregorianischen Kalender (Algorithmus von Howard Hinnant).
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Umkehrung von [`civil_from_days`].
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Kurzname eines IP-Protokolls für die Anzeige.
pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        112 => "VRRP",
        132 => "SCTP",
        _ => "OTHER",
    }
}

/// IP-Adresse als 16 Byte (IPv4 als IPv4-mapped IPv6). So lassen sich v4 und v6 in einer Spalte speichern
/// und CIDR-Bereiche per Byte-Vergleich (`BETWEEN`) abfragen.
pub fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn ip_from_bytes(bytes: &[u8]) -> IpAddr {
    let Ok(octets) = <[u8; 16]>::try_from(bytes) else {
        return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    };
    let v6 = Ipv6Addr::from(octets);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// CIDR-Bereich (z. B. `10.0.0.0/8`, `2001:db8::/32` oder eine einzelne IP) als inklusiver 16-Byte-Bereich.
pub fn cidr_range(input: &str) -> Option<([u8; 16], [u8; 16])> {
    let (addr, prefix) = match input.split_once('/') {
        Some((a, p)) => (a.trim(), Some(p.trim().parse::<u32>().ok()?)),
        None => (input.trim(), None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let bits = match ip {
        IpAddr::V4(_) => 32u32,
        IpAddr::V6(_) => 128u32,
    };
    let prefix = prefix.unwrap_or(bits);
    if prefix > bits {
        return None;
    }
    let base = u128::from_be_bytes(ip_to_bytes(ip));
    let host_bits = bits - prefix;
    let mask: u128 = if host_bits == 0 { 0 } else { (1u128 << host_bits) - 1 };
    let low = base & !mask;
    let high = base | mask;
    Some((low.to_be_bytes(), high.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_roundtrip_v4_and_v6() {
        for ip in ["192.168.1.10", "2001:db8::1", "0.0.0.0"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(ip_from_bytes(&ip_to_bytes(ip)), ip);
        }
    }

    #[test]
    fn direction_from_local_networks() {
        let nets = LocalNetworks::parse(&["192.168.0.0/16", "2001:db8:1::/48", "203.0.113.10"]).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(nets.classify(ip("192.168.1.10"), ip("1.1.1.1")), Direction::Out);
        assert_eq!(nets.classify(ip("1.1.1.1"), ip("192.168.1.10")), Direction::In);
        assert_eq!(nets.classify(ip("45.1.2.3"), ip("203.0.113.10")), Direction::In);
        assert_eq!(nets.classify(ip("2001:db8:1::5"), ip("2001:db8:1:20::7")), Direction::Internal);
        assert_eq!(nets.classify(ip("2001:db8:2::5"), ip("8.8.8.8")), Direction::External);
        assert!(LocalNetworks::parse(&["10.0.0.0/40"]).is_err());
        assert!(LocalNetworks::default().contains(ip("fd12:3456::1")));
        assert_eq!(Direction::parse("OUT"), Some(Direction::Out));
        assert_eq!(Direction::from_u8(Direction::Internal.as_u8()), Direction::Internal);
    }

    #[test]
    fn calendar_conversion() {
        assert_eq!(fmt_utc(1_790_775_907_000), "2026-09-30 13:45:07 UTC");
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        for day in [-1, 0, 59, 60, 365 * 30 + 7, 20_000, 100_000] {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), day);
        }
    }

    #[test]
    fn cidr_ranges() {
        let (lo, hi) = cidr_range("10.0.0.0/8").unwrap();
        assert_eq!(ip_from_bytes(&lo), "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(ip_from_bytes(&hi), "10.255.255.255".parse::<IpAddr>().unwrap());
        let (lo, hi) = cidr_range("192.168.1.5").unwrap();
        assert_eq!(lo, hi);
        assert!(cidr_range("10.0.0.0/33").is_none());
        assert!(cidr_range("kein-ip").is_none());
    }
}
