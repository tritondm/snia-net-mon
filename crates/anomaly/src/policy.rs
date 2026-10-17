//! Netz-Regeln: benannte Zonen (Netze) und eine geordnete Regelliste wie in einer Firewall. Die erste passende Regel
//! entscheidet: `allow` erlaubt still, `alert` meldet. Flows ohne passende Regel bleiben unbeachtet.
//!
//! Ausgewertet wird nur die **Anfrage**-Richtung einer Verbindung. softflowd exportiert jede Verbindung als zwei Flows;
//! sonst würde die Antwort eines Servers in der Verwaltung an einen Schüler-PC als „verwaltung → schüler“ zählen.
//! Anfrage heißt: bei TCP/UDP ist der Zielport der kleinere (der Dienst), bei ICMP ein Echo-Request.

use model::{Direction, FlowRecord, LocalNetworks};
use serde::Deserialize;

/// Zone aus der Konfiguration (`[[anomaly.zones]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub name: String,
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Alert,
    Allow,
}

/// Regel aus der Konfiguration (`[[anomaly.rules]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Anzeigename, Standard „von → nach“
    #[serde(default)]
    pub name: String,
    /// Zone, `extern` (alles außerhalb von `network.local_networks`) oder `*`
    pub from: String,
    pub to: String,
    /// Nur diese Dienste (Zielports bei TCP/UDP); leer = alle
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub action: Action,
    /// `info`, `warn` oder `high` (Standard)
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "high".into()
}

#[derive(Debug, Clone)]
enum Side {
    Any,
    Extern,
    Zone(LocalNetworks),
}

impl Side {
    fn matches(&self, ip: std::net::IpAddr, local: bool) -> bool {
        match self {
            Side::Any => true,
            Side::Extern => !local,
            Side::Zone(nets) => nets.contains(ip),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub from: String,
    pub to: String,
    from_side: Side,
    to_side: Side,
    ports: Vec<u16>,
    pub alert: bool,
    pub severity: crate::Severity,
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub zones: usize,
}

impl Policy {
    pub fn new(zones: &[ZoneConfig], rules: &[RuleConfig]) -> Result<Self, String> {
        let mut named = Vec::new();
        for zone in zones {
            let name = zone.name.trim().to_lowercase();
            if name.is_empty() || name == "extern" || name == "*" {
                return Err(format!("zones: ungültiger Name {:?} (extern und * sind reserviert)", zone.name));
            }
            if named.iter().any(|(n, _)| *n == name) {
                return Err(format!("zones: {name:?} ist doppelt"));
            }
            let nets = LocalNetworks::parse(&zone.networks).map_err(|e| format!("zones {name:?}: {e}"))?;
            if nets.is_empty() {
                return Err(format!("zones {name:?}: networks ist leer"));
            }
            named.push((name, nets));
        }
        let side = |value: &str| -> Result<Side, String> {
            let value = value.trim().to_lowercase();
            match value.as_str() {
                "*" => Ok(Side::Any),
                "extern" => Ok(Side::Extern),
                _ => named
                    .iter()
                    .find(|(n, _)| *n == value)
                    .map(|(_, nets)| Side::Zone(nets.clone()))
                    .ok_or_else(|| format!("rules: unbekannte Zone {value:?} (definiert: {})", named.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "))),
            }
        };
        let rules = rules
            .iter()
            .map(|r| {
                let from = r.from.trim().to_lowercase();
                let to = r.to.trim().to_lowercase();
                Ok(Rule {
                    name: if r.name.trim().is_empty() { format!("{from} → {to}") } else { r.name.trim().to_string() },
                    from_side: side(&from)?,
                    to_side: side(&to)?,
                    from,
                    to,
                    ports: r.ports.clone(),
                    alert: r.action == Action::Alert,
                    severity: crate::Severity::parse(&r.severity).ok_or_else(|| format!("rules: severity {:?} – erlaubt sind info, warn, high", r.severity))?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { rules, zones: named.len() })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Index der Regel, die diesen Flow meldet – `None`, wenn er erlaubt ist, keine Regel passt oder er keine Anfrage ist.
    pub fn check(&self, flow: &FlowRecord) -> Option<usize> {
        if self.rules.is_empty() || !is_request(flow) {
            return None;
        }
        let src_local = matches!(flow.direction, Direction::Out | Direction::Internal);
        let dst_local = matches!(flow.direction, Direction::In | Direction::Internal);
        let port = matches!(flow.proto, 6 | 17 | 132).then_some(flow.dst_port);
        let index = self.rules.iter().position(|r| {
            r.from_side.matches(flow.src_ip, src_local)
                && r.to_side.matches(flow.dst_ip, dst_local)
                && (r.ports.is_empty() || port.is_some_and(|p| r.ports.contains(&p)))
        })?;
        self.rules[index].alert.then_some(index)
    }
}

/// Anfrage-Richtung einer Verbindung (siehe Moduldoku).
pub fn is_request(flow: &FlowRecord) -> bool {
    match flow.proto {
        6 | 17 | 132 => flow.dst_port < flow.src_port,
        // softflowd legt ICMP-Typ und -Code in den Zielport: Echo-Request ist Typ 8 (IPv4) bzw. 128 (IPv6)
        1 => flow.dst_port >> 8 == 8,
        58 => flow.dst_port >> 8 == 128,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src: &str, dst: &str, src_port: u16, dst_port: u16, direction: Direction) -> FlowRecord {
        FlowRecord {
            ts_ms: 0,
            start_ms: 0,
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port,
            dst_port,
            proto: 6,
            bytes: 100,
            packets: 2,
            tcp_flags: 0x1b,
            in_if: 0,
            out_if: 0,
            exporter: "192.0.2.1".parse().unwrap(),
            direction,
        }
    }

    fn zone(name: &str, nets: &[&str]) -> ZoneConfig {
        ZoneConfig { name: name.into(), networks: nets.iter().map(|s| s.to_string()).collect() }
    }

    fn rule(from: &str, to: &str, ports: &[u16], action: Action) -> RuleConfig {
        RuleConfig { name: String::new(), from: from.into(), to: to.into(), ports: ports.to_vec(), action, severity: "high".into() }
    }

    #[test]
    fn first_matching_rule_decides_and_only_requests_count() {
        let policy = Policy::new(
            &[zone("Schueler", &["10.20.0.0/22"]), zone("server", &["10.0.10.0/28"]), zone("verwaltung", &["10.0.5.0/24"])],
            &[
                rule("schueler", "server", &[443, 445], Action::Allow),
                rule("schueler", "server", &[], Action::Alert),
                rule("schueler", "verwaltung", &[], Action::Alert),
                rule("server", "extern", &[22], Action::Alert),
            ],
        )
        .unwrap();
        assert_eq!(policy.rules[1].name, "schueler → server");
        let internal = Direction::Internal;
        assert_eq!(policy.check(&flow("10.20.1.5", "10.0.10.2", 50000, 445, internal)), None, "erlaubt");
        assert_eq!(policy.check(&flow("10.20.1.5", "10.0.10.2", 50000, 3389, internal)), Some(1));
        assert_eq!(policy.check(&flow("10.20.1.5", "10.0.5.7", 50000, 445, internal)), Some(2));
        // Antwort der Verwaltung an den Schüler-PC ist keine Anfrage und passt auch auf keine Regel
        assert_eq!(policy.check(&flow("10.0.5.7", "10.20.1.5", 445, 50000, internal)), None);
        // Verwaltung → Schüler: keine Regel
        assert_eq!(policy.check(&flow("10.0.5.7", "10.20.1.5", 50000, 445, internal)), None);
        // Server nach extern per SSH, nicht aber per HTTPS
        assert_eq!(policy.check(&flow("10.0.10.2", "203.0.113.9", 50000, 22, Direction::Out)), Some(3));
        assert_eq!(policy.check(&flow("10.0.10.2", "203.0.113.9", 50000, 443, Direction::Out)), None);
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        assert!(Policy::new(&[], &[rule("schueler", "extern", &[], Action::Alert)]).unwrap_err().contains("unbekannte Zone"));
        assert!(Policy::new(&[zone("extern", &["10.0.0.0/8"])], &[]).is_err());
        assert!(Policy::new(&[zone("a", &["10.0.0.0/8"]), zone("A", &["10.1.0.0/16"])], &[]).is_err());
        assert!(Policy::new(&[zone("a", &["kein netz"])], &[]).is_err());
        let bad_severity = RuleConfig { severity: "kritisch".into(), ..rule("*", "extern", &[], Action::Alert) };
        assert!(Policy::new(&[], &[bad_severity]).is_err());
        assert!(Policy::new(&[], &[rule("*", "extern", &[25], Action::Alert)]).unwrap().rules[0].alert);
    }

    #[test]
    fn icmp_echo_request_is_a_request() {
        let mut ping = flow("10.20.1.5", "10.0.5.7", 0, 0x0800, Direction::Internal);
        ping.proto = 1;
        assert!(is_request(&ping));
        ping.dst_port = 0;
        assert!(!is_request(&ping), "Echo-Reply");
    }
}
