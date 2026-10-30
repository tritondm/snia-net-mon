//! Ausnahmen aus der Web-UI: Auffälligkeiten, die dazu passen, werden weiter gespeichert, aber in Liste, Zeitleiste und
//! Zählern ausgeblendet und nie gemailt. Sie wirken sofort, ohne Neustart, und ergänzen die Ausnahmen aus `config.toml`.
//!
//! Eine Ausnahme gilt für eine Art und schränkt mit `host` (IP oder Netz, leer = alle Hosts) und `target` ein. Was ein
//! Ziel ist, hängt von der Art ab:
//!
//! | Art | Ziel |
//! |---|---|
//! | `dns` | Resolver (IP oder Netz) |
//! | `beacon` | Anbieter `AS8075`, Anbieter und Port `AS8075:443` oder Gegenstelle (IP oder Netz) |
//! | `policy` | Name der Netz-Regel |
//! | `country` | Ländercode, z. B. `CN` |
//! | `stat`, `ml`, `scan`, `drift` | – (nur `host`) |

use crate::store::Kind;
use model::LocalNetworks;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Ausnahme, wie die Web-UI sie anlegt oder ändert.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ExceptionInput {
    pub kind: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub comment: String,
    /// Ablauf (Unix-ms), `None` = gilt unbefristet
    #[serde(default)]
    pub expires_ms: Option<i64>,
}

/// Gespeicherte Ausnahme samt Treffern, wie die API sie ausliefert.
#[derive(Debug, Clone, Serialize)]
pub struct ExceptionRow {
    pub id: i64,
    pub kind: &'static str,
    pub host: Option<String>,
    pub target: Option<String>,
    pub comment: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub expires_ms: Option<i64>,
    /// ausgeblendete Auffälligkeiten (im Aufbewahrungszeitraum der Meldungen)
    pub hits: i64,
    pub last_hit_ms: Option<i64>,
}

/// Geprüfte, vereinheitlichte Felder einer Ausnahme (so wird sie gespeichert).
#[derive(Debug, Clone, PartialEq)]
pub struct Normalized {
    pub kind: Kind,
    pub host: Option<String>,
    pub target: Option<String>,
    pub comment: String,
    pub expires_ms: Option<i64>,
}

#[derive(Debug, Clone)]
enum Target {
    Net(LocalNetworks),
    Asn(u32, Option<u16>),
    Name(String),
}

#[derive(Debug, Clone)]
struct Rule {
    id: i64,
    kind: Kind,
    hosts: Option<LocalNetworks>,
    target: Option<Target>,
    expires_ms: Option<i64>,
}

/// Wogegen eine Ausnahme geprüft wird: der interne Host und – je nach Art – das Ziel.
#[derive(Debug, Default)]
pub struct Subject<'a> {
    pub host: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub asn: Option<u32>,
    pub port: Option<u16>,
    pub name: Option<&'a str>,
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

fn parse_asn(value: &str) -> Option<(u32, Option<u16>)> {
    let rest = value.strip_prefix("AS").or_else(|| value.strip_prefix("as"))?;
    match rest.split_once(':') {
        Some((asn, port)) => Some((asn.trim().parse().ok()?, Some(port.trim().parse().ok()?))),
        None => Some((rest.trim().parse().ok()?, None)),
    }
}

/// Eingabe prüfen und vereinheitlichen; die Fehlermeldung ist für die Web-UI gedacht.
pub fn normalize(input: &ExceptionInput) -> Result<Normalized, String> {
    let kind = Kind::parse(&input.kind).ok_or_else(|| format!("unbekannte art {:?}", input.kind))?;
    let host = non_empty(&input.host).map(str::to_string);
    if let Some(h) = &host {
        LocalNetworks::parse(&[h]).map_err(|_| format!("host {h:?}: erwartet eine IP oder ein Netz wie 10.0.3.0/24"))?;
    }
    let target = match (kind, non_empty(&input.target)) {
        (_, None) => None,
        (Kind::Dns, Some(t)) => {
            LocalNetworks::parse(&[t]).map_err(|_| format!("ziel {t:?}: erwartet die IP oder das Netz des Resolvers"))?;
            Some(t.to_string())
        }
        (Kind::Beacon, Some(t)) => match parse_asn(t) {
            Some((asn, Some(port))) => Some(format!("AS{asn}:{port}")),
            Some((asn, None)) => Some(format!("AS{asn}")),
            None if t.to_ascii_uppercase().starts_with("AS") => return Err(format!("ziel {t:?}: erwartet AS8075 oder AS8075:443")),
            None => {
                LocalNetworks::parse(&[t]).map_err(|_| format!("ziel {t:?}: erwartet AS8075, AS8075:443 oder eine IP bzw. ein Netz"))?;
                Some(t.to_string())
            }
        },
        (Kind::Policy, Some(t)) => Some(t.to_string()),
        (Kind::Country, Some(t)) if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) => Some(t.to_ascii_uppercase()),
        (Kind::Country, Some(t)) => return Err(format!("ziel {t:?}: erwartet einen Ländercode wie CN")),
        (Kind::Stat | Kind::Ml | Kind::Scan | Kind::Drift, Some(_)) => return Err(format!("{}: hier gibt es kein ziel, nur einen host", kind.name())),
    };
    if host.is_none() && target.is_none() {
        return Err("host oder ziel angeben – sonst wäre die ganze art ausgenommen".into());
    }
    Ok(Normalized { kind, host, target, comment: input.comment.trim().to_string(), expires_ms: input.expires_ms })
}

/// Die geltenden Ausnahmen, schnell prüfbar.
#[derive(Debug, Clone, Default)]
pub struct Exceptions {
    rules: Vec<Rule>,
}

impl Exceptions {
    /// Aus gespeicherten (bereits geprüften) Zeilen; ungültige werden übersprungen.
    pub fn from_rows(rows: &[ExceptionRow]) -> Self {
        let rules = rows
            .iter()
            .filter_map(|r| {
                let kind = Kind::parse(r.kind)?;
                let hosts = match &r.host {
                    Some(h) => Some(LocalNetworks::parse(&[h]).ok()?),
                    None => None,
                };
                let target = match (&r.target, kind) {
                    (None, _) => None,
                    (Some(t), Kind::Dns) => Some(Target::Net(LocalNetworks::parse(&[t]).ok()?)),
                    (Some(t), Kind::Beacon) => Some(match parse_asn(t) {
                        Some((asn, port)) => Target::Asn(asn, port),
                        None => Target::Net(LocalNetworks::parse(&[t]).ok()?),
                    }),
                    (Some(t), _) => Some(Target::Name(t.clone())),
                };
                Some(Rule { id: r.id, kind, hosts, target, expires_ms: r.expires_ms })
            })
            .collect();
        Self { rules }
    }

    /// Erste passende, noch gültige Ausnahme.
    pub fn find(&self, kind: Kind, s: &Subject, now: i64) -> Option<i64> {
        self.rules
            .iter()
            .find(|r| {
                r.kind == kind
                    && r.expires_ms.is_none_or(|t| t > now)
                    && r.hosts.as_ref().is_none_or(|n| s.host.is_some_and(|h| n.contains(h)))
                    && match &r.target {
                        None => true,
                        Some(Target::Net(n)) => s.peer.is_some_and(|p| n.contains(p)),
                        Some(Target::Asn(asn, port)) => s.asn == Some(*asn) && port.is_none_or(|p| s.port == Some(p)),
                        Some(Target::Name(name)) => s.name.is_some_and(|x| x.eq_ignore_ascii_case(name)),
                    }
            })
            .map(|r| r.id)
    }

    /// Ausnahme für eine Auffälligkeit (neu erkannt oder gespeichert). Bei DNS müssen alle Resolver ausgenommen sein.
    pub fn for_event(&self, kind: Kind, host: &str, detail: &serde_json::Value, now: i64) -> Option<i64> {
        if self.rules.is_empty() {
            return None;
        }
        let host = host.parse().ok();
        let ip = |v: &serde_json::Value| v.as_str().and_then(|s| s.parse().ok());
        match kind {
            Kind::Dns => {
                let resolvers: Vec<IpAddr> = detail["resolvers"].as_array().into_iter().flatten().filter_map(|r| ip(&r["ip"])).collect();
                if resolvers.is_empty() {
                    return self.find(kind, &Subject { host, ..Default::default() }, now);
                }
                let ids: Option<Vec<i64>> = resolvers.iter().map(|p| self.find(kind, &Subject { host, peer: Some(*p), ..Default::default() }, now)).collect();
                ids.and_then(|ids| ids.first().copied())
            }
            Kind::Beacon => {
                let s = Subject {
                    host,
                    peer: ip(&detail["peer"]),
                    asn: detail["asn"].as_u64().and_then(|a| u32::try_from(a).ok()),
                    port: detail["port"].as_u64().and_then(|p| u16::try_from(p).ok()),
                    name: None,
                };
                self.find(kind, &s, now)
            }
            Kind::Policy => self.find(kind, &Subject { host, name: detail["rule"].as_str(), ..Default::default() }, now),
            Kind::Country => self.find(kind, &Subject { host, name: detail["cc"].as_str(), ..Default::default() }, now),
            Kind::Stat | Kind::Ml | Kind::Scan | Kind::Drift => self.find(kind, &Subject { host, ..Default::default() }, now),
        }
    }

    /// Nächster Ablauf nach `now` – danach müssen die Meldungen neu zugeordnet werden.
    pub fn next_expiry(&self, now: i64) -> Option<i64> {
        self.rules.iter().filter_map(|r| r.expires_ms).filter(|&t| t > now).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(id: i64, kind: Kind, host: Option<&str>, target: Option<&str>, expires_ms: Option<i64>) -> ExceptionRow {
        ExceptionRow {
            id,
            kind: kind.name(),
            host: host.map(Into::into),
            target: target.map(Into::into),
            comment: String::new(),
            created_ms: 0,
            updated_ms: 0,
            expires_ms,
            hits: 0,
            last_hit_ms: None,
        }
    }

    fn input(kind: &str, host: &str, target: &str) -> ExceptionInput {
        ExceptionInput { kind: kind.into(), host: Some(host.into()), target: Some(target.into()), ..Default::default() }
    }

    #[test]
    fn input_is_checked_and_normalized() {
        assert_eq!(normalize(&input("beacon", "", "as8075:443")).unwrap().target.as_deref(), Some("AS8075:443"));
        assert_eq!(normalize(&input("country", " 10.0.3.0/24 ", "cn")).unwrap().host.as_deref(), Some("10.0.3.0/24"));
        assert_eq!(normalize(&input("country", "", "cn")).unwrap().target.as_deref(), Some("CN"));
        assert!(normalize(&input("dns", "", "")).is_err(), "ganze Art");
        assert!(normalize(&input("dns", "10.0.0.300", "")).is_err());
        assert!(normalize(&input("dns", "", "kein-resolver")).is_err());
        assert!(normalize(&input("scan", "10.0.0.5", "1.2.3.4")).is_err(), "Portscan hat kein Ziel");
        assert!(normalize(&input("beacon", "", "ASx")).is_err());
        assert!(normalize(&input("unsinn", "10.0.0.5", "")).is_err());
    }

    #[test]
    fn events_are_matched() {
        let ex = Exceptions::from_rows(&[
            row(1, Kind::Dns, Some("10.4.3.200"), None, None),
            row(2, Kind::Dns, None, Some("1.1.1.2"), None),
            row(3, Kind::Beacon, None, Some("AS8075:443"), None),
            row(4, Kind::Scan, Some("10.6.0.0/16"), None, Some(1000)),
            row(5, Kind::Country, Some("10.0.3.0/24"), Some("CN"), None),
        ]);
        let dns = |ips: &[&str]| json!({ "resolvers": ips.iter().map(|ip| json!({ "ip": ip, "flows": 1 })).collect::<Vec<_>>() });
        assert_eq!(ex.for_event(Kind::Dns, "10.4.3.200", &dns(&["8.8.8.8", "9.9.9.9"]), 0), Some(1), "ganzer Host");
        assert_eq!(ex.for_event(Kind::Dns, "10.0.0.7", &dns(&["1.1.1.2"]), 0), Some(2), "Resolver für alle");
        assert_eq!(ex.for_event(Kind::Dns, "10.0.0.7", &dns(&["1.1.1.2", "8.8.8.8"]), 0), None, "nicht alle Resolver");
        let beacon = |asn: u32, port: u16| json!({ "peer": "13.107.6.1", "asn": asn, "port": port });
        assert_eq!(ex.for_event(Kind::Beacon, "10.0.0.7", &beacon(8075, 443), 0), Some(3));
        assert_eq!(ex.for_event(Kind::Beacon, "10.0.0.7", &beacon(8075, 80), 0), None, "anderer Port");
        assert_eq!(ex.for_event(Kind::Scan, "10.6.2.116", &json!({}), 999), Some(4));
        assert_eq!(ex.for_event(Kind::Scan, "10.6.2.116", &json!({}), 1000), None, "abgelaufen");
        assert_eq!(ex.for_event(Kind::Scan, "10.4.0.1", &json!({}), 0), None, "anderer Host");
        assert_eq!(ex.for_event(Kind::Country, "10.0.3.9", &json!({ "cc": "CN" }), 0), Some(5));
        assert_eq!(ex.for_event(Kind::Country, "10.0.3.9", &json!({ "cc": "RU" }), 0), None);
        assert_eq!(ex.next_expiry(0), Some(1000));
        assert_eq!(ex.next_expiry(1000), None);
    }
}
