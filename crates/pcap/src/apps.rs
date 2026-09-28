// apps.rs
//
// Anwendungs-Klassifikation: ordnet Domains und IP-Präfixe einer App zu,
// z. B. "youtube.com" -> YouTube, "openai.com" -> AI. Die Regeln kommen aus
// einer JSON-Datei (apps.json, siehe Projektwurzel). Daneben gibt es die
// Signal-Hilfen (DNS-Learning, HTTP-Host), die in analyze.rs eingesetzt werden.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use indexmap::IndexMap;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct AppRule {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ip_prefixes: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct AppRules {
    #[serde(flatten)]
    pub apps: IndexMap<String, AppRule>,
    /// Vorab geparste IP-Präfixe (App-Key, Präfix) in Datei-Reihenfolge
    #[serde(skip)]
    prefixes: Vec<(String, Prefix)>,
}

/// Mitgelieferte Standardregeln (YouTube, Microsoft 365, CDN, AI, Streaming, Messenger …).
const DEFAULT_RULES: &str = include_str!("../apps.json");

#[derive(Clone, Debug)]
struct Prefix {
    ip: IpAddr,
    bits: u8,
}

impl AppRules {
    /// Lädt die Regeln aus einer JSON-Datei. Fehlende/ungültige Datei => leere
    /// Regeln (kein harter Fehler), nur eine Warnung auf stderr.
    pub fn load(path: &std::path::Path) -> AppRules {
        let parsed = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| AppRules::from_json(&text));
        match parsed {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(file = %path.display(), %err, "App-Regeln nicht lesbar – Standardregeln aktiv");
                AppRules::builtin()
            }
        }
    }

    /// Die mitgelieferten Standardregeln.
    pub fn builtin() -> AppRules {
        AppRules::from_json(DEFAULT_RULES).expect("apps.json im Crate ist gültig")
    }

    pub fn from_json(text: &str) -> Result<AppRules, String> {
        let mut rules: AppRules = serde_json::from_str(text).map_err(|e| e.to_string())?;
        rules.prefixes = rules
            .apps
            .iter()
            .flat_map(|(name, rule)| {
                rule.ip_prefixes
                    .iter()
                    .filter_map(|p| parse_prefix(p))
                    .map(move |p| (name.clone(), p))
            })
            .collect();
        Ok(rules)
    }

    pub fn empty() -> AppRules {
        AppRules {
            apps: IndexMap::new(),
            prefixes: Vec::new(),
        }
    }

    pub fn label(&self, app: &str) -> String {
        self.apps
            .get(app)
            .and_then(|r| r.label.as_deref())
            .unwrap_or(app)
            .to_string()
    }

    /// Matcht einen Domain-Namen (Subdomain oder exakt) gegen die Regeln.
    /// Erste passende Regel in Datei-Reihenfolge gewinnt.
    pub fn classify_domain(&self, domain: &str) -> Option<String> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return None;
        }
        for (name, rule) in &self.apps {
            for pat in &rule.domains {
                let p = pat.trim_end_matches('.').to_ascii_lowercase();
                if d == p {
                    return Some(name.clone());
                }
                // exakter Subdomain-Suffix ("sub.youtube.com" endet auf ".youtube.com")
                if d.len() > p.len()
                    && d.ends_with(&p)
                    && d.as_bytes()[d.len() - p.len() - 1] == b'.'
                {
                    return Some(name.clone());
                }
            }
        }
        None
    }

    /// Matcht eine IP-Adresse gegen die IP-Präfix-Regeln.
    pub fn classify_ip(&self, ip: &IpAddr) -> Option<String> {
        self.prefixes
            .iter()
            .find(|(_, prefix)| ip_in_prefix(ip, prefix))
            .map(|(name, _)| name.clone())
    }
}

/// "1.2.3.0/24" (bzw. ohne Slash = /32 oder /128) -> Prefix
fn parse_prefix(s: &str) -> Option<Prefix> {
    let (addr, bits) = match s.trim().split_once('/') {
        Some((a, b)) => (a, Some(b.trim().parse::<u8>().ok()?)),
        None => (s.trim(), None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    Some(Prefix {
        ip,
        bits: bits.unwrap_or(max).min(max),
    })
}

/// Liegt `ip` innerhalb `prefix`?
fn ip_in_prefix(ip: &IpAddr, prefix: &Prefix) -> bool {
    match (ip, prefix.ip) {
        (IpAddr::V4(a), IpAddr::V4(p)) => {
            let bits = prefix.bits.min(32);
            let mask = if bits == 0 {
                0
            } else {
                0xffff_ffffu32 << (32 - bits)
            };
            let an = u32::from_be_bytes(a.octets());
            let pn = u32::from_be_bytes(p.octets());
            (an & mask) == (pn & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(p)) => {
            let bits = prefix.bits.min(128);
            let a = a.octets();
            let p = p.octets();
            let full = (bits / 8) as usize;
            let rem = (bits % 8) as usize;
            if full > 0 && a[..full] != p[..full] {
                return false;
            }
            if rem > 0 {
                let mask = 0xffu8 << (8 - rem);
                if a[full] & mask != p[full] & mask {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// Merkt sich IP -> App aus DNS-Antworten (DNS-Learning).
pub struct DnsLearner {
    /// IP -> App-Key
    ip_app: HashMap<String, String>,
    /// IP -> aufgelöste Domain (für Domain-Samples)
    ip_domain: HashMap<String, String>,
}

impl DnsLearner {
    pub fn new() -> Self {
        DnsLearner {
            ip_app: HashMap::new(),
            ip_domain: HashMap::new(),
        }
    }

    /// Registriert, dass `name` auf `ips` aufgelöst wurde. Passt eine App-Regel
    /// auf den Namen, werden die IPs dieser App zugeordnet (später via
    /// `app_for_ip` abrufbar). Liefert die App, falls eine Regel passte.
    pub fn learn(&mut self, rules: &AppRules, name: &str, ips: &[Ipv4Addr]) -> Option<String> {
        let app = rules.classify_domain(name)?;
        for ip in ips {
            let k = ip.to_string();
            self.ip_app.entry(k.clone()).or_insert_with(|| app.clone());
            self.ip_domain.entry(k).or_insert_with(|| name.to_string());
        }
        Some(app)
    }

    pub fn app_for_ip(&self, ip: &str) -> Option<&str> {
        self.ip_app.get(ip).map(|s| s.as_str())
    }

    pub fn domain_for_ip(&self, ip: &str) -> Option<&str> {
        self.ip_domain.get(ip).map(|s| s.as_str())
    }
}

impl Default for DnsLearner {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_prefixes_are_classified() {
        let rules = AppRules::from_json(r#"{"cdn": {"domains": ["fastly.net"], "ip_prefixes": ["151.101.0.0/16", "2a04:4e40::/32"]}}"#).unwrap();
        assert_eq!(
            rules.classify_domain("a.b.fastly.net.").as_deref(),
            Some("cdn")
        );
        assert_eq!(rules.classify_domain("notfastly.net"), None);
        assert_eq!(
            rules
                .classify_ip(&"151.101.1.140".parse().unwrap())
                .as_deref(),
            Some("cdn")
        );
        assert_eq!(rules.classify_ip(&"151.102.1.140".parse().unwrap()), None);
        assert_eq!(
            rules
                .classify_ip(&"2a04:4e40:1::5".parse().unwrap())
                .as_deref(),
            Some("cdn")
        );
        assert!(
            AppRules::builtin()
                .classify_domain("www.youtube.com")
                .is_some()
        );
    }
}
