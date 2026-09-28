//! GeoIP-Anreicherung: Land und autonomes System (ASN) einer IP aus MaxMind-Datenbanken (GeoLite2-Country/-ASN).
//!
//! Beide Datenbanken sind optional. Fehlt eine, bleiben die zugehörigen Felder leer – die Anwendung läuft ohne Geo-Daten
//! weiter. Private, reservierte und Multicast-Adressen werden gar nicht erst nachgeschlagen.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

#[derive(Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(Deserialize)]
struct CountryRecord {
    country: Option<CountryInfo>,
    /// Fallback für IPs, die nur einem Kontinent-/Registrierungsland zugeordnet sind (z. B. Anycast-Netze)
    registered_country: Option<CountryInfo>,
}

#[derive(Deserialize)]
struct CountryInfo {
    iso_code: Option<String>,
    #[serde(default)]
    names: BTreeMap<String, String>,
}

/// Geo-Daten einer IP. Leere Felder werden nicht serialisiert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GeoInfo {
    /// ISO-3166-Code, z. B. "AT"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        self.cc.is_none() && self.asn.is_none()
    }
}

/// Eine geöffnete Datenbank samt Änderungszeit der Datei (für das Neuladen nach einem Update).
struct Db {
    reader: maxminddb::Reader<Vec<u8>>,
    mtime: Option<SystemTime>,
}

#[derive(Default)]
struct Dbs {
    country: Option<Arc<Db>>,
    asn: Option<Arc<Db>>,
}

/// Geöffnete MaxMind-Datenbanken. Lookups können von beliebig vielen Threads gleichzeitig laufen; nach einem Update der
/// Dateien lädt [`reload_if_changed`](Self::reload_if_changed) sie im laufenden Betrieb neu.
pub struct GeoLookup {
    country_path: Option<PathBuf>,
    asn_path: Option<PathBuf>,
    dbs: RwLock<Arc<Dbs>>,
}

impl GeoLookup {
    /// Datenbanken öffnen. Fehlende oder defekte Dateien ergeben nur eine Warnung.
    pub fn open(country_db: Option<&Path>, asn_db: Option<&Path>) -> Self {
        let dbs = Dbs {
            country: country_db.and_then(|p| open_db(p, "Country")).map(Arc::new),
            asn: asn_db.and_then(|p| open_db(p, "ASN")).map(Arc::new),
        };
        Self {
            country_path: country_db.map(Path::to_path_buf),
            asn_path: asn_db.map(Path::to_path_buf),
            dbs: RwLock::new(Arc::new(dbs)),
        }
    }

    /// Ohne Datenbanken – alle Lookups liefern leere Ergebnisse.
    pub fn disabled() -> Self {
        Self {
            country_path: None,
            asn_path: None,
            dbs: RwLock::new(Arc::default()),
        }
    }

    fn current(&self) -> Arc<Dbs> {
        self.dbs.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Pfade der Datenbanken (Country, ASN) – für den Updater.
    pub fn paths(&self) -> (Option<&Path>, Option<&Path>) {
        (self.country_path.as_deref(), self.asn_path.as_deref())
    }

    /// Dateien neu laden, deren Änderungszeit sich seit dem letzten Laden geändert hat (z. B. nach `geoipupdate` oder dem
    /// eingebauten Updater). Eine defekte neue Datei ersetzt die geladene nicht. Liefert `true`, wenn etwas neu geladen wurde.
    pub fn reload_if_changed(&self) -> bool {
        let old = self.current();
        let country = reload_one(self.country_path.as_deref(), old.country.as_deref(), "Country");
        let asn = reload_one(self.asn_path.as_deref(), old.asn.as_deref(), "ASN");
        if country.is_none() && asn.is_none() {
            return false;
        }
        // Laufende Lookups behalten ihre alten Reader, bis sie ihr Arc freigeben.
        let mut guard = self.dbs.write().unwrap_or_else(|e| e.into_inner());
        *guard = Arc::new(Dbs {
            country: country.map(Arc::new).or_else(|| guard.country.clone()),
            asn: asn.map(Arc::new).or_else(|| guard.asn.clone()),
        });
        true
    }

    pub fn enabled(&self) -> bool {
        let dbs = self.current();
        dbs.asn.is_some() || dbs.country.is_some()
    }

    /// Kurzbeschreibung für `/api/status`, z. B. "country+asn".
    pub fn describe(&self) -> &'static str {
        let dbs = self.current();
        match (dbs.country.is_some(), dbs.asn.is_some()) {
            (true, true) => "country+asn",
            (true, false) => "country",
            (false, true) => "asn",
            (false, false) => "aus",
        }
    }

    /// Erstellungsdatum der geladenen Datenbanken (Unix-Sekunden, aus den Metadaten) – zeigt, wie aktuell sie sind.
    pub fn build_epochs(&self) -> (Option<u64>, Option<u64>) {
        let dbs = self.current();
        let epoch = |db: &Option<Arc<Db>>| db.as_ref().map(|d| d.reader.metadata.build_epoch);
        (epoch(&dbs.country), epoch(&dbs.asn))
    }

    /// Geo-Daten einer IP; leer für nicht-öffentliche Adressen oder unbekannte Netze.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let ip = canonical(ip);
        if !is_public(ip) {
            return GeoInfo::default();
        }
        let dbs = self.current();
        let mut info = GeoInfo::default();
        if let Some(Db { reader, .. }) = dbs.country.as_deref()
            && let Ok(rec) = reader.lookup::<CountryRecord>(ip)
            && let Some(c) = rec.country.or(rec.registered_country)
        {
            info.country = c.names.get("de").or_else(|| c.names.get("en")).cloned();
            info.cc = c.iso_code;
        }
        if let Some(Db { reader, .. }) = dbs.asn.as_deref()
            && let Ok(rec) = reader.lookup::<AsnRecord>(ip)
        {
            info.asn = rec.autonomous_system_number;
            info.org = rec.autonomous_system_organization;
        }
        info
    }

    /// Wie [`lookup`](Self::lookup), aber `None` statt eines leeren Ergebnisses – praktisch für `skip_serializing_if`.
    pub fn lookup_opt(&self, ip: IpAddr) -> Option<GeoInfo> {
        Some(self.lookup(ip)).filter(|g| !g.is_empty())
    }

    /// Wie [`lookup_opt`](Self::lookup_opt) für eine IP als Text.
    pub fn lookup_str(&self, ip: &str) -> Option<GeoInfo> {
        ip.parse().ok().and_then(|ip| self.lookup_opt(ip))
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn open_db(path: &Path, kind: &str) -> Option<Db> {
    let mtime = mtime(path);
    match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => {
            tracing::info!(db = %path.display(), build = reader.metadata.build_epoch, "GeoIP-{kind}-Datenbank geladen");
            Some(Db { reader, mtime })
        }
        Err(err) => {
            tracing::warn!(db = %path.display(), %err, "GeoIP-{kind}-Datenbank nicht verfügbar – Geo-Felder bleiben leer");
            None
        }
    }
}

/// Neue Datenbank, falls sich die Datei geändert hat und lesbar ist; sonst `None` (bisherige bleibt).
fn reload_one(path: Option<&Path>, loaded: Option<&Db>, kind: &str) -> Option<Db> {
    let path = path?;
    let current = mtime(path)?;
    if loaded.is_some_and(|db| db.mtime == Some(current)) {
        return None;
    }
    open_db(path, kind)
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) als IPv4 behandeln.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Öffentlich routbare Adresse? Private, CGNAT, Loopback, Link-Local, Dokumentations-, Multicast- und reservierte Netze nicht.
pub fn is_public(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (b & 0xc0) == 64)
                || (a == 169 && b == 254)
                || (a == 172 && (b & 0xf0) == 16)
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 198 && (b & 0xfe) == 18)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xff00) == 0xff00
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_special_addresses_are_not_public() {
        for ip in [
            "10.1.2.3",
            "192.168.1.1",
            "172.20.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "192.0.2.7",
            "198.51.100.1",
            "203.0.113.9",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::fb",
            "2001:db8::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn missing_databases_give_empty_results() {
        let geo = GeoLookup::open(Some(Path::new("/nonexistent/country.mmdb")), None);
        assert!(!geo.enabled());
        assert_eq!(geo.lookup_str("1.1.1.1"), None);
    }
}
