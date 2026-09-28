//! Automatisches Aktualisieren der GeoLite2-Datenbanken.
//!
//! Mit MaxMind-Konto-ID und Lizenzschlüssel lädt der Server neue Ausgaben selbst herunter (MaxMind veröffentlicht
//! GeoLite2 zweimal pro Woche). Vor jedem Download fragt ein HEAD-Request das Datum der aktuellen Ausgabe ab – das zählt
//! nicht gegen das Download-Limit, geladen wird nur, wenn die lokale Datei älter ist. Die neue Datei wird geprüft,
//! atomar ersetzt und ohne Neustart geladen.
//!
//! Ohne Zugangsdaten prüft der Task nur, ob die Dateien von außen ersetzt wurden (z. B. durch `geoipupdate`), und lädt
//! sie dann ebenfalls neu.

use anyhow::{Context, Result, bail};
use geo::GeoLookup;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Wie oft geprüft wird, ob die Dateien von außen ersetzt wurden.
const RELOAD_CHECK: Duration = Duration::from_secs(600);
/// Höchster Abstand zwischen Bauen und Veröffentlichen einer Ausgabe (MaxMind erscheint zweimal pro Woche)
const PUBLISH_DELAY: Duration = Duration::from_secs(24 * 3600);
const RETRY_AFTER_ERROR: Duration = Duration::from_secs(3600);
const DOWNLOAD_URL: &str = "https://download.maxmind.com/geoip/databases";

pub struct Credentials {
    pub account_id: String,
    pub license_key: String,
}

pub struct UpdaterConfig {
    /// `None` = kein Download, nur Neuladen geänderter Dateien
    pub credentials: Option<Credentials>,
    pub interval: Duration,
}

pub fn spawn(geo: Arc<GeoLookup>, config: UpdaterConfig, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
    let (country, asn) = geo.paths();
    let editions: Vec<(&'static str, PathBuf)> = [("GeoLite2-Country", country), ("GeoLite2-ASN", asn)]
        .into_iter()
        .filter_map(|(edition, path)| Some((edition, path?.to_path_buf())))
        .collect();
    let client = config.credentials.as_ref().map(|_| {
        reqwest::Client::builder()
            .user_agent(concat!("snia-net-mon/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(300))
            .build()
            .expect("HTTP-Client")
    });
    if config.credentials.is_some() {
        tracing::info!(every_h = config.interval.as_secs() / 3600, "GeoIP-Updater aktiv");
    }

    tokio::spawn(async move {
        // Der erste Durchlauf sofort: fehlende Datenbanken werden beim ersten Start gleich geholt.
        let mut next_download = tokio::time::Instant::now();
        loop {
            if let (Some(creds), Some(client)) = (&config.credentials, &client)
                && tokio::time::Instant::now() >= next_download
            {
                let mut failed = false;
                for (edition, path) in &editions {
                    if let Err(err) = update_edition(client, creds, edition, path).await {
                        tracing::warn!(edition, error = %format!("{err:#}"), "GeoIP-Update fehlgeschlagen");
                        failed = true;
                    }
                }
                // Nach einem Fehler (z. B. kein Netz) früher erneut versuchen
                let wait = if failed { config.interval.min(RETRY_AFTER_ERROR) } else { config.interval };
                next_download = tokio::time::Instant::now() + wait;
            }
            let geo = geo.clone();
            if tokio::task::spawn_blocking(move || geo.reload_if_changed()).await.unwrap_or(false) {
                tracing::info!("GeoIP-Datenbanken neu geladen");
            }
            tokio::select! {
                _ = tokio::time::sleep(RELOAD_CHECK) => {}
                _ = shutdown.changed() => return,
            }
        }
    })
}

/// Eine Ausgabe herunterladen, falls MaxMind eine neuere hat als die lokale Datei.
async fn update_edition(client: &reqwest::Client, creds: &Credentials, edition: &str, path: &Path) -> Result<()> {
    let url = format!("{DOWNLOAD_URL}/{edition}/download?suffix=tar.gz");
    let auth = |req: reqwest::RequestBuilder| req.basic_auth(&creds.account_id, Some(&creds.license_key));

    let head = auth(client.head(&url)).send().await.context("MaxMind nicht erreichbar")?;
    check_status(&head)?;
    let remote = head
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok());
    // Maßgeblich ist das Erstellungsdatum in der Datenbank selbst, nicht das Änderungsdatum der Datei (das ändert sich
    // schon beim Kopieren). Veröffentlicht wird eine Ausgabe einige Stunden nach dem Bauen, daher ein Tag Spielraum.
    let local = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || local_build(&path)).await?
    };
    if let (Some(remote), Some(local)) = (remote, local)
        && local + PUBLISH_DELAY >= remote
    {
        tracing::debug!(edition, "GeoIP-Datenbank ist aktuell");
        return Ok(());
    }

    let resp = auth(client.get(&url)).send().await.context("Download fehlgeschlagen")?;
    check_status(&resp)?;
    let archive = resp.bytes().await.context("Download abgebrochen")?;
    let path = path.to_path_buf();
    let edition = edition.to_string();
    tokio::task::spawn_blocking(move || install(&archive, &path, &edition)).await?
}

/// Erstellungszeit der lokalen Datenbank (aus ihren Metadaten); `None`, wenn sie fehlt oder unlesbar ist.
fn local_build(path: &Path) -> Option<SystemTime> {
    let reader = maxminddb::Reader::open_readfile(path).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(reader.metadata.build_epoch))
}

fn check_status(resp: &reqwest::Response) -> Result<()> {
    match resp.status() {
        s if s.is_success() => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => bail!("Konto-ID oder Lizenzschlüssel ungültig (HTTP 401)"),
        reqwest::StatusCode::TOO_MANY_REQUESTS => bail!("Download-Limit von MaxMind erreicht (HTTP 429)"),
        s => bail!("MaxMind antwortet mit HTTP {s}"),
    }
}

/// `.mmdb` aus dem Archiv holen, prüfen und die bisherige Datei atomar ersetzen.
fn install(archive: &[u8], path: &Path, edition: &str) -> Result<()> {
    let mmdb = extract_mmdb(archive)?;
    let reader = maxminddb::Reader::from_source(mmdb.as_slice()).context("heruntergeladene Datenbank ist ungültig")?;
    if reader.metadata.database_type != edition {
        bail!("Archiv enthält {} statt {edition}", reader.metadata.database_type);
    }
    let build = reader.metadata.build_epoch;

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("{} nicht anlegbar", dir.display()))?;
    }
    let tmp = path.with_extension("mmdb.part");
    std::fs::write(&tmp, &mmdb).with_context(|| format!("{} nicht schreibbar", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("{} nicht ersetzbar", path.display()))?;
    let date = SystemTime::UNIX_EPOCH + Duration::from_secs(build);
    tracing::info!(edition, db = %path.display(), built = %httpdate::fmt_http_date(date), "GeoIP-Datenbank aktualisiert");
    Ok(())
}

fn extract_mmdb(archive: &[u8]) -> Result<Vec<u8>> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().context("kein gültiges tar.gz")? {
        let mut entry = entry.context("Archiv beschädigt")?;
        if entry.path()?.extension().is_some_and(|e| e == "mmdb") {
            let mut data = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut data)?;
            return Ok(data);
        }
    }
    bail!("keine .mmdb-Datei im Archiv")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extracts_mmdb_from_archive() {
        let archive = tar_gz(&[
            ("GeoLite2-ASN_20260925/COPYRIGHT.txt", b"c"),
            ("GeoLite2-ASN_20260925/GeoLite2-ASN.mmdb", b"db"),
        ]);
        assert_eq!(extract_mmdb(&archive).unwrap(), b"db");
        assert!(extract_mmdb(&tar_gz(&[("x/README.txt", b"r")])).is_err());
        assert!(extract_mmdb(b"not a gzip").is_err());
    }

    #[test]
    fn install_rejects_invalid_database() {
        let dir = std::env::temp_dir().join(format!("snia-geoupdate-{}", std::process::id()));
        let path = dir.join("GeoLite2-ASN.mmdb");
        let archive = tar_gz(&[("GeoLite2-ASN_1/GeoLite2-ASN.mmdb", b"kaputt")]);
        assert!(install(&archive, &path, "GeoLite2-ASN").is_err());
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn install_replaces_database_and_geo_reloads() {
        let Ok(real) = std::fs::read("../../data/GeoLite2-ASN.mmdb") else {
            return; // GeoLite2-Dateien liegen nicht im Repository
        };
        let dir = std::env::temp_dir().join(format!("snia-geoupdate-ok-{}", std::process::id()));
        let path = dir.join("GeoLite2-ASN.mmdb");
        let geo = GeoLookup::open(None, Some(&path));
        assert!(!geo.enabled());

        install(&tar_gz(&[("GeoLite2-ASN_1/GeoLite2-ASN.mmdb", &real)]), &path, "GeoLite2-ASN").unwrap();
        assert!(install(&tar_gz(&[("x/GeoLite2-ASN.mmdb", &real)]), &path, "GeoLite2-Country").is_err());
        assert!(geo.reload_if_changed());
        assert!(geo.lookup_str("1.1.1.1").and_then(|g| g.asn).is_some());
        assert!(!geo.reload_if_changed());
        let _ = std::fs::remove_dir_all(dir);
    }
}
