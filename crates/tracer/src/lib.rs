//! Gezielte Paketmitschnitte auf der pfSense.
//!
//! Ein Trace startet per SSH `tcpdump -w -` auf der Firewall und streamt die PCAP-Daten direkt in eine lokale Datei.
//! Die Datei ist schon während des Mitschnitts abrufbar (Download oder JSON-Vorschau über [`pcap`]). Traces unterliegen
//! derselben 72-Stunden-Retention wie die Flow-Daten.
//!
//! Sicherheit: Interface und BPF-Filter werden streng gegen eine Zeichen-Whitelist geprüft und der Filter in einfache
//! Anführungszeichen gesetzt – eine Befehlsinjektion auf der Firewall ist damit ausgeschlossen. Der SSH-Hostschlüssel
//! wird gegen den konfigurierten Fingerabdruck geprüft.

mod backend;
pub mod pcap;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub use backend::{Backend, SshConfig};

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("ungültige Anfrage: {0}")]
    Invalid(String),
    #[error("Trace nicht gefunden")]
    NotFound,
    #[error("zu viele gleichzeitige Traces (max. {0})")]
    TooMany(usize),
    #[error("E/A: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP: {0}")]
    Pcap(String),
}

#[derive(Debug, Clone)]
pub struct TracerConfig {
    pub backend: Backend,
    pub storage_dir: PathBuf,
    pub max_duration_secs: u32,
    pub max_packets: u32,
    pub max_concurrent: usize,
    pub retention_hours: u64,
}

/// Anfrage aus dem Frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRequest {
    /// pfSense-Interface, z. B. `igb0`, `igb1.10`, `ovpns1`
    pub interface: String,
    /// BPF-Filter im tcpdump-Syntax, z. B. `host 192.168.1.20 and port 443` (leer = alles)
    #[serde(default)]
    pub filter: String,
    #[serde(default = "default_duration")]
    pub duration_secs: u32,
    #[serde(default = "default_packets")]
    pub max_packets: u32,
    #[serde(default = "default_snaplen")]
    pub snaplen: u32,
}

fn default_duration() -> u32 {
    30
}
fn default_packets() -> u32 {
    10_000
}
fn default_snaplen() -> u32 {
    262_144
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceStatus {
    Running,
    Completed,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInfo {
    pub id: String,
    pub request: TraceRequest,
    pub status: TraceStatus,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
    pub bytes: u64,
    pub error: Option<String>,
    pub backend: String,
}

/// Laufzeitdaten eines Traces, die sich der Hintergrund-Thread und die API teilen.
pub(crate) struct TraceHandle {
    pub info: Mutex<TraceInfo>,
    pub cancel: AtomicBool,
    pub bytes: AtomicU64,
}

impl TraceHandle {
    fn snapshot(&self) -> TraceInfo {
        let mut info = self.info.lock().expect("Trace-Mutex").clone();
        info.bytes = self.bytes.load(Ordering::Relaxed);
        info
    }

    pub(crate) fn finish(&self, status: TraceStatus, error: Option<String>, dir: &Path) {
        let snapshot = {
            let mut info = self.info.lock().expect("Trace-Mutex");
            info.status = status;
            info.error = error;
            info.finished_ms = Some(model::now_ms());
            info.bytes = self.bytes.load(Ordering::Relaxed);
            info.clone()
        };
        if let Err(err) = write_sidecar(dir, &snapshot) {
            tracing::warn!(id = %snapshot.id, %err, "Trace-Metadaten konnten nicht gespeichert werden");
        }
    }
}

#[derive(Clone)]
pub struct Tracer {
    config: Arc<TracerConfig>,
    traces: Arc<Mutex<HashMap<String, Arc<TraceHandle>>>>,
    counter: Arc<AtomicU64>,
}

impl Tracer {
    /// Tracer anlegen und vorhandene Mitschnitte aus früheren Läufen einlesen (abgelaufene werden dabei gelöscht).
    pub fn new(config: TracerConfig) -> Result<Self, TraceError> {
        std::fs::create_dir_all(&config.storage_dir)?;
        let tracer = Self { config: Arc::new(config), traces: Default::default(), counter: Default::default() };
        tracer.load_existing();
        tracer.cleanup_expired();
        Ok(tracer)
    }

    pub fn backend_name(&self) -> &'static str {
        self.config.backend.name()
    }

    pub fn start(&self, request: TraceRequest) -> Result<TraceInfo, TraceError> {
        let request = self.validate(request)?;
        let running = self.list().iter().filter(|t| t.status == TraceStatus::Running).count();
        if running >= self.config.max_concurrent {
            return Err(TraceError::TooMany(self.config.max_concurrent));
        }
        let now = model::now_ms();
        let id = format!("{:x}{:04x}", now, self.counter.fetch_add(1, Ordering::Relaxed) & 0xffff);
        let info = TraceInfo {
            id: id.clone(),
            request,
            status: TraceStatus::Running,
            started_ms: now,
            finished_ms: None,
            bytes: 0,
            error: None,
            backend: self.config.backend.name().to_string(),
        };
        let handle = Arc::new(TraceHandle { info: Mutex::new(info.clone()), cancel: AtomicBool::new(false), bytes: AtomicU64::new(0) });
        self.traces.lock().expect("Trace-Map").insert(id.clone(), handle.clone());
        write_sidecar(&self.config.storage_dir, &info)?;

        let backend = self.config.backend.clone();
        let path = self.pcap_path_unchecked(&id);
        let dir = self.config.storage_dir.clone();
        std::thread::Builder::new().name(format!("trace-{id}")).spawn(move || {
            backend::run(&backend, &handle, &path, &dir);
        })?;
        tracing::info!(%id, interface = %info.request.interface, filter = %info.request.filter, "Trace gestartet");
        Ok(info)
    }

    pub fn stop(&self, id: &str) -> Result<TraceInfo, TraceError> {
        let handle = self.handle(id)?;
        handle.cancel.store(true, Ordering::Relaxed);
        Ok(handle.snapshot())
    }

    pub fn get(&self, id: &str) -> Result<TraceInfo, TraceError> {
        Ok(self.handle(id)?.snapshot())
    }

    pub fn list(&self) -> Vec<TraceInfo> {
        let mut list: Vec<TraceInfo> = self.traces.lock().expect("Trace-Map").values().map(|h| h.snapshot()).collect();
        list.sort_by_key(|t| std::cmp::Reverse(t.started_ms));
        list
    }

    pub fn delete(&self, id: &str) -> Result<(), TraceError> {
        let handle = self.handle(id)?;
        handle.cancel.store(true, Ordering::Relaxed);
        self.traces.lock().expect("Trace-Map").remove(id);
        remove_files(&self.config.storage_dir, id);
        Ok(())
    }

    /// Pfad zur PCAP-Datei eines bekannten Traces.
    pub fn pcap_path(&self, id: &str) -> Result<PathBuf, TraceError> {
        self.handle(id)?;
        Ok(self.pcap_path_unchecked(id))
    }

    /// Pakete eines Traces als JSON-taugliche Zusammenfassung (Seite ab `offset`).
    pub fn packets(&self, id: &str, offset: usize, limit: usize) -> Result<pcap::PacketPage, TraceError> {
        let path = self.pcap_path(id)?;
        let data = std::fs::read(&path)?;
        pcap::summarize(&data, offset, limit.clamp(1, 1000)).map_err(TraceError::Pcap)
    }

    /// Traces löschen, die älter als die Retention sind. Laufende Traces werden vorher beendet.
    pub fn cleanup_expired(&self) -> usize {
        let hours = self.config.retention_hours.clamp(1, model::MAX_RETENTION_HOURS) as i64;
        let cutoff = model::now_ms() - hours * 3_600_000;
        let expired: Vec<String> = self
            .list()
            .into_iter()
            .filter(|t| t.finished_ms.unwrap_or(t.started_ms) < cutoff)
            .map(|t| t.id)
            .collect();
        for id in &expired {
            let _ = self.delete(id);
        }
        // Verwaiste Dateien ohne Eintrag (z. B. nach Absturz) ebenfalls entfernen, wenn sie alt genug sind
        if let Ok(entries) = std::fs::read_dir(&self.config.storage_dir) {
            for entry in entries.flatten() {
                let old = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .is_some_and(|d| (d.as_millis() as i64) < cutoff);
                if old {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        expired.len()
    }

    fn handle(&self, id: &str) -> Result<Arc<TraceHandle>, TraceError> {
        self.traces.lock().expect("Trace-Map").get(id).cloned().ok_or(TraceError::NotFound)
    }

    fn pcap_path_unchecked(&self, id: &str) -> PathBuf {
        self.config.storage_dir.join(format!("{id}.pcap"))
    }

    fn load_existing(&self) {
        let Ok(entries) = std::fs::read_dir(&self.config.storage_dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(mut info) = std::fs::read(&path).map_err(|_| ()).and_then(|b| serde_json::from_slice::<TraceInfo>(&b).map_err(|_| ())) else {
                continue;
            };
            if !is_valid_id(&info.id) {
                continue;
            }
            if info.status == TraceStatus::Running {
                // Programm wurde während des Mitschnitts beendet
                info.status = TraceStatus::Stopped;
                info.finished_ms.get_or_insert(info.started_ms);
            }
            let bytes = std::fs::metadata(self.pcap_path_unchecked(&info.id)).map(|m| m.len()).unwrap_or(0);
            let handle = TraceHandle { info: Mutex::new(info.clone()), cancel: AtomicBool::new(true), bytes: AtomicU64::new(bytes) };
            self.traces.lock().expect("Trace-Map").insert(info.id, Arc::new(handle));
        }
    }

    fn validate(&self, mut r: TraceRequest) -> Result<TraceRequest, TraceError> {
        r.interface = r.interface.trim().to_string();
        r.filter = r.filter.split_whitespace().collect::<Vec<_>>().join(" ");
        validate_interface(&r.interface)?;
        validate_filter(&r.filter)?;
        if r.duration_secs == 0 || r.duration_secs > self.config.max_duration_secs {
            return Err(TraceError::Invalid(format!("Dauer muss zwischen 1 und {} Sekunden liegen", self.config.max_duration_secs)));
        }
        if r.max_packets == 0 || r.max_packets > self.config.max_packets {
            return Err(TraceError::Invalid(format!("Paketlimit muss zwischen 1 und {} liegen", self.config.max_packets)));
        }
        r.snaplen = r.snaplen.clamp(64, 262_144);
        Ok(r)
    }
}

pub(crate) fn validate_interface(interface: &str) -> Result<(), TraceError> {
    let ok = !interface.is_empty()
        && interface.len() <= 32
        && !interface.starts_with('-')
        && interface.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
    if ok { Ok(()) } else { Err(TraceError::Invalid("ungültiger Interface-Name".into())) }
}

/// BPF-Filter prüfen. Erlaubt ist nur, was tcpdump-Ausdrücke brauchen – keine Anführungszeichen, `$`, `;`, `` ` ``,
/// `\` oder Zeilenumbrüche. Damit kann der (in einfache Anführungszeichen gesetzte) Filter die Shell nicht verlassen.
pub(crate) fn validate_filter(filter: &str) -> Result<(), TraceError> {
    if filter.len() > 512 {
        return Err(TraceError::Invalid("Filter zu lang (max. 512 Zeichen)".into()));
    }
    if filter.starts_with('-') {
        return Err(TraceError::Invalid("Filter darf nicht mit '-' beginnen".into()));
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || " .:/_-()!&|<>=[]*+".contains(c);
    match filter.chars().find(|&c| !allowed(c)) {
        Some(c) => Err(TraceError::Invalid(format!("unzulässiges Zeichen im Filter: {c:?}"))),
        None => Ok(()),
    }
}

/// tcpdump-Befehl für die Firewall. Muss nur mit geprüften Werten aufgerufen werden.
pub(crate) fn build_command(r: &TraceRequest) -> String {
    let mut cmd = format!(
        "timeout {} tcpdump -n -U -i {} -s {} -c {} -w -",
        r.duration_secs, r.interface, r.snaplen, r.max_packets
    );
    if !r.filter.is_empty() {
        cmd.push_str(&format!(" -- '{}'", r.filter));
    }
    cmd
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn write_sidecar(dir: &Path, info: &TraceInfo) -> std::io::Result<()> {
    let tmp = dir.join(format!("{}.json.tmp", info.id));
    std::fs::write(&tmp, serde_json::to_vec_pretty(info).map_err(std::io::Error::other)?)?;
    std::fs::rename(tmp, dir.join(format!("{}.json", info.id)))
}

fn remove_files(dir: &Path, id: &str) {
    for ext in ["pcap", "json"] {
        let _ = std::fs::remove_file(dir.join(format!("{id}.{ext}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_whitelist_blocks_shell_injection() {
        for ok in ["", "host 192.168.1.20 and port 443", "tcp[tcpflags] & (tcp-syn) != 0", "net 2001:db8::/32 and not port 22", "ip6 and udp"] {
            assert!(validate_filter(ok).is_ok(), "{ok}");
        }
        for bad in ["port 22'; rm -rf /; '", "host $(id)", "port 22 `id`", "a;b", "-w /etc/passwd", "x\ny", "port \"22\"", "a\\b"] {
            assert!(validate_filter(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn interface_names() {
        for ok in ["igb0", "igb1.10", "ovpns1", "lagg0_vlan20"] {
            assert!(validate_interface(ok).is_ok());
        }
        for bad in ["", "-i", "igb0;reboot", "igb0 igb1", "a/b"] {
            assert!(validate_interface(bad).is_err());
        }
    }

    #[test]
    fn command_quotes_filter_and_ends_options() {
        let r = TraceRequest { interface: "igb0".into(), filter: "port 53".into(), duration_secs: 10, max_packets: 100, snaplen: 1500 };
        assert_eq!(build_command(&r), "timeout 10 tcpdump -n -U -i igb0 -s 1500 -c 100 -w - -- 'port 53'");
    }

    #[test]
    fn mock_trace_produces_readable_pcap_and_can_be_stopped() {
        let dir = std::env::temp_dir().join(format!("snm-tracer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tracer = Tracer::new(TracerConfig {
            backend: Backend::Mock,
            storage_dir: dir.clone(),
            max_duration_secs: 60,
            max_packets: 1000,
            max_concurrent: 1,
            retention_hours: 72,
        })
        .unwrap();
        let info = tracer
            .start(TraceRequest { interface: "igb0".into(), filter: String::new(), duration_secs: 30, max_packets: 1000, snaplen: 1500 })
            .unwrap();
        // Ein zweiter gleichzeitiger Trace überschreitet das Limit
        assert!(matches!(tracer.start(info.request.clone()), Err(TraceError::TooMany(1))));
        std::thread::sleep(std::time::Duration::from_millis(400));
        tracer.stop(&info.id).unwrap();
        for _ in 0..50 {
            if tracer.get(&info.id).unwrap().status != TraceStatus::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(tracer.get(&info.id).unwrap().status, TraceStatus::Stopped);
        let page = tracer.packets(&info.id, 0, 50).unwrap();
        assert!(page.total > 0);
        assert!(!page.packets[0].summary.is_empty());

        // Nach einem "Neustart" ist der Trace wieder da
        let reloaded = Tracer::new(tracer.config.as_ref().clone()).unwrap();
        assert_eq!(reloaded.get(&info.id).unwrap().status, TraceStatus::Stopped);
        reloaded.delete(&info.id).unwrap();
        assert!(!dir.join(format!("{}.pcap", info.id)).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
