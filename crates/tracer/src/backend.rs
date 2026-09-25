//! Ausführung eines Traces: per SSH auf der pfSense oder simuliert (Demo-Modus ohne Firewall).

use crate::{TraceHandle, TraceStatus, build_command};
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Privater Schlüssel (empfohlen). Alternativ `password`.
    pub private_key: Option<PathBuf>,
    pub private_key_passphrase: Option<String>,
    pub password: Option<String>,
    /// Erwarteter Hostschlüssel-Fingerabdruck im OpenSSH-Format (`SHA256:…`), z. B. aus `ssh-keyscan host | ssh-keygen -lf -`.
    /// Ist er nicht gesetzt, wird der Fingerabdruck geloggt und die Verbindung verweigert.
    pub host_key_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Backend {
    /// Simuliert tcpdump und erzeugt synthetische Pakete – zum Ausprobieren ohne pfSense.
    Mock,
    Ssh(SshConfig),
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Mock => "mock",
            Backend::Ssh(_) => "ssh",
        }
    }
}

pub(crate) fn run(backend: &Backend, handle: &TraceHandle, path: &Path, dir: &Path) {
    let request = handle.info.lock().expect("Trace-Mutex").request.clone();
    let result = match backend {
        Backend::Mock => run_mock(handle, path, request.duration_secs, request.max_packets),
        Backend::Ssh(ssh) => run_ssh(ssh, handle, path, &build_command(&request), request.duration_secs),
    };
    let cancelled = handle.cancel.load(Ordering::Relaxed);
    match result {
        Ok(()) if cancelled => handle.finish(TraceStatus::Stopped, None, dir),
        Ok(()) => handle.finish(TraceStatus::Completed, None, dir),
        Err(err) => {
            tracing::warn!(%err, "Trace fehlgeschlagen");
            handle.finish(TraceStatus::Failed, Some(err), dir)
        }
    }
}

fn run_ssh(cfg: &SshConfig, handle: &TraceHandle, path: &Path, command: &str, duration_secs: u32) -> Result<(), String> {
    let addr = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()
        .map_err(|e| format!("Adresse {}: {e}", cfg.host))?
        .next()
        .ok_or_else(|| format!("Adresse {} nicht auflösbar", cfg.host))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("Verbindung zu {addr}: {e}"))?;
    let mut session = ssh2::Session::new().map_err(|e| e.to_string())?;
    session.set_tcp_stream(tcp);
    session.set_timeout(15_000);
    session.handshake().map_err(|e| format!("SSH-Handshake: {e}"))?;

    // Hostschlüssel prüfen (Schutz gegen Man-in-the-Middle)
    let fingerprint = session
        .host_key_hash(ssh2::HashType::Sha256)
        .map(|h| format!("SHA256:{}", base64_nopad(h)))
        .ok_or("Hostschlüssel nicht verfügbar")?;
    match cfg.host_key_sha256.as_deref() {
        Some(expected) if expected.trim() == fingerprint => {}
        Some(_) => return Err(format!("Hostschlüssel stimmt NICHT überein (erhalten: {fingerprint})")),
        None => {
            return Err(format!(
                "kein host_key_sha256 konfiguriert – bitte prüfen und in config.toml eintragen: {fingerprint}"
            ));
        }
    }

    if let Some(key) = &cfg.private_key {
        session
            .userauth_pubkey_file(&cfg.user, None, key, cfg.private_key_passphrase.as_deref())
            .map_err(|e| format!("SSH-Anmeldung mit Schlüssel: {e}"))?;
    } else if let Some(password) = &cfg.password {
        session.userauth_password(&cfg.user, password).map_err(|e| format!("SSH-Anmeldung mit Passwort: {e}"))?;
    } else {
        return Err("weder private_key noch password konfiguriert".into());
    }

    let mut channel = session.channel_session().map_err(|e| e.to_string())?;
    channel.exec(command).map_err(|e| format!("Befehl konnte nicht gestartet werden: {e}"))?;
    // Kurze Lese-Timeouts, damit Stopp-Wunsch und Deadline regelmäßig geprüft werden
    session.set_timeout(300);

    let mut out = BufWriter::with_capacity(256 * 1024, File::create(path).map_err(|e| e.to_string())?);
    let deadline = Instant::now() + Duration::from_secs(duration_secs as u64 + 10);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if handle.cancel.load(Ordering::Relaxed) || Instant::now() > deadline {
            // Kanal schließen: tcpdump erhält beim nächsten Schreiben SIGPIPE, `timeout` beendet ihn spätestens nach der Dauer
            let _ = channel.close();
            break;
        }
        match channel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?; // Datei sofort für Vorschau/Download aktualisieren
                handle.bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => continue,
            Err(e) => return Err(format!("Lesen vom SSH-Kanal: {e}")),
        }
    }
    out.flush().map_err(|e| e.to_string())?;
    session.set_timeout(5_000);
    let mut stderr = String::new();
    let _ = channel.stderr().read_to_string(&mut stderr);
    let _ = channel.wait_close();
    let exit = channel.exit_status().unwrap_or(0);
    // 124 = von `timeout` nach Ablauf der Dauer beendet – das ist der Normalfall
    if !handle.cancel.load(Ordering::Relaxed) && exit != 0 && exit != 124 && handle.bytes.load(Ordering::Relaxed) <= 24 {
        let message = stderr.lines().filter(|l| !l.starts_with("listening on")).collect::<Vec<_>>().join(" ");
        return Err(format!("tcpdump beendet mit Code {exit}: {}", message.trim()));
    }
    Ok(())
}

/// Simulierter Mitschnitt: ~40 Pakete/s mit plausiblen Ethernet/IPv4/TCP-UDP-Paketen im PCAP-Format.
fn run_mock(handle: &TraceHandle, path: &Path, duration_secs: u32, max_packets: u32) -> Result<(), String> {
    let mut out = BufWriter::new(File::create(path).map_err(|e| e.to_string())?);
    let header = crate::pcap::global_header(1, 262_144);
    out.write_all(&header).map_err(|e| e.to_string())?;
    handle.bytes.fetch_add(header.len() as u64, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(duration_secs as u64);
    let mut seed: u64 = model::now_ms() as u64 | 1;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut written = 0u32;
    while written < max_packets && Instant::now() < deadline && !handle.cancel.load(Ordering::Relaxed) {
        for _ in 0..4 {
            let packet = crate::pcap::synthetic_packet(next());
            let record = crate::pcap::record(model::now_ms() * 1000, &packet);
            out.write_all(&record).map_err(|e| e.to_string())?;
            handle.bytes.fetch_add(record.len() as u64, Ordering::Relaxed);
            written += 1;
        }
        out.flush().map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(100));
    }
    out.flush().map_err(|e| e.to_string())
}

/// Base64 ohne Padding (Format der OpenSSH-Fingerabdrücke).
fn base64_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64_nopad(b"Man"), "TWFu");
        assert_eq!(super::base64_nopad(b"Ma"), "TWE");
        assert_eq!(super::base64_nopad(b"M"), "TQ");
        assert_eq!(super::base64_nopad(b""), "");
    }
}
