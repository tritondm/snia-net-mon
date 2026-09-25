//! Async UDP-Empfang.
//!
//! Pro Worker ein eigener Socket mit `SO_REUSEPORT`: Der Kernel verteilt die Pakete per Hash über das Quell-Tupel, d. h.
//! alle Pakete eines Exporters landen immer beim selben Worker (wichtig für dessen Template-Cache). Geparste Flows werden
//! gebündelt (Batch) an die Datenbank-Pipeline weitergereicht; ist diese voll, werden Flows gezählt verworfen statt den
//! Empfang zu blockieren – so läuft der Socket-Puffer nie voll.

use crate::metrics::CollectorMetrics;
use crate::parser::Parser;
use model::{FlowRecord, LocalNetworks};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub bind: SocketAddr,
    pub workers: usize,
    /// Gewünschte Größe des Kernel-Empfangspuffers (SO_RCVBUF). Linux begrenzt sie auf `net.core.rmem_max`.
    pub recv_buffer_bytes: usize,
    pub batch_size: usize,
    pub batch_interval: Duration,
    /// Interne Netze – daraus ergibt sich die Richtung (in/out/intern) jedes Flows.
    pub local_networks: Arc<LocalNetworks>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:2055".parse().expect("gültige Adresse"),
            workers: 1,
            recv_buffer_bytes: 16 * 1024 * 1024,
            batch_size: 2048,
            batch_interval: Duration::from_millis(100),
            local_networks: Arc::new(LocalNetworks::default()),
        }
    }
}

pub type FlowBatch = Vec<FlowRecord>;

/// Collector-Worker starten. Liefert die Task-Handles; die Worker beenden sich, sobald `shutdown` auf `true` wechselt.
pub fn spawn_collector(
    config: CollectorConfig,
    sinks: Vec<mpsc::Sender<Arc<FlowBatch>>>,
    metrics: Arc<CollectorMetrics>,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let workers = config.workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let socket = bind_socket(&config, workers > 1)?;
        let worker = Worker {
            id: worker_id,
            socket,
            config: config.clone(),
            sinks: sinks.clone(),
            metrics: metrics.clone(),
            shutdown: shutdown.clone(),
        };
        handles.push(tokio::spawn(worker.run()));
    }
    tracing::info!(bind = %config.bind, workers, "NetFlow/IPFIX-Collector gestartet");
    Ok(handles)
}

fn bind_socket(config: &CollectorConfig, reuse_port: bool) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(config.bind), Type::DGRAM, Some(Protocol::UDP))?;
    if config.bind.is_ipv6() {
        // [::]:2055 soll auch IPv4-Exporter annehmen
        let _ = socket.set_only_v6(false);
    }
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    if let Err(err) = socket.set_recv_buffer_size(config.recv_buffer_bytes) {
        tracing::warn!(%err, "SO_RCVBUF konnte nicht gesetzt werden");
    }
    let effective = socket.recv_buffer_size().unwrap_or(0);
    if effective < config.recv_buffer_bytes {
        tracing::debug!(
            requested = config.recv_buffer_bytes,
            effective,
            "Empfangspuffer vom Kernel begrenzt (sysctl net.core.rmem_max erhöhen)"
        );
    }
    socket.set_nonblocking(true)?;
    socket.bind(&config.bind.into())?;
    UdpSocket::from_std(socket.into())
}

struct Worker {
    id: usize,
    socket: UdpSocket,
    config: CollectorConfig,
    sinks: Vec<mpsc::Sender<Arc<FlowBatch>>>,
    metrics: Arc<CollectorMetrics>,
    shutdown: watch::Receiver<bool>,
}

impl Worker {
    async fn run(mut self) {
        let mut parser = Parser::new();
        let mut buf = vec![0u8; 65_535];
        let mut batch: FlowBatch = Vec::with_capacity(self.config.batch_size);
        let mut flush_timer = tokio::time::interval(self.config.batch_interval);
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = self.socket.recv_from(&mut buf) => {
                    let (len, from) = match received {
                        Ok(r) => r,
                        Err(err) => {
                            tracing::warn!(worker = self.id, %err, "UDP-Empfang fehlgeschlagen");
                            continue;
                        }
                    };
                    self.metrics.packets.fetch_add(1, Relaxed);
                    self.metrics.bytes.fetch_add(len as u64, Relaxed);
                    let before = batch.len();
                    match parser.parse(from.ip(), &buf[..len], &mut batch) {
                        Ok(stats) => {
                            if stats.missing_template_sets > 0 {
                                self.metrics.missing_template.fetch_add(stats.missing_template_sets as u64, Relaxed);
                            }
                        }
                        Err(err) => {
                            self.metrics.parse_errors.fetch_add(1, Relaxed);
                            tracing::debug!(worker = self.id, %from, %err, "Paket verworfen");
                        }
                    }
                    for flow in &mut batch[before..] {
                        flow.direction = self.config.local_networks.classify(flow.src_ip, flow.dst_ip);
                    }
                    self.metrics.flows.fetch_add((batch.len() - before) as u64, Relaxed);
                    if batch.len() >= self.config.batch_size {
                        self.flush(&mut batch);
                    }
                }
                _ = flush_timer.tick() => {
                    if !batch.is_empty() {
                        self.flush(&mut batch);
                    }
                }
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        self.flush(&mut batch);
                        tracing::debug!(worker = self.id, "Collector-Worker beendet");
                        return;
                    }
                }
            }
        }
    }

    /// Batch an alle Abnehmer (Datenbank, Live-Ansicht) verteilen. Ein voller Abnehmer blockiert den Empfang nie.
    fn flush(&self, batch: &mut FlowBatch) {
        if batch.is_empty() {
            return;
        }
        let shared = Arc::new(std::mem::replace(batch, Vec::with_capacity(self.config.batch_size)));
        for sink in &self.sinks {
            if sink.try_send(shared.clone()).is_err() {
                self.metrics.dropped_flows.fetch_add(shared.len() as u64, Relaxed);
            }
        }
    }
}
