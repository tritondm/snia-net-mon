use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Lock-freie Zähler des Collectors (werden von allen Workern gemeinsam benutzt).
#[derive(Debug, Default)]
pub struct CollectorMetrics {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub flows: AtomicU64,
    pub parse_errors: AtomicU64,
    pub missing_template: AtomicU64,
    /// Flows, die verworfen wurden, weil die Datenbank-Pipeline nicht hinterherkam.
    pub dropped_flows: AtomicU64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MetricsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub flows: u64,
    pub parse_errors: u64,
    pub missing_template: u64,
    pub dropped_flows: u64,
}

impl CollectorMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets: self.packets.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            flows: self.flows.load(Relaxed),
            parse_errors: self.parse_errors.load(Relaxed),
            missing_template: self.missing_template.load(Relaxed),
            dropped_flows: self.dropped_flows.load(Relaxed),
        }
    }
}
