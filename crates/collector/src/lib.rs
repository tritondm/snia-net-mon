//! NetFlow-v9-/IPFIX-Collector.
//!
//! * [`parser`] – zustandsbehafteter Parser (Template-Cache pro Exporter und Observation Domain)
//! * [`listener`] – async UDP-Empfang, optional mit mehreren Workern über `SO_REUSEPORT`
//! * [`synth`] – Encoder und Verkehrsmodell für Tests und den Demo-Generator `flowgen`

pub mod listener;
pub mod metrics;
pub mod parser;
pub mod synth;

pub use listener::{CollectorConfig, spawn_collector};
pub use metrics::{CollectorMetrics, MetricsSnapshot};
pub use parser::{ParseError, Parser};
