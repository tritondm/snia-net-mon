//! Analyse von Capture-Dateien (klassisches PCAP und pcapng), z. B. Mitschnitte von der pfSense
//! (Diagnostics → Packet Capture) oder aus Wireshark.
//!
//! Handgeschriebener Leser und Frame-Zerlegung (Ethernet/VLAN, rohes IP, Linux SLL/SLL2, BSD-Loopback, pflog;
//! IPv4/IPv6, TCP/UDP/ICMP, ARP), dazu DNS-, HTTP- und TLS-SNI-Auswertung. Anwendungen (YouTube, Microsoft 365 …)
//! werden über SNI, DNS-Antworten, HTTP-Host und IP-Präfixe erkannt. Öffentliche Endpunkte bekommen Land und ASN.

mod analyze;
mod apps;
mod dissect;
mod dns;
mod reader;
mod tls;

pub use analyze::analyze;
pub use apps::AppRules;
pub use reader::{CaptureReader, LinkType};
