//! Sendet realistisch verteilten Demo-Verkehr als echte NetFlow-v9-/IPFIX-Pakete an den Collector.
//!
//! ```text
//! flowgen [--target 127.0.0.1:2055] [--rate 500] [--format v9|ipfix] [--exporters 1] [--seconds 0]
//! ```

use anyhow::{Context, Result, bail};
use collector::synth::{Encoder, Format, TrafficModel};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Flows pro Paket – hält NetFlow-v9-Pakete unter der typischen MTU von 1500 Byte.
const FLOWS_PER_PACKET: usize = 24;
/// Templates alle n Pakete wiederholen (wie softflowd), damit ein neu gestarteter Collector schnell dekodieren kann.
const TEMPLATE_EVERY: u32 = 20;

struct Args {
    target: SocketAddr,
    rate: u32,
    format: Format,
    exporters: u32,
    seconds: u64,
}

fn parse_args() -> Result<Args> {
    let mut args = Args { target: "127.0.0.1:2055".parse()?, rate: 500, format: Format::NetflowV9, exporters: 1, seconds: 0 };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().with_context(|| format!("Wert für {flag} fehlt"));
        match flag.as_str() {
            "--target" => args.target = value()?.parse().context("--target: Adresse:Port")?,
            "--rate" => args.rate = value()?.parse().context("--rate: Flows pro Sekunde")?,
            "--exporters" => args.exporters = value()?.parse::<u32>().context("--exporters")?.clamp(1, 64),
            "--seconds" => args.seconds = value()?.parse().context("--seconds")?,
            "--format" => {
                args.format = match value()?.as_str() {
                    "v9" | "netflow" => Format::NetflowV9,
                    "ipfix" => Format::Ipfix,
                    other => bail!("--format {other}: erlaubt sind v9 und ipfix"),
                }
            }
            "-h" | "--help" => {
                println!("flowgen [--target 127.0.0.1:2055] [--rate 500] [--format v9|ipfix] [--exporters 1] [--seconds 0 = endlos]");
                std::process::exit(0);
            }
            other => bail!("unbekannte Option {other} (--help)"),
        }
    }
    Ok(args)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = parse_args()?;
    // Jeder "Exporter" bekommt einen eigenen Socket (Quellport) und eine eigene Source-ID
    let mut exporters = Vec::new();
    for i in 0..args.exporters {
        let socket = tokio::net::UdpSocket::bind(if args.target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
        socket.connect(args.target).await?;
        exporters.push((socket, Encoder::new(args.format, 100 + i), TrafficModel::new(model::now_ms() as u64 ^ (0x5eed + i as u64)), 0u32));
    }
    println!(
        "flowgen: {} Flows/s als {:?} an {} ({} Exporter) – Strg+C beendet",
        args.rate, args.format, args.target, args.exporters
    );

    let tick = Duration::from_millis(50);
    let mut ticker = tokio::time::interval(tick);
    let started = Instant::now();
    let mut carry = 0f64;
    let (mut sent_flows, mut sent_packets) = (0u64, 0u64);
    let mut last_report = Instant::now();
    loop {
        ticker.tick().await;
        if args.seconds > 0 && started.elapsed().as_secs() >= args.seconds {
            break;
        }
        carry += args.rate as f64 * tick.as_secs_f64();
        let due = carry as usize;
        carry -= due as f64;
        let now_ms = model::now_ms();
        let export_secs = (now_ms / 1000) as u32;
        for (i, flows) in (0..due).collect::<Vec<_>>().chunks(FLOWS_PER_PACKET).enumerate() {
            let (socket, encoder, traffic, packets) = &mut exporters[i % args.exporters as usize];
            let batch = traffic.next_flows(flows.len(), now_ms);
            let packet = encoder.encode(&batch, export_secs, *packets % TEMPLATE_EVERY == 0);
            *packets += 1;
            if let Err(err) = socket.send(&packet).await {
                eprintln!("Senden fehlgeschlagen: {err}");
            }
            sent_flows += batch.len() as u64;
            sent_packets += 1;
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            println!("gesendet: {sent_flows} Flows in {sent_packets} Paketen");
            last_report = Instant::now();
        }
    }
    println!("fertig: {sent_flows} Flows in {sent_packets} Paketen");
    Ok(())
}
