# Snia-Net-Mon

**English** · [Deutsch](README_de.md)

Network monitor for anything that exports **NetFlow v9 or IPFIX**: firewalls (pfSense, OPNsense, Fortinet …), routers and
switches (MikroTik, Cisco, Juniper …) or a software probe on a Linux box (softflowd, ipt-netflow, pmacct). It collects the
connection records, shows them live in the browser – with **GeoIP (country, ASN)** for every external peer – and makes
them searchable. On top of that there is a **PCAP analyser** for packet captures, an **upload alert** by mail and
**automatic anomaly detection**.

Snia-Net-Mon was originally built **for schools**: many fixed networks for administration and teaching, a student network
with changing addresses, little time for maintenance, and personal data of students who are often minors. That is where
the [student network and administration example](FEATURES.md#example-student-network-and-administration) and the
detailed [privacy](#privacy) section come from. It fits just as well into any other network with NetFlow or IPFIX
export.

- **Backend:** Rust (Tokio, Axum), SQLite in WAL mode, one file per hour
- **Frontend:** Svelte 5 + Tailwind, Catppuccin Mocha theme in Hyprland style (frosted glass, gradient borders, monospace)
- **Status:** prototype – working and tested, see [limits & next steps](FEATURES.md#limits--next-steps)
- **Language:** the web UI, log messages and the comments in `config.example.toml` are in German

![Dashboard with live throughput, active connections with GeoIP, traffic direction, protocols and top talkers; the five workspaces at the top](docs/screenshot.png)

## What it does

- **Live dashboard:** throughput split into download and upload, active connections, top talkers, ports, countries and
  networks (ASN), protocols and a Sankey diagram source → service → destination. Select a range in the chart to see
  exactly the connections of that period.
- **Flow search** by IP, CIDR, port, protocol, direction and time range, with CSV export.
- **PCAP analysis:** drag and drop a capture file and see which applications (YouTube, Microsoft 365 …), endpoints,
  countries, DNS names and anomalies it contains.
- **Three-stage retention:** 48 hours live, then a history of up to 50 GB that is rotated into a zstd archive. Archives
  are kept for 3 months and can be searched again in the web UI.
- **Upload alert:** if a single connection uploads more than 1 GiB to the outside, the admins get a mail.
- **Anomaly detection:** every internal host is compared with the normal behaviour of its network and, for fixed
  addresses, with its own. Added to that: an Isolation Forest as a second opinion, port scan detection, DNS to foreign
  resolvers, new countries, beaconing (regular connections like those of malware) and network rules between zones
  ("report student network → administration").
- **Data-minimising:** no content, no connection data sent anywhere, networks can be excluded completely, deleted data
  is overwritten.

![Anomaly view from the test environment: status of learning phase, baseline and Isolation Forest, below that network rule violations, a port scan with a statistical hit, external DNS and new countries](docs/anomalies.png)

## Documentation

| File | Contents |
|---|---|
| [INSTALL.md](INSTALL.md) | Requirements, quick start with demo traffic, GeoIP databases, setting up flow export on the exporter, configuration, security, development |
| [FEATURES.md](FEATURES.md) | All features in detail: traffic direction, upload alert, **anomaly detection including the maths**, network rules, architecture, storage and retention, performance, API, limits |

Quick try without a firewall (Rust ≥ 1.88, Node ≥ 20):

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # web UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # second terminal: generates demo traffic
```

## Privacy

Snia-Net-Mon records which device exchanged how much data with whom and when. Via the DHCP server's leases, WLAN logins
or fixed device assignments, IP addresses can usually be linked to a person – the stored data is therefore **personal
data** under the GDPR. This applies especially to schools, where students (often minors) and teachers share the same
network.

> This section describes what the software stores technically and gives advice for operation. It is not legal advice.
> Whether and to what extent operation is permitted must be clarified by the controller (school management or school
> authority) together with their data protection officer.

### What is stored

| Data | Contents | Where | How long (default) |
|---|---|---|---|
| **Flows** (NetFlow/IPFIX) | start and end, source and destination IP, ports, protocol, bytes, packets, TCP flags, interfaces, direction. **No content**, no URLs, no domains | `storage.dir`, one file per hour | 48 h live (up to 49 h on disk), then history and archive |
| **Aggregates** | bytes and packets per IP, service and IP pair per minute and hour | `index.db` | same as the flows |
| **History** | moved hourly files and aggregates | `history.dir` | until `max_size_gb` (50 GB) is reached |
| **Archive** | compressed history | `history.archive_dir` | 90 days after the newest flow |
| **PCAP analyses** | result of an uploaded capture: IPs, **domains** (DNS, TLS SNI), **HTTP hosts and URLs**, detected applications | `index.db` | 48 h, not archived. The capture file itself is deleted right after the analysis |
| **Upload alert** | source, destination, service, volume and period of the connection | mail to `email.admins`, log | depends on the mailbox and the system's log rotation |
| **Anomaly baselines** | mean and spread of the features per network group and – with `host_profiles` – **per host IP** and hour | `anomaly.db` | unlimited, continuously overwritten |
| **Training vectors** | features per host window (volume, number of peers, ports, countries, time of day), **without IP address** | `anomaly.db` | 14 days (`ml_training_days`) |
| **Beaconing** | start times of outgoing connections per host, destination and port | memory only | 12 h, gone after a restart |
| **Anomalies** | host IP, network group, period, finding with values; for DNS the resolvers, for port scans a sample of the targets | `anomaly.db`, log, optionally mail | 30 days (`event_retention_days`) |

Country and ASN of an IP are looked up locally in the GeoLite2 files, not stored. Snia-Net-Mon does not send any
connection data to the outside. The only outgoing connection is the optional download of the GeoIP databases from
MaxMind, which transmits only the account ID and licence key. The web UI loads no external fonts, scripts or images.

**Mind the total duration:** with history and archive, flows are kept for up to three months *after* rotation. In small
networks it can take a long time until the history reaches 50 GB – until then it is not rotated at all. The actual
retention can therefore be well above 90 days. Details under [retention](FEATURES.md#retention-live--history--archive).

### Recommendations for schools

- **Store as briefly as possible** (data minimisation). For troubleshooting and load analysis the live window is usually
  enough:
  ```toml
  [storage]
  retention_hours = 24     # or less

  [history]
  enabled = false          # no history, no archive – deleted after the live window
  ```
  If a history is needed, choose a small `max_size_gb` and set `archive_retention_days` to the period defined by the
  school.
- **Exclude networks** that should not or need not be monitored, e.g. the administration or teachers' network or a guest
  WLAN: `network.exclude_networks`. These flows are discarded immediately and stored nowhere.
- **Restrict access:** the web UI shows all stored connections. Only the responsible administrators should reach it:
  leave `listen` on `127.0.0.1`, or set `api_token` and use HTTPS via a reverse proxy (see
  [security](INSTALL.md#security)).
- **Encrypt the disk** and keep `storage.secure_delete = true`. On SSDs and copy-on-write file systems (btrfs, ZFS)
  overwriting is not guaranteed to be effective; there only encryption reliably protects deleted data.
- **Use PCAP analyses sparingly.** A capture file contains packet contents; the stored analysis contains visited domains
  and unencrypted URLs. Only use it for specific troubleshooting.
- **Review the upload alert:** the mails contain IP addresses and end up in mailboxes outside Snia-Net-Mon. Only enable
  it if needed (`alerts.upload_threshold_mb = 0` turns it off) and keep the recipient list short.
- **Use anomaly detection deliberately:** host profiles describe the behaviour of individual devices. In teacher or
  administration networks this is a form of behavioural analysis that the staff council must be informed about. Add such
  networks to `dynamic_networks` (group profile only) or exclude them completely via `ignore` or
  `network.exclude_networks`. `host_profiles = false` disables per-host profiles entirely, `enabled = false` the whole
  detection.

### Organisational matters

Before deployment the school should usually:

- define the **purpose** (e.g. ensuring network operation, troubleshooting, detecting malware) and add the processing
  to the **record of processing activities**,
- put **retention periods** and **authorised persons** in writing and align the configuration with them,
- **inform** users, for example in the school's acceptable use policy,
- involve the **staff council** if devices of teachers or administration are covered – network monitoring can be
  suitable for monitoring performance and behaviour,
- clarify with the **data protection officer** whether a data protection impact assessment is required.

Snia-Net-Mon is meant for running the network, not for monitoring individual people.

## Licence

[MIT](LICENSE) – free to use, modify and distribute as long as the copyright notice is retained. No warranty.

Third-party content included: country flags from [Twemoji](https://github.com/twitter/twemoji) (© Twitter, Inc. and
contributors, [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)), as a font via
[country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill) (MIT). GeoIP data from MaxMind
GeoLite2 is not included (separate licence, see [GeoIP databases](INSTALL.md#geoip-databases)).
