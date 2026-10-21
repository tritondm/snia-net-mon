# Installation and configuration

**English** · [Deutsch](INSTALL_de.md)

How to build and start Snia-Net-Mon and connect it to an exporter. What the individual features do is described in
[FEATURES.md](FEATURES.md), the overview is in the [README](README.md).

- [Requirements](#requirements)
- [Quick start (demo without exporter)](#quick-start-demo-without-exporter)
- [GeoIP databases](#geoip-databases)
- [Setting up flow export](#setting-up-flow-export)
- [First settings for your own network](#first-settings-for-your-own-network)
- [Configuration](#configuration)
- [Security](#security)
- [Development](#development)

## Requirements

- **Rust ≥ 1.88** (`rustup`), **Node ≥ 20** (only for building the frontend)
- Linux recommended (several receive sockets via `SO_REUSEPORT`)
- An exporter that sends **NetFlow v9 or IPFIX** – for trying it out, the bundled generator `flowgen` is enough
- Disk space: 48 h of raw data at 1,000 flows/s is about 30 GB, plus the history (up to 50 GB by default). In a small
  network it is a fraction of that.

## Quick start (demo without exporter)

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # web UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # second terminal: generates demo traffic
```

Without a `config.toml`, defaults apply: collector on UDP 2055, web UI only local on port 8080.
`flowgen` sends real NetFlow v9 packets to the collector. Options: `--rate 5000`, `--format ipfix`,
`--exporters 4`, `--seconds 60`.

For permanent operation, copy the example configuration and adapt it:

```bash
cp config.example.toml config.toml
./target/release/snia-net-mon                    # reads config.toml in the current directory
./target/release/snia-net-mon /etc/snia-net-mon.toml
```

## GeoIP databases

Countries and ASNs come from the free **MaxMind GeoLite2** databases (mind the licence – the files do not belong in the
repository). Without the files everything keeps working, only the geo fields stay empty. The date of the loaded edition
is shown in the footer of the web UI.

**Automatic (recommended):** register for free at [maxmind.com](https://www.maxmind.com/en/geolite2/signup), create a
licence key under *Account → Manage License Keys* and enter account ID and key – either in `config.toml` or as
environment variables (then the key is not in the file):

```toml
[geoip]
account_id = "123456"
license_key = "abc123_…"
```

```bash
MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=abc123_… cargo run --release --bin snia-net-mon
```

The server fetches missing databases at startup and then checks every `update_interval_hours` (default 24) for a new
edition (MaxMind publishes twice a week). The check via HEAD request does not count against the download limit; only
newer files are downloaded. The new file is verified, replaced atomically and picked up **without a restart**.

**Manually or with `geoipupdate`:** put `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` into `data/` (paths can be changed
under `[geoip]`). Replaced files – also by MaxMind's tool `geoipupdate` via cron – are detected by the server within
10 minutes and reloaded.

The anomaly detection needs the databases too: beaconing groups destinations by provider (ASN), "new country" needs the
country database.

## Setting up flow export

Snia-Net-Mon accepts NetFlow v9 and IPFIX over UDP (default port `2055`, `collector.listen`). Several exporters at once
are possible, their templates are managed separately. What the exporter should deliver:

| Setting | Recommendation | Why |
|---|---|---|
| Destination | IP of the machine running Snia-Net-Mon, UDP `2055` | |
| Format | NetFlow **v9** or **IPFIX** (version 10) | v5 and sFlow are not supported |
| Fields | addresses (IPv4/IPv6), ports, protocol, bytes, packets, start/end, TCP flags | port scan detection needs TCP flags; interface indices are optional |
| Sampling | **off** (every flow, 1:1) | sampled data is not scaled up, volumes would be too small |
| Active timeout | short, e.g. 60 s | otherwise long connections only show up after minutes |
| Measuring point | the **internal** interfaces (LAN, VLANs) | before NAT the internal addresses are visible; exporting on the WAN as well counts internet traffic twice |

After a short while the flows appear in the dashboard. As long as an exporter has not (re)sent its templates, the
collector counts the data as `missing_template` (counter under `/api/status`). Then check `network.local_networks`, see
[traffic direction](FEATURES.md#download--upload-traffic-direction).

### Example: pfSense (softflowd)

1. **System → Package Manager → Available Packages:** install `softflowd`.
2. **Services → softflowd:**
   - *Interface:* the internal interfaces (LAN, VLANs)
   - *Host:* IP of the machine running Snia-Net-Mon, *Port:* `2055`
   - *NetFlow version:* `9` or `IPFIX (10)`
   - *Flow tracking level:* `Full` (5-tuple with ports)
   - *Flow Timeouts:* short values give "more live" data, e.g. `maxlife 60`
3. Save.

### Other exporters

The settings are named slightly differently everywhere, but the table above is always what is meant. Where to find them:

| Exporter | Location of the setting |
|---|---|
| OPNsense | *Reporting → NetFlow*: select interfaces, version v9, destination `IP:2055` |
| MikroTik RouterOS | *IP → Traffic Flow*: enable, select interfaces, under *Targets* destination and version 9 or IPFIX |
| Linux (router, mirror port) | `softflowd -i eth0 -n IP:2055 -v 9`, alternatively ipt-netflow or pmacct (`nfprobe`) |
| Cisco, Juniper, Fortinet, Ubiquiti … | Flexible NetFlow, J-Flow/IPFIX, NetFlow export: version 9 or IPFIX, without sampling |

Snia-Net-Mon is tested with pfSense/softflowd and the bundled generator `flowgen`. Other exporters should work as long
as they send the usual standard fields. If not: the counters `parse_errors` and `missing_template` under `/api/status`
and the log (`RUST_LOG=debug`) show where things go wrong.

## First settings for your own network

A short order of steps to get started. Everything goes into `config.toml` and is explained in [FEATURES.md](FEATURES.md).

1. **Internal networks:** add public IPv6 prefixes and, if needed, the WAN address to `network.local_networks`.
   Otherwise download/upload will be wrong ([traffic direction](FEATURES.md#download--upload-traffic-direction)).
2. **Exclude networks** that should not be recorded: `network.exclude_networks`
   ([excluded networks](FEATURES.md#excluded-networks)).
3. **Define retention:** `storage.retention_hours`, `[history]` (see [privacy](README.md#privacy)).
4. **Set up mail** (`[email]`) and test it with `snia-net-mon --test-mail`.
5. **Anomaly detection:** networks with changing addresses into `anomaly.dynamic_networks`, permitted external resolvers
   into `anomaly.dns_servers`, zones and network rules if needed. Then wait for the learning phase (7 days) and only
   afterwards set `anomaly.mail = true` ([anomaly detection](FEATURES.md#anomaly-detection)).
6. **Access from the network:** set `server.listen` and `server.api_token`, HTTPS via a reverse proxy
   ([security](#security)).

## Configuration

A single file: `cp config.example.toml config.toml`. All keys are commented there (in German). The most important ones:

| Key | Default | Meaning |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | web UI/API. For access from the network `0.0.0.0:8080` **and** set `api_token` |
| `server.api_token` | empty | access protection: the web UI asks for the token once |
| `network.local_networks` | private ranges | internal networks for download/upload detection ([traffic direction](FEATURES.md#download--upload-traffic-direction)) |
| `network.exclude_networks` | empty | networks whose traffic is ignored completely ([excluded networks](FEATURES.md#excluded-networks)) |
| `collector.listen` | `0.0.0.0:2055` | reception of NetFlow/IPFIX |
| `collector.workers` | `2` | parallel receive sockets (`SO_REUSEPORT`) |
| `storage.dir` | `data/live` | live data: `index.db` and one file per hour, see [storage](FEATURES.md#storage-one-sqlite-file-per-hour) |
| `storage.retention_hours` | `48` | live window; values above 72 are capped at 72 |
| `storage.secure_delete` | `true` | overwrite deleted data (also applies to the history), see [storage](FEATURES.md#storage-one-sqlite-file-per-hour) |
| `history.enabled` | `true` | move hours after the live window into the history (`false` = delete) |
| `history.dir` | `data/history` | history directory (same layout as `storage.dir`) |
| `history.max_size_gb` | `50` | from this size the history is rotated into the archive |
| `history.archive_dir` | `data/archive` | archive location (folders `flows_<from>_<to>/`, UTC, each file compressed individually) |
| `history.archive_retention_days` | `90` | archives are kept this long after their newest flow |
| `history.compression_level` | `19` | zstd level 1–22 |
| `alerts.upload_threshold_mb` | `1024` | upload alert from this volume per connection, `0` = off |
| `alerts.session_idle_secs` | `600` | without new flows for this long a connection counts as finished |
| `alerts.max_mails_per_hour` | `20` | cap against mail floods (also applies to anomaly mails) |
| `anomaly.enabled` | `true` | anomaly detection, data in `anomaly.db` (`data/anomaly.db`) |
| `anomaly.window_minutes` / `learning_days` | `10` / `7` | window length, learning phase after the first start |
| `anomaly.z_threshold` | `4.0` | statistics threshold (log scale, 4 ≈ factor 7+), plus minimums `min_upload_mb` (100), `min_download_mb` (1024), `min_flows` (1000), `min_peers` (100), `min_internal_peers` (50), `min_ports` (30), `min_countries` (10) |
| `anomaly.groups` / `group_prefix_v4` / `group_prefix_v6` | empty / `24` / `64` | custom network groups, otherwise the subnet of this length |
| `anomaly.host_profiles` / `dynamic_networks` | `true` / empty | profile per host, except in networks with changing addresses (DHCP) |
| `anomaly.ignore` | empty | hosts that are not evaluated |
| `anomaly.scan_threshold` | `100` | port scan from this many failed attempts per window, `0` = off |
| `anomaly.dns_rule` / `dns_servers` | `true` / empty | report DNS to external resolvers / permitted external resolvers |
| `anomaly.dns_clients` | empty | internal hosts allowed to resolve externally (own DNS servers, routers) |
| `anomaly.new_country` | `true` | report the first country of a network group |
| `anomaly.beacon` | `true` | beaconing detection (only a hint in the web UI, never by mail) |
| `anomaly.beacon_min_connections` / `beacon_min_minutes` / `beacon_max_jitter` | `20` / `120` / `0.2` | pattern from this many connections over this many minutes with at most this relative spread of the intervals |
| `anomaly.beacon_max_hosts` | `3` | from this many hosts with the same pattern to the same provider and port on, it counts as rolled-out software (higher = **more** reports) |
| `anomaly.beacon_allow` / `beacon_allow_asn` / `beacon_allow_ports` | empty / empty / `[123]` | exceptions: hosts or destinations (IP/CIDR), providers (ASN, [list](FEATURES.md#common-harmless-providers)), destination ports |
| `anomaly.ml` / `ml_threshold` / `ml_training_days` | `true` / `0.65` / `14` | Isolation Forest |
| `anomaly.event_retention_days` | `30` | retention of anomalies |
| `anomaly.timezone` | empty | time zone for weekday/hour, empty = system |
| `anomaly.mail` / `mail_min_severity` | `false` / `high` | mails to the admins |
| `anomaly.mail_kinds` | `{}` | switch per kind, e.g. `{ dns = "warn", country = "off" }` |
| `[[anomaly.zones]]` / `[[anomaly.rules]]` | empty | network rules: named zones and ordered rules, see [network rules](FEATURES.md#network-rules) |
| `email.smtp_host` / `smtp_port` / `security` | empty / `587` / `starttls` | SMTP server; `security` = `starttls`, `tls` (465) or `none` (LAN relay only). Empty host = no mail |
| `email.username` / `email.password` | empty | SMTP login; password alternatively via `SNIA_SMTP_PASSWORD` |
| `email.from` / `email.admins` | – | sender and recipients of the alert mails |
| `geoip.country_db` / `geoip.asn_db` | `data/GeoLite2-*.mmdb` | MaxMind databases (see above) |
| `geoip.account_id` / `geoip.license_key` | empty | credentials for the automatic update (or `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`) |
| `geoip.update_interval_hours` | `24` | how often to look for a new GeoLite2 edition |
| `pcap.max_upload_mb` | `512` | largest allowed capture file |
| `pcap.app_rules` | empty | custom app rules as JSON (format as in `crates/pcap/apps.json`), empty = bundled rules |

Using a different file: `snia-net-mon /etc/snia-net-mon.toml`. Logging via `RUST_LOG`, e.g. `RUST_LOG=debug`.
Test mail delivery: `snia-net-mon --test-mail [config.toml]` sends a test mail to the admins and exits.

**Order in the file:** the blocks `[[anomaly.zones]]` and `[[anomaly.rules]]` belong at the **end**. In TOML everything
after such a block belongs to that block; a setting placed after it would end up in the last rule, and startup aborts
with an error message.

## Security

- By default the web UI only listens on `127.0.0.1`. For network access set `api_token` and put a reverse proxy with
  HTTPS in front. The WebSocket accepts the token as `?token=`.
- The token is compared in constant time. There is no user or role concept; everyone with the token sees everything.
- The collector port (UDP 2055) accepts packets from anyone. Use a firewall to allow only your own exporters.
- Increase the receive buffer for high packet rates: `net.core.rmem_max` (Snia-Net-Mon requests 16 MiB).

## Development

```bash
cargo test --workspace              # parser round trips (v9/IPFIX), fuzz-style robustness, retention, history/archive, hourly files, upload alert, anomaly detection (baseline, Isolation Forest, beaconing, rules), filters, PCAP/pcapng reader, app rules, GeoIP
cargo test -p db --release -- --ignored bench --nocapture --test-threads=1   # load tests: statistics with/without aggregates, writing + retention
cargo clippy --workspace --all-targets
cd frontend && npm run dev          # Vite on :5173 with proxy to the backend (:8080), hot reload
```

Code layout: [architecture](FEATURES.md#architecture).
