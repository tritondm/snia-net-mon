# Installation und Konfiguration

[English](INSTALL.md) · **Deutsch**

Wie Snia-Net-Mon gebaut, gestartet und an einen Exporter angebunden wird. Was die einzelnen Funktionen tun, steht in
[FEATURES_de.md](FEATURES_de.md), der Überblick in der [README](README_de.md).

- [Voraussetzungen](#voraussetzungen)
- [Schnellstart (Demo ohne Exporter)](#schnellstart-demo-ohne-exporter)
- [GeoIP-Datenbanken](#geoip-datenbanken)
- [Flow-Export einrichten](#flow-export-einrichten)
- [Erste Einstellungen für das eigene Netz](#erste-einstellungen-für-das-eigene-netz)
- [Konfiguration](#konfiguration)
- [Sicherheit](#sicherheit)
- [Entwicklung](#entwicklung)

## Voraussetzungen

- **Rust ≥ 1.88** (`rustup`), **Node ≥ 20** (nur zum Bauen des Frontends)
- Linux empfohlen (mehrere Empfangs-Sockets per `SO_REUSEPORT`)
- Ein Exporter, der **NetFlow v9 oder IPFIX** sendet – zum Ausprobieren reicht der mitgelieferte Generator `flowgen`
- Plattenplatz: 48 h Rohdaten bei 1.000 Flows/s sind rund 30 GB, dazu die Historie (Standard bis 50 GB). Im kleinen
  Netz ist es ein Bruchteil davon.

## Schnellstart (Demo ohne Exporter)

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # Web-UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # zweites Terminal: erzeugt Demo-Verkehr
```

Ohne `config.toml` laufen Standardwerte: Collector auf UDP 2055, Web-UI nur lokal auf Port 8080.
`flowgen` schickt echte NetFlow-v9-Pakete an den Collector. Optionen: `--rate 5000`, `--format ipfix`,
`--exporters 4`, `--seconds 60`.

Für den Dauerbetrieb die Beispielkonfiguration kopieren und anpassen:

```bash
cp config.example.toml config.toml
./target/release/snia-net-mon                    # liest config.toml im aktuellen Verzeichnis
./target/release/snia-net-mon /etc/snia-net-mon.toml
```

## GeoIP-Datenbanken

Länder und ASN kommen aus den kostenlosen **MaxMind GeoLite2**-Datenbanken (Lizenz beachten – die Dateien gehören nicht
ins Repository). Ohne die Dateien läuft alles weiter, nur die Geo-Felder bleiben leer. Das Datum der geladenen Ausgabe
steht in der Fußzeile der Web-UI.

**Automatisch (empfohlen):** Auf [maxmind.com](https://www.maxmind.com/en/geolite2/signup) kostenlos registrieren, unter
*Account → Manage License Keys* einen Lizenzschlüssel erzeugen und Konto-ID und Schlüssel eintragen – entweder in
`config.toml` oder als Umgebungsvariablen (dann steht der Schlüssel nicht in der Datei):

```toml
[geoip]
account_id = "123456"
license_key = "abc123_…"
```

```bash
MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=abc123_… cargo run --release --bin snia-net-mon
```

Der Server holt fehlende Datenbanken beim Start und prüft danach alle `update_interval_hours` (Standard 24) auf eine neue
Ausgabe (MaxMind veröffentlicht zweimal pro Woche). Die Prüfung per HEAD-Request zählt nicht gegen das Download-Limit;
geladen wird nur, was neuer ist. Die neue Datei wird geprüft, atomar ersetzt und **ohne Neustart** übernommen.

**Manuell oder mit `geoipupdate`:** `GeoLite2-Country.mmdb` und `GeoLite2-ASN.mmdb` nach `data/` legen (Pfade über
`[geoip]` änderbar). Ersetzte Dateien – auch durch MaxMinds Tool `geoipupdate` per Cron – erkennt der Server innerhalb von
10 Minuten und lädt sie neu.

Die ASN-Datenbank braucht auch die Anomalie-Erkennung: Beaconing fasst Ziele nach Anbieter (ASN) zusammen, „neues Land“
braucht die Länder-Datenbank.

## Flow-Export einrichten

Snia-Net-Mon nimmt NetFlow v9 und IPFIX per UDP an (Standard Port `2055`, `collector.listen`). Mehrere Exporter gleichzeitig
sind möglich, ihre Templates werden getrennt verwaltet. Was der Exporter liefern sollte:

| Einstellung | Empfehlung | Warum |
|---|---|---|
| Ziel | IP des Rechners mit Snia-Net-Mon, UDP `2055` | |
| Format | NetFlow **v9** oder **IPFIX** (Version 10) | v5 und sFlow werden nicht unterstützt |
| Felder | Adressen (IPv4/IPv6), Ports, Protokoll, Bytes, Pakete, Start/Ende, TCP-Flags | TCP-Flags braucht die Portscan-Erkennung; Interface-Indizes sind optional |
| Sampling | **aus** (jeder Flow, 1:1) | gesampelte Daten werden nicht hochgerechnet, Mengen wären zu klein |
| Active Timeout | kurz, z. B. 60 s | lange Verbindungen erscheinen sonst erst nach Minuten |
| Messpunkt | die **internen** Interfaces (LAN, VLANs) | vor dem NAT sind die internen Adressen sichtbar; wer zusätzlich am WAN exportiert, zählt Internetverkehr doppelt |

Nach kurzer Zeit erscheinen die Flows im Dashboard. Solange ein Exporter seine Templates noch nicht (erneut) gesendet hat,
zählt der Collector die Daten als `missing_template` (Zähler unter `/api/status`). Danach `network.local_networks` prüfen,
siehe [Verkehrsrichtung](FEATURES_de.md#download--upload-verkehrsrichtung).

### Beispiel: pfSense (softflowd)

1. **System → Package Manager → Available Packages:** `softflowd` installieren.
2. **Services → softflowd:**
   - *Interface:* die internen Interfaces (LAN, VLANs)
   - *Host:* IP des Rechners mit Snia-Net-Mon, *Port:* `2055`
   - *NetFlow version:* `9` oder `IPFIX (10)`
   - *Flow tracking level:* `Full` (5-Tupel mit Ports)
   - *Flow Timeouts:* kurze Werte ergeben „livere“ Daten, z. B. `maxlife 60`
3. Speichern.

### Andere Exporter

Die Einstellungen heißen überall etwas anders, gemeint ist immer die Tabelle oben. Wo man sie findet:

| Exporter | Ort der Einstellung |
|---|---|
| OPNsense | *Reporting → NetFlow*: Interfaces wählen, Version v9, Ziel `IP:2055` |
| MikroTik RouterOS | *IP → Traffic Flow*: aktivieren, Interfaces wählen, unter *Targets* Ziel und Version 9 oder IPFIX |
| Linux (Router, Mirror-Port) | `softflowd -i eth0 -n IP:2055 -v 9`, alternativ ipt-netflow oder pmacct (`nfprobe`) |
| Cisco, Juniper, Fortinet, Ubiquiti … | Flexible NetFlow, J-Flow/IPFIX, NetFlow-Export: Version 9 oder IPFIX, ohne Sampling |

Getestet ist Snia-Net-Mon mit pfSense/softflowd und dem mitgelieferten Generator `flowgen`. Andere Exporter sollten
funktionieren, solange sie die üblichen Standardfelder senden. Wenn nicht: Der Zähler `parse_errors` bzw.
`missing_template` unter `/api/status` und das Log (`RUST_LOG=debug`) zeigen, wo es hakt.

## Erste Einstellungen für das eigene Netz

Eine kurze Reihenfolge für den Start. Alles steht in `config.toml`, erklärt in [FEATURES_de.md](FEATURES_de.md).

1. **Interne Netze:** `network.local_networks` um öffentliche IPv6-Präfixe und ggf. die WAN-Adresse ergänzen. Sonst
   stimmen Download/Upload nicht ([Verkehrsrichtung](FEATURES_de.md#download--upload-verkehrsrichtung)).
2. **Netze ausnehmen**, die nicht erfasst werden sollen: `network.exclude_networks`
   ([Ausgenommene Netze](FEATURES_de.md#ausgenommene-netze)).
3. **Aufbewahrung** festlegen: `storage.retention_hours`, `[history]` (siehe [Datenschutz](README_de.md#datenschutz)).
4. **Mail einrichten** (`[email]`) und mit `snia-net-mon --test-mail` prüfen.
5. **Anomalie-Erkennung:** Netze mit wechselnden Adressen in `anomaly.dynamic_networks`, erlaubte externe Resolver in
   `anomaly.dns_servers`, bei Bedarf Zonen und Netz-Regeln. Dann die Lernphase (7 Tage) abwarten und erst danach
   `anomaly.mail = true` setzen ([Anomalie-Erkennung](FEATURES_de.md#anomalie-erkennung)).
6. **Zugriff aus dem Netz:** `server.listen` und `server.api_token` setzen, HTTPS über einen Reverse-Proxy
   ([Sicherheit](#sicherheit)).

## Konfiguration

Eine einzige Datei: `cp config.example.toml config.toml`. Alle Schlüssel sind dort kommentiert. Die wichtigsten:

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | Web-UI/API. Für Zugriff aus dem Netz `0.0.0.0:8080` **und** `api_token` setzen |
| `server.api_token` | leer | Zugriffsschutz: Die Web-UI fragt einmal nach dem Token |
| `network.local_networks` | private Bereiche | interne Netze für Download/Upload-Erkennung ([Verkehrsrichtung](FEATURES_de.md#download--upload-verkehrsrichtung)) |
| `network.exclude_networks` | leer | Netze, deren Verkehr komplett ignoriert wird ([Ausgenommene Netze](FEATURES_de.md#ausgenommene-netze)) |
| `collector.listen` | `0.0.0.0:2055` | Empfang von NetFlow/IPFIX |
| `collector.workers` | `2` | parallele Empfangs-Sockets (`SO_REUSEPORT`) |
| `storage.dir` | `data/live` | Live-Daten: `index.db` und eine Datei pro Stunde, siehe [Speicher](FEATURES_de.md#speicher-eine-sqlite-datei-pro-stunde) |
| `storage.retention_hours` | `48` | Live-Fenster; Werte über 72 werden auf 72 begrenzt |
| `storage.secure_delete` | `true` | gelöschte Daten überschreiben (gilt auch für die Historie), siehe [Speicher](FEATURES_de.md#speicher-eine-sqlite-datei-pro-stunde) |
| `history.enabled` | `true` | Stunden nach dem Live-Fenster in die Historie verschieben (`false` = löschen) |
| `history.dir` | `data/history` | Verzeichnis der Historie (gleicher Aufbau wie `storage.dir`) |
| `history.max_size_gb` | `50` | ab dieser Größe wird die Historie ins Archiv rotiert |
| `history.archive_dir` | `data/archive` | Ablage der Archive (Ordner `flows_<von>_<bis>/`, UTC, jede Datei einzeln gepackt) |
| `history.archive_retention_days` | `90` | Archive werden so lange nach ihrem jüngsten Flow aufbewahrt |
| `history.compression_level` | `19` | zstd-Stufe 1–22 |
| `alerts.upload_threshold_mb` | `1024` | Upload-Alarm ab dieser Menge je Verbindung, `0` = aus |
| `alerts.session_idle_secs` | `600` | ohne neue Flows so lange gilt eine Verbindung als beendet |
| `alerts.max_mails_per_hour` | `20` | Obergrenze gegen Mail-Fluten (gilt auch für Anomalie-Mails) |
| `anomaly.enabled` | `true` | Anomalie-Erkennung, Daten in `anomaly.db` (`data/anomaly.db`) |
| `anomaly.window_minutes` / `learning_days` | `10` / `7` | Fensterlänge, Lernphase nach dem ersten Start |
| `anomaly.z_threshold` | `4.0` | Schwelle der Statistik (Log-Skala, 4 ≈ Faktor 7+), dazu Mindestwerte `min_upload_mb` (100), `min_download_mb` (1024), `min_flows` (1000), `min_peers` (100), `min_internal_peers` (50), `min_ports` (30), `min_countries` (10) |
| `anomaly.groups` / `group_prefix_v4` / `group_prefix_v6` | leer / `24` / `64` | eigene Netzgruppen, sonst Subnetz dieser Länge |
| `anomaly.host_profiles` / `dynamic_networks` | `true` / leer | Profil je Host, außer in Netzen mit wechselnden Adressen (DHCP) |
| `anomaly.ignore` | leer | Hosts, die nicht ausgewertet werden |
| `anomaly.scan_threshold` | `100` | Portscan ab so vielen fehlgeschlagenen Versuchen je Fenster, `0` = aus |
| `anomaly.dns_rule` / `dns_servers` | `true` / leer | DNS an externe Resolver melden / erlaubte externe Resolver |
| `anomaly.new_country` | `true` | erstes Land einer Netzgruppe melden |
| `anomaly.beacon` | `true` | Beaconing-Erkennung (nur Hinweis in der Web-UI, nie per Mail) |
| `anomaly.beacon_min_connections` / `beacon_min_minutes` / `beacon_max_jitter` | `20` / `120` / `0.2` | Muster ab so vielen Verbindungen über so viele Minuten mit höchstens dieser relativen Streuung der Abstände |
| `anomaly.beacon_max_hosts` | `3` | so viele Hosts mit demselben Muster zum selben Anbieter und Port gelten als ausgerollte Software |
| `anomaly.beacon_allow` / `beacon_allow_asn` / `beacon_allow_ports` | leer / leer / `[123]` | Ausnahmen: Hosts oder Ziele (IP/CIDR), Anbieter (ASN), Zielports |
| `anomaly.ml` / `ml_threshold` / `ml_training_days` | `true` / `0.65` / `14` | Isolation Forest |
| `anomaly.event_retention_days` | `30` | Aufbewahrung der Auffälligkeiten |
| `anomaly.timezone` | leer | Zeitzone für Wochentag/Stunde, leer = System |
| `anomaly.mail` / `mail_min_severity` | `false` / `high` | Mails an die Admins |
| `[[anomaly.zones]]` / `[[anomaly.rules]]` | leer | Netz-Regeln: benannte Zonen und geordnete Regeln, siehe [Netz-Regeln](FEATURES_de.md#netz-regeln) |
| `email.smtp_host` / `smtp_port` / `security` | leer / `587` / `starttls` | SMTP-Server; `security` = `starttls`, `tls` (465) oder `none` (nur Relay im LAN). Leerer Host = kein Mailversand |
| `email.username` / `email.password` | leer | SMTP-Anmeldung; Passwort alternativ per `SNIA_SMTP_PASSWORD` |
| `email.from` / `email.admins` | – | Absender und Empfänger der Alarm-Mails |
| `geoip.country_db` / `geoip.asn_db` | `data/GeoLite2-*.mmdb` | MaxMind-Datenbanken (siehe oben) |
| `geoip.account_id` / `geoip.license_key` | leer | Zugang für das automatische Update (oder `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`) |
| `geoip.update_interval_hours` | `24` | wie oft nach einer neuen GeoLite2-Ausgabe gesucht wird |
| `pcap.max_upload_mb` | `512` | größte erlaubte Capture-Datei |
| `pcap.app_rules` | leer | eigene App-Regeln als JSON (Format wie `crates/pcap/apps.json`), leer = mitgelieferte Regeln |

Aufruf mit anderer Datei: `snia-net-mon /etc/snia-net-mon.toml`. Logging über `RUST_LOG`, z. B. `RUST_LOG=debug`.
Mailversand prüfen: `snia-net-mon --test-mail [config.toml]` schickt eine Test-Mail an die Admins und beendet sich.

**Reihenfolge in der Datei:** Die Blöcke `[[anomaly.zones]]` und `[[anomaly.rules]]` gehören ans **Ende**. In TOML gehört
alles nach einem solchen Block zu diesem Block; eine Einstellung dahinter landet sonst in der letzten Regel, und der
Start bricht mit einer Fehlermeldung ab.

## Sicherheit

- Die Web-UI lauscht standardmäßig nur auf `127.0.0.1`. Für Netzzugriff `api_token` setzen und einen Reverse-Proxy mit HTTPS
  davorstellen. Der WebSocket akzeptiert das Token als `?token=`.
- Das Token wird in konstanter Zeit verglichen. Es gibt kein Benutzer- oder Rollenkonzept, alle mit Token sehen alles.
- Der Collector-Port (UDP 2055) nimmt Pakete von jedem an. Per Firewall nur die eigenen Exporter zulassen.
- Den Empfangspuffer für hohe Paketraten vergrößern: `net.core.rmem_max` (Snia-Net-Mon fordert 16 MiB an).

## Entwicklung

```bash
cargo test --workspace              # Parser-Roundtrips (v9/IPFIX), Fuzz-artige Robustheit, Retention, Historie/Archiv, Stundendateien, Upload-Alarm, Anomalie-Erkennung (Baseline, Isolation Forest, Beaconing, Regeln), Filter, PCAP/pcapng-Leser, App-Regeln, GeoIP
cargo test -p db --release -- --ignored bench --nocapture --test-threads=1   # Lastproben: Statistiken mit/ohne Aggregate, Schreiben + Retention
cargo clippy --workspace --all-targets
cd frontend && npm run dev          # Vite auf :5173 mit Proxy auf das Backend (:8080), Hot Reload
```

Aufbau des Codes: [Architektur](FEATURES_de.md#architektur).
