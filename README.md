# Snia-Net-Mon

Netzwerkmonitor für eine **pfSense-Firewall**. Er sammelt Verbindungsdaten per **NetFlow v9 / IPFIX**, zeigt sie live im Browser – mit
**GeoIP (Land, ASN)** für jede externe Gegenstelle – und macht sie durchsuchbar. Dazu kommt eine **PCAP-Analyse** für
Mitschnitte (pcap/pcapng). Die Live-Daten umfassen die letzten **48 Stunden**, gespeichert als eine SQLite-Datei pro
Stunde. Ältere Stunden wandern in eine **Historie**, die ab 50 GB in ein **zstd-Archiv** rotiert wird. Archive bleiben
**3 Monate** und lassen sich in der Web-UI wieder ansehen. Große Uploads (> 1 GiB in einer Verbindung) melden sich **per Mail bei den Admins**. Eine **automatische
Anomalie-Erkennung** vergleicht jeden internen Host mit dem Normalverhalten seines Netzes und, bei festen Adressen, mit
seinem eigenen. Dazu kommen feste Regeln und ein Isolation Forest als zweite Meinung.

- **Backend:** Rust (Tokio, Axum), SQLite im WAL-Modus, eine Datei pro Stunde
- **Frontend:** Svelte 5 + Tailwind, Catppuccin-Mocha-Theme im Hyprland-Look (Frosted Glass, Verlaufskanten, Monospace)
- **Status:** Prototyp – funktionsfähig und getestet, siehe [Grenzen & nächste Schritte](#grenzen--nächste-schritte)

![Dashboard mit Live-Durchsatz, aktiven Verbindungen samt GeoIP, Verkehrsrichtung, Protokollen und Top Talkern](docs/screenshot.png)

## Funktionen

| Bereich | Was es kann |
|---|---|
| **Dashboard** (`#dashboard`) | Live-Durchsatz getrennt nach **Download ↓ und Upload ↑** (gespiegelter Chart) per WebSocket, Verkehrsrichtung im Zeitfenster, Tabelle der aktiven Verbindungen mit Richtung (einfrierbar, filterbar). **Bereich im Durchsatz-Chart mit der Maus markieren** hält Chart und Tabelle an und zeigt die Verbindungen genau dieses Zeitraums (Klick oder Esc = zurück zu live), Top Talker, Top Ports, **Länder und Netze (ASN)** der Gegenstellen, Protokollverteilung, Sankey-Diagramm Quelle → Dienst → Ziel. Alle Statistiken lassen sich nach Richtung filtern |
| **Flow-Suche** (`#flows`) | Filter nach IP **oder CIDR** (Quelle/Ziel/beides), Port, Protokoll, Richtung, Zeitfenster; CSV-Export. Darunter die **Top Talker grafisch** mit ihren stärksten Gegenstellen (Dienst, gesendet/empfangen). Klick auf eine IP im Dashboard springt direkt hierher |
| **PCAP** (`#pcap`) | Capture-Datei (pcap/pcapng, z. B. aus *Diagnostics → Packet Capture*) per Drag & Drop hochladen: Kennzahlen, Zeitverlauf, Protokolle, **Anwendungen** (YouTube, Microsoft 365, CDN, AI … über TLS-SNI, DNS, HTTP-Host, IP-Präfixe), **Endpunkte mit Land und ASN**, Länder, Top Quellen/Ports/Flows, DNS, HTTP, TCP-Flags und heuristische **Auffälligkeiten** (Portscan, NXDOMAIN-Häufung, DNS/HTTP auf Nicht-Standard-Ports). Verlauf der Analysen; Klick auf eine IP sucht sie in den NetFlow-Daten |
| **Archiv** (`#archive`) | Füllstand der Historie, Liste der Archive mit Zeitraum, Größe und Löschdatum. **Historie oder ein Archiv durchsuchen**: öffnet die Flow-Suche mit dieser Datenquelle (aus Archiven wird nur entpackt, was eine Abfrage braucht) |
| **GeoIP** | Land, Organisation und ASN für alle öffentlichen IPs – in der Live-Tabelle, Flow-Suche (auch CSV), Top Talker, Sankey und PCAP-Analyse |
| **Aufbewahrung** | live 48 h (höchstens 72 h) → Historie bis 50 GB → zstd-Archiv, gelöscht 90 Tage nach dem jüngsten Flow; siehe [Aufbewahrung](#aufbewahrung-live--historie--archiv). PCAP-Analysen folgen dem Live-Fenster, die hochgeladene Datei selbst wird direkt nach der Analyse gelöscht |
| **Ausgenommene Netze** | `network.exclude_networks`: Verkehr von oder zu diesen Netzen wird beim Empfang verworfen – nicht gespeichert, nicht angezeigt, nicht gezählt |
| **Upload-Alarm** | lädt eine Verbindung mehr als 1 GiB nach extern hoch, geht eine Mail an die Admins (Quelle, Ziel mit Land/ASN, Dienst, Menge, Dauer, Rate) |
| **Anomalien** (`#anomalies`) | Statistik gegen eine Baseline je Netzgruppe und Host, Portscan, DNS an externe Resolver, erstes Land einer Gruppe, Netz-Regeln zwischen Zonen, Isolation Forest als zweite Meinung. Status der Lernphase und des Modells, Verlauf der Auffälligkeiten (30 Tage) mit Filter, Klick auf den Host öffnet die Flow-Suche. Siehe [Anomalie-Erkennung](#anomalie-erkennung) |

Tastatur wie in Hyprland: **Alt+1 … Alt+5** wechselt den Workspace. Der Fokus folgt der Maus: Das Fenster unter dem Zeiger
bekommt die aktive Verlaufskante.

## Schnellstart (Demo ohne pfSense)

Voraussetzungen: Rust ≥ 1.88, Node ≥ 20.

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # Web-UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # zweites Terminal: erzeugt Demo-Verkehr
```

Ohne `config.toml` laufen Standardwerte: Collector auf UDP 2055, Web-UI nur lokal auf Port 8080.
`flowgen` schickt echte NetFlow-v9-Pakete an den Collector. Optionen: `--rate 5000`, `--format ipfix`,
`--exporters 4`, `--seconds 60`.

### GeoIP-Datenbanken

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

## Anbindung an die pfSense

### NetFlow-Export (softflowd)

1. **System → Package Manager → Available Packages:** `softflowd` installieren.
2. **Services → softflowd:**
   - *Interface:* die zu überwachenden Interfaces (z. B. LAN, WAN)
   - *Host:* IP des Rechners mit Snia-Net-Mon, *Port:* `2055`
   - *NetFlow version:* `9` oder `IPFIX (10)`
   - *Flow tracking level:* `Full` (5-Tupel mit Ports)
   - *Flow Timeouts:* kurze Werte ergeben „livere“ Daten, z. B. `maxlife 60`
3. Speichern. Nach kurzer Zeit erscheinen die Flows im Dashboard. Solange der Exporter seine Templates noch nicht erneut
   gesendet hat, zählt der Collector die Daten als `missing_template` (Zähler unter `/api/status`).

## Download / Upload (Verkehrsrichtung)

Jeder Flow bekommt beim Empfang eine Richtung. Grundlage ist die Liste der internen Netze (`network.local_networks`):

| Richtung | Bedeutung | Beispiel |
|---|---|---|
| `in` ↓ Download | extern → intern | Antwort eines Webservers, Portscan auf einen weitergeleiteten Server |
| `out` ↑ Upload | intern → extern | Anfrage eines Clients, Cloud-Backup |
| `internal` ⇄ | intern ↔ intern | SMB zwischen LAN und Server-VLAN |
| `external` | weder noch | sollte selten vorkommen; häufig ein Hinweis, dass ein eigenes Netz in der Liste fehlt |

softflowd exportiert jede Verbindung als zwei Flows (Anfrage und Antwort). Deshalb erscheint ein Download als großer `in`-Flow
plus kleiner `out`-Flow. Der Dienst (Top Ports, Sankey, Spalte „Dienst“) ist jeweils der kleinere der beiden Ports, also 443
und nicht der zufällige Client-Port.

Standardmäßig gelten die privaten Bereiche (RFC 1918, CGNAT, Link-Local, IPv6-ULA) als intern. Mit **öffentlichem IPv6** vom
Provider muss dessen Präfix in `local_networks` ergänzt werden, sonst läuft IPv6-Verkehr unter „extern“. Dasselbe gilt für die
WAN-Adresse, wenn Verbindungen zur Firewall selbst als Download zählen sollen. Die Richtung wird beim Empfang gespeichert. Eine
geänderte Liste wirkt daher nur auf neue Flows.

### Ausgenommene Netze

Netze in `network.exclude_networks` (CIDR oder einzelne IP) werden vom Collector direkt nach dem Parsen verworfen, sobald
**Quelle oder Ziel** darin liegt. Sie landen weder in der Datenbank noch in der Live-Ansicht und zählen nicht für den
Upload-Alarm. Typisch: ein Backup-Server, dessen nächtliche Uploads keinen Alarm auslösen sollen, oder ein Gäste-WLAN. Der
Zähler `collector.excluded_flows` unter `/api/status` zeigt, wie viel verworfen wurde. Bereits gespeicherte Flows bleiben
unverändert.

## Anomalie-Erkennung

Der Collector reicht jeden Flow auch an die Anomalie-Erkennung weiter. Sie ordnet ihn dem internen Host zu, der ihn
verursacht (bei Upload und internem Verkehr die Quelle, bei Download das Ziel), und sammelt je Host und Fenster
(Standard 10 min) sieben Merkmale: **Upload, Download, Flows, verschiedene externe Ziele, verschiedene interne Ziele,
verschiedene Dienste (Ports), verschiedene Länder**. Am Ende des Fensters wird ausgewertet:

| Verfahren | Was es meldet | Schwere |
|---|---|---|
| **Statistik** (Baseline) | Ein Merkmal liegt mindestens `z_threshold` Standardabweichungen über dem Typischen **und** erreicht den Mindestwert (z. B. 100 MB Upload pro Fenster). Text z. B. „upload 3.0 GiB statt typisch 38 MiB (80×)“ | warnung, hoch bei Zustimmung des Isolation Forest oder doppelter Schwelle |
| **Isolation Forest** (ML) | Gibt jedem Host-Fenster einen Score. Bei statistischen Treffern steht er als zweite Meinung dabei („ml 0.81 ✓ stimmt zu“). Allein meldet er ungewöhnliche *Kombinationen*, bei denen jeder Einzelwert normal ist, samt den stärksten Abweichungen | info |
| **Portscan** | mindestens `scan_threshold` fehlgeschlagene TCP-Verbindungsversuche (SYN ohne ACK) zu verschiedenen Ziel/Port-Paaren, auch im LAN | hoch |
| **Externes DNS** | DNS (53/853) an einen Resolver außerhalb, der nicht in `dns_servers` steht | warnung |
| **Neues Land** | erste Verbindung einer Netzgruppe in ein Land, das sie nie zuvor kontaktiert hat | info |
| **Netz-Regel** | Verbindung zwischen Zonen, die laut [Netz-Regeln](#netz-regeln) gemeldet werden soll, z. B. Schülernetz → Verwaltung | je Regel, Standard hoch |

**Baseline:** gleitender Mittelwert und gleitende Varianz (EWMA) auf logarithmierten Werten. Ausreißer fließen nur
gedämpft ein, damit ein Angreifer die Baseline nicht langsam „hochziehen“ kann. Es gibt zwei Ebenen:

- **Netzgruppe:** Standard ist das Subnetz (/24 bzw. /64), eigene Gruppen über `groups`. Verglichen wird mit dem
  *typischen Host* der Gruppe zur gleichen Zeit: Wochentag × Stunde (168 Slots), solange das noch nicht eingelernt ist
  nur die Stunde (24 Slots). Das funktioniert auch mit DHCP, wo dieselbe IP morgen ein anderes Gerät ist.
- **Host:** In Netzen mit festen Adressen bekommt jeder Host zusätzlich ein eigenes Profil (Werktag/Wochenende ×
  Stunde). Sobald es eingelernt ist (gut eine Woche), hat es Vorrang. Ein Drucker oder Server, der plötzlich ins
  Internet hochlädt, fällt so gegen sein eigenes Verhalten auf und nicht erst gegen den Durchschnitt des Netzes. Netze
  mit wechselnden Adressen gehören in `dynamic_networks`, dort gibt es nur das Gruppenprofil.

Beispiel für eine Schule mit einem Schülernetz per DHCP und sonst festen Adressen:

```toml
[anomaly]
dynamic_networks = ["10.20.0.0/22"]          # Schüler-WLAN
groups = ["10.0.10.0/28"]                    # Server-VLAN als eigene Gruppe (sonst /24)
ignore = ["10.0.10.5"]                       # Backup-Server, große Uploads sind normal
dns_servers = []                             # externe Resolver, die erlaubt sind
```

**Lernphase:** In den ersten `learning_days` (Standard 7) nach dem ersten Start wird nur gelernt. Portscan, externes
DNS und Netz-Regeln melden sofort. Der Isolation Forest trainiert nach der Lernphase und danach täglich mit den Merkmalsvektoren der
letzten 14 Tage. Er meldet ab `ml_threshold`, mindestens aber ab dem 99,9-%-Quantil der eigenen Trainingsdaten. Die
Score-Verteilung steht in der Web-UI und hilft beim Einstellen.

**Zusammenfassen:** Tritt dieselbe Art beim selben Host innerhalb einer Stunde erneut auf, wird die bestehende Zeile
verlängert („3×“) statt eine neue anzulegen. Die stärkste Messung bestimmt den Text.

### Netz-Regeln

Mit vielen festen Netzen lässt sich genau sagen, wer mit wem reden darf. Dazu werden Netze als **Zonen** benannt und
**Regeln** formuliert. Die Regeln werden der Reihe nach geprüft wie in einer Firewall, die erste passende entscheidet:
`action = "alert"` (Standard) meldet, `"allow"` erlaubt still. Flows, auf die keine Regel passt, bleiben unbeachtet.

```toml
[[anomaly.zones]]
name = "schueler"
networks = ["10.20.0.0/22"]

[[anomaly.zones]]
name = "verwaltung"
networks = ["10.0.5.0/24", "10.0.6.0/24"]

[[anomaly.zones]]
name = "server"
networks = ["10.0.10.0/28"]

[[anomaly.rules]]                # Schüler dürfen DNS, HTTPS und SMB auf den Servern …
from = "schueler"
to = "server"
ports = [53, 443, 445]
action = "allow"

[[anomaly.rules]]                # … alles andere dorthin ist eine Warnung
from = "schueler"
to = "server"
severity = "warn"

[[anomaly.rules]]                # Schülernetz → Verwaltung immer melden (Schwere hoch)
from = "schueler"
to = "verwaltung"

[[anomaly.rules]]
name = "smtp direkt ins internet"
from = "*"
to = "extern"
ports = [25]
```

- `from` / `to`: Zonenname, `extern` (alles außerhalb von `network.local_networks`) oder `*`. Eine IP darf in mehreren
  Zonen liegen, z. B. in `schueler` und einer übergeordneten Zone `intern`.
- `ports`: nur diese Dienste (Zielport bei TCP/UDP), leer = alle. `severity`: `info`, `warn` oder `high`.
- Gezählt wird nur die **Anfrage** einer Verbindung (Zielport kleiner als Quellport, bei ICMP der Echo-Request), nicht die
  Antwort. Sonst würde die Antwort eines Verwaltungsservers an einen Schüler-PC als „verwaltung → schueler“ zählen.
- Gemeldet wird beim internen Beteiligten, normalerweise der Quelle; bei `extern → …` das interne Ziel. Pro Host und
  Regel entsteht eine Zeile mit Zielen, Ports und Menge, Wiederholungen innerhalb einer Stunde werden zusammengefasst.
  `anomaly.ignore` gilt für Netz-Regeln nicht, Ausnahmen gehören als `allow`-Regel davor.
- Netz-Regeln ersetzen keine Firewall-Regeln: Sie melden, was durchgeht, sie blockieren nichts. Gemeldet wird am Ende
  des Fensters (Standard 10 min).

**Mails** sind zunächst aus. Mit `mail = true` gehen neue Auffälligkeiten ab `mail_min_severity` (Standard `high`) an die
Admins aus `[email]`, begrenzt durch `alerts.max_mails_per_hour`. Erst einschalten, wenn die Schwellen zum eigenen Netz
passen.

## Konfiguration

Eine einzige Datei: `cp config.example.toml config.toml`. Alle Schlüssel sind dort kommentiert. Die wichtigsten:

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | Web-UI/API. Für Zugriff aus dem Netz `0.0.0.0:8080` **und** `api_token` setzen |
| `server.api_token` | leer | Zugriffsschutz: Die Web-UI fragt einmal nach dem Token |
| `network.local_networks` | private Bereiche | interne Netze für Download/Upload-Erkennung (siehe oben) |
| `collector.listen` | `0.0.0.0:2055` | Empfang von NetFlow/IPFIX |
| `collector.workers` | `2` | parallele Empfangs-Sockets (`SO_REUSEPORT`) |
| `network.exclude_networks` | leer | Netze, deren Verkehr komplett ignoriert wird (siehe oben) |
| `storage.dir` | `data/live` | Live-Daten: `index.db` und eine Datei pro Stunde, siehe [Speicher](#speicher-eine-sqlite-datei-pro-stunde) |
| `storage.retention_hours` | `48` | Live-Fenster; Werte über 72 werden auf 72 begrenzt |
| `storage.secure_delete` | `true` | gelöschte Daten überschreiben (gilt auch für die Historie), siehe [Speicher](#speicher-eine-sqlite-datei-pro-stunde) |
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
| `anomaly.z_threshold` | `4.0` | Schwelle der Statistik (Log-Skala, 4 ≈ Faktor 7+), dazu Mindestwerte `min_upload_mb` (100), `min_download_mb` (1024), `min_flows`, `min_peers`, `min_internal_peers`, `min_ports`, `min_countries` |
| `anomaly.groups` / `group_prefix_v4` / `group_prefix_v6` | leer / `24` / `64` | eigene Netzgruppen, sonst Subnetz dieser Länge |
| `anomaly.host_profiles` / `dynamic_networks` | `true` / leer | Profil je Host, außer in Netzen mit wechselnden Adressen (DHCP) |
| `anomaly.ignore` | leer | Hosts, die nicht ausgewertet werden |
| `anomaly.scan_threshold` | `100` | Portscan ab so vielen fehlgeschlagenen Versuchen je Fenster, `0` = aus |
| `anomaly.dns_rule` / `dns_servers` | `true` / leer | DNS an externe Resolver melden / erlaubte externe Resolver |
| `anomaly.new_country` | `true` | erstes Land einer Netzgruppe melden |
| `anomaly.ml` / `ml_threshold` / `ml_training_days` | `true` / `0.65` / `14` | Isolation Forest |
| `anomaly.event_retention_days` | `30` | Aufbewahrung der Auffälligkeiten |
| `anomaly.timezone` | leer | Zeitzone für Wochentag/Stunde, leer = System |
| `anomaly.mail` / `mail_min_severity` | `false` / `high` | Mails an die Admins |
| `[[anomaly.zones]]` / `[[anomaly.rules]]` | leer | Netz-Regeln: benannte Zonen und geordnete Regeln, siehe [Netz-Regeln](#netz-regeln) |
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

## Architektur

```text
pfSense (softflowd) ──UDP 2055──▶ collector ──Batches──┬──▶ db: Writer-Thread ──▶ live/ (index.db + Datei je Stunde, 48 h)
                                  (n Worker,            │        Retention-Task ──▶ history/ ──50 GB──▶ archive/flows_<von>_<bis>/
                                   SO_REUSEPORT,        ├──▶ api::LiveHub ──1×/s──▶ WebSocket ──▶ Browser
                                   exclude_networks)    ├──▶ alert: Upload je Verbindung > 1 GiB ──SMTP──▶ Admins
                                                        └──▶ anomaly: Fenster je Host ──▶ Baseline, Regeln, Isolation Forest ──▶ anomaly.db
Browser ──REST──▶ api (Axum) ──▶ db (live, Historie oder geöffnetes Archiv) ──▶ geo (Land/ASN je IP, beim Ausliefern)
Browser ──PCAP-Upload──▶ api ──▶ pcap (Analyse im Blocking-Thread) ──▶ db (Ergebnis als JSON, 48 h)
```

```text
Snia-Net-Mon/
├── Cargo.toml                 Workspace (Abhängigkeiten zentral)
├── config.example.toml
├── crates/
│   ├── model/                 gemeinsame Typen: FlowRecord, Direction, LocalNetworks, IP↔16-Byte, CIDR, MAX_RETENTION_HOURS
│   ├── collector/
│   │   ├── parser.rs          NetFlow v9 + IPFIX: Template-Cache, Dekodierplan, Varlen/Enterprise-Felder
│   │   ├── listener.rs        async UDP-Worker, Batching, Backpressure ohne Blockieren
│   │   ├── metrics.rs         lock-freie Zähler
│   │   └── synth.rs           Encoder + Verkehrsmodell (Tests, flowgen)
│   ├── db/
│   │   ├── lib.rs             Writer-Thread (je Stunde eine Datei), Lese-Pool, Retention-Task (verschieben oder löschen)
│   │   ├── store.rs           Stundendateien: Namen, Anhängen, Abschließen, Verschieben, Löschen
│   │   ├── history.rs         Historie, Rotation, zstd-Archive, Entpacken bei Bedarf
│   │   ├── schema.rs          Tabellen, Indizes, Pragmas
│   │   ├── rollup.rs          Minuten-/Stunden-Aggregate, Zerlegung der Zeitfenster
│   │   ├── query.rs           Suche, Top Talker/Ports/Protokolle, Verbindungen, Gegenstellen, Zeitreihe, Sankey
│   │   └── pcap.rs            gespeicherte PCAP-Analysen
│   ├── geo/                   MaxMind-Lookups (Land, ASN), Erkennung öffentlicher Adressen
│   ├── pcap/
│   │   ├── reader.rs          PCAP- und pcapng-Leser (µs/ns, mehrere Interfaces, Byte-Reihenfolge)
│   │   ├── dissect.rs         Ethernet/VLAN, Raw-IP, SLL/SLL2, Loopback, pflog; IPv4/IPv6, TCP/UDP/ICMP
│   │   ├── dns.rs · tls.rs    DNS-Parser, TLS-SNI aus dem ClientHello
│   │   ├── apps.rs            App-Regeln (Domains, IP-Präfixe) + DNS-Learning; Standardregeln in apps.json
│   │   └── analyze.rs         Aggregation, Heuristiken, Ergebnis-JSON
│   ├── api/
│   │   ├── lib.rs             Axum-Router, Endpunkte, Geo-Anreicherung, Token-Prüfung, Auslieferung der SPA
│   │   ├── pcap.rs            Upload (gestreamt, größenbegrenzt), Verlauf
│   │   └── live.rs            Tabelle aktiver Verbindungen, 1-s-Snapshots per Broadcast
│   ├── alert/
│   │   ├── upload.rs          Upload-Summen je Verbindung, Alarm einmal pro Verbindung, Mail-Text
│   │   └── mail.rs            SMTP-Versand (lettre, rustls)
│   ├── anomaly/
│   │   ├── features.rs        Merkmale je internem Host und Fenster, Rohdaten der Regeln
│   │   ├── baseline.rs        EWMA-Baseline je Netzgruppe (Wochen-/Tages-Slots) und je Host
│   │   ├── forest.rs          Isolation Forest (eigene Implementierung), Score-Quantile, Median/MAD für Erklärungen
│   │   ├── policy.rs          Netz-Regeln: Zonen, geordnete Regeln, Anfrage-Erkennung
│   │   ├── engine.rs          Auswertung eines Fensters, Regeln, Zusammenfassen, tägliches Training
│   │   ├── store.rs           anomaly.db: Baselines, Länder, Trainingsvektoren (ohne IP), Auffälligkeiten
│   │   └── lib.rs             Konfiguration, Task am Flow-Strom, optionale Mails
│   ├── server/                Binary snia-net-mon: Konfiguration + Verdrahtung, --test-mail, geordnetes Herunterfahren
│   └── flowgen/               Binary flowgen: Demo-/Lastgenerator
└── frontend/
    ├── tailwind.config.js     Catppuccin-Mocha-Palette, Glow, Verlaufskante, Animationen
    └── src/
        ├── app.css            Komponenten-Klassen: .window, .window-active, .chip, .btn, .table-flows …
        ├── lib/               API-Client, WebSocket-Store (Runes), Formatierung, UI-Zustand
        └── components/        Dashboard, BandwidthChart, LiveTable, SankeyChart, FlowSearch, TalkerConnections, PcapAnalyzer, ArchiveBrowser, GeoTag …
```

### Leistung bei hoher Paketrate

- **Empfang:** Jeder Worker hat einen eigenen Socket (`SO_REUSEPORT`) und einen eigenen Template-Cache, dadurch gibt es kein
  Locking. Der Kernel verteilt nach Quell-Tupel, ein Exporter landet also immer beim selben Worker. Der Empfangspuffer ist
  standardmäßig 16 MiB groß, dafür `net.core.rmem_max` erhöhen.
- **Parsen:** Templates werden beim Empfang einmal in einen Dekodierplan übersetzt. Datensätze werden ohne Allokationen pro
  Feld dekodiert.
- **Backpressure:** Flows gehen gebündelt per `try_send` an Datenbank und Live-Ansicht. Ist ein Abnehmer voll, werden Flows
  gezählt verworfen (`dropped_flows`), der UDP-Empfang blockiert nie.
- **Schreiben:** Ein eigener Thread schreibt mit vorbereitetem Statement in die Datei der jeweiligen Stunde. Unter Last
  fasst er alle wartenden Batches zu einer Transaktion zusammen (bis 50.000 Zeilen). Ist die Datenbank länger als das Busy-Timeout gesperrt, versucht er es erneut,
  statt die Flows zu verwerfen.
- **Live:** Ein Snapshot pro Sekunde wird einmal serialisiert und an alle Clients geteilt. Die Top-150-Auswahl läuft in O(n).

Gemessen (Release-Build, ein Desktop-Rechner, 4 Exporter): **1.000.000 Flows in 10 s (100.000 Flows/s) ohne Verluste und
ohne Parse-Fehler**.

### Voraggregation (Statistiken bei viel Verkehr)

Der Writer schreibt in derselben Transaktion wie die Flows Summen **je Minute und je Stunde**: pro IP, pro Dienst
(Protokoll + Dienst-Port) und pro Paar Quelle → Ziel je Dienst, jeweils mit Richtung. Eine Statistik-Abfrage zerlegt ihr
Zeitfenster in volle Stunden, volle Minuten und die Ränder darunter. Nur die Ränder (unter einer Minute) kommen aus den
Einzel-Flows der Stundendateien. Das Ergebnis ist **exakt dasselbe** wie über die Rohdaten (per Test gegen die Rohdaten
geprüft).

- Aus den Aggregaten kommen: Top Talker, Länder/ASN, Top Ports, Protokolle, Richtungen, Zeitreihe, Sankey und die
  Gegenstellen der Flow-Suche – solange nur Zeitfenster und Richtung gefiltert werden.
- Mit IP-, Port- oder Protokollfilter sowie für Einzel-Flows und 5-Tupel-Verbindungen (markierter Bereich) wird wie bisher
  über die Rohdaten gesucht. Dafür gibt es Indizes, diese Abfragen betreffen nur einen kleinen Ausschnitt.
- Die Aggregate liegen in `index.db` und wandern mit den Flows in Historie und Archiv, Statistiken dort sind genauso
  schnell.

Lastprobe mit 1 h bei 1.000 Flows/s (3,6 Mio. Flows, 60 Geräte, 20.000 Gegenstellen), Zeitfenster 1 h, Release-Build:

| Abfrage | nur Rohdaten | mit Aggregaten |
|---|---|---|
| Top Talker / Länder | 8,4 s | 0,45 s |
| Top Ports | 1,8 s | 0,02 s |
| Protokolle / Richtungen | 0,7 s | 0,01 s |
| Sankey / Gegenstellen | 4,9 s | 1,7 s |

Schreiben: rund 130.000 Flows/s. Die Aggregate brauchen zusätzlich Platz. Wie viel, hängt davon ab, wie oft dieselben Paare
wiederkehren: bei diesen Testdaten mit sehr vielen einmaligen Gegenstellen rund die Hälfte der Rohdaten, im Heimnetz mit
immer denselben Diensten deutlich weniger. Nachmessen: `cargo test -p db --release -- --ignored bench --nocapture`
(Anzahl per `BENCH_FLOWS`).

### Speicher: eine SQLite-Datei pro Stunde

Live-Daten und Historie sind jeweils ein Verzeichnis:

```text
data/live/
├── index.db                Aggregate (Minute/Stunde), PCAP-Analysen, Meta
├── flows_20261016-13.db    Einzel-Flows mit Flow-Ende zwischen 13:00 und 14:00 UTC
└── flows_20261016-14.db    aktuelle Stunde – nur in diese schreibt der Writer
```

Warum so: Bei einer einzigen großen Datei musste die Retention jede Minute Hunderttausende Zeilen per `DELETE` aus
Tabelle und Indizes entfernen und zum Verschieben in die Historie zeilenweise kopieren. Das kostete Schreibarbeit
proportional zur Datenmenge und sperrte zeitweise den Writer. Jetzt verschwinden alte Daten als ganze Datei
(`rename` in die Historie oder Löschen). Das dauert unabhängig von der Datenmenge Millisekunden. Nur die kleinen
Aggregat- und PCAP-Tabellen in `index.db` werden noch zeilenweise gelöscht.

- **Schreiben:** Der Writer hängt die Datei der Stunde an seine Verbindung (`ATTACH`) und schreibt Flows und Aggregate in
  einer Transaktion. Danach bleibt nur die neueste Stunde angehängt. Flows, deren Zeitstempel schon vor dem
  Retention-Fenster liegt (z. B. bei falscher Uhr des Exporters), werden verworfen und unter `/api/status` als
  `db.late_flows` gezählt.
- **Lesen:** Eine Abfrage hängt die Stundendateien an, die ihr Zeitfenster berührt. Die Flow-Suche geht von der neuesten
  Stunde rückwärts und hört auf, sobald das Limit erreicht ist. Statistiken kommen aus den Aggregaten, nur die Ränder
  (unter einer Minute) aus den Stundendateien. Bis zu acht Dateien werden direkt angehängt (SQLite erlaubt zehn). Bei
  mehr, etwa einer IP-Suche über die ganze Historie, werden die Treffer je Datei vorsummiert in einer temporären Tabelle
  gesammelt. Flow-IDs setzen sich aus Stunde und Zeilennummer zusammen und sind dadurch über alle Dateien eindeutig.
- **Verschieben:** Eine Stundendatei wird erst angefasst, wenn sie ganz vor dem Fenster liegt. Dann wird sie
  abgeschlossen (WAL zurückgeschrieben, Rollback-Journal statt WAL) und ist genau eine Datei. Laufende Abfragen halten
  eine Lese-Sperre, das Verschieben wartet darauf. Der Writer schreibt mit zehn Minuten Abstand zur Grenze nicht mehr
  in solche Stunden.
- **Indizes** je Stundendatei: `ts` (Zeitfenster), `src_ip, ts` und `dst_ip, ts` (IP-/CIDR-Filter). IPs sind 16 Byte
  (IPv4 als IPv4-mapped IPv6), damit IPv4 und IPv6 in denselben Indizes und CIDR-Filter als einfache `BETWEEN`-Bereiche
  funktionieren.
- **`storage.secure_delete`:**
  - `true` (Standard): Gelöschte Stundendateien werden vor dem Entfernen mit Nullen überschrieben. In `index.db`
    überschreibt SQLite gelöschte Seiten (`PRAGMA secure_delete`), danach werden WAL und freie Seiten bereinigt. Auf
    SSDs und Dateisystemen mit Copy-on-Write (btrfs, ZFS) landen die Nullen allerdings nicht zwingend auf denselben
    Blöcken. Dort hilft nur Verschlüsselung des Datenträgers.
  - `false`: Dateien werden einfach gelöscht, freie Seiten in `index.db` wiederverwendet.

Gemessen (Release-Build, NVMe, 2 Mio. Flows mit Aggregaten, je ein Lauf):

| | eine Datei (vorher) | Datei pro Stunde |
|---|---|---|
| Schreiben | 128.000 Flows/s | 131.000 Flows/s |
| Retention | 1 Mio. Flows in 9,5 s (40 `DELETE`-Schritte) | 2 Mio. Flows in 1,0 s (zwei Dateien, inkl. Überschreiben) |
| Top Talker / Länder (1 h, Aggregate) | 0,33 s | 0,25 s |
| Top Ports / Protokolle (1 h, Aggregate) | 12 / 7 ms | 11 / 6 ms |
| Sankey / Gegenstellen (1 h, Aggregate) | 1,0 s | 1,0 s |

Nachmessen: `cargo test -p db --release -- --ignored bench --nocapture --test-threads=1` (Anzahl per `BENCH_FLOWS`; für
echte Plattenwerte `TMPDIR` auf die Zielplatte setzen, `/tmp` ist oft eine RAM-Disk).

### Aufbewahrung (live → Historie → Archiv)

```text
live/ (48 h) ──jede volle Stunde──▶ history/ ──ab 50 GB──▶ archive/flows_<von>_<bis>/ ──90 Tage──▶ gelöscht
```

- **Live:** höchstens 72 h (`model::MAX_RETENTION_HOURS`, fest einkompiliert), Standard 48 h. Dashboard und Live-Ansicht
  arbeiten nur hier. Abfragen schneiden minutengenau ab. Auf der Platte bleibt eine Stunde liegen, bis sie ganz vor dem
  Fenster liegt, also bis zu 49 h.
- **Verschieben:** Der Retention-Task läuft beim Start und danach jede Minute. Liegt eine Stunde ganz vor dem Fenster,
  kopiert er ihre Minuten-Aggregate in die `index.db` der Historie, berechnet dort die Stunden-Aggregate neu und
  verschiebt dann die Stundendatei per `rename` (liegt die Historie auf einem anderen Dateisystem: kopieren und löschen).
  Die erreichte Grenze steht in derselben Transaktion in `meta.moved_until` der Historie. Bricht der Prozess dazwischen
  ab, verschiebt der nächste Lauf die übrigen Dateien, ohne Aggregate doppelt zu zählen. Scheitert das Verschieben
  (z. B. Platte voll), löscht der Task trotzdem alles über 72 h – die Live-Daten wachsen nie unbegrenzt.
- **Ohne Historie** (`history.enabled = false`) werden die Stundendateien gelöscht. Die harte 72-h-Grenze gilt dabei auch
  innerhalb einer Stunde: Der ältere Teil der Grenzstunde wird zeilenweise gelöscht.
- **Rotation:** Erreicht das Verzeichnis der Historie `max_size_gb`, wird es in `history.rotating` umbenannt und durch ein
  leeres ersetzt. Ein eigener Thread packt jede Datei einzeln mit **zstd** (Stufe 19, Long-Distance-Matching, halbe
  Kernzahl als Threads) in einen Ordner unter `archive_dir`. Eine Stundendatei schrumpft dabei typischerweise auf ein
  Sechstel bis Siebtel (flowgen-Testdaten: 8,2 MB → 1,1 MB). Bricht der Prozess ab, setzt der nächste Start die
  Komprimierung fort.
- **Archive:** Ordnername = Zeitraum (UTC) des ältesten und jüngsten Flows. Gelöscht wird `archive_retention_days` nach
  dem jüngsten Flow.
- **Ansehen:** Im Workspace **archiv** ein Archiv öffnen. Dabei wird nur `index.db` nach `archive_dir/.view/` entpackt,
  Top Talker, Länder und andere Statistiken sind danach sofort abfragbar. Eine Stundendatei wird erst entpackt, wenn
  eine Abfrage sie braucht. Die Flow-Suche (neueste zuerst) kommt meist mit den letzten Stunden des Archivs aus, eine
  IP-Suche über den ganzen Zeitraum entpackt dagegen alles. Es ist immer nur ein Archiv geöffnet; nach 30 Minuten ohne
  Abfrage wird das Entpackte wieder gelöscht.
- PCAP-Analysen (sie enthalten IPs, Domains und URLs) werden nach dem Live-Fenster gelöscht und nicht archiviert.
  Hochgeladene Capture-Dateien liegen nur während der Analyse als temporäre Datei in `pcap.upload_dir` und werden danach
  sofort entfernt – auch bei Fehlern; Reste nach einem Absturz räumt der nächste Start weg.

Wie lange Daten damit insgesamt aufbewahrt werden und was das für den Datenschutz bedeutet, steht unter
[Datenschutz](#datenschutz).

### Upload-Alarm

softflowd meldet eine lange Verbindung mehrfach (je `maxlife`). Der Alarm summiert deshalb die ausgehenden Bytes
(Richtung `out`) je **Verbindung** (Quelle, Ziel, Ports, Protokoll) über alle ihre Flows. Beim Überschreiten von
`upload_threshold_mb` geht **eine** Mail an `email.admins` mit Quelle, Ziel (Land, ASN), Dienst, Menge, Beginn, Dauer und
Rate. Die Verbindung wird danach nicht erneut gemeldet. Ohne neue Flows seit `session_idle_secs` gilt sie als beendet.
Ein Upload, der auf viele parallele Verbindungen verteilt ist (manche Cloud-Clients), löst den Alarm nur aus, wenn eine
einzelne Verbindung die Schwelle erreicht. Jeder Alarm steht zusätzlich im Log (`WARN alert::upload`), auch ohne
Mailversand oder wenn `max_mails_per_hour` erreicht ist.

### Sicherheit

- Die Web-UI lauscht standardmäßig nur auf `127.0.0.1`. Für Netzzugriff `api_token` setzen und einen Reverse-Proxy mit HTTPS
  davorstellen. Der WebSocket akzeptiert das Token als `?token=`.

## Datenschutz

Snia-Net-Mon zeichnet auf, welches Gerät wann mit wem wie viel Daten ausgetauscht hat. Über die DHCP-Leases der pfSense,
Anmeldungen am WLAN oder feste Gerätezuordnungen lassen sich IP-Adressen meist einer Person zuordnen – die gespeicherten
Daten sind deshalb **personenbezogen** im Sinne der DSGVO. Das gilt besonders an Schulen, wo Schülerinnen und Schüler
(oft minderjährig) und Lehrkräfte dasselbe Netz nutzen.

> Dieser Abschnitt beschreibt, was die Software technisch speichert, und gibt Hinweise für den Einsatz. Er ist keine
> Rechtsberatung. Ob und in welchem Umfang der Betrieb zulässig ist, klärt die verantwortliche Stelle (Schulleitung bzw.
> Schulerhalter) mit ihrer bzw. ihrem Datenschutzbeauftragten.

### Was gespeichert wird

| Daten | Inhalt | Wo | Wie lange (Standard) |
|---|---|---|---|
| **Flows** (NetFlow/IPFIX) | Beginn und Ende, Quell- und Ziel-IP, Ports, Protokoll, Bytes, Pakete, TCP-Flags, Interfaces, Richtung. **Keine Inhalte**, keine URLs, keine Domains | `storage.dir`, eine Datei pro Stunde | 48 h live (auf der Platte bis 49 h), danach Historie und Archiv |
| **Aggregate** | Bytes und Pakete je IP, Dienst und IP-Paar pro Minute bzw. Stunde | `index.db` | wie die Flows |
| **Historie** | verschobene Stundendateien und Aggregate | `history.dir` | bis `max_size_gb` (50 GB) erreicht ist |
| **Archiv** | gepackte Historie | `history.archive_dir` | 90 Tage nach dem jüngsten Flow |
| **PCAP-Analysen** | Ergebnis einer hochgeladenen Capture-Datei: IPs, **Domains** (DNS, TLS-SNI), **HTTP-Hosts und -URLs**, erkannte Anwendungen | `index.db` | 48 h, nicht archiviert. Die Capture-Datei selbst wird direkt nach der Analyse gelöscht |
| **Upload-Alarm** | Quelle, Ziel, Dienst, Menge und Zeitraum der Verbindung | Mail an `email.admins`, Log | je nach Mailpostfach bzw. Log-Rotation des Systems |
| **Anomalie-Baselines** | Mittelwert und Streuung der Merkmale je Netzgruppe und – bei `host_profiles` – **je Host-IP** und Stunde | `anomaly.db` | unbegrenzt, wird laufend überschrieben |
| **Trainingsvektoren** | Merkmale je Host-Fenster (Volumen, Anzahl Ziele, Ports, Länder, Uhrzeit), **ohne IP-Adresse** | `anomaly.db` | 14 Tage (`ml_training_days`) |
| **Auffälligkeiten** | Host-IP, Netzgruppe, Zeitraum, Befund mit Werten; bei DNS die Resolver, bei Portscans ein Auszug der Ziele | `anomaly.db`, Log, optional Mail | 30 Tage (`event_retention_days`) |

Land und ASN einer IP werden lokal aus den GeoLite2-Dateien nachgeschlagen, nicht gespeichert. Snia-Net-Mon schickt
keine Verbindungsdaten nach außen. Die einzige ausgehende Verbindung ist der optionale Download der GeoIP-Datenbanken bei
MaxMind, dabei werden nur Konto-ID und Lizenzschlüssel übertragen. Die Web-UI lädt keine externen Schriften, Skripte
oder Bilder.

**Gesamtdauer beachten:** Mit Historie und Archiv bleiben Flows bis zu drei Monate *nach* der Rotation erhalten. In
kleinen Netzen kann es lange dauern, bis die Historie 50 GB erreicht – bis dahin wird sie gar nicht rotiert. Die
tatsächliche Aufbewahrung kann so deutlich über 90 Tagen liegen.

### Empfehlungen für Schulen

- **So kurz wie möglich speichern** (Datenminimierung). Für Fehlersuche und Lastanalyse reicht meist das Live-Fenster:
  ```toml
  [storage]
  retention_hours = 24     # oder weniger

  [history]
  enabled = false          # keine Historie, kein Archiv – nach dem Live-Fenster wird gelöscht
  ```
  Wird eine Historie gebraucht, `max_size_gb` klein wählen und `archive_retention_days` auf die Frist setzen, die in der
  Schule festgelegt ist.
- **Netze ausnehmen**, die nicht überwacht werden sollen oder müssen, z. B. das Verwaltungs- oder Lehrkräftenetz oder
  ein Gäste-WLAN: `network.exclude_networks`. Diese Flows werden sofort verworfen und nirgends gespeichert.
- **Zugriff beschränken:** Die Web-UI zeigt alle gespeicherten Verbindungen. Nur die zuständigen Administratorinnen
  und Administratoren sollten sie erreichen: `listen` auf `127.0.0.1` lassen oder `api_token` setzen und HTTPS über einen
  Reverse-Proxy verwenden (siehe [Sicherheit](#sicherheit)).
- **Datenträger verschlüsseln** und `storage.secure_delete = true` lassen. Auf SSDs und Copy-on-Write-Dateisystemen
  (btrfs, ZFS) ist das Überschreiben nicht garantiert wirksam; dort schützt erst die Verschlüsselung gelöschte Daten
  zuverlässig.
- **PCAP-Analysen sparsam einsetzen.** Eine Capture-Datei enthält Paketinhalte; die gespeicherte Analyse enthält
  besuchte Domains und unverschlüsselte URLs. Nur für konkrete Fehlersuche verwenden.
- **Upload-Alarm prüfen:** Die Mails enthalten IP-Adressen und landen in Postfächern außerhalb von Snia-Net-Mon. Nur
  einschalten, wenn er gebraucht wird (`alerts.upload_threshold_mb = 0` schaltet ihn ab), und die Empfängerliste klein
  halten.
- **Anomalie-Erkennung bewusst einsetzen:** Host-Profile beschreiben das Verhalten einzelner Geräte. In Netzen von
  Lehrkräften oder Verwaltung ist das eine Form der Verhaltensauswertung, über die die Personalvertretung zu informieren
  ist. Solche Netze in `dynamic_networks` aufnehmen (nur Gruppenprofil) oder per `ignore` bzw.
  `network.exclude_networks` ganz ausnehmen. `host_profiles = false` schaltet Profile je Host komplett ab,
  `enabled = false` die ganze Erkennung.

### Organisatorisches

Vor dem Einsatz sollte die Schule in der Regel:

- den **Zweck** festlegen (z. B. Sicherstellung des Netzbetriebs, Fehlersuche, Erkennen von Schadsoftware) und die
  Verarbeitung ins **Verzeichnis der Verarbeitungstätigkeiten** aufnehmen,
- **Speicherfristen** und **zugriffsberechtigte Personen** schriftlich festhalten und die Konfiguration daran ausrichten,
- die Nutzerinnen und Nutzer **informieren**, etwa in der Nutzungsordnung bzw. IT-Benutzungsordnung der Schule,
- die **Personalvertretung** bzw. den Personalrat einbeziehen, wenn auch Geräte von Lehrkräften oder Verwaltung
  erfasst werden – eine Netzwerküberwachung kann zur Leistungs- und Verhaltenskontrolle geeignet sein,
- mit der bzw. dem **Datenschutzbeauftragten** klären, ob eine Datenschutz-Folgenabschätzung nötig ist.

Snia-Net-Mon ist für den Netzbetrieb gedacht, nicht zur Überwachung einzelner Personen.

## API

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/status` | Collector-Zähler (inkl. `excluded_flows`), DB-Statistik (inkl. `late_flows`), Live-Fenster, Historie, GeoIP-Status, `anomalies_24h` (Auffälligkeiten je Schwere) |
| GET | `/api/flows` | Flow-Suche (mit `src_geo`/`dst_geo`). Parameter: `source` (`live` Standard, `history`, `archive:<name>` – gilt für alle `/flows`- und `/stats`-Endpunkte), `from`, `to` (Unix-ms), `ip`, `src`, `dst` (IP/CIDR), `port`, `proto`, `dir` (`in`/`out`/`internal`/`external`), `limit` (≤ 5000) |
| GET | `/api/stats/talkers` · `/ports` · `/protocols` | Aggregationen, gleiche Filterparameter |
| GET | `/api/stats/directions` | Bytes, Pakete, Flows und ø Bandbreite je Richtung |
| GET | `/api/stats/timeseries` | Zeitreihe mit `bytes_in`/`bytes_out` je Stützstelle, zusätzlich `points` |
| GET | `/api/stats/connections` | Verbindungen (5-Tupel) summiert über das Zeitfenster, nach Bytes sortiert, `limit` ≤ 2000 |
| GET | `/api/stats/peers` | Paare Quelle → Ziel je Dienst (`proto`, `port`; Client-Ports zusammengefasst) mit Geo, nach Bytes sortiert, `limit` ≤ 5000 |
| GET | `/api/stats/geo` | Verkehr externer Gegenstellen nach Land (`countries`) und ASN (`asns`), `limit` ≤ 50 |
| GET | `/api/stats/sankey` | Knoten/Kanten Quelle → Dienst → Ziel, `limit` = Anzahl Verbindungen |
| WS | `/api/live` | beim Verbinden `{"type":"history"}`, danach jede Sekunde `{"type":"tick"}` mit Rate (gesamt, `bytes_in`, `bytes_out`), aktiven Verbindungen inkl. Richtung, Zählern und GeoIP |
| GET | `/api/anomalies` | Auffälligkeiten, neueste zuerst. Parameter: `from`, `to` (Unix-ms), `kind` (`stat`, `ml`, `scan`, `dns`, `country`, `policy`), `host`, `severity` (Mindestschwere `info`/`warn`/`high`), `limit` (≤ 5000) |
| GET | `/api/anomalies/status` | Lernphase, Anzahl Gruppen und Host-Profile, letztes Fenster, Isolation Forest (Training, Schwelle, Score-Quantile), Zähler der letzten 24 h |
| GET | `/api/archives` | Historie (Größe, Zeitraum, `compressing`) und Archive mit `state` (`packed`, `unpacking`, `ready`, `failed`) |
| POST | `/api/archives/{name}/open` | Archiv öffnen (`index.db` im Hintergrund entpacken), danach mit `source=archive:{name}` abfragbar; Stundendateien entpackt die jeweilige Abfrage |
| POST | `/api/pcap?name=datei.pcap` | Capture-Datei als Rohdaten im Body (`curl --data-binary @datei.pcap`), liefert das Analyse-Ergebnis mit `id` |
| GET | `/api/pcap` · `/api/pcap/{id}` | Verlauf der Analysen / gespeichertes Ergebnis |
| DELETE | `/api/pcap/{id}` | Analyse löschen |

## Entwicklung

```bash
cargo test --workspace              # Parser-Roundtrips (v9/IPFIX), Fuzz-artige Robustheit, Retention, Historie/Archiv, Stundendateien, Upload-Alarm, Anomalie-Erkennung (Baseline, Isolation Forest, Regeln), Filter, PCAP/pcapng-Leser, App-Regeln, GeoIP
cargo test -p db --release -- --ignored bench --nocapture --test-threads=1   # Lastproben: Statistiken mit/ohne Aggregate, Schreiben + Retention
cargo clippy --workspace --all-targets
cd frontend && npm run dev          # Vite auf :5173 mit Proxy auf das Backend (:8080), Hot Reload
```

## Grenzen & nächste Schritte

- **Skalierung:** Mit den Aggregaten bleiben die Statistiken auch bei ~1.000 Flows/s schnell. Grenze ist dann eher der
  Platz: 48 h Rohdaten bei 1.000 Flows/s sind ~30 GB, die Historie füllt 50 GB dann in gut drei Tagen.
- **Platz:** SQLite speichert zeilenweise, unkomprimiert. Wird der Platz knapp, wäre **DuckDB** mit **Parquet**-Dateien
  (spaltenweise, komprimiert, Archive ohne Entpacken abfragbar) der nächste Schritt. Der Aufbau mit einer Datei pro
  Stunde passt bereits dazu.
- **Abfragen über sehr viele Stunden** mit IP-, Port- oder Protokollfilter (z. B. eine IP über drei Monate Historie)
  öffnen jede Stundendatei einzeln und dauern entsprechend. In einem Archiv entpacken sie zudem alle Stunden und
  brauchen dann so viel freien Platz wie die ursprüngliche Historie.
- **NetFlow v5 / sFlow** werden nicht unterstützt, softflowd kann v9/IPFIX.
- **Zeitstempel:** Flows werden nach ihrem Ende (`ts`) einsortiert. Lange Flows erscheinen im Durchsatz-Chart daher als Spitze
  zum Exportzeitpunkt, wie bei NetFlow üblich.
- **PCAP-Analyse** erkennt Anwendungen nur über unverschlüsselte Merkmale (SNI, DNS, HTTP-Host). Mit ECH (Encrypted Client
  Hello) oder DNS-over-HTTPS sinkt die Trefferquote. Die Analyse hält pro Paket nur einen Zeitstempel im Speicher, sehr große
  Mitschnitte (Hunderte Millionen Pakete) brauchen entsprechend RAM.
- **GeoIP** wird beim Ausliefern nachgeschlagen, nicht gespeichert – ein Datenbank-Update wirkt daher auch auf ältere Flows.
- **Kein Benutzer-/Rollenkonzept**, nur ein gemeinsames API-Token.

## Lizenz

[MIT](LICENSE) – frei nutzbar, veränderbar und weitergebbar, solange der Copyright-Hinweis erhalten bleibt. Ohne Gewährleistung.

Enthaltene Fremdinhalte: Länderflaggen aus [Twemoji](https://github.com/twitter/twemoji) (© Twitter, Inc. und
Mitwirkende, [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)), als Schrift über
[country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill) (MIT). GeoIP-Daten von MaxMind
GeoLite2 werden nicht mitgeliefert (eigene Lizenz, siehe [GeoIP-Datenbanken](#geoip-datenbanken)).
