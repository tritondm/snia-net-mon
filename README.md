# Snia-Net-Mon

Netzwerkmonitor für eine **pfSense-Firewall**. Er sammelt Verbindungsdaten per **NetFlow v9 / IPFIX**, zeigt sie live im Browser – mit
**GeoIP (Land, ASN)** für jede externe Gegenstelle – und macht sie durchsuchbar. Dazu kommt eine **PCAP-Analyse** für
Mitschnitte (pcap/pcapng). Die Live-Datenbank hält die letzten **48 Stunden**. Ältere Flows wandern in eine
**Historie**, die ab 50 GB in ein **zstd-Archiv** rotiert wird. Archive bleiben **3 Monate** und lassen sich in der Web-UI
wieder ansehen. Große Uploads (> 1 GiB in einer Verbindung) melden sich **per Mail bei den Admins**.

- **Backend:** Rust (Tokio, Axum), SQLite im WAL-Modus
- **Frontend:** Svelte 5 + Tailwind, Catppuccin-Mocha-Theme im Hyprland-Look (Frosted Glass, Verlaufskanten, Monospace)
- **Status:** Prototyp – funktionsfähig und getestet, siehe [Grenzen & nächste Schritte](#grenzen--nächste-schritte)

![Dashboard mit Live-Durchsatz, aktiven Verbindungen samt GeoIP, Verkehrsrichtung, Protokollen und Top Talkern](docs/screenshot.png)

## Funktionen

| Bereich | Was es kann |
|---|---|
| **Dashboard** (`#dashboard`) | Live-Durchsatz getrennt nach **Download ↓ und Upload ↑** (gespiegelter Chart) per WebSocket, Verkehrsrichtung im Zeitfenster, Tabelle der aktiven Verbindungen mit Richtung (einfrierbar, filterbar). **Bereich im Durchsatz-Chart mit der Maus markieren** hält Chart und Tabelle an und zeigt die Verbindungen genau dieses Zeitraums (Klick oder Esc = zurück zu live), Top Talker, Top Ports, **Länder und Netze (ASN)** der Gegenstellen, Protokollverteilung, Sankey-Diagramm Quelle → Dienst → Ziel. Alle Statistiken lassen sich nach Richtung filtern |
| **Flow-Suche** (`#flows`) | Filter nach IP **oder CIDR** (Quelle/Ziel/beides), Port, Protokoll, Richtung, Zeitfenster; CSV-Export. Darunter die **Top Talker grafisch** mit ihren stärksten Gegenstellen (Dienst, gesendet/empfangen). Klick auf eine IP im Dashboard springt direkt hierher |
| **PCAP** (`#pcap`) | Capture-Datei (pcap/pcapng, z. B. aus *Diagnostics → Packet Capture*) per Drag & Drop hochladen: Kennzahlen, Zeitverlauf, Protokolle, **Anwendungen** (YouTube, Microsoft 365, CDN, AI … über TLS-SNI, DNS, HTTP-Host, IP-Präfixe), **Endpunkte mit Land und ASN**, Länder, Top Quellen/Ports/Flows, DNS, HTTP, TCP-Flags und heuristische **Auffälligkeiten** (Portscan, NXDOMAIN-Häufung, DNS/HTTP auf Nicht-Standard-Ports). Verlauf der Analysen; Klick auf eine IP sucht sie in den NetFlow-Daten |
| **Archiv** (`#archive`) | Füllstand der Historie, Liste der Archive mit Zeitraum, Größe und Löschdatum. **Historie oder ein Archiv durchsuchen**: öffnet die Flow-Suche mit dieser Datenquelle (Archive werden dafür im Hintergrund entpackt) |
| **GeoIP** | Land, Organisation und ASN für alle öffentlichen IPs – in der Live-Tabelle, Flow-Suche (auch CSV), Top Talker, Sankey und PCAP-Analyse |
| **Aufbewahrung** | live 48 h (höchstens 72 h) → Historie bis 50 GB → zstd-Archiv, gelöscht 90 Tage nach dem jüngsten Flow; siehe [Aufbewahrung](#aufbewahrung-live--historie--archiv). PCAP-Analysen folgen dem Live-Fenster, die hochgeladene Datei selbst wird direkt nach der Analyse gelöscht |
| **Ausgenommene Netze** | `network.exclude_networks`: Verkehr von oder zu diesen Netzen wird beim Empfang verworfen – nicht gespeichert, nicht angezeigt, nicht gezählt |
| **Upload-Alarm** | lädt eine Verbindung mehr als 1 GiB nach extern hoch, geht eine Mail an die Admins (Quelle, Ziel mit Land/ASN, Dienst, Menge, Dauer, Rate) |

Tastatur wie in Hyprland: **Alt+1 … Alt+4** wechselt den Workspace. Der Fokus folgt der Maus: Das Fenster unter dem Zeiger
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
| `storage.retention_hours` | `48` | Live-Fenster; Werte über 72 werden auf 72 begrenzt |
| `history.enabled` | `true` | Flows nach dem Live-Fenster in die Historie übernehmen (`false` = löschen) |
| `history.max_size_gb` | `50` | ab dieser Größe wird die Historie ins Archiv rotiert |
| `history.archive_dir` | `data/archive` | Ablage der Archive (`flows_<von>_<bis>.db.zst`, UTC) |
| `history.archive_retention_days` | `90` | Archive werden so lange nach ihrem jüngsten Flow aufbewahrt |
| `history.compression_level` | `19` | zstd-Stufe 1–22 |
| `alerts.upload_threshold_mb` | `1024` | Upload-Alarm ab dieser Menge je Verbindung, `0` = aus |
| `alerts.session_idle_secs` | `600` | ohne neue Flows so lange gilt eine Verbindung als beendet |
| `alerts.max_mails_per_hour` | `20` | Obergrenze gegen Mail-Fluten |
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
pfSense (softflowd) ──UDP 2055──▶ collector ──Batches──┬──▶ db: Writer-Thread ──▶ flows.db (live, 48 h)
                                  (n Worker,            │        Retention-Task ──▶ history.db ──50 GB──▶ archive/*.db.zst
                                   SO_REUSEPORT,        ├──▶ api::LiveHub ──1×/s──▶ WebSocket ──▶ Browser
                                   exclude_networks)    └──▶ alert: Upload je Verbindung > 1 GiB ──SMTP──▶ Admins
Browser ──REST──▶ api (Axum) ──▶ db (live, Historie oder entpacktes Archiv) ──▶ geo (Land/ASN je IP, beim Ausliefern)
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
│   │   ├── lib.rs             Writer-Thread, Lese-Pool, Retention-Task (verschieben oder löschen)
│   │   ├── history.rs         Historie, Rotation, zstd-Archive, Entpacken zum Ansehen
│   │   ├── schema.rs          Tabellen, Indizes, Pragmas, Migrationen
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
- **Schreiben:** Ein eigener Thread schreibt mit vorbereitetem Statement. Unter Last fasst er alle wartenden Batches zu einer
  Transaktion zusammen (bis 50.000 Zeilen).
- **Live:** Ein Snapshot pro Sekunde wird einmal serialisiert und an alle Clients geteilt. Die Top-150-Auswahl läuft in O(n).

Gemessen (Release-Build, ein Desktop-Rechner, 4 Exporter): **1.000.000 Flows in 10 s (100.000 Flows/s) ohne Verluste und
ohne Parse-Fehler**.

### Voraggregation (Statistiken bei viel Verkehr)

Der Writer schreibt in derselben Transaktion wie die Flows Summen **je Minute und je Stunde**: pro IP, pro Dienst
(Protokoll + Dienst-Port) und pro Paar Quelle → Ziel je Dienst, jeweils mit Richtung. Eine Statistik-Abfrage zerlegt ihr
Zeitfenster in volle Stunden, volle Minuten und die Ränder darunter. Nur die Ränder (unter einer Minute) kommen aus den
Einzel-Flows. Das Ergebnis ist **exakt dasselbe** wie über die Rohdaten (per Test gegen die Rohdaten geprüft).

- Aus den Aggregaten kommen: Top Talker, Länder/ASN, Top Ports, Protokolle, Richtungen, Zeitreihe, Sankey und die
  Gegenstellen der Flow-Suche – solange nur Zeitfenster und Richtung gefiltert werden.
- Mit IP-, Port- oder Protokollfilter sowie für Einzel-Flows und 5-Tupel-Verbindungen (markierter Bereich) wird wie bisher
  über die Rohdaten gesucht. Dafür gibt es Indizes, diese Abfragen betreffen nur einen kleinen Ausschnitt.
- Eine bestehende Datenbank bekommt die Aggregate beim ersten Start einmalig nachberechnet (Log: „Aggregat-Tabellen
  angelegt“). Bei einer großen Datei kann das einige Minuten dauern.
- Die Aggregate wandern mit den Flows in Historie und Archiv, Statistiken dort sind genauso schnell.

Lastprobe mit 1 h bei 1.000 Flows/s (3,6 Mio. Flows, 60 Geräte, 20.000 Gegenstellen), Zeitfenster 1 h, Release-Build:

| Abfrage | nur Rohdaten | mit Aggregaten |
|---|---|---|
| Top Talker / Länder | 8,4 s | 0,45 s |
| Top Ports | 1,8 s | 0,02 s |
| Protokolle / Richtungen | 0,7 s | 0,01 s |
| Sankey / Gegenstellen | 4,9 s | 1,7 s |

Schreiben: 135.000 Flows/s. Die Aggregate brauchen zusätzlich Platz. Wie viel, hängt davon ab, wie oft dieselben Paare
wiederkehren: bei diesen Testdaten mit sehr vielen einmaligen Gegenstellen rund die Hälfte der Rohdaten, im Heimnetz mit
immer denselben Diensten deutlich weniger. Nachmessen: `cargo test -p db --release -- --ignored bench --nocapture`
(Anzahl per `BENCH_FLOWS`).

### Aufbewahrung (live → Historie → Archiv)

```text
flows.db (live, 48 h) ──jede Minute──▶ history.db ──ab 50 GB──▶ archive/flows_<von>_<bis>.db.zst ──90 Tage──▶ gelöscht
```

- **Live:** höchstens 72 h (`model::MAX_RETENTION_HOURS`, fest einkompiliert), Standard 48 h. Dashboard und Live-Ansicht
  arbeiten nur hier.
- **Verschieben:** Der Retention-Task läuft beim Start und danach jede Minute. Er kopiert alle Flows vor der
  minutengenauen Grenze samt Minuten-Aggregaten in `history.db` (in Schritten zu 10 Minuten) und berechnet dort die
  Stunden-Aggregate neu. Erst danach löscht er sie in der Live-Datenbank (`secure_delete`, `wal_checkpoint(TRUNCATE)`,
  `incremental_vacuum`). Die erreichte Grenze steht in derselben Transaktion in `meta.moved_until` der Historie: Bricht
  der Prozess dazwischen ab, wird nichts doppelt kopiert. Scheitert das Kopieren (z. B. Platte voll), löscht der Task
  trotzdem alles über 72 h – die Live-Datenbank wächst nie unbegrenzt.
- **Rotation:** Erreicht die Historie `max_size_gb` (Datei + WAL), wird sie geschlossen, in `history.db.rotating`
  umbenannt und durch eine leere ersetzt. Ein eigener Thread komprimiert sie mit **zstd** (Stufe 19, Long-Distance-
  Matching, halbe Kernzahl als Threads) nach `archive_dir`. Flow-Datenbanken schrumpfen dabei typischerweise auf ein
  Sechstel (Testdaten: 13,6 MB → 2,1 MB). Bricht der Prozess ab, setzt der nächste Start die Komprimierung fort.
- **Archive:** Dateiname = Zeitraum (UTC) des ältesten und jüngsten Flows. Gelöscht wird `archive_retention_days` nach
  dem jüngsten Flow.
- **Ansehen:** Im Workspace **archiv** ein Archiv öffnen: Es wird nach `archive_dir/.view/` entpackt (braucht so viel
  Platz wie die ursprüngliche Historie, bei 50 GB also 50 GB und einige Minuten). Danach lässt es sich in der Flow-Suche
  wie die Live-Daten durchsuchen, inklusive Top Talker und CSV-Export. Es ist immer nur ein Archiv entpackt; nach 30 Minuten
  ohne Abfrage wird es wieder gelöscht.
- **Ohne Historie** (`history.enabled = false`) gilt das bisherige Verhalten: Flows werden nach dem Live-Fenster
  unwiderruflich gelöscht.
- PCAP-Analysen (sie enthalten IPs, Domains und URLs) werden nach dem Live-Fenster gelöscht und nicht archiviert.
  Hochgeladene Capture-Dateien liegen nur während der Analyse als temporäre Datei in `pcap.upload_dir` und werden danach
  sofort entfernt – auch bei Fehlern; Reste nach einem Absturz räumt der nächste Start weg.

**Datenschutz:** Verbindungsdaten sind personenbezogen. Mit Historie und Archiv werden sie bis zu drei Monate (plus die
Zeit bis zur Rotation) aufbewahrt – das sollte zur internen Richtlinie bzw. Betriebsvereinbarung passen. Kleine Netze
erreichen 50 GB eventuell nie; dann bleibt die Historie so lange liegen, bis sie voll ist. `max_size_gb` entsprechend
wählen.

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

## API

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/status` | Collector-Zähler (inkl. `excluded_flows`), DB-Statistik, Live-Fenster, Historie, GeoIP-Status |
| GET | `/api/flows` | Flow-Suche (mit `src_geo`/`dst_geo`). Parameter: `source` (`live` Standard, `history`, `archive:<name>` – gilt für alle `/flows`- und `/stats`-Endpunkte), `from`, `to` (Unix-ms), `ip`, `src`, `dst` (IP/CIDR), `port`, `proto`, `dir` (`in`/`out`/`internal`/`external`), `limit` (≤ 5000) |
| GET | `/api/stats/talkers` · `/ports` · `/protocols` | Aggregationen, gleiche Filterparameter |
| GET | `/api/stats/directions` | Bytes, Pakete, Flows und ø Bandbreite je Richtung |
| GET | `/api/stats/timeseries` | Zeitreihe mit `bytes_in`/`bytes_out` je Stützstelle, zusätzlich `points` |
| GET | `/api/stats/connections` | Verbindungen (5-Tupel) summiert über das Zeitfenster, nach Bytes sortiert, `limit` ≤ 2000 |
| GET | `/api/stats/peers` | Paare Quelle → Ziel je Dienst (`proto`, `port`; Client-Ports zusammengefasst) mit Geo, nach Bytes sortiert, `limit` ≤ 5000 |
| GET | `/api/stats/geo` | Verkehr externer Gegenstellen nach Land (`countries`) und ASN (`asns`), `limit` ≤ 50 |
| GET | `/api/stats/sankey` | Knoten/Kanten Quelle → Dienst → Ziel, `limit` = Anzahl Verbindungen |
| WS | `/api/live` | beim Verbinden `{"type":"history"}`, danach jede Sekunde `{"type":"tick"}` mit Rate (gesamt, `bytes_in`, `bytes_out`), aktiven Verbindungen inkl. Richtung, Zählern und GeoIP |
| GET | `/api/archives` | Historie (Größe, Zeitraum, `compressing`) und Archive mit `state` (`packed`, `unpacking`, `ready`, `failed`) |
| POST | `/api/archives/{name}/open` | Archiv im Hintergrund entpacken, danach mit `source=archive:{name}` abfragbar |
| POST | `/api/pcap?name=datei.pcap` | Capture-Datei als Rohdaten im Body (`curl --data-binary @datei.pcap`), liefert das Analyse-Ergebnis mit `id` |
| GET | `/api/pcap` · `/api/pcap/{id}` | Verlauf der Analysen / gespeichertes Ergebnis |
| DELETE | `/api/pcap/{id}` | Analyse löschen |

## Entwicklung

```bash
cargo test --workspace              # Parser-Roundtrips (v9/IPFIX), Fuzz-artige Robustheit, Retention, Historie/Archiv, Upload-Alarm, Filter, PCAP/pcapng-Leser, App-Regeln, GeoIP
cargo clippy --workspace --all-targets
cd frontend && npm run dev          # Vite auf :5173 mit Proxy auf das Backend (:8080), Hot Reload
```

## Grenzen & nächste Schritte

- **Skalierung:** Mit den Aggregaten bleiben die Statistiken auch bei ~1.000 Flows/s schnell. Grenze ist dann eher der
  Platz: 48 h Rohdaten bei 1.000 Flows/s sind ~33 GB, die Historie füllt 50 GB dann in gut drei Tagen. Für sehr hohe
  Raten wären DuckDB/ClickHouse der nächste Schritt; die Schnittstelle des `db`-Crates ist dafür ausgelegt.
- **Archive ansehen** braucht so viel freien Platz wie die entpackte Historie und dauert bei 50 GB einige Minuten.
  Kleinere `max_size_gb` ergeben kleinere, schneller geöffnete Archive.
- **Partitionierung:** Jeder Datensatz trägt seinen Stunden-Bucket, gelöscht wird über den Zeitindex. Echte Stunden-Tabellen
  mit `DROP TABLE` wären bei sehr großen Datenmengen schneller.
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
