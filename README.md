# Snia-Net-Mon

Netzwerkmonitor für eine **pfSense-Firewall**. Er sammelt Verbindungsdaten per **NetFlow v9 / IPFIX**, zeigt sie live im Browser, macht
sie durchsuchbar und startet auf Knopfdruck **Paketmitschnitte (tcpdump) direkt auf der pfSense**. Alle Daten werden nach
spätestens **72 Stunden automatisch und unwiderruflich gelöscht**.

- **Backend:** Rust (Tokio, Axum), SQLite im WAL-Modus, `ssh2` für die Mitschnitte
- **Frontend:** Svelte 5 + Tailwind, Catppuccin-Mocha-Theme im Hyprland-Look (Frosted Glass, Verlaufskanten, Monospace)
- **Status:** Prototyp – funktionsfähig und getestet, siehe [Grenzen & nächste Schritte](#grenzen--nächste-schritte)

## Funktionen

| Bereich | Was es kann |
|---|---|
| **Dashboard** (`#dashboard`) | Live-Durchsatz getrennt nach **Download ↓ und Upload ↑** (gespiegelter Chart) per WebSocket, Verkehrsrichtung im Zeitfenster, Tabelle der aktiven Verbindungen mit Richtung (einfrierbar, filterbar), Top Talker, Top Ports, Protokollverteilung, Sankey-Diagramm Quelle → Dienst → Ziel. Alle Statistiken lassen sich nach Richtung filtern |
| **Flow-Suche** (`#flows`) | Filter nach IP **oder CIDR** (Quelle/Ziel/beides), Port, Protokoll, Richtung, Zeitfenster; CSV-Export. Klick auf eine IP im Dashboard springt direkt hierher |
| **Tracing** (`#trace`) | tcpdump auf einem pfSense-Interface mit BPF-Filter starten/stoppen, Fortschritt live, PCAP-Download (für Wireshark), Paketvorschau mit Hex-Dump |
| **Retention** | harte Obergrenze 72 h für Flows **und** Mitschnitte; Abfragen liefern nie ältere Daten, auch bevor der Cleanup gelaufen ist |

Tastatur wie in Hyprland: **Alt+1 / Alt+2 / Alt+3** wechselt den Workspace. Der Fokus folgt der Maus: Das Fenster unter dem Zeiger
bekommt die aktive Verlaufskante.

## Schnellstart (Demo ohne pfSense)

Voraussetzungen: Rust ≥ 1.88, Node ≥ 20. Für `ssh2` wird OpenSSL benötigt (Arch: `openssl`, Debian: `libssl-dev pkg-config`).

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # Web-UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # zweites Terminal: erzeugt Demo-Verkehr
```

Ohne `config.toml` laufen Standardwerte: Collector auf UDP 2055, Web-UI nur lokal auf Port 8080, simulierte Mitschnitte
(`backend = "mock"`). `flowgen` schickt echte NetFlow-v9-Pakete an den Collector. Optionen: `--rate 5000`, `--format ipfix`,
`--exporters 4`, `--seconds 60`.

## Anbindung an die pfSense

### 1. NetFlow-Export (softflowd)

1. **System → Package Manager → Available Packages:** `softflowd` installieren.
2. **Services → softflowd:**
   - *Interface:* die zu überwachenden Interfaces (z. B. LAN, WAN)
   - *Host:* IP des Rechners mit Snia-Net-Mon, *Port:* `2055`
   - *NetFlow version:* `9` oder `IPFIX (10)`
   - *Flow tracking level:* `Full` (5-Tupel mit Ports)
   - *Flow Timeouts:* kurze Werte ergeben „livere“ Daten, z. B. `maxlife 60`
3. Speichern. Nach kurzer Zeit erscheinen die Flows im Dashboard. Solange der Exporter seine Templates noch nicht erneut
   gesendet hat, zählt der Collector die Daten als `missing_template` (Zähler unter `/api/status`).

### 2. Mitschnitte per SSH (optional)

1. **System → Advanced → Admin Access:** *Secure Shell* aktivieren, möglichst *Public Key Only*.
2. **System → User Manager:** beim Benutzer (z. B. `admin`) den öffentlichen Schlüssel eintragen.
3. Test vom Monitor-Rechner: `ssh admin@192.168.1.1 'tcpdump -D'` muss die Interfaces auflisten.
4. Fingerabdruck des Hostschlüssels ermitteln: `ssh-keyscan -t ed25519 192.168.1.1 2>/dev/null | ssh-keygen -lf -`
5. In `config.toml` `tracer.backend = "ssh"` setzen und `[tracer.ssh]` ausfüllen (siehe `config.example.toml`).

Ohne passenden `host_key_sha256` verweigert der Tracer die Verbindung und meldet den tatsächlichen Fingerabdruck. Das schützt vor
Man-in-the-Middle-Angriffen.

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
geänderte Liste wirkt daher nur auf neue Flows, alte sind nach spätestens 72 h ohnehin gelöscht.

## Konfiguration

Eine einzige Datei: `cp config.example.toml config.toml`. Alle Schlüssel sind dort kommentiert. Die wichtigsten:

| Schlüssel | Standard | Bedeutung |
|---|---|---|
| `server.listen` | `127.0.0.1:8080` | Web-UI/API. Für Zugriff aus dem Netz `0.0.0.0:8080` **und** `api_token` setzen |
| `server.api_token` | leer | Zugriffsschutz: Die Web-UI fragt einmal nach dem Token |
| `network.local_networks` | private Bereiche | interne Netze für Download/Upload-Erkennung (siehe oben) |
| `collector.listen` | `0.0.0.0:2055` | Empfang von NetFlow/IPFIX |
| `collector.workers` | `2` | parallele Empfangs-Sockets (`SO_REUSEPORT`) |
| `storage.retention_hours` | `72` | Aufbewahrung; Werte über 72 werden auf 72 begrenzt |
| `tracer.backend` | `mock` | `mock` (simuliert) oder `ssh` (echte pfSense) |

Aufruf mit anderer Datei: `snia-net-mon /etc/snia-net-mon.toml`. Logging über `RUST_LOG`, z. B. `RUST_LOG=debug`.

## Architektur

```text
pfSense (softflowd) ──UDP 2055──▶ collector ──Batches──┬──▶ db: Writer-Thread ──▶ SQLite (WAL)
                                  (n Worker,            │        Retention-Task ──▶ DELETE > 72 h, secure_delete
                                   SO_REUSEPORT)        └──▶ api::LiveHub ──1×/s──▶ WebSocket ──▶ Browser
Browser ──REST──▶ api (Axum) ──▶ db (Abfragen, Lese-Pool)
                            └──▶ tracer ──SSH──▶ tcpdump -w - auf der pfSense ──▶ data/traces/<id>.pcap
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
│   │   ├── lib.rs             Writer-Thread, Lese-Pool, Retention-Task
│   │   ├── schema.rs          Tabelle, Indizes, Pragmas
│   │   └── query.rs           Suche, Top Talker/Ports/Protokolle, Zeitreihe, Sankey
│   ├── tracer/
│   │   ├── lib.rs             Trace-Verwaltung, Validierung, Retention
│   │   ├── backend.rs         SSH (ssh2) und Mock
│   │   └── pcap.rs            PCAP-Leser (Vorschau) und -Schreiber
│   ├── api/
│   │   ├── lib.rs             Axum-Router, Endpunkte, Token-Prüfung, Auslieferung der SPA
│   │   └── live.rs            Tabelle aktiver Verbindungen, 1-s-Snapshots per Broadcast
│   ├── server/                Binary snia-net-mon: Konfiguration + Verdrahtung, geordnetes Herunterfahren
│   └── flowgen/               Binary flowgen: Demo-/Lastgenerator
└── frontend/
    ├── tailwind.config.js     Catppuccin-Mocha-Palette, Glow, Verlaufskante, Animationen
    └── src/
        ├── app.css            Komponenten-Klassen: .window, .window-active, .chip, .btn, .table-flows …
        ├── lib/               API-Client, WebSocket-Store (Runes), Formatierung, UI-Zustand
        └── components/        Dashboard, BandwidthChart, LiveTable, SankeyChart, FlowSearch, TracePanel …
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
ohne Parse-Fehler**. Aggregationen über diese Million Zeilen dauern 1–2 s.

### Retention (72 Stunden)

- `model::MAX_RETENTION_HOURS = 72` ist fest einkompiliert. Die Konfiguration kann den Wert nur verkleinern.
- Der Retention-Task läuft beim Start und danach jede Minute. Er löscht in Blöcken zu je 20.000 Zeilen
  (`DELETE … WHERE ts < now − 72 h`), damit der Writer nicht blockiert.
- **Unwiderruflich:** `PRAGMA secure_delete = ON` überschreibt gelöschte Inhalte in der Datei. Danach folgt
  `wal_checkpoint(TRUNCATE)`, damit nichts im WAL zurückbleibt, und `incremental_vacuum` gibt freie Seiten zurück.
- Jede Abfrage begrenzt das Zeitfenster zusätzlich auf die letzten 72 h. So erscheinen alte Daten auch zwischen zwei
  Cleanup-Läufen nie.
- Mitschnitte (`.pcap` + Metadaten) werden nach derselben Frist gelöscht, auch verwaiste Dateien nach einem Absturz.

### Sicherheit

- **Befehlsinjektion auf der Firewall ausgeschlossen:** Interface-Namen und BPF-Filter werden gegen eine Zeichen-Whitelist geprüft
  (keine Anführungszeichen, `$`, `;`, `` ` ``, `\`, Zeilenumbrüche). Der Filter steht in einfachen Anführungszeichen hinter `--`,
  Dauer und Paketanzahl sind begrenzt. Tests dazu stehen in `crates/tracer/src/lib.rs`.
- SSH-Hostschlüssel-Prüfung ist Pflicht (siehe oben).
- Die Web-UI lauscht standardmäßig nur auf `127.0.0.1`. Für Netzzugriff `api_token` setzen und einen Reverse-Proxy mit HTTPS
  davorstellen. WebSocket und PCAP-Download akzeptieren das Token als `?token=`.

## API

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/status` | Collector-Zähler, DB-Statistik, Retention, Tracer-Backend |
| GET | `/api/flows` | Flow-Suche. Parameter: `from`, `to` (Unix-ms), `ip`, `src`, `dst` (IP/CIDR), `port`, `proto`, `dir` (`in`/`out`/`internal`/`external`), `limit` (≤ 5000) |
| GET | `/api/stats/talkers` · `/ports` · `/protocols` | Aggregationen, gleiche Filterparameter |
| GET | `/api/stats/directions` | Bytes, Pakete, Flows und ø Bandbreite je Richtung |
| GET | `/api/stats/timeseries` | Zeitreihe mit `bytes_in`/`bytes_out` je Stützstelle, zusätzlich `points` |
| GET | `/api/stats/sankey` | Knoten/Kanten Quelle → Dienst → Ziel, `limit` = Anzahl Verbindungen |
| WS | `/api/live` | beim Verbinden `{"type":"history"}`, danach jede Sekunde `{"type":"tick"}` mit Rate (gesamt, `bytes_in`, `bytes_out`), aktiven Verbindungen inkl. Richtung und Zählern |
| GET/POST | `/api/traces` | Mitschnitte auflisten / starten (`{"interface","filter","duration_secs","max_packets"}`) |
| GET/DELETE | `/api/traces/{id}` | Status / löschen |
| POST | `/api/traces/{id}/stop` | Mitschnitt beenden |
| GET | `/api/traces/{id}/pcap` | PCAP-Datei (auch während der Aufnahme) |
| GET | `/api/traces/{id}/packets` | Paketvorschau als JSON, `offset`, `limit` |

## Entwicklung

```bash
cargo test --workspace              # Parser-Roundtrips (v9/IPFIX), Fuzz-artige Robustheit, Retention, Filter, PCAP, Injektionsschutz
cargo clippy --workspace --all-targets
cd frontend && npm run dev          # Vite auf :5173 mit Proxy auf das Backend (:8080), Hot Reload
```

## Grenzen & nächste Schritte

- **Skalierung:** SQLite reicht für mittlere Netze. Bei dauerhaft sehr hohen Raten sind vorberechnete Minuten-Aggregate
  sinnvoll (Dashboards dann ohne Scan der Rohdaten) oder der Wechsel auf TimescaleDB mit `drop_chunks` für die Retention.
  Die Schnittstelle des `db`-Crates ist dafür ausgelegt.
- **Partitionierung:** Jeder Datensatz trägt seinen Stunden-Bucket, gelöscht wird über den Zeitindex. Echte Stunden-Tabellen
  mit `DROP TABLE` wären bei sehr großen Datenmengen schneller.
- **NetFlow v5 / sFlow** werden nicht unterstützt, softflowd kann v9/IPFIX.
- **Mock-Tracer** wendet den BPF-Filter nicht an, er prüft ihn nur. **pcapng** wird in der Vorschau nicht gelesen (tcpdump
  schreibt klassisches PCAP).
- **Zeitstempel:** Flows werden nach ihrem Ende (`ts`) einsortiert. Lange Flows erscheinen im Durchsatz-Chart daher als Spitze
  zum Exportzeitpunkt, wie bei NetFlow üblich.
- **Kein Benutzer-/Rollenkonzept**, nur ein gemeinsames API-Token.

## Lizenz

[MIT](LICENSE) – frei nutzbar, veränderbar und weitergebbar, solange der Copyright-Hinweis erhalten bleibt. Ohne Gewährleistung.
