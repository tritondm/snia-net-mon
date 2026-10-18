# Snia-Net-Mon

[English](README.md) · **Deutsch**

Netzwerkmonitor für alles, was **NetFlow v9 oder IPFIX** exportiert: Firewalls (pfSense, OPNsense, Fortinet …), Router und
Switches (MikroTik, Cisco, Juniper …) oder eine Software-Probe auf einem Linux-Rechner (softflowd, ipt-netflow, pmacct).
Er sammelt die Verbindungsdaten, zeigt sie live im Browser – mit **GeoIP (Land, ASN)** für jede externe Gegenstelle – und
macht sie durchsuchbar. Dazu kommen eine **PCAP-Analyse** für Mitschnitte, ein **Upload-Alarm** per Mail und eine
**automatische Anomalie-Erkennung**.

Ursprünglich ist Snia-Net-Mon **für Schulen** entstanden: viele feste Netze für Verwaltung und Unterricht, ein Schülernetz
mit wechselnden Adressen, wenig Zeit für die Betreuung und personenbezogene Daten von oft minderjährigen Schülerinnen und
Schülern. Daher kommen das [Beispiel Schülernetz und Verwaltung](FEATURES_de.md#beispiel-schülernetz-und-verwaltung) und der
ausführliche Abschnitt zum [Datenschutz](#datenschutz). Genauso gut passt es in jedes andere Netz mit NetFlow- oder
IPFIX-Export.

- **Backend:** Rust (Tokio, Axum), SQLite im WAL-Modus, eine Datei pro Stunde
- **Frontend:** Svelte 5 + Tailwind, Catppuccin-Mocha-Theme im Hyprland-Look (Frosted Glass, Verlaufskanten, Monospace)
- **Status:** Prototyp – funktionsfähig und getestet, siehe [Grenzen & nächste Schritte](FEATURES_de.md#grenzen--nächste-schritte)

![Dashboard mit Live-Durchsatz, aktiven Verbindungen samt GeoIP, Verkehrsrichtung, Protokollen und Top Talkern; oben die fünf Workspaces](docs/screenshot.png)

## Was es kann

- **Live-Dashboard:** Durchsatz getrennt nach Download und Upload, aktive Verbindungen, Top Talker, Ports, Länder und
  Netze (ASN), Protokolle und ein Sankey-Diagramm Quelle → Dienst → Ziel. Ein Bereich im Chart lässt sich markieren und
  zeigt dann genau die Verbindungen dieses Zeitraums.
- **Flow-Suche** nach IP, CIDR, Port, Protokoll, Richtung und Zeitfenster, mit CSV-Export.
- **PCAP-Analyse:** Capture-Datei per Drag & Drop hochladen und sehen, welche Anwendungen (YouTube, Microsoft 365 …),
  Endpunkte, Länder, DNS-Namen und Auffälligkeiten darin stecken.
- **Aufbewahrung in drei Stufen:** 48 Stunden live, danach eine Historie bis 50 GB, die in ein zstd-Archiv rotiert wird.
  Archive bleiben 3 Monate und lassen sich in der Web-UI wieder durchsuchen.
- **Upload-Alarm:** Lädt eine einzelne Verbindung mehr als 1 GiB nach extern hoch, bekommen die Admins eine Mail.
- **Anomalie-Erkennung:** Jeder interne Host wird mit dem Normalverhalten seines Netzes verglichen und, bei festen
  Adressen, mit seinem eigenen. Dazu kommen ein Isolation Forest als zweite Meinung, Portscan-Erkennung, DNS an fremde
  Resolver, neue Länder, Beaconing (regelmäßige Verbindungen wie bei Schadsoftware) und Netz-Regeln zwischen Zonen
  („Schülernetz → Verwaltung melden“).
- **Datensparsam:** Keine Inhalte, keine Verbindungsdaten nach außen, Netze lassen sich komplett ausnehmen, gelöschte
  Daten werden überschrieben.

![Anomalie-Ansicht aus der Testumgebung: Status von Lernphase, Baseline und Isolation Forest, darunter Netz-Regel-Verstöße, ein Portscan samt statistischem Treffer, externes DNS und neue Länder](docs/anomalies.png)

## Dokumentation

| Datei | Inhalt |
|---|---|
| [INSTALL_de.md](INSTALL_de.md) | Voraussetzungen, Schnellstart mit Demo-Verkehr, GeoIP-Datenbanken, Flow-Export am Exporter einrichten, Konfiguration, Sicherheit, Entwicklung |
| [FEATURES_de.md](FEATURES_de.md) | Alle Funktionen im Detail: Verkehrsrichtung, Upload-Alarm, **Anomalie-Erkennung samt Mathematik**, Netz-Regeln, Architektur, Speicher und Aufbewahrung, Leistung, API, Grenzen |

Kurz ausprobieren, ganz ohne Firewall (Rust ≥ 1.88, Node ≥ 20):

```bash
cd frontend && npm install && npm run build && cd ..
cargo run --release --bin snia-net-mon          # Web-UI: http://127.0.0.1:8080
cargo run --release --bin flowgen               # zweites Terminal: erzeugt Demo-Verkehr
```

## Datenschutz

Snia-Net-Mon zeichnet auf, welches Gerät wann mit wem wie viel Daten ausgetauscht hat. Über die Leases des DHCP-Servers,
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
| **Beaconing** | Startzeiten ausgehender Verbindungen je Host, Ziel und Port | nur im Arbeitsspeicher | 12 h, weg nach einem Neustart |
| **Auffälligkeiten** | Host-IP, Netzgruppe, Zeitraum, Befund mit Werten; bei DNS die Resolver, bei Portscans ein Auszug der Ziele | `anomaly.db`, Log, optional Mail | 30 Tage (`event_retention_days`) |

Land und ASN einer IP werden lokal aus den GeoLite2-Dateien nachgeschlagen, nicht gespeichert. Snia-Net-Mon schickt
keine Verbindungsdaten nach außen. Die einzige ausgehende Verbindung ist der optionale Download der GeoIP-Datenbanken bei
MaxMind, dabei werden nur Konto-ID und Lizenzschlüssel übertragen. Die Web-UI lädt keine externen Schriften, Skripte
oder Bilder.

**Gesamtdauer beachten:** Mit Historie und Archiv bleiben Flows bis zu drei Monate *nach* der Rotation erhalten. In
kleinen Netzen kann es lange dauern, bis die Historie 50 GB erreicht – bis dahin wird sie gar nicht rotiert. Die
tatsächliche Aufbewahrung kann so deutlich über 90 Tagen liegen. Details unter
[Aufbewahrung](FEATURES_de.md#aufbewahrung-live--historie--archiv).

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
  Reverse-Proxy verwenden (siehe [Sicherheit](INSTALL_de.md#sicherheit)).
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

## Lizenz

[MIT](LICENSE) – frei nutzbar, veränderbar und weitergebbar, solange der Copyright-Hinweis erhalten bleibt. Ohne Gewährleistung.

Enthaltene Fremdinhalte: Länderflaggen aus [Twemoji](https://github.com/twitter/twemoji) (© Twitter, Inc. und
Mitwirkende, [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)), als Schrift über
[country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill) (MIT). GeoIP-Daten von MaxMind
GeoLite2 werden nicht mitgeliefert (eigene Lizenz, siehe [GeoIP-Datenbanken](INSTALL_de.md#geoip-datenbanken)).
