# Funktionen

[English](FEATURES.md) · **Deutsch**

Was Snia-Net-Mon im Einzelnen tut und wie. Der Schwerpunkt liegt auf der [Anomalie-Erkennung](#anomalie-erkennung),
einschließlich der Mathematik dahinter. Installation und Konfigurationsschlüssel stehen in [INSTALL_de.md](INSTALL_de.md), der
Überblick in der [README](README_de.md).

- [Übersicht](#übersicht)
- [Download / Upload (Verkehrsrichtung)](#download--upload-verkehrsrichtung)
- [Upload-Alarm](#upload-alarm)
- [Anomalie-Erkennung](#anomalie-erkennung)
  - [Ablauf](#ablauf)
  - [Merkmale je Host und Fenster](#merkmale-je-host-und-fenster)
  - [Statistik gegen die Baseline](#1-statistik-gegen-die-baseline)
  - [Isolation Forest](#2-isolation-forest)
  - [Feste Regeln: Portscan, externes DNS, neues Land](#3-feste-regeln-portscan-externes-dns-neues-land)
  - [Beaconing](#4-beaconing)
  - [Netz-Regeln](#netz-regeln)
  - [Lernphase, Zusammenfassen, Zeitleiste, Mails](#lernphase-zusammenfassen-zeitleiste-mails)
  - [Einstellen in der Praxis](#einstellen-in-der-praxis)
- [Architektur](#architektur)
- [Leistung bei hoher Paketrate](#leistung-bei-hoher-paketrate)
- [Voraggregation](#voraggregation-statistiken-bei-viel-verkehr)
- [Speicher: eine SQLite-Datei pro Stunde](#speicher-eine-sqlite-datei-pro-stunde)
- [Aufbewahrung](#aufbewahrung-live--historie--archiv)
- [API](#api)
- [Grenzen & nächste Schritte](#grenzen--nächste-schritte)

## Übersicht

| Bereich | Was es kann |
|---|---|
| **Dashboard** (`#dashboard`) | Live-Durchsatz getrennt nach **Download ↓ und Upload ↑** (gespiegelter Chart) per WebSocket, Verkehrsrichtung im Zeitfenster, Tabelle der aktiven Verbindungen mit Richtung (einfrierbar, filterbar). **Bereich im Durchsatz-Chart mit der Maus markieren** hält Chart und Tabelle an und zeigt die Verbindungen genau dieses Zeitraums (Klick oder Esc = zurück zu live), Top Talker, Top Ports, **Länder und Netze (ASN)** der Gegenstellen, Protokollverteilung, Sankey-Diagramm Quelle → Dienst → Ziel. Alle Statistiken lassen sich nach Richtung filtern |
| **Flow-Suche** (`#flows`) | Filter nach IP **oder CIDR** (Quelle/Ziel/beides), Port, Protokoll, Richtung, Zeitfenster; CSV-Export. Darunter die **Top Talker grafisch** mit ihren stärksten Gegenstellen (Dienst, gesendet/empfangen). Klick auf eine IP im Dashboard springt direkt hierher |
| **PCAP** (`#pcap`) | Capture-Datei (pcap/pcapng, z. B. von tcpdump, Wireshark oder der Paketaufzeichnung der Firewall) per Drag & Drop hochladen: Kennzahlen, Zeitverlauf, Protokolle, **Anwendungen** (YouTube, Microsoft 365, CDN, AI … über TLS-SNI, DNS, HTTP-Host, IP-Präfixe), **Endpunkte mit Land und ASN**, Länder, Top Quellen/Ports/Flows, DNS, HTTP, TCP-Flags und heuristische **Auffälligkeiten** (Portscan, NXDOMAIN-Häufung, DNS/HTTP auf Nicht-Standard-Ports). Verlauf der Analysen; Klick auf eine IP sucht sie in den NetFlow-Daten |
| **Archiv** (`#archive`) | Füllstand der Historie, Liste der Archive mit Zeitraum, Größe und Löschdatum. **Historie oder ein Archiv durchsuchen**: öffnet die Flow-Suche mit dieser Datenquelle (aus Archiven wird nur entpackt, was eine Abfrage braucht) |
| **Anomalien** (`#anomalies`) | Statistik gegen eine Baseline je Netzgruppe und Host, Isolation Forest als zweite Meinung, Portscan, DNS an externe Resolver, erstes Land einer Gruppe, Beaconing, Netz-Regeln zwischen Zonen. Status der Lernphase und des Modells, **Zeitleiste** (aktive Auffälligkeiten je Stunde bzw. Tag nach Schwere, Klick auf einen Balken filtert die Liste), Verlauf der Auffälligkeiten (30 Tage) mit Filter. Externe IPs stehen mit Land und Anbieter da, Klick auf den Host öffnet die Flow-Suche. Siehe [Anomalie-Erkennung](#anomalie-erkennung) |
| **GeoIP** | Land, Organisation und ASN für alle öffentlichen IPs – in der Live-Tabelle, Flow-Suche (auch CSV), Top Talker, Sankey, Anomalien und PCAP-Analyse |
| **Aufbewahrung** | live 48 h (höchstens 72 h) → Historie bis 50 GB → zstd-Archiv, gelöscht 90 Tage nach dem jüngsten Flow; siehe [Aufbewahrung](#aufbewahrung-live--historie--archiv). PCAP-Analysen folgen dem Live-Fenster, die hochgeladene Datei selbst wird direkt nach der Analyse gelöscht |
| **Ausgenommene Netze** | `network.exclude_networks`: Verkehr von oder zu diesen Netzen wird beim Empfang verworfen – nicht gespeichert, nicht angezeigt, nicht gezählt |
| **Upload-Alarm** | lädt eine Verbindung mehr als 1 GiB nach extern hoch, geht eine Mail an die Admins (Quelle, Ziel mit Land/ASN, Dienst, Menge, Dauer, Rate) |

Tastatur wie in Hyprland: **Alt+1 … Alt+5** wechselt den Workspace. Der Fokus folgt der Maus: Das Fenster unter dem Zeiger
bekommt die aktive Verlaufskante.

## Download / Upload (Verkehrsrichtung)

Jeder Flow bekommt beim Empfang eine Richtung. Grundlage ist die Liste der internen Netze (`network.local_networks`):

| Richtung | Bedeutung | Beispiel |
|---|---|---|
| `in` ↓ Download | extern → intern | Antwort eines Webservers, Portscan auf einen weitergeleiteten Server |
| `out` ↑ Upload | intern → extern | Anfrage eines Clients, Cloud-Backup |
| `internal` ⇄ | intern ↔ intern | SMB zwischen LAN und Server-VLAN |
| `external` | weder noch | sollte selten vorkommen; häufig ein Hinweis, dass ein eigenes Netz in der Liste fehlt |

Die meisten Exporter (z. B. softflowd) melden jede Verbindung als zwei Flows (Anfrage und Antwort). Deshalb erscheint ein
Download als großer `in`-Flow plus kleiner `out`-Flow. Der Dienst (Top Ports, Sankey, Spalte „Dienst“) ist jeweils der
kleinere der beiden Ports, also 443 und nicht der zufällige Client-Port.

Standardmäßig gelten die privaten Bereiche (RFC 1918, CGNAT, Link-Local, IPv6-ULA) als intern. Mit **öffentlichem IPv6** vom
Provider muss dessen Präfix in `local_networks` ergänzt werden, sonst läuft IPv6-Verkehr unter „extern“. Dasselbe gilt für die
öffentliche Adresse des Exporters (z. B. die WAN-Adresse der Firewall), wenn Verbindungen zu ihm selbst als Download zählen
sollen. Die Richtung wird beim Empfang gespeichert. Eine geänderte Liste wirkt daher nur auf neue Flows.

### Ausgenommene Netze

Netze in `network.exclude_networks` (CIDR oder einzelne IP) werden vom Collector direkt nach dem Parsen verworfen, sobald
**Quelle oder Ziel** darin liegt. Sie landen weder in der Datenbank noch in der Live-Ansicht und zählen nicht für den
Upload-Alarm. Typisch: ein Backup-Server, dessen nächtliche Uploads keinen Alarm auslösen sollen, oder ein Gäste-WLAN. Der
Zähler `collector.excluded_flows` unter `/api/status` zeigt, wie viel verworfen wurde. Bereits gespeicherte Flows bleiben
unverändert.

## Upload-Alarm

Exporter melden eine lange Verbindung mehrfach (je Active Timeout, bei softflowd `maxlife`). Der Alarm summiert deshalb die
ausgehenden Bytes (Richtung `out`) je **Verbindung** (Quelle, Ziel, Ports, Protokoll) über alle ihre Flows. Beim
Überschreiten von `upload_threshold_mb` geht **eine** Mail an `email.admins` mit Quelle, Ziel (Land, ASN), Dienst, Menge,
Beginn, Dauer und Rate. Die Verbindung wird danach nicht erneut gemeldet. Ohne neue Flows seit `session_idle_secs` gilt sie
als beendet. Ein Upload, der auf viele parallele Verbindungen verteilt ist (manche Cloud-Clients), löst den Alarm nur aus,
wenn eine einzelne Verbindung die Schwelle erreicht – solche Fälle findet eher die Statistik der Anomalie-Erkennung. Jeder
Alarm steht zusätzlich im Log (`WARN alert::upload`), auch ohne Mailversand oder wenn `max_mails_per_hour` erreicht ist.

## Anomalie-Erkennung

![Anomalie-Ansicht aus der Testumgebung: Status von Lernphase, Baseline und Isolation Forest, darunter Netz-Regel-Verstöße, ein Portscan samt statistischem Treffer, externes DNS und neue Länder](docs/anomalies.png)

*Testumgebung mit flowgen-Verkehr, 1-Minuten-Fenstern, ohne Lernphase und den Regeln aus dem
[Beispiel unten](#netz-regeln) (dazu SSH erlaubt). Die Auffälligkeiten wurden gezielt eingespielt. Ein
Schüler-PC scannt das Server-Netz: Das ergibt den Portscan, einen statistischen Treffer (79 statt typisch 3 interne Ziele)
und einen Verstoß gegen „schueler → server“. Die vielen „neues land“-Einträge entstehen nur, weil die Lernphase hier
abgeschaltet ist.*

Die Erkennung beantwortet für jeden internen Host alle zehn Minuten die Frage: *Verhält er sich anders als sonst – oder
anders als die Geräte in seinem Netz zu dieser Zeit?* Dafür gibt es mehrere Verfahren, die sich ergänzen:

| Verfahren | Was es meldet | Schwere |
|---|---|---|
| **Statistik** (Baseline) | Ein Merkmal liegt mindestens `z_threshold` Standardabweichungen über dem Typischen **und** erreicht den Mindestwert (z. B. 100 MB Upload pro Fenster). Text z. B. „upload 3.0 GiB statt typisch 38 MiB (80×)“ | warnung; hoch, wenn der Isolation Forest zustimmt oder die doppelte Schwelle erreicht ist |
| **Isolation Forest** (ML) | Gibt jedem Host-Fenster einen Score. Bei statistischen Treffern steht er als zweite Meinung dabei („ml 0.81 ✓ stimmt zu“). Allein meldet er ungewöhnliche *Kombinationen*, bei denen jeder Einzelwert normal ist, samt den stärksten Abweichungen | info |
| **Portscan** | mindestens `scan_threshold` fehlgeschlagene TCP-Verbindungsversuche (SYN ohne ACK) zu verschiedenen Ziel/Port-Paaren, auch im LAN | hoch |
| **Externes DNS** | DNS (53/853) an einen Resolver außerhalb, der nicht in `dns_servers` steht | warnung |
| **Neues Land** | erste Verbindung einer Netzgruppe in ein Land, das sie nie zuvor kontaktiert hat | info |
| **Beaconing** | ein Host meldet sich in fast gleichen Abständen beim selben externen Ziel, wie Schadsoftware bei ihrem Steuerserver | info, nie per Mail |
| **Netz-Regel** | Verbindung zwischen Zonen, die laut [Netz-Regeln](#netz-regeln) gemeldet werden soll, z. B. Schülernetz → Verwaltung | je Regel, Standard hoch |

### Ablauf

```text
Collector ──Flows──▶ Fenster (10 min, an der Uhr ausgerichtet: 10:00, 10:10 …)
                       │  je Flow: internen Host bestimmen, Zähler erhöhen,
                       │  Netz-Regeln prüfen, Verbindungsstart für Beaconing merken
                       ▼
               Fenster abgeschlossen (Prüfung alle 5 s)
                       │
   ┌───────────────────┼───────────────────────────┬──────────────────────┐
   ▼                   ▼                           ▼                      ▼
Statistik         Isolation Forest           feste Regeln             Beaconing
(Baseline)        (Score je Host)       (Scan, DNS, neues Land,   (12 h Verbindungs-
   │                   │                     Netz-Regeln)            historie je Paar)
   └──────── vergleichen, dann Baseline aktualisieren ───┴──────────────────────┘
                       │
                       ▼
          zusammenfassen (gleiche Art, gleicher Host, < 1 h) ──▶ anomaly.db ──▶ Web-UI, Log, optional Mail
```

Die Fenster beginnen bei Vielfachen der Fensterlänge (bei 10 Minuten also zur vollen Stunde, 10 nach usw.). Startet das
Programm mitten in einem Fenster (mehr als 10 % nach seinem Beginn), wäre es unvollständig und die Werte zu klein. Ein
solches Fenster läuft nur durch die festen Regeln und fließt nicht in Statistik, Baseline und Training ein. Die Auswertung
läuft in einem eigenen Thread und hält den Empfang nicht auf.

### Merkmale je Host und Fenster

Jeder Flow wird dem internen Host zugeordnet, der ihn **verursacht**: bei Upload (`out`) und internem Verkehr die Quelle,
bei Download (`in`) das Ziel. Verkehr ohne internen Beteiligten (`external`) und Hosts aus `anomaly.ignore` zählen nicht.
Je Host und Fenster entstehen sieben Rohwerte:

| Nr. | Merkmal | gezählt wird | Mindestwert für eine Meldung |
|---|---|---|---|
| 1 | **upload** | Bytes der `out`-Flows | 100 MiB (`min_upload_mb`) |
| 2 | **download** | Bytes der `in`-Flows | 1 GiB (`min_download_mb`) |
| 3 | **flows** | Flows, die der Host selbst sendet (`out` und `internal`) | 1000 (`min_flows`) |
| 4 | **externe ziele** | verschiedene externe Gegenstellen | 100 (`min_peers`) |
| 5 | **interne ziele** | verschiedene interne Gegenstellen | 50 (`min_internal_peers`) |
| 6 | **ports** | verschiedene Dienste (jeweils der kleinere Port eines Flows) | 30 (`min_ports`) |
| 7 | **länder** | verschiedene Länder der externen Ziele | 10 (`min_countries`) |

Dazu sammelt das Fenster die Rohdaten der festen Regeln (fehlgeschlagene TCP-Versuche, DNS an externe Resolver,
Verstöße gegen Netz-Regeln) und die Startzeiten ausgehender Verbindungen für das Beaconing. Mengen wie „verschiedene
Ziele“ sind je Host auf 50.000 begrenzt, damit ein Scan über ein ganzes Netz den Speicher nicht sprengt – mehr braucht
keine Schwelle.

Die **Mindestwerte** verhindern Meldungen, die statistisch stimmen, aber niemanden interessieren: Ein Drucker, der statt
1 MB plötzlich 20 MB hochlädt, ist 20-mal so aktiv wie sonst, aber kein Sicherheitsproblem.

### 1. Statistik gegen die Baseline

#### Log-Skala

Netzverkehr ist extrem schief verteilt: Die meisten Fenster eines Hosts haben ein paar hundert Kilobyte, einzelne
mehrere Gigabyte. Mittelwert und Standardabweichung der Rohwerte würden von den wenigen großen Werten bestimmt. Gerechnet
wird deshalb auf logarithmierten Werten:

```math
y = \ln(1 + x)
```

Das `+1` sorgt dafür, dass `x = 0` (z. B. kein Upload) den Wert `y = 0` ergibt statt minus unendlich. Auf der Log-Skala
werden aus **Faktoren Abstände**: Ein Host, der zehnmal so viel lädt wie sonst, liegt immer um `ln 10 ≈ 2,3` über seinem
Typischen – egal, ob es 10 MB statt 1 MB oder 10 GB statt 1 GB sind. Die Verteilung wird dabei annähernd symmetrisch, und
Mittelwert und Standardabweichung werden sinnvoll.

#### Gleitender Mittelwert und gleitende Varianz (EWMA)

Für jedes Merkmal und jeden Zeit-Slot (siehe unten) speichert die Baseline nur drei Zahlen: die Anzahl der Stichproben
`n`, den Mittelwert `μ` und die Varianz `σ²`. Jede neue Messung `y` wird so eingerechnet:

```math
\begin{aligned}
n &\leftarrow n + 1, \qquad \alpha = \max\left(\frac{1}{n},\ 0{,}002\right) \\
d &= y - \mu \\
\mu &\leftarrow \mu + \alpha \, d \\
\sigma^2 &\leftarrow (1 - \alpha)\left(\sigma^2 + \alpha \, d^2\right)
\end{aligned}
```

Das sind zwei Verfahren in einem:

- **Lernphase eines Slots** (`n ≤ 500`, also `α = 1/n`): Die Formeln ergeben **exakt** den arithmetischen Mittelwert und
  die Populationsvarianz aller bisherigen Messungen (eine Form des Welford-Algorithmus, numerisch stabil, ohne die
  Messungen selbst zu speichern). Für die Werte 2, 4, 4, 4, 5, 5, 7, 9 kommt `μ = 5`, `σ² = 4` heraus – das prüft ein Test.
- **Danach** (`α = 0,002`): ein **exponentiell gewichteter** gleitender Mittelwert (EWMA). Die Messung von vor `k`
  Schritten zählt mit dem Gewicht `α (1 − α)^k`. Das Gedächtnis umfasst damit rund `1/α = 500` Stichproben, nach
  `ln 2 / α ≈ 350` Stichproben ist eine Messung nur noch halb so wichtig. So passt sich die Baseline langsam an, wenn sich
  das Netz ändert (neue Software, mehr Geräte), vergisst aber nicht nach ein paar Stunden alles.

#### Mindest-Standardabweichung

Manche Slots sind sehr gleichförmig – ein Server, der jede Nacht um 3 Uhr fast genau gleich viel tut. Dort wäre `σ` nahezu
null und schon eine winzige Abweichung ein riesiger Z-Score. Deshalb gilt eine Untergrenze:

```math
\hat\sigma = \max\left(\sqrt{\sigma^2},\ 0{,}5\right)
```

#### Z-Score und Schwelle

Für die aktuelle Messung `y` eines Merkmals gegen das Vergleichsprofil:

```math
z = \frac{y - \mu}{\hat\sigma}
```

Gemeldet wird ein Merkmal, wenn **beide** Bedingungen gelten:

```math
z \ge z_{\text{thr}} \quad \text{und} \quad x \ge x_{\min}
```

Nur Ausschläge **nach oben** zählen. Dass ein Host weniger tut als sonst, ist für die Sicherheit uninteressant.

**Was bedeutet `z_threshold = 4` in Faktoren?** Mit dem typischen Wert `t = e^μ − 1` lässt sich die Bedingung umformen:

```math
z \ge z_{\text{thr}}
\iff \ln(1+x) - \ln(1+t) \ge z_{\text{thr}} \cdot \hat\sigma
\iff \frac{1+x}{1+t} \ge e^{\,z_{\text{thr}} \cdot \hat\sigma}
```

Bei der kleinsten Streuung `σ̂ = 0,5` heißt das: mindestens `e² ≈ 7,4`-mal so viel wie typisch. Streut ein Slot stärker
(`σ̂ = 1`), braucht es schon `e⁴ ≈ 55`-mal so viel. Die Schwelle passt sich also von selbst an: Wo es immer wild zugeht,
muss es wilder werden, bevor gemeldet wird.

Der angezeigte **typische Wert** `t = e^μ − 1` ist wegen der Log-Skala das geometrische Mittel (genauer: von `1 + x`, dann
minus 1). Er liegt näher am Median als das arithmetische Mittel und wird von einzelnen großen Fenstern kaum verzerrt. Der
angezeigte Faktor ist `(x + 1) / (t + 1)`.

**Rechenbeispiel:** Ein Server lädt typisch 38 MiB pro Fenster hoch, die Streuung seines Slots ist `σ̂ = 0,6`.

```math
\mu = \ln(1 + 38 \cdot 2^{20}) \approx 17{,}50
```

Jetzt lädt er 3 GiB hoch:

```math
y = \ln(1 + 3 \cdot 2^{30}) \approx 21{,}89,
\qquad z = \frac{21{,}89 - 17{,}50}{0{,}6} \approx 7{,}3
```

`z ≥ 4` und 3 GiB ≥ 100 MiB: Meldung „upload 3.0 GiB statt typisch 38 MiB (81×)“. Da `z < 2 · 4 = 8`, ist die Schwere
**warnung** – außer der Isolation Forest stimmt zu, dann **hoch**.

**Reihenfolge:** Erst wird verglichen, dann wird die Messung in die Baseline eingerechnet. Das aktuelle Fenster beeinflusst
seinen eigenen Vergleich also nicht. Treffen mehrere Merkmale, bestimmt das mit dem höchsten Z-Score den Text („· +2
weitere“), alle stehen in den Details.

#### Schutz vor Vergiftung

Ein Angreifer könnte versuchen, die Baseline langsam „hochzuziehen“, damit ein großer Abfluss später normal aussieht. Und
ein einzelner Ausreißer soll die Baseline nicht für Wochen verschieben. Deshalb wird ein Wert, sobald der Slot eingelernt
ist (`n ≥ 30`), vor dem Einrechnen gekappt:

```math
y' = \min\left(y,\ \mu + 3\hat\sigma\right)
```

Ein Fenster kann den Mittelwert so höchstens um `α · 3σ̂` verschieben, nach der Lernphase also um `0,006 σ̂`. Ein
3-GiB-Ausreißer zählt nicht mehr als ein Wert knapp über drei Standardabweichungen. Eine langsame, dauerhafte Steigerung
wird trotzdem gelernt – das ist gewollt, Netze wachsen. Wer über Wochen hinweg täglich ein bisschen mehr hochlädt, fällt
der Statistik nicht auf; dafür gibt es die Regeln, den Upload-Alarm und die Netz-Regeln.

#### Netzgruppe und Host: die Vergleichsprofile

Womit wird verglichen? Es gibt zwei Ebenen und drei Arten von Slots:

| Profil | Schlüssel | Slots | wofür |
|---|---|---|---|
| **Host** | Host-IP | 48: Werktag/Wochenende × Stunde | Geräte mit fester Adresse gegen ihr eigenes Verhalten |
| **Gruppe, Wochentag** | Netzgruppe | 168: Wochentag × Stunde | der *typische Host* der Gruppe zu genau dieser Zeit |
| **Gruppe, Stunde** | Netzgruppe | 24: nur Stunde | Rückfall, solange der Wochen-Slot noch zu wenige Daten hat |

Eine **Netzgruppe** ist das Subnetz des Hosts (Standard /24 bzw. /64) oder ein eigener Bereich aus `anomaly.groups` (der
engste passende gewinnt). Das Gruppenprofil beschreibt den typischen Host der Gruppe: Jede Messung jedes Hosts der Gruppe
ist eine Stichprobe davon. Das funktioniert auch mit DHCP, wo dieselbe IP morgen ein anderes Gerät ist.

Jede Messung fließt in **alle** passenden Profile ein: Wochen-Slot und Stunden-Slot der Gruppe und – außer in
`dynamic_networks` oder mit `host_profiles = false` – den Host-Slot. Verglichen wird mit dem ersten **eingelernten**
Profil (mindestens 30 Stichproben) in dieser Reihenfolge:

```text
Host-Slot (eigenes Verhalten)  →  Gruppe Wochentag × Stunde  →  Gruppe Stunde  →  noch kein Vergleich
```

**Wie schnell wird ein Slot eingelernt?** Bei 10-Minuten-Fenstern liefert jede Stunde 6 Messungen je aktivem Host:

- Host-Slot Werktag 10 Uhr: 5 Tage × 6 = 30 Messungen pro Woche → nach **gut einer Woche** eingelernt. Der Wochenend-Slot
  bekommt nur 12 pro Woche und braucht entsprechend knapp drei Wochen.
- Gruppen-Slot Montag 10 Uhr: 6 Messungen je Host und Woche. Mit 5 aktiven Hosts sind es 30 – eingelernt nach einer
  Woche. Ein Netz mit nur einem Gerät bräuchte fünf Wochen; bis dahin greift der Stunden-Slot (6 × 7 = 42 pro Woche).

Wochentag und Stunde richten sich nach `anomaly.timezone` (leer = Systemzeit), damit „Montag 8 Uhr“ wirklich der
Unterrichtsbeginn ist und nicht UTC.

Das Host-Profil hat Vorrang, weil es schärfer ist: Ein Drucker oder Server, der plötzlich ins Internet hochlädt, fällt
gegen sein eigenes Verhalten auf und nicht erst gegen den Durchschnitt des Netzes. Umgekehrt löst ein Backup-Server, der
immer viel hochlädt, keine Meldungen aus, nur weil seine Nachbarn wenig tun. Welches Profil diente, steht in den Details
(`host`, `gruppe wochentag+stunde`, `gruppe stunde`).

Beispiel für eine Schule mit einem Schülernetz per DHCP und sonst festen Adressen:

```toml
[anomaly]
dynamic_networks = ["10.20.0.0/22"]          # Schüler-WLAN
groups = ["10.0.10.0/28"]                    # Server-VLAN als eigene Gruppe (sonst /24)
ignore = ["10.0.10.5"]                       # Backup-Server, große Uploads sind normal
dns_servers = []                             # externe Resolver, die erlaubt sind
```

### 2. Isolation Forest

Die Statistik schaut jedes Merkmal einzeln an. Manches ist aber nur als **Kombination** ungewöhnlich: um 3 Uhr nachts
Verbindungen in sechs Länder über zwanzig verschiedene Ports, bei geringem Volumen. Jeder Einzelwert liegt unter seiner
Schwelle, das Gesamtbild passt trotzdem zu keinem normalen Fenster. Dafür gibt es als zweites Verfahren einen
**Isolation Forest** (Liu, Ting & Zhou, 2008), eine eigene Implementierung ohne externe ML-Bibliothek.

#### Merkmalsvektor

Jedes Host-Fenster wird zu einem Punkt in einem 11-dimensionalen Raum:

```math
\mathbf{v} = \Big(\, y_1, \dots, y_7,\ \ u,\ \ \sin\tfrac{2\pi h}{24},\ \cos\tfrac{2\pi h}{24},\ \ w \,\Big)
```

- `y₁ … y₇`: die sieben logarithmierten Merkmale
- `u = upload / (upload + download)`: Anteil des Uploads am Volumen (0 … 1). Ein Client lädt normalerweise viel mehr
  herunter als hoch; kippt das, ist es auffällig, auch wenn die Mengen klein sind.
- `h`: Uhrzeit (Ortszeit, mit Minuten als Bruchteil). Sie geht als **Punkt auf einem Kreis** ein: Mit `h` direkt wären
  23:50 und 00:10 maximal weit auseinander, auf dem Kreis liegen sie nebeneinander.
- `w`: 1 am Wochenende, sonst 0

Die IP-Adresse gehört **nicht** dazu. Je Fenster werden höchstens 100 zufällig gewählte Vektoren für das Training
aufgehoben, damit große Gruppen das Modell nicht dominieren und alle Tageszeiten vorkommen.

#### Die Idee: Ausreißer sind schnell isoliert

Man stelle sich vor, die Punktwolke wird immer wieder zufällig zerschnitten: ein zufälliges Merkmal, an einer zufälligen
Stelle zwischen seinem kleinsten und größten Wert. Ein Punkt mitten in der dichten Wolke braucht viele Schnitte, bis er
allein steht. Ein Punkt weit draußen ist oft schon nach zwei, drei Schnitten isoliert, weil ein zufälliger Schnitt mit
hoher Wahrscheinlichkeit in die Lücke zwischen ihm und dem Rest fällt. **Die Zahl der nötigen Schnitte ist das Maß für
„normal“.**

#### Training

Täglich (nach der Lernphase, mit mindestens 1000 Vektoren der letzten `ml_training_days` = 14 Tage):

1. **100 Bäume.** Für jeden Baum werden `ψ = 256` Vektoren zufällig gezogen (mit Zurücklegen).
2. Ein Baum teilt seine Stichprobe rekursiv: ein Merkmal `q`, gleichverteilt unter denen, die im aktuellen Knoten noch
   streuen, und ein Schnittpunkt `p` gleichverteilt zwischen dessen Minimum und Maximum im Knoten. Links landet alles
   mit `v_q < p`, rechts der Rest.
3. Abbruch, wenn ein Knoten nur noch einen Punkt hat, kein Merkmal mehr streut oder die Höhengrenze erreicht ist:

```math
\ell = \lceil \log_2 \psi \rceil = 8
```

Tiefer zu teilen lohnt nicht: Was nach acht Schnitten noch nicht allein steht, ist ohnehin normal.

#### Score

Für einen neuen Vektor `x` wird in jedem Baum die **Pfadlänge** bestimmt: die Zahl der Kanten von der Wurzel bis zum
Blatt, plus eine Korrektur, wenn das Blatt wegen der Höhengrenze noch `m > 1` Trainingspunkte enthält:

```math
h(x) = e + c(m)
```

`c(n)` ist die mittlere Pfadlänge einer erfolglosen Suche in einem binären Suchbaum mit `n` Elementen – also wie viele
Schnitte man im Mittel noch bräuchte, um `n` Punkte zu trennen:

```math
c(n) = 2\,H(n-1) - \frac{2(n-1)}{n}, \qquad H(i) \approx \ln i + \gamma, \quad \gamma \approx 0{,}5772
```

mit `c(2) = 1` und `c(1) = 0`. Der Score mittelt über alle Bäume und normiert mit `c(ψ)`:

```math
s(x) = 2^{-\,\frac{\mathrm{E}[h(x)]}{c(\psi)}}, \qquad c(256) \approx 10{,}24
```

| mittlere Pfadlänge E[h(x)] | Score s(x) | Bedeutung |
|---|---|---|
| ≈ 10,2 (= c(ψ)) | 0,50 | durchschnittlicher Punkt |
| 6,4 | 0,65 | Standardschwelle `ml_threshold` |
| 3,3 | 0,80 | deutlich auffällig |
| 1,6 | 0,90 | nach ein, zwei Schnitten isoliert |
| → 0 | → 1 | extrem auffällig |

#### Schwelle

Die wirksame Schwelle ist

```math
\theta = \max\left(\texttt{ml\_threshold},\ Q_{0{,}999}\right)
```

wobei `Q₀,₉₉₉` das 99,9-%-Quantil der Scores auf den eigenen Trainingsdaten ist. Damit liegen höchstens 0,1 % der
normalen Fenster darüber, selbst wenn das Netz insgesamt höhere Scores erzeugt. Zur Einordnung: 100 aktive Hosts ergeben
14.400 Host-Fenster am Tag, 0,1 % davon wären 14 Treffer. Deshalb ist ein ML-Treffer allein nur **info**, und
`ml_threshold` (0,65) wirkt als Untergrenze, falls das Quantil sehr niedrig liegt. Die Score-Verteilung (Median, 99 %, 99,9 %, Maximum) steht in der
Statuskarte der Web-UI und hilft beim Einstellen.

Die Trainingsdaten enthalten auch die Auffälligkeiten der letzten zwei Wochen. Das ist beim Isolation Forest unkritisch:
Er setzt nur voraus, dass Ausreißer selten sind, nicht dass sie fehlen.

#### Erklärung eines Treffers

Ein Score allein sagt nicht, *was* auffällig ist. Zu jedem Treffer werden deshalb die Merkmale gesucht, die am stärksten
vom Typischen der Trainingsdaten abweichen – mit **robusten** Kennzahlen, Median und MAD (Median der absoluten
Abweichungen vom Median), die von den Ausreißern selbst nicht verzerrt werden:

```math
r_d = \frac{\lvert v_d - \operatorname{med}_d \rvert}{\max\left(1{,}4826 \cdot \operatorname{MAD}_d,\ f_d\right)}
```

Der Faktor `1,4826 = 1 / Φ⁻¹(0,75)` macht die MAD bei normalverteilten Daten zu einem Schätzer der Standardabweichung, `r_d`
ist also ein „robuster Z-Score“. Die Untergrenze `f_d` ist 0,5 für die Log-Merkmale (wie bei der Baseline) und 0,1 für den
Upload-Anteil. Gezeigt werden die bis zu drei Merkmale mit `r_d > 2`; die Zeitmerkmale nicht, sie sind Kontext. Sind alle
gefundenen Abweichungen **nach unten** (der Host war nur ruhiger als sonst), wird nichts gemeldet. Findet sich kein
einzelnes Merkmal, lautet der Text „kombination aus uhrzeit und werten“.

#### Zusammenspiel mit der Statistik

| Statistik | Isolation Forest | Ergebnis |
|---|---|---|
| Treffer | Score ≥ θ | **hoch** – zwei unabhängige Verfahren sind sich einig („✓ stimmt zu“) |
| Treffer, z ≥ 2 · z_thr | beliebig | **hoch** |
| Treffer | Score < θ oder noch kein Modell | **warnung**, Score steht als Information dabei |
| kein Treffer | Score ≥ θ | **info** „ungewöhnliches gesamtmuster“ mit den stärksten Abweichungen |

### 3. Feste Regeln: Portscan, externes DNS, neues Land

Diese Regeln brauchen keine Lernphase (außer „neues Land“) und laufen auch in unvollständigen Fenstern.

**Portscan.** NetFlow-Exporter liefern je Flow die TCP-Flags als ODER über alle Pakete. Ist **SYN** (0x02) gesetzt, aber nie
**ACK** (0x10), kam der Verbindungsaufbau nie zustande: Das Ziel hat mit RST abgelehnt oder gar nicht geantwortet. Je Host
und Fenster wird die Menge der verschiedenen Paare (Ziel-IP, Zielport) solcher Versuche gezählt, über `out`- und
`internal`-Flows, also auch Scans im eigenen Netz:

```math
P = \{\, (\text{ziel}, \text{port}) \;:\; \text{SYN} \land \lnot\text{ACK} \,\}, \qquad \text{Meldung, wenn } |P| \ge \texttt{scan\_threshold}\ (100)
```

Ein Paar zählt einmal, egal wie oft es versucht wird. So zählen ein horizontaler Scan (ein Port, viele Hosts) und ein
vertikaler (ein Host, viele Ports) gleich. Ein Programm, das einen ausgefallenen Server immer wieder anfragt, löst nichts
aus. Die Meldung nennt Versuche, Hosts, Ports und einen Auszug der Ziele. Schwere **hoch**.

**Externes DNS.** TCP oder UDP an Port 53 (DNS) oder 853 (DNS over TLS), Richtung `out`, an einen Resolver, der nicht in
`dns_servers` steht. Geräte, die den Schul- oder Firmen-DNS umgehen, umgehen oft auch dessen Filter; manche Schadsoftware
nutzt eigene Resolver. DNS over HTTPS (Port 443) ist so nicht erkennbar. Schwere **warnung**.

**Neues Land.** Je Netzgruppe merkt sich `anomaly.db` die Menge `C_g` aller Länder, in die jemals hochgeladen wurde
(Länder aus `out`-Flows). Ein Land, das neu in `C_g` kommt, wird gemeldet, sobald die Lernphase vorbei ist; in der
Lernphase wird nur gesammelt. Diese Meldungen werden nicht zusammengefasst – jedes neue Land ist ein eigenes Ereignis.
Schwere **info**.

### 4. Beaconing

Schadsoftware meldet sich oft in festen Abständen bei ihrem Steuerserver (Command & Control, C2), um nach Befehlen zu
fragen – alle 60 Sekunden, alle 5 Minuten, manchmal mit etwas Zufall („Jitter“). Volumen und Ports sind dabei unauffällig,
verräterisch ist nur der **Rhythmus**. Die anderen Verfahren sehen das nicht, weil sie nur einzelne Fenster betrachten.

#### Datenbasis

Beobachtet werden Paare `(interner Host, externes Ziel, Zielport, Protokoll)`: nur TCP und UDP, nur Richtung `out` und nur
die Anfrage (Zielport kleiner als Quellport). Je Paar merkt sich ein Tracker im Arbeitsspeicher die **Startzeiten** der
Verbindungen der letzten **12 Stunden** (höchstens 512 je Paar, höchstens 300.000 Paare). Mehrere Flow-Datensätze mit
derselben Startzeit sind dieselbe Verbindung (Active Timeout) und zählen einmal.

Nicht beobachtet werden Ausnahmen aus der Konfiguration: Zielports aus `beacon_allow_ports` (Standard 123, NTP – Zeit-Sync
ist von Natur aus regelmäßig), Hosts oder Ziele aus `beacon_allow` und Ziele in Anbietern aus `beacon_allow_asn`.

#### Ist das Muster regelmäßig?

Nach jedem Fenster werden die Paare mit neuen Verbindungen geprüft. Aus den sortierten Startzeiten `t₁ < t₂ < … < tₙ`
entstehen die Abstände:

```math
g_i = t_{i+1} - t_i, \qquad i = 1, \dots, n-1
```

Daraus der typische Abstand und die typische Abweichung davon, beide als **Median**:

```math
I = \operatorname{median}(g_i), \qquad
J = \frac{\operatorname{median}\left(\lvert g_i - I \rvert\right)}{I}
```

`J` ist die MAD relativ zum Intervall, also „wie viel Prozent weicht ein Abstand typischerweise ab“. Ein Paar gilt als
Beacon, wenn alle Bedingungen erfüllt sind:

| Bedingung | Standard | warum |
|---|---|---|
| `n ≥ beacon_min_connections` | 20 | wenige Punkte sehen leicht zufällig regelmäßig aus |
| `tₙ − t₁ ≥ beacon_min_minutes` | 120 min | ein kurzes Muster ist eher eine einzelne Sitzung |
| `I ≥ 10 s` | fest | kürzere Abstände sind Verbindungsbündel, etwa ein Browser, der eine Seite lädt |
| `J ≤ beacon_max_jitter` | 0,2 | Abstände weichen typischerweise höchstens 20 % ab |

**Warum Median und MAD statt Mittelwert und Standardabweichung?** Fällt eine einzige Meldung aus (Gerät kurz offline, Paket
verloren), entsteht ein doppelt so langer Abstand. Bei 179 Abständen von 60 s und einem von 120 s bleibt der Median bei
60 s und die MAD praktisch unverändert. Mittelwert und Standardabweichung dagegen springen – ein einzelner Ausfall würde den
Beacon „unregelmäßig“ machen. Der Median hat einen Bruchpunkt von 50 %: Erst wenn die Hälfte der Werte gestört ist,
kippt er.

**Rechenbeispiel:** Ein Beacon alle 60 s, jeder Start zufällig bis ±5 s verschoben (gleichverteilt). Ein Abstand ist dann
`60 s + ε₂ − ε₁`; die Differenz zweier Gleichverteilungen auf [−5, 5] ist dreieckverteilt auf [−10, 10]. Deren Median
des Betrags `a` folgt aus

```math
P(\lvert D \rvert \le a) = 1 - \left(1 - \tfrac{a}{10}\right)^2 = \tfrac12
\quad\Rightarrow\quad a = 10\left(1 - \tfrac{1}{\sqrt2}\right) \approx 2{,}9\ \text{s}
```

also `J ≈ 2,9 / 60 ≈ 5 %` – deutlich unter 20 %, wird gemeldet. Selbst ±20 s Zufall (`J ≈ 20 %`) läge noch an der Grenze.

#### Ausgerollte Software: die Flotten-Prüfung

Regelmäßige Verbindungen sind meistens harmlos: Virenschutz, Push-Dienste, Office, Messenger. Der Unterschied zu
Schadsoftware: Solche Software läuft auf **vielen** Geräten und spricht mit demselben **Anbieter**. Weil Cloud-Dienste
dabei ständig die IP wechseln, zählt nicht die Ziel-IP, sondern das autonome System (ASN) des Ziels, ersatzweise sein
/24- bzw. /48-Netz:

```math
F(\text{anbieter}, \text{port}, \text{proto}) = \left|\{\, \text{interne Hosts mit regelmäßigem Muster dorthin} \,\}\right|
```

Gemeldet wird nur, wenn `F < beacon_max_hosts` (Standard 3). Für `F` zählen auch Paare, die im aktuellen Fenster keine
neuen Verbindungen hatten. Ein einzelner Rechner mit eigenem Muster bleibt so sichtbar, die Virenschutz-Flotte nicht.

Die Meldung nennt Ziel samt Land und Anbieter, Anzahl der Verbindungen, Intervall, Streuung, typische Größe und Dauer:

```text
● info   beaconing   10.0.1.20   beaconing zu 198.51.100.7:443 (NL, Example Hosting): 132 verbindungen, alle 5.0 min ± 3 %, je ~1.2 KiB, seit 11 h
```

Beaconing ist immer nur **info** und geht **nie per Mail** raus: ein Hinweis zum Nachsehen, kein Alarm. Solange das Muster
anhält, wird dieselbe Zeile verlängert. Häufige harmlose Treffer gehören als Ausnahme in die Konfiguration, z. B.
`beacon_allow_asn = [8075]` für Microsoft.

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
  des Fensters (Standard 10 min). Sie wirken ab dem ersten Start, ohne Lernphase.

#### Beispiel: Schülernetz und Verwaltung

Eine Schule hat drei Netze, die interessieren (die Adressen sind Beispiele, die eigenen stehen in der Firewall bzw. im
Router bei den Interfaces):

| Netz | Adressen | Vergabe |
|---|---|---|
| Schülernetz (WLAN und Schul-PCs) | `172.20.8.0/22` | DHCP, Adressen wechseln |
| Verwaltung, Sekretariat | `172.20.1.0/24` | feste Adressen |
| Verwaltung, Direktion | `172.20.2.0/24` | feste Adressen |

Ziel: Das Schülernetz bekommt nur ein Gruppenprofil (eine IP ist morgen ein anderes Gerät), und jede Verbindung aus dem
Schülernetz in die Verwaltung wird gemeldet. Dazu in `config.toml`:

```toml
[anomaly]
# Schülernetz per DHCP: nur Gruppenprofil, kein Profil je IP
dynamic_networks = ["172.20.8.0/22"]

# … weitere Einstellungen von [anomaly] hier, VOR den Zonen und Regeln …

[[anomaly.zones]]
name = "schueler"
networks = ["172.20.8.0/22"]

[[anomaly.zones]]
name = "verwaltung"
networks = ["172.20.1.0/24", "172.20.2.0/24"]   # eine Zone darf mehrere Netze haben

# Schülernetz → Verwaltung: immer melden (Schwere hoch)
[[anomaly.rules]]
from = "schueler"
to = "verwaltung"
```

**Wohin in der Datei:** Gibt es schon einen Abschnitt `[anomaly]`, kommt `dynamic_networks` dort hinein, ohne zweite
`[anomaly]`-Zeile. Die Blöcke `[[anomaly.zones]]` und `[[anomaly.rules]]` kommen ans **Ende der Datei**: In TOML gehört
alles nach einem solchen Block zu diesem Block, eine Einstellung dahinter landet sonst in der letzten Regel. Der Start
bricht dann mit einer Fehlermeldung ab.

**Was passiert:** Nach dem Neustart zeigt die Statuskarte unter *anomalien* „netz-regeln: 1 regeln, 2 zonen“. Versucht
ein Schüler-PC etwa, eine Freigabe im Sekretariat zu öffnen, erscheint am Ende des Fensters eine Zeile wie

```text
● hoch   netz-regel   172.20.9.41   netz-regel schueler → verwaltung: 3 verbindungen zu 172.20.1.10, ports 139, 445
```

Klick auf die IP öffnet die Flow-Suche mit allen Verbindungen dieses Geräts. Die Antworten der Verwaltung an den
Schüler-PC lösen keine Meldung aus, gezählt wird nur die Anfrage.

**Typische Erweiterungen:**

- *Ein Dienst in der Verwaltung ist für Schüler erlaubt*, z. B. ein Drucker (IPP, Port 631). Die `allow`-Regel muss
  **vor** der Meldung stehen, weil die erste passende Regel entscheidet:

  ```toml
  [[anomaly.rules]]
  from = "schueler"
  to = "verwaltung"
  ports = [631]
  action = "allow"

  [[anomaly.rules]]
  from = "schueler"
  to = "verwaltung"
  ```

- *Die Gegenrichtung als Warnung sehen.* Bewusst nicht im Grundbeispiel: Admins und Software zur Klassenraumsteuerung
  greifen oft auf Schüler-Geräte zu, das würde ständig anschlagen.

  ```toml
  [[anomaly.rules]]
  from = "verwaltung"
  to = "schueler"
  severity = "warn"
  ```

- *Keine Profile je Gerät in der Verwaltung* (siehe [Datenschutz](README_de.md#empfehlungen-für-schulen)): die
  Verwaltungsnetze zusätzlich in `dynamic_networks` aufnehmen. Die Netz-Regel funktioniert weiter, nur die Statistik
  vergleicht dort mit dem Gruppenprofil statt mit jedem einzelnen Gerät.

  ```toml
  dynamic_networks = ["172.20.8.0/22", "172.20.1.0/24", "172.20.2.0/24"]
  ```

### Lernphase, Zusammenfassen, Zeitleiste, Mails

**Lernphase:** In den ersten `learning_days` (Standard 7) nach dem ersten Start wird nur gelernt: Baselines füllen sich,
Länder werden gesammelt, Trainingsvektoren gespeichert. Statistik, Isolation Forest und „neues Land“ melden in dieser Zeit
nichts. Portscan, externes DNS, Beaconing und Netz-Regeln melden sofort. Der Isolation Forest trainiert nach der Lernphase
und danach täglich; reichen die Daten noch nicht (unter 1000 Vektoren), versucht er es stündlich erneut. Der Beginn der
Lernphase steht in `anomaly.db` und überlebt Neustarts.

**Zusammenfassen:** Tritt dieselbe Art beim selben Host (bei Netz-Regeln: dieselbe Regel, bei Beaconing: dasselbe Ziel)
innerhalb einer Stunde erneut auf, wird die bestehende Zeile verlängert („3×“) statt eine neue anzulegen. Die stärkste
Messung bestimmt den Text. Ein Host, der zwei Stunden lang ununterbrochen auffällt, ergibt so eine Zeile mit „12×“ statt
zwölf Zeilen und nur eine Mail.

**Zeitleiste:** Über der Liste zeigt ein Balkendiagramm, wie viele Auffälligkeiten je Abschnitt aktiv waren (24 h: je
Stunde, 7 Tage: je 6 Stunden, 30 Tage: je Tag), gestapelt nach Schwere. Eine zusammengefasste Zeile zählt in jedem
Abschnitt, den sie überdeckt. Ein Klick auf einen Balken zeigt in der Liste nur diesen Abschnitt, ein zweiter Klick hebt
die Auswahl auf. Die Filter für Art, Schwere und Host gelten auch für die Zeitleiste.

**Mails** sind zunächst aus. Mit `mail = true` gehen **neue** Auffälligkeiten ab `mail_min_severity` (Standard `high`) an die
Admins aus `[email]`, begrenzt durch `alerts.max_mails_per_hour`. Verlängerte Zeilen lösen keine weitere Mail aus,
Beaconing nie. Erst einschalten, wenn die Schwellen zum eigenen Netz passen. Jede Auffälligkeit steht zusätzlich im Log.

### Einstellen in der Praxis

Nach der Lernphase lohnt ein Blick auf die Liste der ersten Tage. Typische Fälle:

| Beobachtung | Abhilfe |
|---|---|
| Ein Server (Backup, Update-Cache) erscheint ständig bei „statistik“ | eigene Gruppe in `groups`, damit er nicht gegen Clients verglichen wird; ist sein Verhalten immer so, hilft nach einer Woche sein Host-Profil. Sonst `ignore` |
| Viele Statistik-Treffer mit kleinen Mengen | Mindestwerte (`min_upload_mb`, `min_flows` …) erhöhen |
| Viele Statistik-Treffer mit großen Faktoren, aber harmlos | `z_threshold` erhöhen (5 ≈ Faktor 12, 6 ≈ Faktor 20 bei σ̂ = 0,5) |
| Viele „ungewöhnliches gesamtmuster“ | `ml_threshold` über das 99,9-%-Quantil aus der Statuskarte setzen oder `ml = false` |
| Beaconing zu bekannter Software | Anbieter in `beacon_allow_asn`, Ziel in `beacon_allow` oder `beacon_max_hosts` senken |
| Externes DNS von einem erlaubten Resolver | Resolver in `dns_servers` |
| Netz-Regel schlägt bei einem erlaubten Dienst an | `allow`-Regel mit `ports` **vor** die meldende Regel |

## Architektur

```text
Exporter (Firewall, ──UDP 2055──▶ collector ──Batches──┬──▶ db: Writer-Thread ──▶ live/ (index.db + Datei je Stunde, 48 h)
Router, softflowd …)              (n Worker,            │        Retention-Task ──▶ history/ ──50 GB──▶ archive/flows_<von>_<bis>/
                                   SO_REUSEPORT,        ├──▶ api::LiveHub ──1×/s──▶ WebSocket ──▶ Browser
                                   exclude_networks)    ├──▶ alert: Upload je Verbindung > 1 GiB ──SMTP──▶ Admins
                                                        └──▶ anomaly: Fenster je Host ──▶ Baseline, Regeln, Isolation Forest, Beaconing ──▶ anomaly.db
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
│   │   ├── features.rs        Merkmale je internem Host und Fenster, Rohdaten der Regeln und des Beaconing
│   │   ├── baseline.rs        EWMA-Baseline je Netzgruppe (Wochen-/Tages-Slots) und je Host
│   │   ├── forest.rs          Isolation Forest (eigene Implementierung), Score-Quantile, Median/MAD für Erklärungen
│   │   ├── beacon.rs          Beaconing: Verbindungshistorie je Paar, Median/MAD der Abstände, Flotten-Prüfung je ASN
│   │   ├── policy.rs          Netz-Regeln: Zonen, geordnete Regeln, Anfrage-Erkennung
│   │   ├── engine.rs          Auswertung eines Fensters, Regeln, Zusammenfassen, tägliches Training
│   │   ├── store.rs           anomaly.db: Baselines, Länder, Trainingsvektoren (ohne IP), Auffälligkeiten, Zeitleiste
│   │   └── lib.rs             Konfiguration, Task am Flow-Strom, optionale Mails
│   ├── server/                Binary snia-net-mon: Konfiguration + Verdrahtung, --test-mail, geordnetes Herunterfahren
│   └── flowgen/               Binary flowgen: Demo-/Lastgenerator
└── frontend/
    ├── tailwind.config.js     Catppuccin-Mocha-Palette, Glow, Verlaufskante, Animationen
    └── src/
        ├── app.css            Komponenten-Klassen: .window, .window-active, .chip, .btn, .table-flows …
        ├── lib/               API-Client, WebSocket-Store (Runes), Formatierung, UI-Zustand
        └── components/        Dashboard, BandwidthChart, LiveTable, SankeyChart, FlowSearch, TalkerConnections, PcapAnalyzer, ArchiveBrowser, Anomalies, GeoTag …
```

## Leistung bei hoher Paketrate

- **Empfang:** Jeder Worker hat einen eigenen Socket (`SO_REUSEPORT`) und einen eigenen Template-Cache, dadurch gibt es kein
  Locking. Der Kernel verteilt nach Quell-Tupel, ein Exporter landet also immer beim selben Worker. Der Empfangspuffer ist
  standardmäßig 16 MiB groß, dafür `net.core.rmem_max` erhöhen.
- **Parsen:** Templates werden beim Empfang einmal in einen Dekodierplan übersetzt. Datensätze werden ohne Allokationen pro
  Feld dekodiert.
- **Backpressure:** Flows gehen gebündelt per `try_send` an Datenbank und Live-Ansicht. Ist ein Abnehmer voll, werden Flows
  gezählt verworfen (`dropped_flows`), der UDP-Empfang blockiert nie.
- **Schreiben:** Ein eigener Thread schreibt mit vorbereitetem Statement in die Datei der jeweiligen Stunde. Unter Last
  fasst er alle wartenden Batches zu einer Transaktion zusammen (bis 50.000 Zeilen). Ist die Datenbank länger als das
  Busy-Timeout gesperrt, versucht er es erneut, statt die Flows zu verwerfen.
- **Live:** Ein Snapshot pro Sekunde wird einmal serialisiert und an alle Clients geteilt. Die Top-150-Auswahl läuft in O(n).

Gemessen (Release-Build, ein Desktop-Rechner, 4 Exporter): **1.000.000 Flows in 10 s (100.000 Flows/s) ohne Verluste und
ohne Parse-Fehler**.

## Voraggregation (Statistiken bei viel Verkehr)

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

## Speicher: eine SQLite-Datei pro Stunde

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

## Aufbewahrung (live → Historie → Archiv)

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
[Datenschutz](README_de.md#datenschutz).

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
| GET | `/api/anomalies` | Auffälligkeiten, neueste zuerst, mit Land und Anbieter der externen IPs. Parameter: `from`, `to` (Unix-ms), `kind` (`stat`, `ml`, `scan`, `dns`, `country`, `policy`, `beacon`), `host`, `severity` (Mindestschwere `info`/`warn`/`high`), `limit` (≤ 5000) |
| GET | `/api/anomalies/timeline` | Zeitleiste: je Abschnitt die darin aktiven Auffälligkeiten nach Schwere (`[{ts, info, warn, high}]`). Parameter: `from`, `to`, `bucket` (Länge eines Abschnitts in ms, Standard 1 h, höchstens 500 Abschnitte) sowie dieselben Filter wie `/api/anomalies` |
| GET | `/api/anomalies/status` | Lernphase, Anzahl Gruppen und Host-Profile, letztes Fenster, Isolation Forest (Training, Schwelle, Score-Quantile), Beaconing (beobachtete Paare), Zähler der letzten 24 h |
| GET | `/api/archives` | Historie (Größe, Zeitraum, `compressing`) und Archive mit `state` (`packed`, `unpacking`, `ready`, `failed`) |
| POST | `/api/archives/{name}/open` | Archiv öffnen (`index.db` im Hintergrund entpacken), danach mit `source=archive:{name}` abfragbar; Stundendateien entpackt die jeweilige Abfrage |
| POST | `/api/pcap?name=datei.pcap` | Capture-Datei als Rohdaten im Body (`curl --data-binary @datei.pcap`), liefert das Analyse-Ergebnis mit `id` |
| GET | `/api/pcap` · `/api/pcap/{id}` | Verlauf der Analysen / gespeichertes Ergebnis |
| DELETE | `/api/pcap/{id}` | Analyse löschen |

## Grenzen & nächste Schritte

- **Skalierung:** Mit den Aggregaten bleiben die Statistiken auch bei ~1.000 Flows/s schnell. Grenze ist dann eher der
  Platz: 48 h Rohdaten bei 1.000 Flows/s sind ~30 GB, die Historie füllt 50 GB dann in gut drei Tagen.
- **Platz:** SQLite speichert zeilenweise, unkomprimiert. Wird der Platz knapp, wäre **DuckDB** mit **Parquet**-Dateien
  (spaltenweise, komprimiert, Archive ohne Entpacken abfragbar) der nächste Schritt. Der Aufbau mit einer Datei pro
  Stunde passt bereits dazu.
- **Abfragen über sehr viele Stunden** mit IP-, Port- oder Protokollfilter (z. B. eine IP über drei Monate Historie)
  öffnen jede Stundendatei einzeln und dauern entsprechend. In einem Archiv entpacken sie zudem alle Stunden und
  brauchen dann so viel freien Platz wie die ursprüngliche Historie.
- **NetFlow v5, sFlow und IPFIX-Biflows** (beide Richtungen in einem Datensatz, RFC 5103) werden nicht unterstützt.
  **Gesampelte** Exporte werden nicht hochgerechnet: Mengen erscheinen um den Sampling-Faktor zu klein, und die
  Anomalie-Erkennung sieht nur einen Teil der Verbindungen.
- **Zeitstempel:** Flows werden nach ihrem Ende (`ts`) einsortiert. Lange Flows erscheinen im Durchsatz-Chart daher als Spitze
  zum Exportzeitpunkt, wie bei NetFlow üblich.
- **Anomalie-Erkennung:** Sie sieht nur Metadaten, keine Inhalte. Langsame, über Wochen wachsende Abflüsse lernt die
  Baseline mit; Beaconing mit stark zufälligen Abständen (mehr als `beacon_max_jitter`) oder über wechselnde Anbieter
  fällt nicht auf. DNS over HTTPS ist als „externes DNS“ nicht erkennbar. Die Beaconing-Historie liegt nur im Speicher
  und beginnt nach einem Neustart von vorn.
- **PCAP-Analyse** erkennt Anwendungen nur über unverschlüsselte Merkmale (SNI, DNS, HTTP-Host). Mit ECH (Encrypted Client
  Hello) oder DNS-over-HTTPS sinkt die Trefferquote. Die Analyse hält pro Paket nur einen Zeitstempel im Speicher, sehr große
  Mitschnitte (Hunderte Millionen Pakete) brauchen entsprechend RAM.
- **GeoIP** wird beim Ausliefern nachgeschlagen, nicht gespeichert – ein Datenbank-Update wirkt daher auch auf ältere Flows.
- **Kein Benutzer-/Rollenkonzept**, nur ein gemeinsames API-Token.
