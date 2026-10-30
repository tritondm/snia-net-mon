# TODO – Optimierung der Anomalie-Erkennung

Ideen zur Verbesserung der Anomalie-Erkennung, geprüft gegen den aktuellen Stand (`crates/anomaly/src/`,
[FEATURES_de.md](FEATURES_de.md#anomalie-erkennung)). Sortiert nach Priorität.

| Prio | Thema | Stand | Bewertung |
|---|---|---|---|
| 1 | [Low-and-Slow per CUSUM](#1-low-and-slow-exfiltration-cusum-statt-mehrerer-zeitfenster) | **umgesetzt** (Upload) | war eine echte, dokumentierte Lücke |
| 2 | [First-Seen-Ziele und -Ports](#2-first-seen-ziele-und-ports) | teilweise (neues Land) | stärkt den Upload-Alarm am meisten |
| 3 | [Rollen-Gruppen](#3-rollen-gruppen-über-subnetze-hinweg) | teilweise (Netzgruppen) | überschaubar, sinnvoll |
| 4 | [Ferien / Feiertage, Host-Slots](#4-saisonalität-ferien-feiertage-und-wochentage-im-host-profil) | größtenteils vorhanden | Feinschliff |
| 5 | [Kappen in der Lernphase](#5-robustere-schwellenwerte-kappen-schon-in-der-lernphase) | teilweise | kleiner, günstiger Fix |
| 6 | [Weitere kombinierte Metriken](#6-kombinierte-metriken-entropie-richtungs-verhältnis) | größtenteils vorhanden | zurückgestellt |

---

## 1. Low-and-Slow-Exfiltration: CUSUM statt mehrerer Zeitfenster

- [x] CUSUM je Host über die Z-Scores des Uploads (`crates/anomaly/src/drift.rs`, Art `drift`, Schwere warnung)
- [x] Parameter in `[anomaly]` (`drift`, `drift_k`, `drift_h`, `drift_min_mb`) und Meldungstext („upload seit 1 h 40 min erhöht …“)
- [ ] Optional: weitere Merkmale (externe Ziele, Flows) – erst, wenn sich der Upload im Betrieb bewährt hat
- [ ] Optional: Zustand in `anomaly.db` speichern – bewusst weggelassen, liegt wie die Beaconing-Historie nur im
      Speicher; ein Neustart kostet nur die Summe der letzten Stunden

**Problem:** Ein plötzlicher Spike in einem 10-Minuten-Fenster wird sofort gemeldet. Ein langsamer Datenabfluss, der über
viele Stunden konstant nur leicht erhöht ist, bleibt in jedem einzelnen Fenster unter `z_threshold`. Die Doku sagt selbst:
*„Wer über Wochen hinweg täglich ein bisschen mehr hochlädt, fällt der Statistik nicht auf.“*

**Ursprüngliche Idee:** Die Baseline parallel auf 5-Minuten-, 1-Stunden- und 24-Stunden-Akkumulationen rechnen.

**Warum nicht so:** Ein 24-h-Profil braucht 30 Stichproben pro Slot, also rund 6 Wochen Lernzeit (Werktag) bzw.
15 Wochen (Wochenende). Gleitende, überlappende Fenster liefern zudem korrelierte Werte und verfälschen `n`.

**Besser – CUSUM** auf den bereits berechneten Z-Scores:

```math
S_t = \max\left(0,\ S_{t-1} + z_t - k\right), \qquad \text{Meldung, wenn } S_t \ge h
```

Mit z. B. `k = 0,5` und `h = 8` summieren sich kleine, aber dauerhafte Erhöhungen auf, während normales Rauschen
(`z` um 0) die Summe immer wieder auf 0 zieht. Kostet eine Zahl je Host und Merkmal, braucht keine neue Baseline
und ist sofort aktiv, sobald das Vergleichsprofil eingelernt ist. Auch hier gilt der Mindestwert: Die Summe der Rohwerte
im auffälligen Zeitraum muss eine Schwelle erreichen, damit leise Geräte nicht gemeldet werden.

## 2. First-Seen-Ziele und -Ports

- [ ] Neues Ziel-**ASN** (ersatzweise /24 bzw. /48) je Netzgruppe merken und melden
- [ ] Neuer Zielport / neues Protokoll je Netzgruppe merken und melden
- [ ] Statistik-Treffer hochstufen (**warnung → hoch**), wenn das größte Upload-Ziel erstmals gesehen wurde
- [ ] Lernphase wie bei „neues Land“: erst sammeln, dann melden

**Problem:** Reines Volumen zeigt nicht, wohin die Daten fließen. 10 GB zum internen Backup-Server sind okay, 10 GB zu
einem nie gesehenen Anbieter nicht.

**Stand:** „Neues Land“ je Netzgruppe gibt es bereits (Schwere info).

**Anmerkungen:**

- Erstmaligkeit pro **einzelner IP** wäre wegen CDNs und Cloud-Diensten zu laut – deshalb ASN, wie schon beim
  Beaconing (Flotten-Prüfung).
- „Neue Domain“ geht mit NetFlow nicht (keine Domains im Flow), nur mit DNS-Logs bzw. in der PCAP-Analyse.
- Es gibt keine Stufe „Critical“; die Stufen sind `info`, `warn`, `high`.

## 3. Rollen-Gruppen über Subnetze hinweg

- [ ] Benannte Gruppen in der Konfiguration, z. B. `[[anomaly.roles]] name = "dns-server", hosts = [...]`
- [ ] Rollen-Gruppe hat Vorrang vor der Subnetz-Gruppe als Vergleichsprofil
- [ ] Rolle in der Web-UI und in den Details der Meldung anzeigen

**Problem:** Ein neuer Rechner hat noch keine eigene Baseline (`n < 30`).

**Stand:** Bereits gelöst für Subnetze: Bis das Host-Profil eingelernt ist, wird gegen die **Netzgruppe** (Subnetz oder
Bereich aus `anomaly.groups`) verglichen – auch am ersten Tag, sofern die Gruppe eingelernt ist.

**Was fehlt:** Rollen, die quer über Subnetze verteilt sind (alle DNS-Server, alle Buchhaltungs-PCs). Automatisches
Clustering nach Verhalten ist **nicht** geplant – aufwendig, schwer nachvollziehbar und selbst eine Fehlerquelle.

## 4. Saisonalität: Ferien, Feiertage und Wochentage im Host-Profil

- [ ] Kalender-Option (`holidays`, Datumsbereiche), deren Tage wie Wochenende behandelt werden
- [ ] Optional: 168 statt 48 Host-Slots (`host_slots = "week"`), mit Hinweis auf ~5 Wochen Lernzeit

**Stand:** Größtenteils umgesetzt – Gruppen haben 168 Slots (Wochentag × Stunde) plus 24 Stunden-Slots als Rückfall,
Hosts 48 Slots (Werktag/Wochenende × Stunde), Zeitzone über `anomaly.timezone`.

**Was fehlt:**

- **Ferien und Feiertage** (für Schulen der wichtigere Punkt): Ein Ferien-Montag wird heute mit normalen Montagen
  verglichen.
- **Wochentag im Host-Profil:** Ein Backup jeden Sonntag um 02:00 teilt sich den Host-Slot mit Samstag 02:00. Die
  Streuung dieses Slots wird groß, die Erkennung um diese Zeit unschärfer. 168 Host-Slots lösen das, kosten aber
  Lernzeit (6 Stichproben pro Woche und Slot). Alternative bleibt `ignore` für bekannte Backup-Server.

## 5. Robustere Schwellenwerte: Kappen schon in der Lernphase

- [ ] Kappen bei `μ + 3σ̂` schon ab z. B. `n ≥ 10` statt erst ab `n ≥ 30`

**Ursprüngliche Idee:** MAD bzw. Quantile statt Standardabweichung, weil ein fester Z-Score nicht für jedes Verhalten passt.

**Warum nicht so:** `z_threshold = 4` wirkt nicht starr, da σ je Slot gelernt wird – wo es stark streut, braucht es ein
Vielfaches mehr bis zur Meldung. Ausreißer sind bereits durch Log-Skala, Mindest-Streuung (`σ̂ ≥ 0,5`) und Kappen
abgefangen. Eine MAD lässt sich nicht mit drei Zahlen pro Slot mitführen, dafür bräuchte es Quantil-Sketches (P²,
t-Digest) für jedes Merkmal in jedem Slot jedes Hosts. MAD wird schon dort genutzt, wo es sich lohnt: Erklärung von
ML-Treffern und Beaconing.

**Kleiner Rest:** In den ersten 30 Messungen eines Slots wird nicht gekappt. Ein Ausreißer in dieser Zeit bläht σ
dauerhaft auf. Früheres Kappen behebt das ohne zusätzlichen Speicher.

## 6. Kombinierte Metriken (Entropie & Richtungs-Verhältnis)

- [ ] Zurückgestellt – erst angehen, wenn 1 und 2 umgesetzt sind und Fälle auftauchen, die sie nicht erkennen

**Problem:** Ein Angreifer hält das reine Volumen unter der Alarm-Schwelle.

**Stand:** Größtenteils vorhanden:

- **Inbound vs. Outbound:** Upload-Anteil `u = upload / (upload + download)` ist ein Merkmal des Isolation Forest.
- **Verbindungsrate vs. Volumen:** Flows, externe/interne Ziele und Ports sind eigene Merkmale; Portscan und Beaconing
  (C2) haben eigene Regeln.

**Was fehlt:** Entropie der Ziel-IPs bzw. Ports wäre möglich, bringt gegenüber „Anzahl verschiedener Ziele“ und dem
Isolation Forest aber wenig. Gegen Abfluss knapp unter der Schwelle helfen Punkt 1 (CUSUM) und Punkt 2 (First-Seen) mehr.
