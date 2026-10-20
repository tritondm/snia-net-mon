<script>
  // Anomalie-Erkennung: Status (Lernphase, Baseline, Isolation Forest), Zeitleiste und Liste der Auffälligkeiten.
  // Klick auf einen Balken der Zeitleiste zeigt in der Liste nur diesen Abschnitt.
  import Window from './Window.svelte';
  import { api } from '../lib/api.js';
  import { searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtDate, fmtNum, flag, geoTitle } from '../lib/format.js';

  let status = $state(null);
  let rows = $state([]);
  let error = $state('');
  let disabled = $state(false);
  let filter = $state({ range: '24h', kind: '', severity: '', host: '' });
  let open = $state(null); // id der aufgeklappten Zeile
  let timeline = $state([]);
  let slot = $state(null); // gewählter Abschnitt der Zeitleiste {from, to}
  let tlWidth = $state(800);

  const HOUR = 3_600_000;
  const DAY = 24 * HOUR;
  // [Wert, Anzeige, Zeitraum, Abschnitt der Zeitleiste]
  const RANGES = [
    ['24h', '24 h', DAY, HOUR],
    ['7d', '7 tage', 7 * DAY, 6 * HOUR],
    ['30d', '30 tage', 30 * DAY, DAY],
  ];
  const range = () => RANGES.find((r) => r[0] === filter.range) ?? RANGES[0];

  const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})/gi;
  /** Text in Stücke zerlegen, IPs mit GeoIP-Daten (aus row.geo) als eigene Stücke. */
  function ipSegments(text, geo) {
    if (!geo) return [{ text }];
    return String(text)
      .split(IP_RE)
      .filter((t) => t !== '')
      .map((t) => (geo[t] ? { text: t, geo: geo[t] } : { text: t }));
  }

  /** Beginn der Zeitleiste, ausgerichtet auf volle Stunden bzw. Tage in Ortszeit; der letzte Abschnitt enthält jetzt. */
  function timelineStart([, , span, bucket]) {
    const d = new Date(Date.now() - span + bucket);
    if (bucket >= DAY) d.setHours(0, 0, 0, 0);
    else {
      d.setMinutes(0, 0, 0);
      d.setHours(d.getHours() - (d.getHours() % (bucket / HOUR)));
    }
    return d.getTime();
  }
  const KINDS = {
    stat: { label: 'statistik', color: 'text-ctp-peach border-ctp-peach/50', title: 'Merkmale weit über der Baseline' },
    ml: { label: 'ml', color: 'text-ctp-mauve border-ctp-mauve/50', title: 'nur der Isolation Forest schlägt an' },
    scan: { label: 'portscan', color: 'text-ctp-red border-ctp-red/50', title: 'viele fehlgeschlagene TCP-Verbindungsversuche' },
    dns: { label: 'externes dns', color: 'text-ctp-yellow border-ctp-yellow/50', title: 'DNS an externe Resolver statt an den eigenen' },
    country: { label: 'neues land', color: 'text-ctp-sapphire border-ctp-sapphire/50', title: 'erste Verbindung der Gruppe in dieses Land' },
    policy: { label: 'netz-regel', color: 'text-ctp-pink border-ctp-pink/50', title: 'Verstoß gegen eine Netz-Regel aus [anomaly] rules' },
    beacon: { label: 'beaconing', color: 'text-ctp-lavender border-ctp-lavender/50', title: 'regelmäßige Verbindungen zum selben externen Ziel' },
  };
  const SEVERITY = {
    info: ['bg-ctp-overlay0', 'info'],
    warn: ['bg-ctp-yellow', 'warnung'],
    high: ['bg-ctp-red animate-pulse-dot', 'hoch'],
  };

  async function load() {
    try {
      const r = range();
      const query = { kind: filter.kind, severity: filter.severity, host: filter.host.trim() };
      [status, timeline, rows] = await Promise.all([
        api('/anomalies/status'),
        api('/anomalies/timeline', { query: { ...query, from: timelineStart(r), bucket: r[3] } }),
        api('/anomalies', { query: { ...query, from: slot?.from ?? timelineStart(r), to: slot?.to, limit: 1000 } }),
      ]);
      error = '';
      disabled = false;
    } catch (err) {
      if (/abgeschaltet/.test(err.message)) disabled = true;
      else error = err.message;
    }
  }

  // Ein anderer Zeitraum hebt die Auswahl in der Zeitleiste auf
  $effect(() => {
    filter.range;
    slot = null;
  });

  $effect(() => {
    filter.range, filter.kind, filter.severity, filter.host, slot;
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  });

  const learnedDays = $derived(status ? (Date.now() - status.started_ms) / DAY : 0);
  const learnFill = $derived(status?.learning_days ? Math.min(1, learnedDays / status.learning_days) : 1);
  const ml = $derived(status?.ml);
  const fmtValue = (f) => (f.bytes ? fmtBytes(f.value) : f.percent ? `${Math.round(f.value * 100)} %` : fmtNum(f.value));
  // Zeitleiste: gestapelte Balken je Abschnitt (unten hoch, darüber warnung und info)
  const TL_H = 96;
  const TL_PAD = { l: 34, r: 8, t: 8, b: 20 };
  const tlMax = $derived(Math.max(1, ...timeline.map((b) => b.info + b.warn + b.high)));
  // ganzzahlige Hilfslinien: Maximum und, wenn es sich lohnt, die Hälfte
  const tlTicks = $derived(tlMax >= 4 ? [tlMax, Math.floor(tlMax / 2)] : [tlMax]);
  const tlStep = $derived(timeline.length ? (tlWidth - TL_PAD.l - TL_PAD.r) / timeline.length : 0);
  const tlY = (n) => ((TL_H - TL_PAD.t - TL_PAD.b) * n) / tlMax;
  const tlLabel = (ts) => {
    const d = new Date(ts);
    if (range()[3] >= DAY) return d.toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit' });
    if (range()[3] > HOUR) return `${d.toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit' })} ${String(d.getHours()).padStart(2, '0')}h`;
    return `${String(d.getHours()).padStart(2, '0')}:00`;
  };
  // höchstens ~8 Beschriftungen auf der Zeitachse
  const tlEvery = $derived(Math.max(1, Math.ceil(timeline.length / Math.max(2, Math.floor(tlWidth / 110)))));
  const bucketMs = () => range()[3];
  function pick(b) {
    slot = slot?.from === b.ts ? null : { from: b.ts, to: b.ts + bucketMs() - 1 };
  }
  /** Zeitraum einer zusammengefassten Auffälligkeit: erstes bis letztes Fenster (am selben Tag nur mit Uhrzeit). */
  function fmtSpan(r) {
    if (r.last_ts - r.ts < 60_000) return fmtDate(r.ts);
    const a = new Date(r.ts);
    const b = new Date(r.last_ts);
    if (a.toDateString() === b.toDateString()) return `${fmtDate(r.ts)}–${b.toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', hour12: false })}`;
    return `${fmtDate(r.ts)} – ${fmtDate(r.last_ts)}`;
  }
  const fmtInterval = (s) => (s >= 90 ? `${(s / 60).toFixed(1)} min` : `${Math.round(s)} s`);
  const fmtTypical = (f) => (f.bytes ? fmtBytes(f.typical) : f.percent ? `${Math.round(f.typical * 100)} %` : fmtNum(f.typical));
</script>

{#snippet ipText(text, geo)}
  {#each ipSegments(text, geo) as seg}{#if seg.geo}{seg.text}<span class="text-ctp-overlay1" title={geoTitle(seg.geo)}
        >{' '}({seg.geo.cc ? `${flag(seg.geo.cc)} ${seg.geo.cc}` : ''}{seg.geo.cc && seg.geo.org ? ', ' : ''}{seg.geo.org ?? (seg.geo.asn ? `AS${seg.geo.asn}` : '')})</span
      >{:else}{seg.text}{/if}{/each}
{/snippet}

<!-- IP-Liste untereinander, so viele Spalten wie die Fensterbreite zulässt -->
{#snippet ipList(label, ips, geo)}
  <div class="mt-1 text-ctp-overlay1">{label}:</div>
  <div class="mt-0.5 grid grid-cols-[repeat(auto-fill,minmax(15rem,1fr))] gap-x-4 tabular-nums">
    {#each ips ?? [] as ip}<div class="truncate" title={ip}>{@render ipText(ip, geo)}</div>{/each}
  </div>
{/snippet}

<div class="grid grid-cols-1 gap-2.5">
  {#if disabled}
    <Window title="Anomalie-Erkennung">
      <div class="py-8 text-center text-ctp-overlay1">abgeschaltet – in config.toml unter <span class="text-ctp-text">[anomaly]</span> enabled = true setzen</div>
    </Window>
  {:else}
    <Window title="Erkennung" subtitle="baseline je netzgruppe und host · feste regeln · isolation forest als zweite meinung">
      {#if error}<div class="mb-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
      {#if status}
        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">1 · lernphase</div>
            {#if status.learning}
              <div class="text-ctp-yellow">lernt noch · {learnedDays.toFixed(1)} von {status.learning_days} tagen</div>
            {:else}
              <div class="text-ctp-green">aktiv seit {fmtDate(status.started_ms + status.learning_days * DAY)}</div>
            {/if}
            <div class="mt-2 h-1.5 overflow-hidden rounded-full bg-ctp-surface0/70">
              <div class="h-full rounded-full" style="width: {Math.max(1, learnFill * 100)}%; background: linear-gradient(90deg, #94e2d5, #cba6f7)"></div>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">portscan, externes dns, netz-regeln und beaconing melden sofort, statistik, ml und neue länder erst nach der lernphase</div>
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">2 · baseline (statistik)</div>
            <div class="text-ctp-text">{status.groups} gruppen · {status.host_profiles} host-profile</div>
            <div class="mt-1 text-[11px] text-ctp-overlay0">
              fenster {status.window_minutes} min · meldung ab z ≥ {status.z_threshold} und mindestwert · zeitzone {status.timezone}
            </div>
            {#if status.last_window}
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                letztes fenster {fmtDate(status.last_window.end_ms)} · {status.last_window.hosts} hosts{status.last_window.partial ? ' · unvollständig (nur regeln)' : ''}
              </div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">3 · isolation forest (ml)</div>
            {#if !ml.enabled}
              <div class="text-ctp-overlay1">abgeschaltet</div>
            {:else if ml.trained_ms}
              <div class="text-ctp-text">trainiert {fmtDate(ml.trained_ms)}</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                {fmtNum(ml.trained_vectors)} vektoren · {ml.trees} bäume · schwelle {ml.effective_threshold?.toFixed(2)}
                {#if ml.quantiles}· training median {ml.quantiles.p50.toFixed(2)}, p99 {ml.quantiles.p99.toFixed(2)}, max {ml.quantiles.max.toFixed(2)}{/if}
              </div>
            {:else}
              <div class="text-ctp-yellow">sammelt daten · {fmtNum(ml.stored_vectors)} / {fmtNum(ml.min_vectors)} vektoren</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">training nach der lernphase, danach täglich mit den letzten {ml.training_days} tagen (ohne ip-adressen)</div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">4 · letzte 24 h</div>
            <div class="flex flex-wrap gap-2">
              <span class="chip"><span class="led bg-ctp-red"></span>hoch {status.counts_24h.high}</span>
              <span class="chip"><span class="led bg-ctp-yellow"></span>warnung {status.counts_24h.warn}</span>
              <span class="chip"><span class="led bg-ctp-overlay0"></span>info {status.counts_24h.info}</span>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">
              netz-regeln: {status.policy_rules ? `${status.policy_rules} regeln, ${status.policy_zones} zonen` : 'keine'} · beaconing {status.beacon ? `an (${fmtNum(status.beacon_pairs)} paare)` : 'aus'} · mails {status.mail ? 'an' : 'aus'}
            </div>
          </div>
        </div>
      {/if}
    </Window>

    <Window title="Zeitleiste" subtitle="aktive auffälligkeiten je {range()[3] >= DAY ? 'tag' : range()[3] > HOUR ? `${range()[3] / HOUR} stunden` : 'stunde'} · klick auf einen balken filtert die liste">
      {#snippet actions()}
        <span class="chip"><span class="led bg-ctp-red"></span>hoch</span>
        <span class="chip"><span class="led bg-ctp-yellow"></span>warnung</span>
        <span class="chip"><span class="led bg-ctp-overlay0"></span>info</span>
      {/snippet}
      <div bind:clientWidth={tlWidth} class="w-full min-w-0 overflow-hidden">
        <svg width="100%" height={TL_H} class="block select-none" role="img" aria-label="Zeitleiste der Auffälligkeiten">
          {#each tlTicks as n}
            {@const y = TL_H - TL_PAD.b - tlY(n)}
            <line x1={TL_PAD.l} x2={tlWidth - TL_PAD.r} y1={y} y2={y} class="stroke-ctp-surface0" stroke-dasharray="2 4" />
            <text x={TL_PAD.l - 6} y={y + 3} text-anchor="end" class="fill-ctp-overlay0 text-[10px]">{n}</text>
          {/each}
          <line x1={TL_PAD.l} x2={tlWidth - TL_PAD.r} y1={TL_H - TL_PAD.b} y2={TL_H - TL_PAD.b} class="stroke-ctp-surface1" />
          {#each timeline as b, i (b.ts)}
            {@const x = TL_PAD.l + i * tlStep}
            {@const w = Math.max(1, tlStep - Math.min(4, tlStep * 0.25))}
            {@const base = TL_H - TL_PAD.b}
            {@const selected = slot?.from === b.ts}
            <g
              class="cursor-pointer"
              role="button"
              tabindex="-1"
              onclick={() => pick(b)}
              onkeydown={(e) => e.key === 'Enter' && pick(b)}
              opacity={slot && !selected ? 0.35 : 1}
            >
              <title>{tlLabel(b.ts)} · hoch {b.high} · warnung {b.warn} · info {b.info}</title>
              <rect {x} y={TL_PAD.t} width={tlStep} height={base - TL_PAD.t} class={selected ? 'fill-ctp-surface0/60' : 'fill-transparent hover:fill-ctp-surface0/40'} />
              <rect {x} y={base - tlY(b.high)} width={w} height={tlY(b.high)} class="fill-ctp-red" />
              <rect {x} y={base - tlY(b.high + b.warn)} width={w} height={tlY(b.warn)} class="fill-ctp-yellow" />
              <rect {x} y={base - tlY(b.high + b.warn + b.info)} width={w} height={tlY(b.info)} class="fill-ctp-overlay0" />
            </g>
            {#if i % tlEvery === 0}
              <text x={x + w / 2} y={TL_H - 5} text-anchor="middle" class="fill-ctp-overlay0 text-[10px]">{tlLabel(b.ts)}</text>
            {/if}
          {/each}
        </svg>
      </div>
    </Window>

    <Window title="Auffälligkeiten" subtitle="wiederholungen desselben hosts werden zusammengefasst" bodyClass="p-0 overflow-auto max-h-[70vh]">
      {#snippet actions()}
        {#if slot}
          <button class="chip text-ctp-teal" title="auswahl aufheben" onclick={() => (slot = null)}>{fmtDate(slot.from)} – {fmtDate(slot.to + 1)} ✕</button>
        {/if}
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.range}>{#each RANGES as [v, l]}<option value={v}>{l}</option>{/each}</select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.kind}>
          <option value="">alle arten</option>
          {#each Object.entries(KINDS) as [k, v]}<option value={k}>{v.label}</option>{/each}
        </select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.severity}>
          <option value="">alle</option>
          <option value="warn">ab warnung</option>
          <option value="high">nur hoch</option>
        </select>
        <input class="input !w-36 !py-0.5 text-[11px]" placeholder="host-ip" bind:value={filter.host} />
      {/snippet}
      <table class="table-flows">
        <thead><tr><th></th><th>Zeit</th><th>Art</th><th>Host</th><th>Gruppe</th><th class="w-full">Befund</th></tr></thead>
        <tbody>
          {#each rows as r (r.id)}
            {@const kind = KINDS[r.kind] ?? KINDS.stat}
            <tr class="cursor-pointer" onclick={() => (open = open === r.id ? null : r.id)}>
              <td title={SEVERITY[r.severity]?.[1]}><span class="led {SEVERITY[r.severity]?.[0]}"></span></td>
              <td class="tabular-nums text-ctp-subtext0" title="erstes bis letztes fenster">
                {fmtSpan(r)}{#if r.count > 1}<span class="text-ctp-overlay0"> · {r.count}×</span>{/if}
              </td>
              <td><span class="chip !py-0 {kind.color}" title={kind.title}>{kind.label}</span></td>
              <td>
                <button class="text-ctp-teal hover:underline" title="in der flow-suche öffnen" onclick={(e) => (e.stopPropagation(), searchFor({ ip: r.host }))}>{r.host}</button>
              </td>
              <td class="text-ctp-overlay1">{r.group}</td>
              <td class="whitespace-normal text-ctp-text [overflow-wrap:anywhere]">
                {#if r.kind === 'country'}<span class="mr-1">{flag(r.detail?.cc)}</span>{/if}{#if r.kind === 'beacon'}{r.title}{:else}{@render ipText(r.title, r.geo)}{/if}
                {#if r.kind === 'stat' && r.detail?.ml_score != null}
                  <span
                    class="chip ml-1 !py-0 {r.detail.ml_agrees ? 'border-ctp-mauve/60 text-ctp-mauve' : 'text-ctp-overlay0'}"
                    title="zweite meinung des isolation forest">ml {r.detail.ml_score.toFixed(2)} {r.detail.ml_agrees ? '✓ stimmt zu' : '· unauffällig'}</span
                  >
                {/if}
              </td>
            </tr>
            {#if open === r.id}
              <tr class="!bg-ctp-mantle/50">
                <td></td>
                <td colspan="5" class="whitespace-normal text-[11px] [overflow-wrap:anywhere] text-ctp-subtext0">
                  {#if r.kind === 'stat'}
                    <div class="mb-1 text-ctp-overlay1">verglichen mit: {r.detail.slot ?? '–'}</div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.features ?? [] as f}
                        <span class="chip">{f.name} <span class="text-ctp-text">{fmtValue(f)}</span> · typisch {fmtTypical(f)} · z {f.z}</span>
                      {/each}
                    </div>
                  {:else if r.kind === 'ml'}
                    <div class="mb-1 text-ctp-overlay1">ml-score {r.detail.ml_score} – stärkste abweichungen vom median der trainingsdaten:</div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.deviations ?? [] as d}
                        <span class="chip">{d.name} <span class="text-ctp-text">{fmtValue(d)}</span> · typisch {fmtTypical(d)}</span>
                      {:else}
                        <span class="text-ctp-overlay0">keine einzelne kennzahl sticht heraus – die kombination (auch mit der uhrzeit) ist ungewöhnlich</span>
                      {/each}
                    </div>
                  {:else if r.kind === 'scan'}
                    <div>{r.detail.attempts} versuche · {r.detail.hosts} ziel-hosts · {r.detail.ports} ports</div>
                    <div class="mt-1 text-ctp-overlay1">ports: {(r.detail.sample_ports ?? []).join(', ')}</div>
                    {@render ipList(r.detail.hosts > (r.detail.sample_hosts?.length ?? 0) ? 'ziele (auszug)' : 'ziele', r.detail.sample_hosts, r.geo)}
                  {:else if r.kind === 'dns'}
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.resolvers ?? [] as res}<span class="chip">{@render ipText(res.ip, r.geo)} · {res.flows} flows</span>{/each}
                    </div>
                    <div class="mt-1 text-ctp-overlay0">erlaubte externe resolver: [anomaly] dns_servers</div>
                  {:else if r.kind === 'policy'}
                    <div>regel <span class="text-ctp-text">{r.detail.rule}</span> ({r.detail.from} → {r.detail.to}) · {r.detail.flows} verbindungen · {fmtBytes(r.detail.bytes)}</div>
                    {#if r.detail.ports?.length}<div class="mt-1 text-ctp-overlay1">ports: {r.detail.ports.join(', ')}</div>{/if}
                    {@render ipList(r.detail.peers > (r.detail.sample_peers?.length ?? 0) ? 'ziele (auszug)' : 'ziele', r.detail.sample_peers, r.geo)}
                  {:else if r.kind === 'beacon'}
                    <div>
                      ziel <span class="text-ctp-text">{r.detail.peer}:{r.detail.port}/{r.detail.proto}</span>
                      {#if r.detail.cc}<span class="ml-1">{flag(r.detail.cc)} {r.detail.cc}</span>{/if}
                      {#if r.detail.org}<span class="text-ctp-overlay1"> · {r.detail.org}{r.detail.asn ? ` (AS${r.detail.asn})` : ''}</span>{/if}
                    </div>
                    <div class="mt-1 flex flex-wrap gap-2">
                      <span class="chip">{r.detail.connections} verbindungen</span>
                      <span class="chip">alle {fmtInterval(r.detail.interval_s)} ± {Math.round(r.detail.jitter * 100)} %</span>
                      <span class="chip">je ~{fmtBytes(r.detail.median_bytes)}</span>
                      <span class="chip">{fmtDate(r.detail.first_ms)} – {fmtDate(r.detail.last_ms)}</span>
                      {#if r.detail.fleet_hosts > 1}
                        <span class="chip">{r.detail.fleet_hosts} hosts mit gleichem muster zu {r.detail.asn ? `AS${r.detail.asn}` : 'diesem netz'}</span>
                      {/if}
                    </div>
                    <div class="mt-1 text-ctp-overlay0">nur ein hinweis: auch updates, push-dienste oder geräte, die ihren status melden, verbinden sich regelmäßig</div>
                  {:else if r.kind === 'country'}
                    <div>{flag(r.detail.cc)} {r.detail.cc} · {fmtBytes(r.detail.bytes)} hochgeladen im ersten fenster</div>
                  {/if}
                  <div class="mt-2 text-ctp-overlay0">zuletzt {fmtDate(r.last_ts)} · klick auf die ip öffnet die flow-suche</div>
                </td>
              </tr>
            {/if}
          {:else}
            <tr>
              <td colspan="6" class="py-12 text-center text-ctp-overlay0">
                {slot ? 'keine auffälligkeiten in diesem abschnitt' : status?.learning ? 'keine auffälligkeiten – die erkennung lernt noch' : 'keine auffälligkeiten im gewählten zeitraum'}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Window>
  {/if}
</div>
