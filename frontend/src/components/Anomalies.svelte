<script>
  // Anomalie-Erkennung: Status (Lernphase, Baseline, Isolation Forest), Zeitleiste und Liste der Auffälligkeiten.
  // Klick auf einen Balken der Zeitleiste zeigt in der Liste nur diesen Abschnitt.
  import Window from './Window.svelte';
  import ExceptionDialog from './ExceptionDialog.svelte';
  import AnomalyExceptions from './AnomalyExceptions.svelte';
  import { KINDS, SEVERITY, targetsOf } from '../lib/anomaly.js';
  import { api } from '../lib/api.js';
  import { searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtDate, fmtNum, flag, geoTitle, serviceName } from '../lib/format.js';
  import { t, locale } from '../lib/i18n.svelte.js';

  let status = $state(null);
  let rows = $state([]);
  let error = $state('');
  let disabled = $state(false);
  let filter = $state({ range: '24h', kind: '', severity: '', host: '', excepted: false });
  let open = $state(null); // id der aufgeklappten Zeile
  let timeline = $state([]);
  let slot = $state(null); // gewählter Abschnitt der Zeitleiste {from, to}
  let tlWidth = $state(800);
  let exceptions = $state([]);
  let dialog = $state(null); // { value, targets, event } des offenen Ausnahme-Dialogs

  const HOUR = 3_600_000;
  const DAY = 24 * HOUR;
  // [Wert, Anzeige, Zeitraum, Abschnitt der Zeitleiste]
  const RANGES = $derived([
    ['24h', '24 h', DAY, HOUR],
    ['7d', t('7 tage', '7 days'), 7 * DAY, 6 * HOUR],
    ['30d', t('30 tage', '30 days'), 30 * DAY, DAY],
  ]);
  const range = () => RANGES.find((r) => r[0] === filter.range) ?? RANGES[0];

  const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})/gi;
  /** Text in Stücke zerlegen, IPs mit GeoIP-Daten (aus row.geo) als eigene Stücke. */
  function ipSegments(text, geo) {
    if (!geo) return [{ text }];
    return String(text)
      .split(IP_RE)
      .filter((seg) => seg !== '')
      .map((seg) => (geo[seg] ? { text: seg, geo: geo[seg] } : { text: seg }));
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
  async function load() {
    try {
      const r = range();
      const query = { kind: filter.kind, severity: filter.severity, host: filter.host.trim(), excepted: filter.excepted ? 'true' : '' };
      [status, timeline, rows, exceptions] = await Promise.all([
        api('/anomalies/status'),
        api('/anomalies/timeline', { query: { ...query, from: timelineStart(r), bucket: r[3] } }),
        api('/anomalies', { query: { ...query, from: slot?.from ?? timelineStart(r), to: slot?.to, limit: 1000 } }),
        api('/anomalies/exceptions'),
      ]);
      error = '';
      disabled = false;
    } catch (err) {
      if (/abgeschaltet|disabled/.test(err.message)) disabled = true;
      else error = err.message;
    }
  }

  // Ein anderer Zeitraum hebt die Auswahl in der Zeitleiste auf
  $effect(() => {
    filter.range;
    slot = null;
  });

  $effect(() => {
    filter.range, filter.kind, filter.severity, filter.host, filter.excepted, slot;
    // kurz warten, damit nicht jeder Tastendruck im Host-Feld eine Abfrage auslöst
    const first = setTimeout(load, 250);
    const id = setInterval(load, 30_000);
    return () => (clearTimeout(first), clearInterval(id));
  });

  const learnedDays = $derived(status ? (Date.now() - status.started_ms) / DAY : 0);
  const learnFill = $derived(status?.learning_days ? Math.min(1, learnedDays / status.learning_days) : 1);
  const ml = $derived(status?.ml);
  // welche Arten ab welcher Schwere per Mail gehen
  const mailKinds = $derived(Object.entries(status?.mail_kinds ?? {}).map(([k, min]) => `${(KINDS[k] ?? KINDS.stat).label} ${t('ab', 'from')} ${SEVERITY[min]?.[1] ?? min}`));
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
    if (range()[3] >= DAY) return d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' });
    if (range()[3] > HOUR) return `${d.toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' })} ${String(d.getHours()).padStart(2, '0')}h`;
    return `${String(d.getHours()).padStart(2, '0')}:00`;
  };
  // höchstens ~8 Beschriftungen auf der Zeitachse
  const tlEvery = $derived(Math.max(1, Math.ceil(timeline.length / Math.max(2, Math.floor(tlWidth / 110)))));
  const bucketMs = () => range()[3];
  function pick(b) {
    slot = slot?.from === b.ts ? null : { from: b.ts, to: b.ts + bucketMs() - 1 };
  }
  // Sortierung der Liste per Klick auf die Spaltenköpfe; Standard: zuletzt aktive zuerst
  let sort = $state({ key: 'last_ts', dir: -1 });
  const SEV_RANK = { info: 0, warn: 1, high: 2 };
  /** IPv4 numerisch vergleichbar machen (10.0.0.9 vor 10.0.0.10), IPv6 dahinter als Text. */
  const ipKey = (ip) => (/^\d+(\.\d+){3}$/.test(ip) ? ip.split('.').map((n) => n.padStart(3, '0')).join('.') : `~${ip}`);
  const SORT_KEYS = {
    severity: (r) => SEV_RANK[r.severity] ?? 0,
    ts: (r) => r.ts,
    last_ts: (r) => r.last_ts,
    kind: (r) => (KINDS[r.kind] ?? KINDS.stat).label,
    host: (r) => ipKey(r.host),
    group: (r) => r.group,
  };
  function cmp(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
  }
  const sorted = $derived.by(() => {
    const key = SORT_KEYS[sort.key];
    return [...rows].sort((a, b) => sort.dir * cmp(key(a), key(b)) || b.last_ts - a.last_ts);
  });
  function sortBy(key) {
    // Zeiten und Schwere zuerst absteigend, Texte aufsteigend
    if (sort.key === key) sort.dir = -sort.dir;
    else sort = { key, dir: ['ts', 'last_ts', 'severity'].includes(key) ? -1 : 1 };
  }
  /** Ausnahme-Dialog: neu (aus einer Auffälligkeit oder leer) oder eine bestehende bearbeiten. */
  function exceptionFor(r) {
    const targets = targetsOf(r);
    dialog = { value: { kind: r.kind, host: r.host, target: targets[0] ?? '' }, targets, event: r };
  }
  function editException(x) {
    dialog = { value: x ?? { kind: 'dns', host: '', target: '' }, targets: [], event: null };
  }
  const exceptionById = $derived(new Map(exceptions.map((x) => [x.id, x])));

  // Flow-Suche im Zeitraum der Auffälligkeit (eine Minute Rand für spät exportierte Flows)
  const windowLen = () => (status?.window_minutes ?? 10) * 60_000;
  const eventRange = (r) => ({ from: (r.kind === 'beacon' && r.detail?.first_ms) || (r.kind === 'drift' && r.detail?.since_ms) || r.ts - windowLen(), to: r.last_ts + 60_000 });
  // Zeitraum des Fensters, aus dem der Kontext einer Meldung stammt
  const contextRange = (from) => ({ from, to: from + windowLen() + 60_000 });

  const hosts = $derived([...new Set(rows.map((r) => r.host))].sort((a, b) => cmp(ipKey(a), ipKey(b))));
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

<!-- externe Gegenstellen eines Fensters; klick sucht die Flows mit dieser IP in genau diesem Fenster -->
{#snippet peerList(peers, geo, from)}
  <div class="mt-0.5 grid grid-cols-[repeat(auto-fill,minmax(22rem,1fr))] gap-x-4 tabular-nums">
    {#each peers ?? [] as p}
      <div class="truncate">
        <button class="text-ctp-teal hover:underline" title={t('flows mit dieser ip in diesem fenster', 'flows with this ip in this window')} onclick={() => searchFor({ ip: p.ip, ...contextRange(from) })}>{p.ip}</button
        ><span class="text-ctp-overlay1">:{p.port}</span>
        {#if geo?.[p.ip]}<span class="text-ctp-overlay1" title={geoTitle(geo[p.ip])}> {flag(geo[p.ip].cc)} {geo[p.ip].cc ?? ''}{geo[p.ip].org ? `, ${geo[p.ip].org}` : ''}</span
          >{:else if p.cc}<span class="text-ctp-overlay1"> {flag(p.cc)} {p.cc}</span>{/if}
        <span class="text-ctp-overlay0"> · {p.flows} flows · {fmtBytes(p.bytes)}↑</span>
        {#if p.served}<span class="chip ml-1 !py-0 text-ctp-overlay1" title={t('die gegenstelle hat verbunden, der host hat nur geantwortet (er ist hier der server)', 'the peer connected, the host only answered (it is the server here)')}>{t('eingehend', 'inbound')}</span>{/if}
      </div>
    {/each}
  </div>
{/snippet}

<!-- was der host im fenster getan hat: ziele, dienste, länder -->
{#snippet hostContext(c, geo)}
  {#if c}
    <div class="mt-2 text-ctp-overlay1">
      {t('im fenster', 'in the window')} {fmtDate(c.from_ms)} – {fmtDate(c.from_ms + windowLen())}: {c.ext_peers} {t('externe ziele', 'external destinations')} · {c.int_peers} {t('interne ziele', 'internal destinations')} · {t('größte ziele', 'biggest destinations')}:
    </div>
    {@render peerList(c.peers, geo, c.from_ms)}
    {#if c.ports?.length}
      <div class="mt-1 flex flex-wrap gap-1.5">
        <span class="text-ctp-overlay1">ports:</span>
        {#each c.ports as p}<span class="chip !py-0">{p.port}{serviceName(p.port) ? ` ${serviceName(p.port)}` : ''} <span class="text-ctp-overlay0">· {p.flows}</span></span>{/each}
      </div>
    {/if}
    {#if c.countries?.length}
      <div class="mt-1 flex flex-wrap gap-1.5">
        <span class="text-ctp-overlay1">{t('länder', 'countries')}:</span>
        {#each c.countries as k}<span class="chip !py-0 {k.opened ? '' : 'text-ctp-overlay0'}" title={k.opened ? '' : t('nur antworten an clients von dort', 'only replies to clients from there')}
            >{flag(k.cc)} {k.cc} <span class="text-ctp-overlay0">· {fmtBytes(k.bytes)}{k.opened ? '' : ` · ${t('eingehend', 'inbound')}`}</span></span
          >{/each}
      </div>
    {/if}
  {/if}
{/snippet}

<div class="grid grid-cols-1 gap-2.5">
  {#if disabled}
    <Window title={t('Anomalie-Erkennung', 'Anomaly detection')}>
      <div class="py-8 text-center text-ctp-overlay1">{t('abgeschaltet – in config.toml unter', 'disabled – set in config.toml under')} <span class="text-ctp-text">[anomaly]</span> enabled = true{t(' setzen', '')}</div>
    </Window>
  {:else}
    <Window title={t('Erkennung', 'Detection')} subtitle={t('baseline je netzgruppe und host · feste regeln · isolation forest als zweite meinung', 'baseline per network group and host · fixed rules · isolation forest as a second opinion')}>
      {#if error}<div class="mb-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
      {#if status}
        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">1 · {t('lernphase', 'learning phase')}</div>
            {#if status.learning}
              <div class="text-ctp-yellow">{t('lernt noch', 'still learning')} · {learnedDays.toFixed(1)} {t('von', 'of')} {status.learning_days} {t('tagen', 'days')}</div>
            {:else}
              <div class="text-ctp-green">{t('aktiv seit', 'active since')} {fmtDate(status.started_ms + status.learning_days * DAY)}</div>
            {/if}
            <div class="mt-2 h-1.5 overflow-hidden rounded-full bg-ctp-surface0/70">
              <div class="h-full rounded-full" style="width: {Math.max(1, learnFill * 100)}%; background: linear-gradient(90deg, #94e2d5, #cba6f7)"></div>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">{t('portscan, externes dns, netz-regeln und beaconing melden sofort, statistik, schleichender anstieg, ml und neue länder erst nach der lernphase', 'port scan, external dns, network rules and beaconing report immediately; statistics, creeping increase, ml and new countries only after the learning phase')}</div>
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">2 · baseline ({t('statistik', 'statistics')})</div>
            <div class="text-ctp-text">{status.groups} {t('gruppen', 'groups')} · {status.host_profiles} {t('host-profile', 'host profiles')}</div>
            <div class="mt-1 text-[11px] text-ctp-overlay0">
              {t('fenster', 'window')} {status.window_minutes} min · {t('meldung ab', 'report at')} z ≥ {status.z_threshold} {t('und mindestwert', 'and minimum value')} · {t('zeitzone', 'time zone')} {status.timezone}
            </div>
            {#if status.last_window}
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                {t('letztes fenster', 'last window')} {fmtDate(status.last_window.end_ms)} · {status.last_window.hosts} hosts{status.last_window.partial ? t(' · unvollständig (nur regeln)', ' · incomplete (rules only)') : ''}
              </div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">3 · isolation forest (ml)</div>
            {#if !ml.enabled}
              <div class="text-ctp-overlay1">{t('abgeschaltet', 'disabled')}</div>
            {:else if ml.trained_ms}
              <div class="text-ctp-text">{t('trainiert', 'trained')} {fmtDate(ml.trained_ms)}</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                {fmtNum(ml.trained_vectors)} {t('vektoren', 'vectors')} · {ml.trees} {t('bäume', 'trees')} · {t('schwelle', 'threshold')} {ml.effective_threshold?.toFixed(2)}
                {#if ml.quantiles}· training median {ml.quantiles.p50.toFixed(2)}, p99 {ml.quantiles.p99.toFixed(2)}, max {ml.quantiles.max.toFixed(2)}{/if}
              </div>
            {:else}
              <div class="text-ctp-yellow">{t('sammelt daten', 'collecting data')} · {fmtNum(ml.stored_vectors)} / {fmtNum(ml.min_vectors)} {t('vektoren', 'vectors')}</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">{t(`training nach der lernphase, danach täglich mit den letzten ${ml.training_days} tagen (ohne ip-adressen)`, `training after the learning phase, then daily with the last ${ml.training_days} days (without ip addresses)`)}</div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">4 · {t('letzte 24 h', 'last 24 h')}</div>
            <div class="flex flex-wrap gap-2">
              <span class="chip"><span class="led bg-ctp-red"></span>{t('hoch', 'high')} {status.counts_24h.high}</span>
              <span class="chip"><span class="led bg-ctp-yellow"></span>{t('warnung', 'warning')} {status.counts_24h.warn}</span>
              <span class="chip"><span class="led bg-ctp-overlay0"></span>info {status.counts_24h.info}</span>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">
              {t('netz-regeln', 'network rules')}: {status.policy_rules ? t(`${status.policy_rules} regeln, ${status.policy_zones} zonen`, `${status.policy_rules} rules, ${status.policy_zones} zones`) : t('keine', 'none')} · beaconing {status.beacon ? t(`an (${fmtNum(status.beacon_pairs)} paare)`, `on (${fmtNum(status.beacon_pairs)} pairs)`) : t('aus', 'off')} · {t('schleichend', 'creeping')} {status.drift ? t(`an (${status.drift_rising} steigend)`, `on (${status.drift_rising} rising)`) : t('aus', 'off')} · mails {status.mail ? (mailKinds.length ? t('an', 'on') : t('an, aber alle arten aus', 'on, but all kinds off')) : t('aus', 'off')}
            </div>
            {#if status.mail && mailKinds.length}
              <div class="mt-1 text-[11px] text-ctp-overlay0" title="[anomaly] mail_min_severity, mail_kinds">{t('mails für', 'mails for')}: {mailKinds.join(', ')}</div>
            {/if}
          </div>
        </div>
      {/if}
    </Window>

    <Window
      title={t('Zeitleiste', 'Timeline')}
      subtitle="{t('aktive auffälligkeiten je', 'active anomalies per')} {range()[3] >= DAY ? t('tag', 'day') : range()[3] > HOUR ? `${range()[3] / HOUR} ${t('stunden', 'hours')}` : t('stunde', 'hour')} · {t('klick auf einen balken filtert die liste', 'click a bar to filter the list')}"
    >
      {#snippet actions()}
        <span class="chip"><span class="led bg-ctp-red"></span>{t('hoch', 'high')}</span>
        <span class="chip"><span class="led bg-ctp-yellow"></span>{t('warnung', 'warning')}</span>
        <span class="chip"><span class="led bg-ctp-overlay0"></span>info</span>
      {/snippet}
      <div bind:clientWidth={tlWidth} class="w-full min-w-0 overflow-hidden">
        <svg width="100%" height={TL_H} class="block select-none" role="img" aria-label={t('Zeitleiste der Auffälligkeiten', 'Timeline of anomalies')}>
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
              <title>{tlLabel(b.ts)} · {t('hoch', 'high')} {b.high} · {t('warnung', 'warning')} {b.warn} · info {b.info}</title>
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

    <Window title={t('Auffälligkeiten', 'Anomalies')} subtitle={t('wiederholungen desselben hosts werden zusammengefasst', 'repeats of the same host are merged')} bodyClass="p-0 overflow-auto max-h-[70vh]">
      {#snippet actions()}
        {#if slot}
          <button class="chip text-ctp-teal" title={t('auswahl aufheben', 'clear selection')} onclick={() => (slot = null)}>{fmtDate(slot.from)} – {fmtDate(slot.to + 1)} ✕</button>
        {/if}
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.range}>{#each RANGES as [v, l]}<option value={v}>{l}</option>{/each}</select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.kind}>
          <option value="">{t('alle arten', 'all kinds')}</option>
          {#each Object.entries(KINDS) as [k, v]}<option value={k}>{v.label}</option>{/each}
        </select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.severity}>
          <option value="">{t('alle', 'all')}</option>
          <option value="warn">{t('ab warnung', 'warning and up')}</option>
          <option value="high">{t('nur hoch', 'high only')}</option>
        </select>
        <div class="relative">
          <label class="chip cursor-pointer" title={t('auch auffälligkeiten zeigen, die eine ausnahme ausblendet', 'also show anomalies hidden by an exception')}
          ><input type="checkbox" class="accent-ctp-teal" bind:checked={filter.excepted} />{t('ausgenommene', 'excepted')}</label
        >
        <input class="input !w-40 !py-0.5 !pr-5 text-[11px]" placeholder={t('host-ip oder teil davon', 'host ip or part of it')} list="anomaly-hosts" bind:value={filter.host} />
          {#if filter.host}<button class="absolute right-1.5 top-1/2 -translate-y-1/2 text-ctp-overlay1 hover:text-ctp-text" title={t('host-filter aufheben', 'clear host filter')} onclick={() => (filter.host = '')}>✕</button>{/if}
          <datalist id="anomaly-hosts">{#each hosts as h}<option value={h}></option>{/each}</datalist>
        </div>
      {/snippet}
      <table class="table-flows">
        <thead>
          <tr>
            {#each [['severity', ''], ['ts', t('Beginn', 'Start')], ['last_ts', t('Zuletzt', 'Last')], ['kind', t('Art', 'Kind')], ['host', 'Host'], ['group', t('Gruppe', 'Group')]] as [key, label]}
              <th>
                <button class="uppercase tracking-wider hover:text-ctp-text {sort.key === key ? 'text-ctp-teal' : ''}" title={t('sortieren', 'sort')} onclick={() => sortBy(key)}
                  >{label || '●'}{sort.key === key ? (sort.dir < 0 ? ' ↓' : ' ↑') : ''}</button
                >
              </th>
            {/each}
            <th class="w-full">{t('Befund', 'Finding')}</th>
          </tr>
        </thead>
        <tbody>
          {#each sorted as r (r.id)}
            {@const kind = KINDS[r.kind] ?? KINDS.stat}
            <tr class="cursor-pointer {r.exception_id ? 'opacity-50' : ''}" onclick={() => (open = open === r.id ? null : r.id)}>
              <td title={SEVERITY[r.severity]?.[1]}><span class="led {SEVERITY[r.severity]?.[0]}"></span></td>
              <td class="tabular-nums text-ctp-subtext0" title={t('erstes fenster', 'first window')}>{fmtDate(r.ts)}</td>
              <td class="tabular-nums text-ctp-subtext0" title={t('letztes fenster', 'last window')}>
                {#if r.count > 1}{fmtDate(r.last_ts)}<span class="text-ctp-overlay0"> · {r.count}×</span>{:else}<span class="text-ctp-overlay0">–</span>{/if}
              </td>
              <td><span class="chip !py-0 {kind.color}" title={kind.title}>{kind.label}</span></td>
              <td>
                <button class="text-ctp-teal hover:underline" title={t('in der flow-suche öffnen', 'open in flow search')} onclick={(e) => (e.stopPropagation(), searchFor({ ip: r.host, ...eventRange(r) }))}>{r.host}</button>
                <button
                  class="ml-1 text-ctp-overlay0 hover:text-ctp-teal"
                  title={t('nur auffälligkeiten dieses hosts zeigen', 'show only anomalies of this host')}
                  onclick={(e) => (e.stopPropagation(), (filter.host = filter.host === r.host ? '' : r.host))}>{filter.host === r.host ? '✕' : '⧩'}</button
                >
              </td>
              <td class="text-ctp-overlay1">{r.group}</td>
              <td class="whitespace-normal text-ctp-text [overflow-wrap:anywhere]">
                {#if r.kind === 'country'}<span class="mr-1">{flag(r.detail?.cc)}</span>{/if}{#if r.kind === 'beacon'}{r.title}{:else}{@render ipText(r.title, r.geo)}{/if}
                {#if r.exception_id}<span class="chip ml-1 !py-0 text-ctp-overlay1" title={exceptionById.get(r.exception_id)?.comment}>{t('ausgenommen', 'excepted')} #{r.exception_id}</span>{/if}
                {#if r.kind === 'stat' && r.detail?.ml_score != null}
                  <span
                    class="chip ml-1 !py-0 {r.detail.ml_agrees ? 'border-ctp-mauve/60 text-ctp-mauve' : 'text-ctp-overlay0'}"
                    title={t('zweite meinung des isolation forest', 'second opinion of the isolation forest')}>ml {r.detail.ml_score.toFixed(2)} {r.detail.ml_agrees ? t('✓ stimmt zu', '✓ agrees') : t('· unauffällig', '· normal')}</span
                  >
                {/if}
              </td>
            </tr>
            {#if open === r.id}
              <tr class="!bg-ctp-mantle/50">
                <td></td>
                <td colspan="6" class="whitespace-normal text-[11px] [overflow-wrap:anywhere] text-ctp-subtext0">
                  {#if r.kind === 'stat'}
                    <div class="mb-1 text-ctp-overlay1">{t('verglichen mit', 'compared with')}: {r.detail.slot ?? '–'}</div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.features ?? [] as f}
                        <span class="chip">{f.name} <span class="text-ctp-text">{fmtValue(f)}</span> · {t('typisch', 'typical')} {fmtTypical(f)} · z {f.z}</span>
                      {/each}
                    </div>
                    {@render hostContext(r.detail.context, r.geo)}
                  {:else if r.kind === 'ml'}
                    <div class="mb-1 text-ctp-overlay1">
                      ml-score {r.detail.ml_score} – {t('stärkste abweichungen vom median aller hosts', 'largest deviations from the median of all hosts')}{r.detail.slot ? ` · ${t('eigenes profil', 'own profile')}: ${r.detail.slot}` : ''}:
                    </div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.deviations ?? [] as d}
                        <span class="chip"
                          >{d.name} <span class="text-ctp-text">{fmtValue(d)}</span> · {t('alle hosts', 'all hosts')} {fmtTypical(d)}{#if d.own_typical != null}
                            · {t('eigenes profil', 'own profile')} {fmtTypical({ ...d, typical: d.own_typical })} (z {d.own_z}){/if}</span
                        >
                      {:else}
                        <span class="text-ctp-overlay0">{t('keine einzelne kennzahl sticht heraus – die kombination (auch mit der uhrzeit) ist ungewöhnlich', 'no single metric stands out – the combination (including the time of day) is unusual')}</span>
                      {/each}
                    </div>
                    {@render hostContext(r.detail.context, r.geo)}
                  {:else if r.kind === 'scan'}
                    <div>{r.detail.attempts} {t('versuche', 'attempts')} · {r.detail.hosts} {t('ziel-hosts', 'target hosts')} · {r.detail.ports} ports</div>
                    <div class="mt-1 text-ctp-overlay1">ports: {(r.detail.sample_ports ?? []).join(', ')}</div>
                    {@render ipList(r.detail.hosts > (r.detail.sample_hosts?.length ?? 0) ? t('ziele (auszug)', 'targets (sample)') : t('ziele', 'targets'), r.detail.sample_hosts, r.geo)}
                  {:else if r.kind === 'dns'}
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.resolvers ?? [] as res}<span class="chip">{@render ipText(res.ip, r.geo)} · {res.flows} flows</span>{/each}
                    </div>
                    <div class="mt-1 text-ctp-overlay0">{t('erlaubte externe resolver', 'allowed external resolvers')}: [anomaly] dns_servers</div>
                  {:else if r.kind === 'policy'}
                    <div>{t('regel', 'rule')} <span class="text-ctp-text">{r.detail.rule}</span> ({r.detail.from} → {r.detail.to}) · {r.detail.flows} {t('verbindungen', 'connections')} · {fmtBytes(r.detail.bytes)}</div>
                    {#if r.detail.ports?.length}<div class="mt-1 text-ctp-overlay1">ports: {r.detail.ports.join(', ')}</div>{/if}
                    {@render ipList(r.detail.peers > (r.detail.sample_peers?.length ?? 0) ? t('ziele (auszug)', 'destinations (sample)') : t('ziele', 'destinations'), r.detail.sample_peers, r.geo)}
                  {:else if r.kind === 'beacon'}
                    <div>
                      {t('ziel', 'destination')} <span class="text-ctp-text">{r.detail.peer}:{r.detail.port}/{r.detail.proto}</span>
                      {#if r.detail.cc}<span class="ml-1">{flag(r.detail.cc)} {r.detail.cc}</span>{/if}
                      {#if r.detail.org}<span class="text-ctp-overlay1"> · {r.detail.org}{r.detail.asn ? ` (AS${r.detail.asn})` : ''}</span>{/if}
                    </div>
                    <div class="mt-1 flex flex-wrap gap-2">
                      <span class="chip">{r.detail.connections} {t('verbindungen', 'connections')}</span>
                      <span class="chip">{t('alle', 'every')} {fmtInterval(r.detail.interval_s)} ± {Math.round(r.detail.jitter * 100)} %</span>
                      <span class="chip">{t('je', 'each')} ~{fmtBytes(r.detail.median_bytes)}</span>
                      <span class="chip">{fmtDate(r.detail.first_ms)} – {fmtDate(r.detail.last_ms)}</span>
                      {#if r.detail.fleet_hosts > 1}
                        <span class="chip">{r.detail.fleet_hosts} {t('hosts mit gleichem muster zu', 'hosts with the same pattern to')} {r.detail.asn ? `AS${r.detail.asn}` : t('diesem netz', 'this network')}</span>
                      {/if}
                    </div>
                    <div class="mt-1 text-ctp-overlay0">{t('nur ein hinweis: auch updates, push-dienste oder geräte, die ihren status melden, verbinden sich regelmäßig', 'just a hint: updates, push services or devices reporting their status also connect regularly')}</div>
                  {:else if r.kind === 'drift'}
                    <div class="mb-1 text-ctp-overlay1">{t('verglichen mit', 'compared with')}: {r.detail.slot ?? '–'}</div>
                    <div class="flex flex-wrap gap-2">
                      <span class="chip">{r.detail.name} <span class="text-ctp-text">{fmtBytes(r.detail.value)}</span> · {t('typisch', 'typical')} {fmtBytes(r.detail.typical)}</span>
                      <span class="chip">{fmtBytes(r.detail.excess)} {t('mehr als typisch', 'more than typical')}</span>
                      <span class="chip">{t('seit', 'since')} {fmtDate(r.detail.since_ms)} · {r.detail.windows} {t('fenster', 'windows')}</span>
                      <span class="chip" title={t('summe aus min(z, z_threshold) − k je fenster, gemeldet ab h', 'sum of min(z, z_threshold) − k per window, reported from h')}>cusum {r.detail.cusum} (k {r.detail.k}, h {r.detail.h})</span>
                    </div>
                    <div class="mt-1 text-ctp-overlay0">{t('in keinem einzelnen fenster auffällig, aber über längere zeit dauerhaft leicht erhöht – auch ein neuer cloud-sync kann so aussehen', 'not unusual in any single window, but slightly raised for a long time – a new cloud sync can look like this too')}</div>
                    {@render hostContext(r.detail.context, r.geo)}
                  {:else if r.kind === 'country'}
                    <div>{flag(r.detail.cc)} {r.detail.cc} · {fmtBytes(r.detail.bytes)} {t('hochgeladen im ersten fenster', 'uploaded in the first window')}</div>
                    {#if r.detail.peers?.length}
                      <div class="mt-1 text-ctp-overlay1">{t('ziele in', 'destinations in')} {r.detail.cc}{r.detail.peer_count > r.detail.peers.length ? ` (${r.detail.peers.length} ${t('von', 'of')} ${r.detail.peer_count})` : ''}:</div>
                      {@render peerList(r.detail.peers, r.geo, r.detail.from_ms)}
                    {:else}
                      <div class="mt-1 text-ctp-overlay0">{t('ziel-ips wurden für diese ältere meldung nicht gespeichert', 'destination ips were not stored for this older report')}</div>
                    {/if}
                  {/if}
                  <div class="mt-2 flex flex-wrap items-center gap-3 text-ctp-overlay0">
                    <span>{t('zuletzt', 'last')} {fmtDate(r.last_ts)} · {t('klick auf eine ip öffnet die flow-suche für diesen zeitraum', 'click an ip to open the flow search for this period')}</span>
                    {#if r.exception_id && exceptionById.has(r.exception_id)}
                      <button class="chip hover:text-ctp-text" onclick={() => editException(exceptionById.get(r.exception_id))}>{t(`ausnahme #${r.exception_id} bearbeiten…`, `edit exception #${r.exception_id}…`)}</button>
                    {:else}
                      <button class="chip hover:text-ctp-text" title={t('solche auffälligkeiten künftig ausblenden und nicht mailen', 'hide such anomalies from now on and do not mail them')} onclick={() => exceptionFor(r)}
                        >{t('ausnahme anlegen…', 'create exception…')}</button
                      >
                    {/if}
                  </div>
                </td>
              </tr>
            {/if}
          {:else}
            <tr>
              <td colspan="7" class="py-12 text-center text-ctp-overlay0">
                {slot
                  ? t('keine auffälligkeiten in diesem abschnitt', 'no anomalies in this section')
                  : status?.learning
                    ? t('keine auffälligkeiten – die erkennung lernt noch', 'no anomalies – the detection is still learning')
                    : t('keine auffälligkeiten im gewählten zeitraum', 'no anomalies in the selected period')}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Window>

    <AnomalyExceptions list={exceptions} retentionDays={status?.event_retention_days} onedit={editException} onchanged={load} />
  {/if}
</div>

{#if dialog}
  <ExceptionDialog {...dialog} onclose={() => (dialog = null)} onsaved={() => ((dialog = null), load())} />
{/if}
