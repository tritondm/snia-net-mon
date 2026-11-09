<script>
  // Sicherheitsanalyse: Flows nach IP/CIDR, Port, Protokoll und Zeitfenster durchsuchen.
  import Window from './Window.svelte';
  import { api } from '../lib/api.js';
  import { ui, windowMs } from '../lib/state.svelte.js';
  import { fmtBytes, fmtTime, fmtDate, serviceName, isPrivate, protoColor, toLocalInput, fromLocalInput, geoTitle, DIRECTIONS } from '../lib/format.js';
  import DirectionFilter from './DirectionFilter.svelte';
  import GeoTag from './GeoTag.svelte';
  import TalkerConnections from './TalkerConnections.svelte';
  import { t } from '../lib/i18n.svelte.js';

  let form = $state({ ip: '', src: '', dst: '', port: '', proto: '', dir: '', from: '', to: '', limit: 500 });
  let rows = $state([]);
  let loading = $state(false);
  let error = $state('');
  let searched = $state(false);
  let talkers = $state([]);
  let connections = $state([]);
  let talkerLimit = $state(10);

  // Datenquellen: live, Historie und entpackte Archive (aus /api/archives)
  let sources = $state([]);
  async function loadSources() {
    try {
      const data = await api('/archives');
      const list = [];
      if (data.history?.oldest_ts_ms) list.push({ value: 'history', label: t('historie', 'history'), from: data.history.oldest_ts_ms, to: data.history.newest_ts_ms });
      for (const a of data.archives.filter((a) => a.state === 'ready')) {
        list.push({ value: `archive:${a.name}`, label: `${t('archiv', 'archive')} ${fmtDate(a.from_ms)} – ${fmtDate(a.to_ms)}`, from: a.from_ms, to: a.to_ms });
      }
      sources = list;
    } catch {
      sources = [];
    }
  }
  $effect(() => {
    ui.source;
    loadSources();
  });

  function selectSource(value) {
    ui.source = value;
    ui.sourceInfo = sources.find((s) => s.value === value) ?? null;
    form.from = '';
    form.to = '';
    rows = [];
    talkers = [];
    connections = [];
    searched = false;
  }

  // Bezugszeitpunkt für Zeitangaben ohne Datum: jetzt (live) oder das Ende der Historie bzw. des Archivs
  const anchor = () => (ui.source && ui.sourceInfo?.to ? ui.sourceInfo.to : Date.now());

  const PROTOS = $derived([['', t('alle', 'all')], ['6', 'TCP'], ['17', 'UDP'], ['1', 'ICMP'], ['58', 'ICMPv6'], ['50', 'ESP'], ['47', 'GRE']]);

  async function search() {
    loading = true;
    error = '';
    try {
      const to = fromLocalInput(form.to) || anchor();
      const from = fromLocalInput(form.from) || to - windowMs();
      if (ui.source) {
        // Historie/Archiv: verwendeten Zeitraum anzeigen, er liegt nicht bei „jetzt“
        form.from = toLocalInput(from);
        form.to = toLocalInput(to);
      }
      const filter = { source: ui.source, ip: form.ip.trim(), src: form.src.trim(), dst: form.dst.trim(), port: form.port, proto: form.proto, dir: form.dir, from, to };
      // Grafik unten: Top Talker mit ihren Verbindungen – aggregiert über alle Treffer, nicht nur die angezeigten Zeilen
      [rows, talkers, connections] = await Promise.all([
        api('/flows', { query: { ...filter, limit: form.limit } }),
        api('/stats/talkers', { query: { ...filter, limit: talkerLimit } }),
        api('/stats/peers', { query: { ...filter, limit: 2000 } }),
      ]);
      searched = true;
    } catch (err) {
      error = err.message;
      rows = [];
      talkers = [];
      connections = [];
    } finally {
      loading = false;
    }
  }

  function reset() {
    form = { ip: '', src: '', dst: '', port: '', proto: '', dir: '', from: '', to: '', limit: 500 };
    rows = [];
    talkers = [];
    connections = [];
    searched = false;
  }

  function pickIp(ip) {
    form.ip = ip;
    search();
  }

  function setRange(hours) {
    const end = anchor();
    form.from = toLocalInput(end - hours * 3_600_000);
    form.to = toLocalInput(end);
  }

  // Sprung aus dem Dashboard (Klick auf IP/Port) übernimmt die Werte und sucht sofort
  let lastNonce = 0;
  $effect(() => {
    if (ui.searchNonce !== lastNonce) {
      lastNonce = ui.searchNonce;
      form.ip = ui.search.ip;
      form.port = ui.search.port;
      form.from = ui.search.from ? toLocalInput(ui.search.from) : '';
      form.to = ui.search.to ? toLocalInput(ui.search.to) : '';
      search();
    }
  });

  const totals = $derived(rows.reduce((acc, r) => ({ bytes: acc.bytes + r.bytes, packets: acc.packets + r.packets }), { bytes: 0, packets: 0 }));

  function exportCsv() {
    const header = t(
      'zeit,richtung,quelle,quellport,quelle_land,quelle_asn,ziel,zielport,ziel_land,ziel_asn,proto,bytes,pakete,tcp_flags,exporter',
      'time,direction,source,source_port,source_country,source_asn,destination,destination_port,destination_country,destination_asn,proto,bytes,packets,tcp_flags,exporter',
    );
    const lines = rows.map((r) =>
      [new Date(r.ts).toISOString(), r.direction, r.src_ip, r.src_port, r.src_geo?.cc ?? '', r.src_geo?.asn ?? '', r.dst_ip, r.dst_port, r.dst_geo?.cc ?? '', r.dst_geo?.asn ?? '', r.proto_name, r.bytes, r.packets, r.tcp_flags, r.exporter].join(','),
    );
    const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `flows-${ui.source ? ui.source.replace(/^archive:/, '').replace(/\.db\.zst$/, '') + '-' : ''}${new Date().toISOString().slice(0, 19)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function tcpFlags(f) {
    return [[2, 'S'], [16, 'A'], [1, 'F'], [4, 'R'], [8, 'P'], [32, 'U']].filter(([bit]) => f & bit).map(([, c]) => c).join('') || '·';
  }
</script>

<div class="grid gap-2.5">
  <Window title={t('Flow-Suche', 'Flow search')} subtitle={t('ip/cidr trifft quelle oder ziel · leere felder = alle', 'ip/cidr matches source or destination · empty fields = all')}>
    {#snippet actions()}
      <label class="flex items-center gap-2 text-ctp-overlay1" title={t('Datenquelle: Live-Datenbank, Historie oder ein entpacktes Archiv (Workspace archiv)', 'Data source: live database, history or an unpacked archive (archive workspace)')}>{t('daten', 'data')}
        <select class="input !w-auto !py-0.5 text-[11px] {ui.source ? '!border-ctp-peach/60 text-ctp-peach' : ''}" value={ui.source} onchange={(e) => selectSource(e.currentTarget.value)}>
          <option value="">live</option>
          {#each sources as src (src.value)}<option value={src.value}>{src.label}</option>{/each}
          {#if ui.source && !sources.some((s) => s.value === ui.source)}<option value={ui.source}>{ui.sourceInfo?.label ?? ui.source}</option>{/if}
        </select>
      </label>
    {/snippet}
    {#if ui.source && ui.sourceInfo}
      <div class="mb-3 rounded-lg border border-ctp-peach/40 bg-ctp-peach/10 px-3 py-2 text-ctp-peach">
        {ui.sourceInfo.label} · {t('enthält', 'contains')} {fmtDate(ui.sourceInfo.from)} – {fmtDate(ui.sourceInfo.to)} · {t('ohne Von/Bis wird das Ende des Zeitraums durchsucht', 'without From/To the end of the period is searched')}
      </div>
    {/if}
    <form class="grid gap-3 md:grid-cols-4 xl:grid-cols-8" onsubmit={(e) => { e.preventDefault(); search(); }}>
      <label class="xl:col-span-2"><span class="label">IP / CIDR</span><input class="input" placeholder="192.168.1.0/24" bind:value={form.ip} /></label>
      <label><span class="label">{t('Quelle', 'Source')}</span><input class="input" placeholder="10.0.0.5" bind:value={form.src} /></label>
      <label><span class="label">{t('Ziel', 'Destination')}</span><input class="input" placeholder="2001:db8::/32" bind:value={form.dst} /></label>
      <label><span class="label">Port</span><input class="input" type="number" min="0" max="65535" placeholder="443" bind:value={form.port} /></label>
      <label><span class="label">{t('Protokoll', 'Protocol')}</span>
        <select class="input" bind:value={form.proto}>{#each PROTOS as [v, l]}<option value={v}>{l}</option>{/each}</select>
      </label>
      <label><span class="label">{t('Von', 'From')}</span><input class="input" type="datetime-local" bind:value={form.from} /></label>
      <label><span class="label">{t('Bis', 'To')}</span><input class="input" type="datetime-local" bind:value={form.to} /></label>
      <div class="flex flex-wrap items-center gap-2 md:col-span-4 xl:col-span-8">
        <DirectionFilter bind:value={form.dir} />
        <button class="btn btn-primary" type="submit" disabled={loading}>{loading ? t('suche …', 'searching …') : t('⌕ suchen', '⌕ search')}</button>
        <button class="btn" type="button" onclick={reset}>{t('zurücksetzen', 'reset')}</button>
        <span class="ml-2 text-ctp-overlay0">{t('schnell', 'quick')}:</span>
        {#each [[1, '1h'], [6, '6h'], [24, '24h'], [72, '72h']] as [h, l]}
          <button class="chip hover:text-ctp-teal" type="button" onclick={() => setRange(h)}>{t('letzte', 'last')} {l}</button>
        {/each}
        <span class="text-ctp-overlay0">({t('ohne Angabe: Zeitfenster oben', 'if empty: time window above')}, {ui.window}{ui.source ? t(', bis zum Ende der Daten', ', up to the end of the data') : ''})</span>
        <label class="ml-auto flex items-center gap-2 text-ctp-overlay1">max
          <select class="input !w-24 !py-1" bind:value={form.limit}>{#each [100, 500, 1000, 5000] as n}<option value={n}>{n}</option>{/each}</select>
        </label>
      </div>
    </form>
    {#if error}<div class="mt-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
  </Window>

  <Window title={t('Ergebnis', 'Results')} subtitle={searched ? `${rows.length} flows · ${fmtBytes(totals.bytes)} · ${totals.packets} ${t('pakete', 'packets')}` : ''} class="h-[620px]" bodyClass="p-0 overflow-auto">
    {#snippet actions()}
      <button class="btn !py-0.5 text-[11px]" onclick={exportCsv} disabled={!rows.length}>⤓ csv</button>
    {/snippet}
    <table class="table-flows">
      <thead><tr><th>{t('Zeit', 'Time')}</th><th title={t('Richtung', 'Direction')}>{t('Ri.', 'Dir')}</th><th>Proto</th><th>{t('Quelle', 'Source')}</th><th>{t('Ziel', 'Destination')}</th><th title={t('Organisation der externen Gegenstelle (GeoIP/ASN)', 'Organisation of the external peer (GeoIP/ASN)')}>{t('Netz', 'Network')}</th><th>{t('Dienst', 'Service')}</th><th>Flags</th><th class="text-right">Bytes</th><th class="text-right">{t('Pakete', 'Packets')}</th><th class="text-right">{t('Dauer', 'Duration')}</th></tr></thead>
      <tbody>
        {#each rows as r (r.id)}
          <tr>
            <td class="text-ctp-overlay1">{fmtTime(r.ts, true)}</td>
            <td class="text-base leading-none" style="color: {DIRECTIONS[r.direction]?.color}" title={DIRECTIONS[r.direction]?.title}>{DIRECTIONS[r.direction]?.icon}</td>
            <td><span style="color: {protoColor(r.proto_name)}">{r.proto_name}</span></td>
            <td><span class={isPrivate(r.src_ip) ? 'text-ctp-sapphire' : ''}>{r.src_ip}</span><span class="text-ctp-overlay0">:{r.src_port}</span> <GeoTag geo={r.src_geo} /></td>
            <td><span class={isPrivate(r.dst_ip) ? 'text-ctp-sapphire' : ''}>{r.dst_ip}</span><span class="text-ctp-overlay0">:{r.dst_port}</span> <GeoTag geo={r.dst_geo} /></td>
            <td class="max-w-[14rem] truncate text-[11px] text-ctp-overlay1" title={geoTitle(r.dst_geo ?? r.src_geo)}>{(r.dst_geo ?? r.src_geo)?.org ?? ''}</td>
            <td class="text-ctp-mauve">{serviceName(Math.min(r.src_port, r.dst_port), r.proto)}</td>
            <td class="text-ctp-peach">{r.proto === 6 ? tcpFlags(r.tcp_flags) : ''}</td>
            <td class="text-right tabular-nums">{fmtBytes(r.bytes)}</td>
            <td class="text-right tabular-nums">{r.packets}</td>
            <td class="text-right tabular-nums text-ctp-overlay1">{((r.ts - r.start_ts) / 1000).toFixed(1)}s</td>
          </tr>
        {:else}
          <tr><td colspan="11" class="py-16 text-center text-ctp-overlay0">{searched ? t('keine Treffer', 'no matches') : t('Filter setzen und suchen – oder im Dashboard auf eine IP klicken', 'set filters and search – or click an IP in the dashboard')}</td></tr>
        {/each}
      </tbody>
    </table>
  </Window>

  <Window title={t('Top Talker · Verbindungen', 'Top talkers · connections')} subtitle={searched ? t('bytes je ip · segmente = stärkste gegenstellen · ↑ gesendet ↓ empfangen', 'bytes per ip · segments = biggest peers · ↑ sent ↓ received') : ''}>
    {#snippet actions()}
      <span class="text-ctp-overlay0">talker</span>
      {#each [6, 10, 20] as n}
        <button class="chip !py-0 {talkerLimit === n ? '!border-ctp-mauve/60 text-ctp-mauve' : ''}" onclick={() => { talkerLimit = n; if (searched) search(); }}>{n}</button>
      {/each}
    {/snippet}
    <TalkerConnections {talkers} {connections} onpick={pickIp} />
  </Window>
</div>
