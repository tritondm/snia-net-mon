<script>
  import Window from './Window.svelte';
  import StatTiles from './StatTiles.svelte';
  import BandwidthChart from './BandwidthChart.svelte';
  import LiveTable from './LiveTable.svelte';
  import BarList from './BarList.svelte';
  import ProtocolDonut from './ProtocolDonut.svelte';
  import SankeyChart from './SankeyChart.svelte';
  import DirectionSummary from './DirectionSummary.svelte';
  import DirectionFilter from './DirectionFilter.svelte';
  import { api } from '../lib/api.js';
  import { ui, windowMs, searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtBits, fmtTime, serviceName, isPrivate, flag, geoTitle, DIRECTIONS } from '../lib/format.js';
  import { t, locale } from '../lib/i18n.svelte.js';

  let talkers = $state([]);
  let ports = $state([]);
  let protocols = $state([]);
  let graph = $state({ nodes: [], links: [] });
  let directions = $state([]);
  let geoStats = $state({ countries: [], asns: [], unknown_bytes: 0, enabled: true });
  let sankeyLimit = $state(25);
  let error = $state('');
  let updated = $state(null);

  let seq = 0;

  async function refresh() {
    // Nur die jüngste Anfrage zählt – sonst könnte eine langsame Live-Abfrage den markierten Bereich überschreiben
    const mine = ++seq;
    // Im Durchsatz-Chart markierter Bereich hat Vorrang vor dem Zeitfenster
    const to = ui.range?.to ?? Date.now();
    const range = { from: ui.range?.from ?? to - windowMs(), to };
    const query = { ...range, dir: ui.dir };
    try {
      const results = await Promise.all([
        api('/stats/directions', { query: range }), // Übersicht immer über alle Richtungen
        api('/stats/talkers', { query: { ...query, limit: 10 } }),
        api('/stats/ports', { query: { ...query, limit: 10 } }),
        api('/stats/protocols', { query }),
        api('/stats/sankey', { query: { ...query, limit: sankeyLimit } }),
        api('/stats/geo', { query: { ...query, limit: 10 } }),
      ]);
      if (mine !== seq) return;
      [directions, talkers, ports, protocols, graph, geoStats] = results;
      error = '';
      updated = new Date();
    } catch (err) {
      if (mine === seq) error = err.message;
    }
  }

  // Neu laden bei Wechsel von Zeitfenster, markiertem Bereich, Richtung oder Sankey-Größe; live alle 10 Sekunden,
  // ein markierter Bereich ist fest und wird nicht wiederholt abgefragt
  $effect(() => {
    ui.window;
    ui.dir;
    sankeyLimit;
    const frozen = ui.range;
    refresh();
    if (frozen) return;
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const dirLabel = $derived(ui.dir ? ` · ${DIRECTIONS[ui.dir].icon} ${DIRECTIONS[ui.dir].label}` : '');
  // Zeitangabe in den Fenstertiteln: Zeitfenster oder markierter Bereich
  const span = $derived(ui.range ? `${fmtTime(ui.range.from)}–${fmtTime(ui.range.to)}` : ui.window);

  const talkerItems = $derived(
    talkers.map((tk) => ({
      key: tk.ip,
      label: tk.ip,
      sub: isPrivate(tk.ip) ? t('intern', 'internal') : tk.geo ? `${flag(tk.geo.cc)} ${tk.geo.cc ?? ''} ${tk.geo.org ?? ''}` : '',
      title: geoTitle(tk.geo),
      value: tk.bytes,
      display: `${fmtBytes(tk.bytes)} · ø ${fmtBits(tk.bps)}`,
      color: isPrivate(tk.ip) ? '#74c7ec' : '#94e2d5',
      color2: isPrivate(tk.ip) ? '#89b4fa' : '#a6e3a1',
      onclick: () => searchFor({ ip: tk.ip }),
    })),
  );
  const portItems = $derived(
    ports.map((p) => ({
      key: `${p.proto}/${p.port}`,
      label: `${p.proto_name}/${p.port}`,
      sub: serviceName(p.port, p.proto),
      value: p.bytes,
      display: `${fmtBytes(p.bytes)} · ${p.flows} flows`,
      color: '#cba6f7',
      color2: '#f5c2e7',
      onclick: () => searchFor({ port: p.port }),
    })),
  );
  const countryItems = $derived(
    geoStats.countries.map((c) => ({
      key: c.cc,
      label: `${flag(c.cc)} ${c.country ?? c.cc}`,
      sub: `${c.ips} ip${c.ips === 1 ? '' : 's'}`,
      value: c.bytes,
      display: `${fmtBytes(c.bytes)} · ${c.flows} flows`,
      color: '#f9e2af',
      color2: '#fab387',
    })),
  );
  const asnItems = $derived(
    geoStats.asns.map((a) => ({
      key: a.asn,
      label: a.org ?? `AS${a.asn}`,
      sub: `AS${a.asn}${a.cc ? ' · ' + flag(a.cc) + ' ' + a.cc : ''}`,
      value: a.bytes,
      display: `${fmtBytes(a.bytes)} · ${a.ips} ip${a.ips === 1 ? '' : 's'}`,
      color: '#89b4fa',
      color2: '#b4befe',
    })),
  );
  const geoEmpty = $derived(
    geoStats.enabled
      ? t('keine externen Gegenstellen im Zeitfenster', 'no external peers in the time window')
      : t('GeoIP aus – GeoLite2-Datenbanken fehlen (siehe README)', 'GeoIP off – GeoLite2 databases missing (see README)'),
  );
</script>

<div class="grid gap-2.5">
  <StatTiles />
  {#if error}
    <div class="window border-ctp-red/50 px-4 py-2 text-ctp-red">{t('API-Fehler', 'API error')}: {error}</div>
  {/if}

  <div class="grid gap-2.5 xl:grid-cols-3">
    <Window title={t('Durchsatz', 'Throughput')} subtitle={ui.range ? t('angehalten · klick oder esc = live', 'paused · click or esc = live') : t('live · 5 min · bereich markieren filtert verbindungen und statistiken', 'live · 5 min · select a range to filter connections and statistics')} class="xl:col-span-2" bodyClass="p-3">
      <BandwidthChart />
    </Window>
    <Window title={t('Verkehrsrichtung', 'Traffic direction')} subtitle={span}>
      {#snippet actions()}
        <DirectionFilter bind:value={ui.dir} compact />
      {/snippet}
      <DirectionSummary stats={directions} />
    </Window>
  </div>

  <div class="grid gap-2.5 xl:grid-cols-3">
    <Window title={t('Aktive Verbindungen', 'Active connections')} subtitle={ui.range ? t('zeitbereich', 'time range') : 'live'} class="h-[560px] xl:col-span-2 xl:h-0 xl:min-h-full" bodyClass="p-0">
      <LiveTable />
    </Window>
    <div class="grid gap-2.5">
      <Window title={t('Protokolle', 'Protocols')} subtitle="{span}{dirLabel}">
        <ProtocolDonut {protocols} />
      </Window>
      <Window title="Top Talker" subtitle="{span}{dirLabel} · {t('bytes je ip', 'bytes per ip')}" bodyClass="p-2">
        <BarList items={talkerItems} />
      </Window>
      <Window title="Top Ports" subtitle="{span}{dirLabel}" bodyClass="p-2">
        <BarList items={portItems} />
      </Window>
    </div>
  </div>

  <div class="grid gap-2.5 xl:grid-cols-2">
    <Window title={t('Länder', 'Countries')} subtitle="{span}{dirLabel} · {t('externe gegenstellen (geoip)', 'external peers (geoip)')}" bodyClass="p-2">
      <BarList items={countryItems} empty={geoEmpty} />
      {#if geoStats.unknown_bytes > 0}
        <div class="px-2 pt-1 text-[11px] text-ctp-overlay0">{t('ohne zuordnung', 'unassigned')}: {fmtBytes(geoStats.unknown_bytes)}</div>
      {/if}
    </Window>
    <Window title={t('Netze', 'Networks')} subtitle="{span}{dirLabel} · {t('autonome systeme (asn)', 'autonomous systems (asn)')}" bodyClass="p-2">
      <BarList items={asnItems} empty={geoEmpty} />
    </Window>
  </div>

  <Window title={t('Flow-Diagramm', 'Flow diagram')} subtitle="{t('quelle → dienst → ziel', 'source → service → destination')} · {span}{dirLabel}">
    {#snippet actions()}
      <span class="text-ctp-overlay0">{t('verbindungen', 'connections')}</span>
      {#each [15, 25, 50] as n}
        <button class="chip !py-0 {sankeyLimit === n ? '!border-ctp-mauve/60 text-ctp-mauve' : ''}" onclick={() => (sankeyLimit = n)}>{n}</button>
      {/each}
      {#if updated}<span class="text-ctp-overlay0">· {updated.toLocaleTimeString(locale())}</span>{/if}
    {/snippet}
    <SankeyChart {graph} />
  </Window>
</div>
