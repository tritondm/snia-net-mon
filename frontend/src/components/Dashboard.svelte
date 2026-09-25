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
  import { fmtBytes, fmtBits, serviceName, isPrivate, DIRECTIONS } from '../lib/format.js';

  let talkers = $state([]);
  let ports = $state([]);
  let protocols = $state([]);
  let graph = $state({ nodes: [], links: [] });
  let directions = $state([]);
  let sankeyLimit = $state(25);
  let error = $state('');
  let updated = $state(null);

  async function refresh() {
    const to = Date.now();
    const range = { from: to - windowMs(), to };
    const query = { ...range, dir: ui.dir };
    try {
      [directions, talkers, ports, protocols, graph] = await Promise.all([
        api('/stats/directions', { query: range }), // Übersicht immer über alle Richtungen
        api('/stats/talkers', { query: { ...query, limit: 10 } }),
        api('/stats/ports', { query: { ...query, limit: 10 } }),
        api('/stats/protocols', { query }),
        api('/stats/sankey', { query: { ...query, limit: sankeyLimit } }),
      ]);
      error = '';
      updated = new Date();
    } catch (err) {
      error = err.message;
    }
  }

  // Neu laden bei Wechsel des Zeitfensters bzw. der Sankey-Größe und alle 10 Sekunden
  $effect(() => {
    ui.window;
    ui.dir;
    sankeyLimit;
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const dirLabel = $derived(ui.dir ? ` · ${DIRECTIONS[ui.dir].icon} ${DIRECTIONS[ui.dir].label}` : '');

  const talkerItems = $derived(
    talkers.map((t) => ({
      key: t.ip,
      label: t.ip,
      sub: isPrivate(t.ip) ? 'intern' : '',
      value: t.bytes,
      display: `${fmtBytes(t.bytes)} · ø ${fmtBits(t.bps)}`,
      color: isPrivate(t.ip) ? '#74c7ec' : '#94e2d5',
      color2: isPrivate(t.ip) ? '#89b4fa' : '#a6e3a1',
      onclick: () => searchFor({ ip: t.ip }),
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
</script>

<div class="grid gap-2.5">
  <StatTiles />
  {#if error}
    <div class="window border-ctp-red/50 px-4 py-2 text-ctp-red">API-Fehler: {error}</div>
  {/if}

  <div class="grid gap-2.5 xl:grid-cols-3">
    <Window title="Durchsatz" subtitle="live · 5 min · download ↓ / upload ↑" class="xl:col-span-2" bodyClass="p-3">
      <BandwidthChart />
    </Window>
    <Window title="Verkehrsrichtung" subtitle={ui.window}>
      {#snippet actions()}
        <DirectionFilter bind:value={ui.dir} compact />
      {/snippet}
      <DirectionSummary stats={directions} />
    </Window>
  </div>

  <div class="grid gap-2.5 xl:grid-cols-3">
    <Window title="Aktive Verbindungen" subtitle="live" class="h-[560px] xl:col-span-2 xl:h-0 xl:min-h-full" bodyClass="p-0">
      <LiveTable />
    </Window>
    <div class="grid gap-2.5">
      <Window title="Protokolle" subtitle="{ui.window}{dirLabel}">
        <ProtocolDonut {protocols} />
      </Window>
      <Window title="Top Talker" subtitle="{ui.window}{dirLabel} · bytes je ip" bodyClass="p-2">
        <BarList items={talkerItems} />
      </Window>
      <Window title="Top Ports" subtitle="{ui.window}{dirLabel}" bodyClass="p-2">
        <BarList items={portItems} />
      </Window>
    </div>
  </div>

  <Window title="Flow-Diagramm" subtitle="quelle → dienst → ziel · {ui.window}{dirLabel}">
    {#snippet actions()}
      <span class="text-ctp-overlay0">verbindungen</span>
      {#each [15, 25, 50] as n}
        <button class="chip !py-0 {sankeyLimit === n ? '!border-ctp-mauve/60 text-ctp-mauve' : ''}" onclick={() => (sankeyLimit = n)}>{n}</button>
      {/each}
      {#if updated}<span class="text-ctp-overlay0">· {updated.toLocaleTimeString('de-AT')}</span>{/if}
    {/snippet}
    <SankeyChart {graph} />
  </Window>
</div>
