<script>
  import { ui, WINDOWS } from '../lib/state.svelte.js';
  import { live } from '../lib/live.svelte.js';
  import { fmtBits, fmtNum, DIRECTIONS } from '../lib/format.js';

  let { status } = $props();
  let clock = $state(new Date());
  $effect(() => {
    const id = setInterval(() => (clock = new Date()), 1000);
    return () => clearInterval(id);
  });

  const workspaces = [
    { key: 'dashboard', n: 1, label: 'dashboard' },
    { key: 'flows', n: 2, label: 'flows' },
    { key: 'pcap', n: 3, label: 'pcap' },
    { key: 'archive', n: 4, label: 'archiv' },
    { key: 'anomalies', n: 5, label: 'anomalien' },
  ];

  // Auffälligkeiten der letzten 24 h als Zähler am Workspace (rot bei "hoch", gelb bei Warnungen)
  const alerts = $derived(status?.anomalies_24h);
  const alertCount = $derived((alerts?.high ?? 0) + (alerts?.warn ?? 0));

  const drops = $derived((live.collector?.dropped_flows ?? 0) + (live.collector?.parse_errors ?? 0));
</script>

<!-- Waybar-artige Leiste: Workspaces links, Zeitfenster mittig, System-Indikatoren rechts -->
<nav class="window !animate-none mx-2.5 mt-2.5 flex flex-wrap items-center gap-3 rounded-window px-3 py-2">
  <div class="flex items-center gap-2 pr-2">
    <svg viewBox="0 0 32 32" class="h-5 w-5"><path d="M4 21l6-8 5 6 4-4 9 9" fill="none" stroke="url(#g)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" /><defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="#94e2d5" /><stop offset="1" stop-color="#cba6f7" /></linearGradient></defs></svg>
    <span class="font-semibold tracking-tight text-ctp-text">snia<span class="text-ctp-teal">·</span>net<span class="text-ctp-mauve">·</span>mon</span>
  </div>

  <div class="flex items-center gap-1 rounded-lg bg-ctp-mantle/60 p-1">
    {#each workspaces as ws}
      <button
        class="rounded-md px-2.5 py-0.5 transition {ui.workspace === ws.key
          ? 'bg-ctp-teal/20 text-ctp-teal shadow-glow'
          : 'text-ctp-overlay1 hover:bg-ctp-surface0 hover:text-ctp-text'}"
        onclick={() => (ui.workspace = ws.key)}
        title="Alt+{ws.n}"
      >
        <span class="text-ctp-overlay0">{ws.n}</span> {ws.label}
        {#if ws.key === 'anomalies' && alertCount > 0}
          <span
            class="ml-0.5 rounded px-1 text-[10px] {alerts.high > 0 ? 'bg-ctp-red/20 text-ctp-red' : 'bg-ctp-yellow/20 text-ctp-yellow'}"
            title="{alerts.high} hoch, {alerts.warn} warnung in den letzten 24 h">{alertCount}</span
          >
        {/if}
      </button>
    {/each}
  </div>

  <div class="mx-auto flex items-center gap-1 rounded-lg bg-ctp-mantle/60 p-1" title="Zeitfenster für Statistiken">
    {#each WINDOWS as w}
      <button
        class="rounded-md px-2 py-0.5 transition {ui.window === w.key ? 'bg-ctp-mauve/20 text-ctp-mauve' : 'text-ctp-overlay1 hover:text-ctp-text'}"
        onclick={() => (ui.window = w.key)}>{w.label}</button
      >
    {/each}
  </div>

  <div class="flex flex-wrap items-center gap-2">
    <span class="chip" title="WebSocket-Live-Stream">
      <span class="led {live.connected ? 'animate-pulse-dot bg-ctp-green' : 'bg-ctp-red'}"></span>
      {live.connected ? 'live' : 'offline'}
    </span>
    <span class="chip" title="Download (letzte Sekunde)"><span style="color: {DIRECTIONS.in.color}">↓</span>{fmtBits((live.current.bytes_in ?? 0) * 8)}</span>
    <span class="chip" title="Upload (letzte Sekunde)"><span style="color: {DIRECTIONS.out.color}">↑</span>{fmtBits((live.current.bytes_out ?? 0) * 8)}</span>
    <span class="chip" title="Flows pro Sekunde"><span class="text-ctp-mauve">≋</span>{fmtNum(live.current.flows)}/s</span>
    <span class="chip {drops > 0 ? '!border-ctp-red/60 text-ctp-red' : ''}" title="Verworfene Flows + Parse-Fehler seit Start">
      <span class="led {drops > 0 ? 'bg-ctp-red' : 'bg-ctp-green'}"></span>drop {fmtNum(drops)}
    </span>
    <span class="chip" title="Flows in der Live-Datenbank / Live-Fenster">
      <span class="text-ctp-sapphire">◫</span>{fmtNum(status?.db?.rows ?? 0)} · {status?.retention_hours ?? 48}h
    </span>
    <span class="chip text-ctp-text">{clock.toLocaleTimeString('de-AT', { hour12: false })}</span>
  </div>
</nav>
