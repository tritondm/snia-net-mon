<script>
  import TopBar from './components/TopBar.svelte';
  import Dashboard from './components/Dashboard.svelte';
  import FlowSearch from './components/FlowSearch.svelte';
  import PcapAnalyzer from './components/PcapAnalyzer.svelte';
  import ArchiveBrowser from './components/ArchiveBrowser.svelte';
  import Anomalies from './components/Anomalies.svelte';
  import TokenDialog from './components/TokenDialog.svelte';
  import { ui } from './lib/state.svelte.js';
  import { live } from './lib/live.svelte.js';
  import { api } from './lib/api.js';
  import { fmtBytes } from './lib/format.js';

  let status = $state(null);

  // Workspace in der URL (#dashboard, #flows, #pcap, #archive, #anomalies) – Links und Zurück-Taste funktionieren
  const WORKSPACES = ['dashboard', 'flows', 'pcap', 'archive', 'anomalies'];
  const fromHash = () => {
    const key = location.hash.slice(1);
    if (WORKSPACES.includes(key)) ui.workspace = key;
  };
  fromHash();
  $effect(() => {
    if (location.hash.slice(1) !== ui.workspace) history.replaceState(null, '', '#' + ui.workspace);
  });

  $effect(() => {
    live.start();
    const load = () => api('/status').then((s) => (status = s)).catch(() => {});
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  });

  // Tastenkürzel wie in Hyprland: Alt+1…5 wechselt den Workspace
  function onKey(event) {
    if (!event.altKey) return;
    const target = WORKSPACES[Number(event.key) - 1];
    if (target) {
      ui.workspace = target;
      event.preventDefault();
    }
  }
</script>

<svelte:window onkeydown={onKey} onhashchange={fromHash} />

<div class="flex min-h-screen flex-col">
  <TopBar {status} />
  <main class="flex-1 p-2.5">
    {#if ui.workspace === 'dashboard'}
      <Dashboard />
    {:else if ui.workspace === 'flows'}
      <FlowSearch />
    {:else if ui.workspace === 'pcap'}
      <PcapAnalyzer />
    {:else if ui.workspace === 'anomalies'}
      <Anomalies />
    {:else}
      <ArchiveBrowser {status} />
    {/if}
  </main>
  <footer class="px-4 pb-2 text-[10px] text-ctp-overlay0">
    live {status?.retention_hours ?? 48} h · {#if status?.history}danach historie bis {fmtBytes(status.history.max_bytes)}, archive {status.history.archive_retention_days}
      tage{:else}danach automatisch gelöscht{/if} · geoip {status?.geoip ?? '–'}{#if status?.geoip_built_ms}
      · stand {new Date(status.geoip_built_ms).toLocaleDateString('de-AT')}{/if} (maxmind geolite2) · catppuccin mocha
  </footer>
</div>

{#if ui.authRequired}
  <TokenDialog />
{/if}
