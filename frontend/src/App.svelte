<script>
  import TopBar from './components/TopBar.svelte';
  import Dashboard from './components/Dashboard.svelte';
  import FlowSearch from './components/FlowSearch.svelte';
  import TracePanel from './components/TracePanel.svelte';
  import TokenDialog from './components/TokenDialog.svelte';
  import { ui } from './lib/state.svelte.js';
  import { live } from './lib/live.svelte.js';
  import { api } from './lib/api.js';

  let status = $state(null);

  // Workspace in der URL (#dashboard, #flows, #trace) – Links und Zurück-Taste funktionieren
  const WORKSPACES = ['dashboard', 'flows', 'trace'];
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

  // Tastenkürzel wie in Hyprland: Alt+1/2/3 wechselt den Workspace
  function onKey(event) {
    if (!event.altKey) return;
    const target = { 1: 'dashboard', 2: 'flows', 3: 'trace' }[event.key];
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
    {:else}
      <TracePanel backend={status?.tracer_backend ?? 'mock'} />
    {/if}
  </main>
  <footer class="px-4 pb-2 text-[10px] text-ctp-overlay0">
    daten werden nach {status?.retention_hours ?? 72} h automatisch gelöscht · catppuccin mocha
  </footer>
</div>

{#if ui.authRequired}
  <TokenDialog />
{/if}
