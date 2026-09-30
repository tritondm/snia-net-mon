<script>
  // Historie und Archive: Füllstand der Historie, Liste der komprimierten Archive, Entpacken und Durchsuchen.
  import Window from './Window.svelte';
  import { api } from '../lib/api.js';
  import { browseSource } from '../lib/state.svelte.js';
  import { fmtBytes, fmtDate, fmtNum } from '../lib/format.js';

  let { status } = $props();
  let data = $state(null);
  let error = $state('');

  async function load() {
    try {
      data = await api('/archives');
      error = '';
    } catch (err) {
      error = err.message;
    }
  }

  // Beim Entpacken oder Komprimieren öfter nachsehen
  const busy = $derived(data?.history?.compressing || data?.archives?.some((a) => a.state === 'unpacking'));
  $effect(() => {
    load();
    const id = setInterval(load, busy ? 2000 : 15_000);
    return () => clearInterval(id);
  });

  async function open(archive) {
    try {
      await api(`/archives/${encodeURIComponent(archive.name)}/open`, { method: 'POST' });
      await load();
    } catch (err) {
      error = err.message;
    }
  }

  function browseHistory() {
    const h = data.history;
    browseSource('history', { label: 'historie', from: h.oldest_ts_ms, to: h.newest_ts_ms });
  }

  function browseArchive(a) {
    browseSource(`archive:${a.name}`, { label: `archiv ${fmtDate(a.from_ms)} – ${fmtDate(a.to_ms)}`, from: a.from_ms, to: a.to_ms });
  }

  const fill = $derived(data?.history ? Math.min(1, data.history.bytes / data.history.max_bytes) : 0);
  const STATES = {
    packed: ['gepackt', 'text-ctp-overlay1'],
    unpacking: ['wird entpackt …', 'text-ctp-yellow'],
    ready: ['entpackt', 'text-ctp-green'],
    failed: ['fehler', 'text-ctp-red'],
  };
</script>

<div class="grid gap-2.5">
  <Window title="Aufbewahrung" subtitle="live → historie → archiv">
    {#if error}<div class="mb-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
    <div class="grid gap-3 md:grid-cols-3">
      <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
        <div class="label">1 · live</div>
        <div class="text-ctp-text">letzte {status?.retention_hours ?? 48} h · {fmtNum(status?.db?.rows ?? 0)} flows</div>
        <div class="mt-1 text-[11px] text-ctp-overlay0">{fmtBytes(status?.db?.file_bytes ?? 0)} · dashboard und flow-suche</div>
      </div>

      <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
        <div class="label">2 · historie</div>
        {#if data?.enabled && data.history}
          {@const h = data.history}
          <div class="flex items-baseline gap-2">
            <span class="text-ctp-text">{fmtBytes(h.bytes)}</span>
            <span class="text-[11px] text-ctp-overlay0">von {fmtBytes(h.max_bytes)}</span>
            {#if h.compressing}<span class="chip !py-0 text-ctp-yellow"><span class="led animate-pulse-dot bg-ctp-yellow"></span>archiviert …</span>{/if}
          </div>
          <div class="mt-2 h-1.5 overflow-hidden rounded-full bg-ctp-surface0/70" title="rotation ins archiv bei {fmtBytes(h.max_bytes)}">
            <div class="h-full rounded-full" style="width: {Math.max(1, fill * 100)}%; background: linear-gradient(90deg, #94e2d5, {fill > 0.9 ? '#f38ba8' : '#cba6f7'})"></div>
          </div>
          <div class="mt-2 flex items-center gap-2 text-[11px] text-ctp-overlay0">
            {#if h.oldest_ts_ms}
              <span>{fmtDate(h.oldest_ts_ms)} – {fmtDate(h.newest_ts_ms)}</span>
              <button class="btn btn-primary ml-auto !py-0.5 text-[11px]" onclick={browseHistory}>⌕ durchsuchen</button>
            {:else}
              <span>noch leer – flows kommen nach {status?.retention_hours ?? 48} h hierher</span>
            {/if}
          </div>
        {:else if data}
          <div class="text-ctp-overlay1">abgeschaltet</div>
          <div class="mt-1 text-[11px] text-ctp-overlay0">flows werden nach dem live-fenster gelöscht ([history] enabled)</div>
        {/if}
      </div>

      <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
        <div class="label">3 · archiv</div>
        {#if data?.enabled}
          <div class="text-ctp-text">{data.archives.length} archive · {fmtBytes(data.archives.reduce((sum, a) => sum + a.bytes, 0))}</div>
          <div class="mt-1 text-[11px] text-ctp-overlay0">zstd-komprimiert · gelöscht {data.history?.archive_retention_days ?? 90} tage nach dem jüngsten flow</div>
        {/if}
      </div>
    </div>
  </Window>

  {#if data?.enabled}
    <Window title="Archive" subtitle="zum ansehen wird ein archiv entpackt (braucht platz wie die ursprüngliche historie) und nach 30 min ohne abfrage wieder entfernt" bodyClass="p-0 overflow-auto">
      <table class="table-flows">
        <thead><tr><th>Zeitraum</th><th class="text-right">Größe</th><th>Wird gelöscht</th><th>Status</th><th></th></tr></thead>
        <tbody>
          {#each data.archives as a (a.name)}
            <tr>
              <td class="text-ctp-text" title={a.name}>{fmtDate(a.from_ms)} – {fmtDate(a.to_ms)}</td>
              <td class="text-right tabular-nums">{fmtBytes(a.bytes)}</td>
              <td class="text-ctp-overlay1">{fmtDate(a.expires_ms)}</td>
              <td class={STATES[a.state]?.[1]} title={a.error ?? ''}>{STATES[a.state]?.[0] ?? a.state}</td>
              <td class="text-right">
                {#if a.state === 'ready'}
                  <button class="btn btn-primary !py-0.5 text-[11px]" onclick={() => browseArchive(a)}>⌕ durchsuchen</button>
                {:else if a.state === 'unpacking'}
                  <button class="btn !py-0.5 text-[11px]" disabled>entpacken …</button>
                {:else}
                  <button class="btn !py-0.5 text-[11px]" onclick={() => open(a)} disabled={busy}>⇪ öffnen</button>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="5" class="py-12 text-center text-ctp-overlay0">noch keine archive – sie entstehen, wenn die historie {fmtBytes(data.history?.max_bytes ?? 0)} erreicht</td></tr>
          {/each}
        </tbody>
      </table>
    </Window>
  {/if}
</div>
