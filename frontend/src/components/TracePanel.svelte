<script>
  // Mitschnitte auf der pfSense starten/stoppen, herunterladen und in der Vorschau ansehen.
  import Window from './Window.svelte';
  import { api, withToken } from '../lib/api.js';
  import { fmtBytes, fmtTime, protoColor } from '../lib/format.js';

  let { backend = 'mock' } = $props();

  let form = $state({ interface: 'igb0', filter: '', duration_secs: 30, max_packets: 10000 });
  let traces = $state([]);
  let error = $state('');
  let starting = $state(false);
  let selected = $state(null);
  let page = $state(null);
  let offset = $state(0);
  let detail = $state(null);
  const PAGE = 100;

  const PRESETS = [
    ['host …', 'host 192.168.1.10'],
    ['DNS', 'port 53'],
    ['HTTPS', 'tcp port 443'],
    ['SYN-Scans', 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'],
    ['ICMP', 'icmp or icmp6'],
    ['ohne SSH', 'not port 22'],
  ];

  async function loadTraces() {
    try {
      traces = await api('/traces');
    } catch (err) {
      error = err.message;
    }
  }

  async function start() {
    starting = true;
    error = '';
    try {
      const info = await api('/traces', { method: 'POST', body: { ...form, duration_secs: Number(form.duration_secs), max_packets: Number(form.max_packets) } });
      await loadTraces();
      select(info.id);
    } catch (err) {
      error = err.message;
    } finally {
      starting = false;
    }
  }

  async function stop(id) {
    await api(`/traces/${id}/stop`, { method: 'POST' }).catch((e) => (error = e.message));
    loadTraces();
  }

  async function remove(id) {
    if (!confirm('Mitschnitt endgültig löschen?')) return;
    await api(`/traces/${id}`, { method: 'DELETE' }).catch((e) => (error = e.message));
    if (selected === id) {
      selected = null;
      page = null;
    }
    loadTraces();
  }

  function select(id) {
    selected = id;
    offset = 0;
    detail = null;
    loadPackets();
  }

  async function loadPackets() {
    if (!selected) return;
    try {
      page = await api(`/traces/${selected}/packets`, { query: { offset, limit: PAGE } });
    } catch (err) {
      page = null;
      error = err.message;
    }
  }

  // Liste jede Sekunde aktualisieren, solange ein Trace läuft (sonst alle 10 s); Vorschau des laufenden Traces mitziehen
  const anyRunning = $derived(traces.some((t) => t.status === 'running'));
  $effect(() => {
    loadTraces();
    const id = setInterval(() => {
      loadTraces();
      if (selected && traces.find((t) => t.id === selected)?.status === 'running') loadPackets();
    }, anyRunning ? 1000 : 10_000);
    return () => clearInterval(id);
  });

  const STATUS = {
    running: ['bg-ctp-green animate-pulse-dot', 'text-ctp-green', 'läuft'],
    completed: ['bg-ctp-teal', 'text-ctp-teal', 'fertig'],
    stopped: ['bg-ctp-yellow', 'text-ctp-yellow', 'gestoppt'],
    failed: ['bg-ctp-red', 'text-ctp-red', 'fehler'],
  };

  function elapsed(t) {
    const end = t.finished_ms ?? Date.now();
    return Math.round((end - t.started_ms) / 1000);
  }
</script>

<div class="grid gap-2.5 xl:grid-cols-5">
  <div class="grid content-start gap-2.5 xl:col-span-2">
    <Window title="Neuer Mitschnitt" subtitle="tcpdump auf der pfSense">
      {#snippet actions()}
        <span class="chip {backend === 'mock' ? '!border-ctp-yellow/50 text-ctp-yellow' : 'text-ctp-green'}">backend: {backend}</span>
      {/snippet}
      <form class="grid gap-3" onsubmit={(e) => { e.preventDefault(); start(); }}>
        <div class="grid grid-cols-3 gap-3">
          <label><span class="label">Interface</span><input class="input" bind:value={form.interface} placeholder="igb0" required /></label>
          <label><span class="label">Dauer (s)</span><input class="input" type="number" min="1" max="3600" bind:value={form.duration_secs} /></label>
          <label><span class="label">max. Pakete</span><input class="input" type="number" min="1" bind:value={form.max_packets} /></label>
        </div>
        <label>
          <span class="label">BPF-Filter</span>
          <input class="input" bind:value={form.filter} placeholder="host 192.168.1.10 and port 443" />
        </label>
        <div class="flex flex-wrap gap-1.5">
          {#each PRESETS as [label, value]}
            <button type="button" class="chip hover:border-ctp-mauve/60 hover:text-ctp-mauve" onclick={() => (form.filter = value)}>{label}</button>
          {/each}
        </div>
        {#if backend === 'mock'}
          <p class="text-[11px] text-ctp-overlay0">Demo-Modus: Pakete werden simuliert, der Filter wird nur geprüft, nicht angewendet. Für echte Mitschnitte in <code class="text-ctp-peach">config.toml</code> <code class="text-ctp-peach">tracer.backend = "ssh"</code> setzen.</p>
        {/if}
        <button class="btn btn-primary justify-center" type="submit" disabled={starting}>{starting ? 'starte …' : '● capture starten'}</button>
        {#if error}<div class="rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
      </form>
    </Window>

    <Window title="Mitschnitte" subtitle="werden nach 72 h gelöscht" bodyClass="p-2">
      <ul class="space-y-1.5">
        {#each traces as t (t.id)}
          {@const s = STATUS[t.status]}
          <li class="rounded-lg border px-3 py-2 transition {selected === t.id ? 'border-ctp-teal/60 bg-ctp-teal/5 shadow-glow' : 'border-ctp-surface0 hover:border-ctp-surface2'}">
            <button class="w-full text-left" onclick={() => select(t.id)}>
              <div class="flex items-center gap-2">
                <span class="led {s[0]}"></span>
                <span class={s[1]}>{s[2]}</span>
                <span class="text-ctp-text">{t.request.interface}</span>
                <span class="ml-auto text-[11px] text-ctp-overlay1">{fmtTime(t.started_ms, true)}</span>
              </div>
              <div class="mt-0.5 truncate text-[11px] text-ctp-subtext0">{t.request.filter || 'alle Pakete'}</div>
              <div class="text-[11px] text-ctp-overlay0">{fmtBytes(t.bytes)} · {elapsed(t)}s / {t.request.duration_secs}s</div>
              {#if t.error}<div class="mt-1 text-[11px] text-ctp-red">{t.error}</div>{/if}
            </button>
            <div class="mt-2 flex gap-1.5">
              {#if t.status === 'running'}
                <button class="btn btn-danger !py-0.5 text-[11px]" onclick={() => stop(t.id)}>■ stop</button>
              {/if}
              <a class="btn !py-0.5 text-[11px]" href={withToken(`/api/traces/${t.id}/pcap`).toString()} download>⤓ pcap</a>
              <button class="btn !py-0.5 text-[11px]" onclick={() => remove(t.id)}>löschen</button>
            </div>
          </li>
        {:else}
          <li class="py-6 text-center text-ctp-overlay0">noch keine Mitschnitte</li>
        {/each}
      </ul>
    </Window>
  </div>

  <Window title="Paket-Vorschau" subtitle={page ? `${page.total} pakete` : ''} class="h-[calc(100vh-7rem)] min-h-[500px] xl:col-span-3" bodyClass="flex min-h-0 flex-col p-0">
    {#snippet actions()}
      {#if page && page.total > PAGE}
        <button class="chip" disabled={offset === 0} onclick={() => { offset = Math.max(0, offset - PAGE); loadPackets(); }}>‹</button>
        <span class="text-ctp-overlay1">{offset + 1}–{Math.min(offset + PAGE, page.total)}</span>
        <button class="chip" disabled={offset + PAGE >= page.total} onclick={() => { offset += PAGE; loadPackets(); }}>›</button>
      {/if}
    {/snippet}
    {#if page}
      <div class="min-h-0 flex-1 overflow-auto">
        <table class="table-flows">
          <thead><tr><th>#</th><th>Zeit</th><th>Proto</th><th>Zusammenfassung</th><th class="text-right">Länge</th></tr></thead>
          <tbody>
            {#each page.packets as p (p.index)}
              <tr class="cursor-pointer {detail?.index === p.index ? '!bg-ctp-mauve/10' : ''}" onclick={() => (detail = p)}>
                <td class="text-ctp-overlay0">{p.index + 1}</td>
                <td class="text-ctp-overlay1">{new Date(p.ts_us / 1000).toLocaleTimeString('de-AT', { hour12: false })}.{String(p.ts_us % 1_000_000).padStart(6, '0').slice(0, 3)}</td>
                <td style="color: {protoColor(p.proto)}">{p.proto}</td>
                <td class="max-w-[520px] truncate">{p.summary}</td>
                <td class="text-right tabular-nums">{p.len}</td>
              </tr>
            {:else}
              <tr><td colspan="5" class="py-10 text-center text-ctp-overlay0">noch keine Pakete</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if detail}
        <div class="border-t border-ctp-surface0 bg-ctp-mantle/60 p-3 text-[11px]">
          <div class="mb-1 text-ctp-subtext1">Paket {detail.index + 1} · {detail.caplen}/{detail.len} Byte</div>
          <pre class="whitespace-pre-wrap break-all text-ctp-teal/90">{detail.hex}</pre>
        </div>
      {/if}
    {:else}
      <div class="flex h-full items-center justify-center text-ctp-overlay0">Mitschnitt links auswählen</div>
    {/if}
  </Window>
</div>
