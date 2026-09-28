<script>
  // PCAP-Analyse: Capture-Datei hochladen (pcap/pcapng, z. B. aus pfSense → Diagnostics → Packet Capture oder Wireshark),
  // Ergebnis mit Protokollen, Anwendungen, Endpunkten inkl. GeoIP, DNS, HTTP und Auffälligkeiten anzeigen.
  import Window from './Window.svelte';
  import BarList from './BarList.svelte';
  import GeoTag from './GeoTag.svelte';
  import { api, withToken } from '../lib/api.js';
  import { ui, searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtTime, isPrivate, geoTitle, flag, protoColor } from '../lib/format.js';

  let history = $state([]);
  let result = $state(null);
  let busy = $state(null); // { name, progress (0..1), phase: 'upload' | 'analyse' }
  let error = $state('');
  let dragging = $state(false);
  let fileInput;

  async function loadHistory() {
    try {
      history = await api('/pcap');
    } catch (err) {
      error = err.message;
    }
  }
  $effect(() => {
    loadHistory();
  });

  // Upload per XHR – nur so gibt es einen Fortschritt beim Hochladen großer Dateien
  function upload(file) {
    if (!file || busy) return;
    error = '';
    busy = { name: file.name, progress: 0, phase: 'upload' };
    const xhr = new XMLHttpRequest();
    const url = withToken('/api/pcap');
    url.searchParams.set('name', file.name);
    xhr.open('POST', url);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) busy = { ...busy, progress: e.loaded / e.total, phase: e.loaded >= e.total ? 'analyse' : 'upload' };
    };
    xhr.upload.onload = () => (busy = { ...busy, progress: 1, phase: 'analyse' });
    xhr.onload = () => {
      busy = null;
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* keine JSON-Antwort */
      }
      if (xhr.status === 401) ui.authRequired = true;
      if (xhr.status >= 200 && xhr.status < 300 && body) {
        result = body;
        loadHistory();
      } else {
        error = body?.error ?? `Upload fehlgeschlagen (HTTP ${xhr.status})`;
      }
    };
    xhr.onerror = () => {
      busy = null;
      error = 'Verbindung zum Server abgebrochen';
    };
    xhr.send(file);
  }

  async function open(id) {
    error = '';
    try {
      result = { ...(await api(`/pcap/${id}`)), id };
    } catch (err) {
      error = err.message;
    }
  }

  async function remove(id) {
    if (!confirm('Analyse löschen?')) return;
    try {
      await api(`/pcap/${id}`, { method: 'DELETE' });
      if (result?.id === id) result = null;
      loadHistory();
    } catch (err) {
      error = err.message;
    }
  }

  function onDrop(event) {
    event.preventDefault();
    dragging = false;
    upload(event.dataTransfer?.files?.[0]);
  }

  const APP_COLORS = ['#94e2d5', '#cba6f7', '#89b4fa', '#fab387', '#f9e2af', '#a6e3a1', '#f5c2e7', '#74c7ec', '#eba0ac'];
  const SEVERITY = { high: ['hoch', 'text-ctp-red border-ctp-red/50 bg-ctp-red/10'], medium: ['mittel', 'text-ctp-peach border-ctp-peach/50 bg-ctp-peach/10'], low: ['niedrig', 'text-ctp-yellow border-ctp-yellow/50 bg-ctp-yellow/10'] };

  const r = $derived(result);
  const protoItems = $derived(
    (r?.protocols ?? []).map((p) => ({
      key: p.name,
      label: p.name,
      sub: `${p.pct}% der pakete`,
      value: p.bytes,
      display: `${fmtBytes(p.bytes)} · ${p.packets} pkt`,
      color: protoColor(p.name),
      color2: protoColor(p.name),
    })),
  );
  const appItems = $derived(
    (r?.apps?.top ?? []).map((a, i) => ({
      key: a.app,
      label: a.label,
      sub: Object.entries(a.signals).filter(([, n]) => n).map(([s]) => s).join(' · '),
      title: a.domains.join(', '),
      value: a.bytes,
      display: `${fmtBytes(a.bytes)} · ${a.pct}%`,
      color: APP_COLORS[i % APP_COLORS.length],
      color2: APP_COLORS[(i + 1) % APP_COLORS.length],
    })),
  );
  const sourceItems = $derived(
    (r?.top_ips ?? []).map((t) => ({
      key: t.src,
      label: t.src,
      sub: isPrivate(t.src) ? 'intern' : '',
      value: t.bytes,
      display: `${fmtBytes(t.bytes)} · ${t.pkts} pkt`,
      color: isPrivate(t.src) ? '#74c7ec' : '#94e2d5',
      color2: isPrivate(t.src) ? '#89b4fa' : '#a6e3a1',
      onclick: () => searchFor({ ip: t.src }),
    })),
  );
  const portItems = $derived(
    (r?.top_ports ?? []).map((p) => ({
      key: p.port,
      label: `${p.protocol}/${p.port}`,
      sub: p.name === 'custom' ? '' : p.name,
      value: p.pkts,
      display: `${p.pkts} pkt · ${fmtBytes(p.bytes)}`,
      color: '#cba6f7',
      color2: '#f5c2e7',
    })),
  );
  const flowItems = $derived(
    (r?.top_flows ?? []).map((f) => ({
      key: f.src_dst_dstport,
      label: f.src_dst_dstport.replace('->', ' → '),
      value: f.bytes,
      display: `${fmtBytes(f.bytes)} · ${f.pkts} pkt`,
      color: '#89b4fa',
      color2: '#b4befe',
    })),
  );
  // Endpunkte je Land zusammengefasst (nur öffentliche IPs mit GeoIP-Treffer)
  const countryItems = $derived.by(() => {
    const by = new Map();
    for (const e of r?.endpoints ?? []) {
      if (!e.geo?.cc) continue;
      const c = by.get(e.geo.cc) ?? { cc: e.geo.cc, country: e.geo.country, bytes: 0, ips: 0 };
      c.bytes += e.total_bytes;
      c.ips += 1;
      by.set(e.geo.cc, c);
    }
    return [...by.values()]
      .sort((a, b) => b.bytes - a.bytes)
      .map((c) => ({ key: c.cc, label: `${flag(c.cc)} ${c.country ?? c.cc}`, sub: `${c.ips} ip${c.ips === 1 ? '' : 's'}`, value: c.bytes, display: fmtBytes(c.bytes), color: '#f9e2af', color2: '#fab387' }));
  });
  const timelineMax = $derived(Math.max(1, ...(r?.timeline?.values ?? []).map((v) => v[0])));
</script>

<div class="grid gap-2.5">
  <div class="grid gap-2.5 xl:grid-cols-3">
    <Window title="PCAP-Analyse" subtitle="pcap / pcapng · pfsense packet capture, wireshark, tcpdump" class="xl:col-span-2">
      <button
        class="flex w-full flex-col items-center justify-center gap-2 rounded-window border-2 border-dashed px-4 py-8 text-center transition
          {dragging ? 'border-ctp-teal bg-ctp-teal/10' : 'border-ctp-surface1 hover:border-ctp-mauve/60 hover:bg-ctp-surface0/30'}"
        onclick={() => fileInput.click()}
        ondragover={(e) => { e.preventDefault(); dragging = true; }}
        ondragleave={() => (dragging = false)}
        ondrop={onDrop}
        disabled={!!busy}
      >
        {#if busy}
          <div class="text-ctp-text">{busy.phase === 'upload' ? 'lade hoch' : 'analysiere'} · {busy.name}</div>
          <div class="h-1.5 w-full max-w-md overflow-hidden rounded-full bg-ctp-surface0">
            <div class="h-full rounded-full bg-gradient-to-r from-ctp-teal to-ctp-mauve transition-[width] {busy.phase === 'analyse' ? 'animate-pulse' : ''}" style="width: {busy.progress * 100}%"></div>
          </div>
          <div class="text-[11px] text-ctp-overlay0">{busy.phase === 'upload' ? `${Math.round(busy.progress * 100)} %` : 'der rust-kern wertet die pakete aus …'}</div>
        {:else}
          <div class="text-2xl text-ctp-teal">⬆</div>
          <div class="text-ctp-text">Capture-Datei hierher ziehen oder klicken</div>
          <div class="text-[11px] text-ctp-overlay0">
            .pcap / .pcapng · ethernet, vlan, raw ip, linux sll, pflog, loopback · die datei wird nach der analyse gelöscht, das ergebnis nach der retention
          </div>
        {/if}
      </button>
      <input bind:this={fileInput} type="file" accept=".pcap,.pcapng,.cap,.dmp" hidden onchange={(e) => { upload(e.currentTarget.files?.[0]); e.currentTarget.value = ''; }} />
      {#if error}<div class="mt-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
    </Window>

    <Window title="Verlauf" subtitle="{history.length} analysen" class="h-[240px] xl:h-auto" bodyClass="p-0 overflow-auto">
      <table class="table-flows">
        <thead><tr><th>Datei</th><th class="text-right">Pakete</th><th class="text-right">Größe</th><th>Zeit</th><th></th></tr></thead>
        <tbody>
          {#each history as h (h.id)}
            <tr class="cursor-pointer {result?.id === h.id ? 'bg-ctp-mauve/10' : ''}" onclick={() => open(h.id)}>
              <td class="max-w-[12rem] truncate text-ctp-text" title={h.name}>{h.name}</td>
              <td class="text-right tabular-nums">{h.packets}</td>
              <td class="text-right tabular-nums">{fmtBytes(h.size)}</td>
              <td class="text-ctp-overlay1">{fmtTime(h.created_ms, true)}</td>
              <td><button class="text-ctp-overlay0 hover:text-ctp-red" title="löschen" onclick={(e) => { e.stopPropagation(); remove(h.id); }}>✕</button></td>
            </tr>
          {:else}
            <tr><td colspan="5" class="py-8 text-center text-ctp-overlay0">noch keine analysen</td></tr>
          {/each}
        </tbody>
      </table>
    </Window>
  </div>

  {#if r}
    <!-- Kennzahlen -->
    <div class="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-6">
      {#each [['datei', r.filename, fmtBytes(r.file_size ?? 0)], ['pakete', r.total.packets.toLocaleString('de-AT'), `v4 ${r.protocol_split.IPv4} · v6 ${r.protocol_split.IPv6}`], ['bytes', fmtBytes(r.total.bytes), ''], ['dauer', r.total.duration_human, r.total.start_ms ? `${fmtTime(r.total.start_ms, true)} – ${fmtTime(r.total.end_ms)}` : ''], ['ø pakete/s', r.total.pps, ''], ['ø bandbreite', r.total.mbps, '']] as [label, value, sub]}
        <div class="window px-4 py-3">
          <div class="text-[10px] uppercase tracking-widest text-ctp-overlay1">{label}</div>
          <div class="truncate text-lg font-semibold text-ctp-text" title={String(value)}>{value}</div>
          {#if sub}<div class="truncate text-[11px] text-ctp-overlay0">{sub}</div>{/if}
        </div>
      {/each}
    </div>

    <Window title="Zeitverlauf" subtitle="pakete je {r.timeline.seconds_per_bucket}s">
      {#if r.timeline.values.length}
        <div class="flex h-28 items-end gap-px">
          {#each r.timeline.values as [pct, ts]}
            <div class="group relative flex-1 rounded-t bg-gradient-to-t from-ctp-teal/40 to-ctp-teal hover:from-ctp-mauve/40 hover:to-ctp-mauve" style="height: {Math.max(1, (pct / timelineMax) * 100)}%" title="{fmtTime(ts * 1000)} · {pct.toFixed(0)}% vom maximum"></div>
          {/each}
        </div>
        <div class="mt-1 flex justify-between text-[10px] text-ctp-overlay0"><span>{fmtTime(r.timeline.values[0][1] * 1000, true)}</span><span>{r.total.end_ms ? fmtTime(r.total.end_ms) : ''}</span></div>
      {:else}
        <div class="py-6 text-center text-ctp-overlay0">zu kurzer mitschnitt für einen zeitverlauf</div>
      {/if}
    </Window>

    <div class="grid gap-2.5 xl:grid-cols-3">
      <Window title="Bedrohungen" subtitle="heuristiken · {r.threats.length} treffer" bodyClass="p-3">
        <ul class="space-y-2">
          {#each r.threats as t}
            <li class="rounded-lg border px-3 py-2 {SEVERITY[t.severity]?.[1] ?? SEVERITY.low[1]}">
              <div class="flex items-center gap-2"><span class="chip !py-0 text-[10px]">{SEVERITY[t.severity]?.[0] ?? t.severity}</span><span class="font-semibold">{t.title}</span></div>
              <div class="mt-1 text-[11px] text-ctp-subtext0">{t.detail}</div>
            </li>
          {:else}
            <li class="rounded-lg border border-ctp-green/40 bg-ctp-green/10 px-3 py-2 text-ctp-green">keine auffälligkeiten gefunden</li>
          {/each}
        </ul>
        <div class="mt-3 flex gap-2 text-[11px]">
          <span class="chip">SYN <b class="text-ctp-teal">{r.tcp.syn}</b></span>
          <span class="chip">RST <b class="text-ctp-red">{r.tcp.rst}</b></span>
          <span class="chip">FIN <b class="text-ctp-peach">{r.tcp.fin}</b></span>
        </div>
      </Window>
      <Window title="Anwendungen" subtitle="{r.apps.identified_pct}% des ip-verkehrs erkannt · sni, dns, http, ip" bodyClass="p-2">
        <BarList items={appItems} empty="keine bekannte anwendung erkannt" />
      </Window>
      <Window title="Protokolle" subtitle="bytes je kategorie" bodyClass="p-2">
        <BarList items={protoItems} empty="keine pakete" />
      </Window>
    </div>

    <Window title="Endpunkte" subtitle="top 20 nach volumen · in/out aus sicht der ip · geoip" bodyClass="p-0 overflow-auto">
      <table class="table-flows">
        <thead><tr><th>IP</th><th>Land</th><th>Netz (ASN)</th><th>Anwendung</th><th class="text-right">↓ in</th><th class="text-right">↑ out</th><th class="text-right">Gesamt</th><th class="text-right">Pakete</th><th>Zuletzt</th></tr></thead>
        <tbody>
          {#each r.endpoints as e (e.ip)}
            <tr>
              <td><button class="hover:text-ctp-teal hover:underline {isPrivate(e.ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" title="in den netflow-daten suchen" onclick={() => searchFor({ ip: e.ip })}>{e.ip}</button></td>
              <td>{#if e.geo?.cc}<GeoTag geo={e.geo} /> <span class="text-[11px] text-ctp-overlay1">{e.geo.country ?? ''}</span>{:else}<span class="text-ctp-overlay0">{isPrivate(e.ip) ? 'intern' : '–'}</span>{/if}</td>
              <td class="max-w-[16rem] truncate text-[11px] text-ctp-overlay1" title={geoTitle(e.geo)}>{e.geo?.asn ? `AS${e.geo.asn} ${e.geo.org ?? ''}` : ''}</td>
              <td class="text-ctp-mauve">{e.app_label ?? ''}</td>
              <td class="text-right tabular-nums text-ctp-sapphire">{fmtBytes(e.in_bytes)}</td>
              <td class="text-right tabular-nums text-ctp-peach">{fmtBytes(e.out_bytes)}</td>
              <td class="text-right tabular-nums">{fmtBytes(e.total_bytes)}</td>
              <td class="text-right tabular-nums text-ctp-overlay1">{e.in_packets + e.out_packets}</td>
              <td class="text-ctp-overlay1">{e.last_ms ? fmtTime(e.last_ms, true) : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Window>

    <div class="grid gap-2.5 xl:grid-cols-3">
      <Window title="Länder" subtitle="endpunkte je land" bodyClass="p-2">
        <BarList items={countryItems} empty="keine öffentlichen endpunkte mit geoip-treffer" />
      </Window>
      <Window title="Top Quellen" subtitle="bytes gesendet" bodyClass="p-2">
        <BarList items={sourceItems} empty="keine ip-pakete" />
      </Window>
      <Window title="Top Ziel-Ports" subtitle="pakete" bodyClass="p-2">
        <BarList items={portItems} empty="keine tcp/udp-pakete" />
      </Window>
    </div>

    <div class="grid gap-2.5 xl:grid-cols-3">
      <Window title="Top Flows" subtitle="quelle → ziel:port" bodyClass="p-2">
        <BarList items={flowItems} empty="keine flows" />
      </Window>
      <Window title="DNS" subtitle="{r.dns.queries_total} anfragen · {r.dns.unique_domains} domains · {r.dns.nxdomain_total} nxdomain" bodyClass="p-0 overflow-auto max-h-[420px]">
        <table class="table-flows">
          <thead><tr><th>Domain</th><th class="text-right">Anfragen</th><th>Auflösung</th></tr></thead>
          <tbody>
            {#each r.dns.top_queries as q (q.domain)}
              <tr>
                <td class="max-w-[14rem] truncate text-ctp-text" title={q.domain}>{q.domain}</td>
                <td class="text-right tabular-nums">{q.count}</td>
                <td class="max-w-[12rem] truncate text-[11px] text-ctp-overlay1" title={q.resolved.join(', ')}>{q.resolved.join(', ')}</td>
              </tr>
            {:else}
              <tr><td colspan="3" class="py-6 text-center text-ctp-overlay0">keine dns-anfragen</td></tr>
            {/each}
          </tbody>
        </table>
      </Window>
      <Window title="HTTP" subtitle="{r.http.requests_total} anfragen (unverschlüsselt)" bodyClass="p-0 overflow-auto max-h-[420px]">
        {#if r.http.requests_total}
          <div class="flex flex-wrap gap-1.5 px-3 pt-2">
            {#each Object.entries(r.http.methods) as [m, n]}<span class="chip">{m} <b>{n}</b></span>{/each}
          </div>
          <table class="table-flows mt-1">
            <thead><tr><th>Host / URL</th><th class="text-right">Anfragen</th></tr></thead>
            <tbody>
              {#each r.http.top_hosts as h (h.host)}
                <tr><td class="text-ctp-text">{h.host}</td><td class="text-right tabular-nums">{h.count}</td></tr>
              {/each}
              {#each r.http.top_urls as u (u.url)}
                <tr><td class="max-w-[18rem] truncate text-[11px] text-ctp-overlay1" title={u.url}>{u.url}</td><td class="text-right tabular-nums text-ctp-overlay1">{u.count}</td></tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <div class="py-6 text-center text-ctp-overlay0">kein unverschlüsseltes http</div>
        {/if}
      </Window>
    </div>
  {/if}
</div>
