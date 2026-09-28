<script>
  // Aktive Verbindungen (Live-Stream, jede Sekunde aktualisiert).
  // Ist im Durchsatz-Chart ein Bereich markiert (ui.range), zeigt die Tabelle angehalten die Verbindungen dieses Zeitraums.
  import { live } from '../lib/live.svelte.js';
  import { api } from '../lib/api.js';
  import { ui, searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtBits, fmtAgo, fmtTime, serviceName, isPrivate, protoColor, DIRECTIONS } from '../lib/format.js';
  import DirectionFilter from './DirectionFilter.svelte';
  import GeoTag from './GeoTag.svelte';

  let filter = $state('');
  let dir = $state('');
  let paused = $state(false);
  let frozen = $state([]);

  let ranged = $state([]);
  let rangeError = $state('');
  let rangeLoading = $state(false);

  $effect(() => {
    if (!paused && !ui.range) frozen = live.connections;
  });

  // Verbindungen im markierten Zeitraum aus der Datenbank; "Rate" ist dann der Mittelwert über den Bereich
  $effect(() => {
    const range = ui.range;
    if (!range) return;
    const seconds = Math.max(1, (range.to - range.from) / 1000);
    rangeLoading = true;
    rangeError = '';
    api('/stats/connections', { query: { from: range.from, to: range.to, limit: 500 } })
      .then((list) => {
        if (ui.range !== range) return; // inzwischen neue Auswahl
        ranged = list.map((c) => ({ ...c, recent_bytes: Math.round(c.bytes / seconds) }));
      })
      .catch((err) => {
        rangeError = err.message;
        ranged = [];
      })
      .finally(() => (rangeLoading = false));
  });

  const source = $derived(ui.range ? ranged : frozen);

  function togglePause() {
    if (ui.range) ui.range = null;
    else paused = !paused;
  }

  const rows = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const byDir = dir ? source.filter((c) => c.direction === dir) : source;
    if (!q) return byDir;
    const geoText = (g) => (g ? `${g.cc ?? ''} ${g.country ?? ''} ${g.org ?? ''} as${g.asn ?? ''}` : '');
    return byDir.filter((c) =>
      `${c.src_ip}:${c.src_port} ${c.dst_ip}:${c.dst_port} ${c.proto_name} ${serviceName(Math.min(c.src_port, c.dst_port), c.proto)} ${geoText(c.src_geo)} ${geoText(c.dst_geo)}`
        .toLowerCase()
        .includes(q),
    );
  });
  const maxRecent = $derived(Math.max(1, ...rows.map((r) => r.recent_bytes)));
</script>

<div class="flex h-full flex-col">
  <div class="flex items-center gap-2 border-b border-ctp-surface0/60 px-3 py-2">
    <input class="input !py-1" placeholder="filtern: ip, port, proto, dienst, land, netz …" bind:value={filter} />
    <DirectionFilter bind:value={dir} compact />
    <button class="btn !py-1 {paused || ui.range ? '!border-ctp-yellow/60 !text-ctp-yellow' : ''}" onclick={togglePause} title={ui.range ? 'Zeitbereich aufheben, zurück zu live' : 'Tabelle einfrieren'}>
      {paused || ui.range ? '▶ live' : '❚❚ pause'}
    </button>
    <span class="chip shrink-0">{rows.length} / {ui.range ? source.length : live.active}</span>
  </div>
  {#if ui.range}
    <div class="flex items-center gap-2 border-b border-ctp-yellow/30 bg-ctp-yellow/5 px-3 py-1 text-[11px] text-ctp-yellow">
      <span>❚❚ zeitbereich {fmtTime(ui.range.from)} – {fmtTime(ui.range.to)} ({Math.round((ui.range.to - ui.range.from) / 1000)} s)</span>
      <span class="text-ctp-overlay0">· rate = ø über den bereich · nach bytes sortiert</span>
      {#if rangeLoading}<span class="text-ctp-overlay1">lädt …</span>{/if}
      {#if rangeError}<span class="text-ctp-red">{rangeError}</span>{/if}
      <button class="ml-auto hover:text-ctp-text" onclick={() => (ui.range = null)} title="Auswahl aufheben">✕</button>
    </div>
  {/if}
  <div class="min-h-0 flex-1 overflow-auto">
    <table class="table-flows">
      <thead>
        <tr><th title="Richtung">Ri.</th><th>Proto</th><th>Quelle</th><th></th><th>Ziel</th><th title="Organisation der externen Gegenstelle (GeoIP/ASN)">Netz</th><th>Dienst</th><th class="text-right">{ui.range ? 'ø Rate' : 'Rate'}</th><th class="text-right">Gesamt</th><th class="text-right">{ui.range ? 'Dauer' : 'Alter'}</th></tr>
      </thead>
      <tbody>
        {#each rows as c (c.src_ip + c.src_port + c.dst_ip + c.dst_port + c.proto)}
          <tr>
            <td class="text-base leading-none" style="color: {DIRECTIONS[c.direction]?.color}" title={DIRECTIONS[c.direction]?.title}>{DIRECTIONS[c.direction]?.icon}</td>
            <td><span class="chip !py-0" style="color: {protoColor(c.proto_name)}">{c.proto_name}</span></td>
            <td>
              <button class="hover:text-ctp-teal hover:underline {isPrivate(c.src_ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" onclick={() => searchFor({ ip: c.src_ip })}>{c.src_ip}</button><span class="text-ctp-overlay0">:{c.src_port}</span>
              <GeoTag geo={c.src_geo} />
            </td>
            <td class="text-ctp-overlay0">→</td>
            <td>
              <button class="hover:text-ctp-teal hover:underline {isPrivate(c.dst_ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" onclick={() => searchFor({ ip: c.dst_ip })}>{c.dst_ip}</button><span class="text-ctp-overlay0">:{c.dst_port}</span>
              <GeoTag geo={c.dst_geo} />
            </td>
            <td class="max-w-[14rem] truncate text-[11px] text-ctp-overlay1" title={(c.dst_geo ?? c.src_geo)?.org ?? ''}>{(c.dst_geo ?? c.src_geo)?.org ?? ''}</td>
            <td class="text-ctp-mauve">{serviceName(Math.min(c.src_port, c.dst_port), c.proto)}</td>
            <td class="w-36 text-right tabular-nums">
              <div class="flex items-center justify-end gap-2">
                <div class="h-1 w-14 overflow-hidden rounded-full bg-ctp-surface0">
                  <div class="h-full rounded-full bg-ctp-teal" style="width: {(c.recent_bytes / maxRecent) * 100}%"></div>
                </div>
                <span class={c.recent_bytes ? 'text-ctp-teal' : 'text-ctp-overlay0'}>{fmtBits(c.recent_bytes * 8)}</span>
              </div>
            </td>
            <td class="text-right tabular-nums">{fmtBytes(c.bytes)}</td>
            <td class="text-right tabular-nums text-ctp-overlay1">{ui.range ? fmtAgo(c.first_seen, c.last_seen) : fmtAgo(c.first_seen, live.lastTick)}</td>
          </tr>
        {:else}
          <tr><td colspan="10" class="py-10 text-center text-ctp-overlay0">
            {#if ui.range}{rangeLoading ? 'lädt …' : 'keine Verbindungen in diesem Zeitbereich'}{:else}keine aktiven Verbindungen – sendet die pfSense NetFlow an Port 2055?{/if}
          </td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
