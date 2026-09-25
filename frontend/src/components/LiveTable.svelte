<script>
  // Aktive Verbindungen (Live-Stream, jede Sekunde aktualisiert).
  import { live } from '../lib/live.svelte.js';
  import { searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtBits, fmtAgo, serviceName, isPrivate, protoColor, DIRECTIONS } from '../lib/format.js';
  import DirectionFilter from './DirectionFilter.svelte';

  let filter = $state('');
  let dir = $state('');
  let paused = $state(false);
  let frozen = $state([]);

  $effect(() => {
    if (!paused) frozen = live.connections;
  });

  const rows = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    const byDir = dir ? frozen.filter((c) => c.direction === dir) : frozen;
    if (!q) return byDir;
    return byDir.filter((c) =>
      `${c.src_ip}:${c.src_port} ${c.dst_ip}:${c.dst_port} ${c.proto_name} ${serviceName(Math.min(c.src_port, c.dst_port), c.proto)}`.toLowerCase().includes(q),
    );
  });
  const maxRecent = $derived(Math.max(1, ...rows.map((r) => r.recent_bytes)));
</script>

<div class="flex h-full flex-col">
  <div class="flex items-center gap-2 border-b border-ctp-surface0/60 px-3 py-2">
    <input class="input !py-1" placeholder="filtern: ip, port, proto, dienst …" bind:value={filter} />
    <DirectionFilter bind:value={dir} compact />
    <button class="btn !py-1 {paused ? '!border-ctp-yellow/60 !text-ctp-yellow' : ''}" onclick={() => (paused = !paused)} title="Tabelle einfrieren">
      {paused ? '▶ weiter' : '❚❚ pause'}
    </button>
    <span class="chip shrink-0">{rows.length} / {live.active}</span>
  </div>
  <div class="min-h-0 flex-1 overflow-auto">
    <table class="table-flows">
      <thead>
        <tr><th title="Richtung">Ri.</th><th>Proto</th><th>Quelle</th><th></th><th>Ziel</th><th>Dienst</th><th class="text-right">Rate</th><th class="text-right">Gesamt</th><th class="text-right">Alter</th></tr>
      </thead>
      <tbody>
        {#each rows as c (c.src_ip + c.src_port + c.dst_ip + c.dst_port + c.proto)}
          <tr>
            <td class="text-base leading-none" style="color: {DIRECTIONS[c.direction]?.color}" title={DIRECTIONS[c.direction]?.title}>{DIRECTIONS[c.direction]?.icon}</td>
            <td><span class="chip !py-0" style="color: {protoColor(c.proto_name)}">{c.proto_name}</span></td>
            <td>
              <button class="hover:text-ctp-teal hover:underline {isPrivate(c.src_ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" onclick={() => searchFor({ ip: c.src_ip })}>{c.src_ip}</button><span class="text-ctp-overlay0">:{c.src_port}</span>
            </td>
            <td class="text-ctp-overlay0">→</td>
            <td>
              <button class="hover:text-ctp-teal hover:underline {isPrivate(c.dst_ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" onclick={() => searchFor({ ip: c.dst_ip })}>{c.dst_ip}</button><span class="text-ctp-overlay0">:{c.dst_port}</span>
            </td>
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
            <td class="text-right tabular-nums text-ctp-overlay1">{fmtAgo(c.first_seen, live.lastTick)}</td>
          </tr>
        {:else}
          <tr><td colspan="9" class="py-10 text-center text-ctp-overlay0">keine aktiven Verbindungen – sendet die pfSense NetFlow an Port 2055?</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
