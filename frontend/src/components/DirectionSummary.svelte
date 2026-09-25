<script>
  // Verteilung des Verkehrs nach Richtung im Zeitfenster: ein gestapelter Balken + Werte je Richtung.
  import { DIRECTIONS, fmtBytes, fmtBits } from '../lib/format.js';
  import { ui } from '../lib/state.svelte.js';
  let { stats = [] } = $props();

  const total = $derived(stats.reduce((s, d) => s + d.bytes, 0));
  const visible = $derived(stats.filter((d) => d.direction !== 'external' || d.bytes > 0));
</script>

<div class="space-y-3">
  <div class="flex h-2.5 overflow-hidden rounded-full bg-ctp-surface0/70">
    {#each stats as d (d.direction)}
      {#if d.bytes > 0}
        <div class="h-full transition-[width] duration-500" style="width: {(d.bytes / total) * 100}%; background: {DIRECTIONS[d.direction].color}" title={DIRECTIONS[d.direction].title}></div>
      {/if}
    {/each}
  </div>
  <div class="grid grid-cols-2 gap-2">
    {#each visible as d (d.direction)}
      {@const meta = DIRECTIONS[d.direction]}
      <button
        class="rounded-lg border px-3 py-2 text-left transition {ui.dir === d.direction ? 'border-ctp-mauve/60 bg-ctp-surface0/60' : 'border-ctp-surface0 hover:border-ctp-surface2'}"
        title="{meta.title} – klicken filtert das Dashboard"
        onclick={() => (ui.dir = ui.dir === d.direction ? '' : d.direction)}
      >
        <div class="flex items-center gap-1.5 text-[11px] uppercase tracking-wider" style="color: {meta.color}">
          <span class="text-sm">{meta.icon}</span>{meta.label}
          <span class="ml-auto normal-case tracking-normal text-ctp-overlay0">{total ? ((d.bytes / total) * 100).toFixed(0) : 0}%</span>
        </div>
        <div class="mt-0.5 tabular-nums text-ctp-text">{fmtBytes(d.bytes)}</div>
        <div class="text-[11px] tabular-nums text-ctp-overlay1">ø {fmtBits(d.bps)} · {d.flows} flows</div>
      </button>
    {/each}
  </div>
</div>
