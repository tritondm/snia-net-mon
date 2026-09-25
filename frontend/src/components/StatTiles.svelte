<script>
  import { live } from '../lib/live.svelte.js';
  import { DIRECTIONS, fmtBits, fmtNum } from '../lib/format.js';

  // Mini-Sparkline aus den letzten 60 Sekunden
  function spark(values, w = 120, h = 28) {
    if (values.length < 2) return '';
    const max = Math.max(...values, 1);
    return values.map((v, i) => `${i === 0 ? 'M' : 'L'}${((i / (values.length - 1)) * w).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`).join(' ');
  }

  const recent = $derived(live.points.slice(-60));
  const now = $derived(live.current);
  const tiles = $derived([
    { label: `${DIRECTIONS.in.icon} Download`, value: fmtBits((now.bytes_in ?? 0) * 8), color: DIRECTIONS.in.color, path: spark(recent.map((p) => p.bytes_in ?? 0)) },
    { label: `${DIRECTIONS.out.icon} Upload`, value: fmtBits((now.bytes_out ?? 0) * 8), color: DIRECTIONS.out.color, path: spark(recent.map((p) => p.bytes_out ?? 0)) },
    { label: 'Flows / s', value: fmtNum(now.flows), color: '#cba6f7', path: spark(recent.map((p) => p.flows)) },
    { label: 'Pakete / s', value: fmtNum(now.packets), color: '#94e2d5', path: spark(recent.map((p) => p.packets)) },
    { label: 'Aktive Verbindungen', value: fmtNum(live.active), color: '#f9e2af', path: '' },
  ]);
</script>

<div class="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-5">
  {#each tiles as tile}
    <div class="window flex items-end justify-between gap-3 px-4 py-3">
      <div>
        <div class="label">{tile.label}</div>
        <div class="text-2xl font-semibold tabular-nums" style="color: {tile.color}">{tile.value}</div>
      </div>
      {#if tile.path}
        <svg viewBox="0 0 120 28" class="h-7 w-24 overflow-visible" preserveAspectRatio="none">
          <path d={tile.path} fill="none" stroke={tile.color} stroke-width="1.5" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
        </svg>
      {:else}
        <div class="text-right text-[11px] text-ctp-overlay0">letzte 90 s</div>
      {/if}
    </div>
  {/each}
</div>
