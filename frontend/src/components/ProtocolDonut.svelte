<script>
  import { fmtBytes, protoColor } from '../lib/format.js';
  let { protocols = [] } = $props();

  const total = $derived(protocols.reduce((s, p) => s + p.bytes, 0));
  const arcs = $derived.by(() => {
    let angle = -Math.PI / 2;
    return protocols.map((p) => {
      const share = total ? p.bytes / total : 0;
      const start = angle;
      angle += share * Math.PI * 2;
      return { ...p, share, path: arc(start, angle) };
    });
  });

  function arc(a0, a1, r = 58, r0 = 40) {
    if (a1 - a0 >= Math.PI * 2 - 1e-6) a1 = a0 + Math.PI * 2 - 1e-4;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const p = (a, rad) => `${(70 + rad * Math.cos(a)).toFixed(2)},${(70 + rad * Math.sin(a)).toFixed(2)}`;
    return `M${p(a0, r)}A${r},${r} 0 ${large} 1 ${p(a1, r)}L${p(a1, r0)}A${r0},${r0} 0 ${large} 0 ${p(a0, r0)}Z`;
  }
  let hovered = $state(null);
</script>

<div class="flex items-center gap-4">
  <svg viewBox="0 0 140 140" class="h-36 w-36 shrink-0">
    {#each arcs as a (a.proto)}
      {#if a.share > 0}
        <path d={a.path} fill={protoColor(a.proto_name)} opacity={hovered === null || hovered === a.proto ? 0.9 : 0.25}
          stroke="#1e1e2e" stroke-width="1.5" role="presentation"
          onmouseenter={() => (hovered = a.proto)} onmouseleave={() => (hovered = null)} />
      {/if}
    {/each}
    <text x="70" y="67" text-anchor="middle" class="fill-ctp-overlay1 text-[9px] uppercase tracking-widest">gesamt</text>
    <text x="70" y="82" text-anchor="middle" class="fill-ctp-text text-[12px] font-semibold">{fmtBytes(total)}</text>
  </svg>
  <ul class="min-w-0 flex-1 space-y-1">
    {#each arcs as a (a.proto)}
      <li class="flex items-center gap-2 rounded px-1 {hovered === a.proto ? 'bg-ctp-surface0/60' : ''}"
        role="presentation" onmouseenter={() => (hovered = a.proto)} onmouseleave={() => (hovered = null)}>
        <span class="h-2.5 w-2.5 rounded-sm" style="background: {protoColor(a.proto_name)}"></span>
        <span>{a.proto_name}</span>
        <span class="text-[11px] text-ctp-overlay0">#{a.proto}</span>
        <span class="ml-auto tabular-nums text-ctp-subtext1">{(a.share * 100).toFixed(1)}%</span>
      </li>
    {:else}
      <li class="text-ctp-overlay0">keine Daten</li>
    {/each}
  </ul>
</div>
