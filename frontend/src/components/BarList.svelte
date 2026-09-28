<script>
  // Horizontale Balkenliste (Top Talker, Top Ports). items: [{ key, label, sub, value, display, color, onclick }]
  let { items = [], empty = 'keine Daten im Zeitfenster' } = $props();
  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

<ul class="space-y-1.5">
  {#each items as item, rank (item.key)}
    <li>
      <button class="group w-full rounded-lg px-2 py-1 text-left transition hover:bg-ctp-surface0/50" onclick={item.onclick} disabled={!item.onclick} title={item.title ?? ''}>
        <div class="flex items-baseline gap-2">
          <span class="w-4 text-right text-[10px] text-ctp-overlay0">{rank + 1}</span>
          <span class="truncate group-hover:text-ctp-teal">{item.label}</span>
          {#if item.sub}<span class="truncate text-[11px] text-ctp-overlay1">{item.sub}</span>{/if}
          <span class="ml-auto shrink-0 tabular-nums text-ctp-subtext1">{item.display}</span>
        </div>
        <div class="ml-6 mt-1 h-1.5 overflow-hidden rounded-full bg-ctp-surface0/70">
          <div class="h-full rounded-full transition-[width] duration-500" style="width: {(item.value / max) * 100}%; background: linear-gradient(90deg, {item.color ?? '#94e2d5'}, {item.color2 ?? '#74c7ec'})"></div>
        </div>
      </button>
    </li>
  {:else}
    <li class="py-6 text-center text-ctp-overlay0">{empty}</li>
  {/each}
</ul>
