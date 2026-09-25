<script>
  // Sankey: Quelle → Dienst (Protokoll/Port) → Ziel, gewichtet nach Bytes. Layout mit d3-sankey, Rendering als SVG.
  import { sankey as d3sankey, sankeyLinkHorizontal, sankeyJustify } from 'd3-sankey';
  import { fmtBytes, isPrivate } from '../lib/format.js';
  import { searchFor } from '../lib/state.svelte.js';

  let { graph = { nodes: [], links: [] } } = $props();
  let width = $state(900);
  const height = 380;
  let hover = $state(null); // Knoten-ID oder Link-Index
  let tip = $state(null);

  const COLORS = { src: '#74c7ec', service: '#cba6f7', dst: '#94e2d5' };

  const layout = $derived.by(() => {
    if (!graph.nodes.length || width < 200) return null;
    const generator = d3sankey()
      .nodeId((d) => d.id)
      .nodeAlign(sankeyJustify)
      .nodeWidth(10)
      .nodePadding(8)
      .extent([[4, 8], [width - 4, height - 8]]);
    try {
      return generator({ nodes: graph.nodes.map((n) => ({ ...n })), links: graph.links.map((l) => ({ ...l })) });
    } catch (err) {
      console.warn('Sankey-Layout fehlgeschlagen', err);
      return null;
    }
  });
  const linkPath = sankeyLinkHorizontal();

  function touches(link) {
    if (hover === null) return true;
    return typeof hover === 'number' ? link.index === hover : link.source.id === hover || link.target.id === hover;
  }

  function showTip(event, text) {
    const rect = event.currentTarget.ownerSVGElement.getBoundingClientRect();
    tip = { x: event.clientX - rect.left, y: event.clientY - rect.top, text };
  }
</script>

<div class="relative w-full" bind:clientWidth={width}>
  {#if layout}
    <svg {width} {height} class="block">
      <defs>
        {#each layout.links as link (link.index)}
          <linearGradient id="sk-{link.index}" gradientUnits="userSpaceOnUse" x1={link.source.x1} x2={link.target.x0}>
            <stop offset="0" stop-color={COLORS[link.source.kind]} />
            <stop offset="1" stop-color={COLORS[link.target.kind]} />
          </linearGradient>
        {/each}
      </defs>
      <g fill="none">
        {#each layout.links as link (link.index)}
          <path
            d={linkPath(link)}
            stroke="url(#sk-{link.index})"
            stroke-width={Math.max(1, link.width)}
            stroke-opacity={touches(link) ? 0.45 : 0.06}
            class="transition-[stroke-opacity] duration-200"
            role="presentation"
            onmouseenter={(e) => { hover = link.index; showTip(e, `${link.source.label} → ${link.target.label}: ${fmtBytes(link.value)}`); }}
            onmousemove={(e) => showTip(e, tip?.text ?? '')}
            onmouseleave={() => { hover = null; tip = null; }}
          />
        {/each}
      </g>
      {#each layout.nodes as node (node.id)}
        <g role="presentation"
          onmouseenter={(e) => { hover = node.id; showTip(e, `${node.label}: ${fmtBytes(node.value)}`); }}
          onmouseleave={() => { hover = null; tip = null; }}>
          <rect x={node.x0} y={node.y0} width={node.x1 - node.x0} height={Math.max(1, node.y1 - node.y0)} rx="3"
            fill={COLORS[node.kind]} opacity={hover === null || hover === node.id ? 0.95 : 0.5} />
          <text
            x={node.x0 < width / 2 ? node.x1 + 6 : node.x0 - 6}
            y={(node.y0 + node.y1) / 2}
            dy="0.35em"
            text-anchor={node.x0 < width / 2 ? 'start' : 'end'}
            class="cursor-pointer text-[10.5px] {node.kind === 'service' ? 'fill-ctp-mauve' : isPrivate(node.label) ? 'fill-ctp-sapphire' : 'fill-ctp-subtext1'} hover:fill-ctp-teal"
            role="button"
            tabindex="-1"
            onclick={() => node.kind !== 'service' && searchFor({ ip: node.label })}
            onkeydown={() => {}}
          >{node.label}</text>
        </g>
      {/each}
    </svg>
    {#if tip}
      <div class="pointer-events-none absolute z-20 rounded-lg border border-ctp-surface1 bg-ctp-mantle/95 px-2.5 py-1.5 text-[11px] shadow-window"
        style="left: {Math.min(tip.x + 14, width - 260)}px; top: {tip.y + 10}px">{tip.text}</div>
    {/if}
    <div class="flex justify-between px-1 pt-1 text-[10px] uppercase tracking-widest text-ctp-overlay0">
      <span style="color: {COLORS.src}">quelle</span><span style="color: {COLORS.service}">dienst</span><span style="color: {COLORS.dst}">ziel</span>
    </div>
  {:else}
    <div class="flex h-40 items-center justify-center text-ctp-overlay0">keine Flows im Zeitfenster</div>
  {/if}
</div>
