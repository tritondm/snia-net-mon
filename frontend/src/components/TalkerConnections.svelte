<script>
  // Verbindungen je Top Talker: Balken = Gesamtvolumen der IP, Segmente = ihre stärksten Gegenstellen.
  // `talkers` kommt aus /stats/talkers (vollständige Summen), `connections` aus /stats/peers (stärkste IP-Paare je Dienst).
  import { fmtBytes, serviceName, isPrivate } from '../lib/format.js';
  import GeoTag from './GeoTag.svelte';

  let { talkers = [], connections = [], onpick } = $props();

  const PEERS = 6;
  const PALETTE = ['#94e2d5', '#89b4fa', '#cba6f7', '#fab387', '#f9e2af', '#a6e3a1'];

  function service(c) {
    const port = c.port;
    const name = serviceName(port, c.proto);
    return c.proto === 6 || c.proto === 17 || c.proto === 132 ? `${c.proto_name}/${port}${name ? ' ' + name : ''}` : c.proto_name;
  }

  const groups = $derived.by(() => {
    const max = Math.max(1, ...talkers.map((t) => t.bytes));
    return talkers.map((t) => {
      const peers = new Map();
      let count = 0;
      for (const c of connections) {
        const sent = c.src_ip === t.ip;
        if (!sent && c.dst_ip !== t.ip) continue;
        count++;
        const peer = sent ? c.dst_ip : c.src_ip;
        const key = `${peer}|${service(c)}`;
        const geo = sent ? c.dst_geo : c.src_geo;
        const entry = peers.get(key) ?? { peer, geo, service: service(c), bytes: 0, sent: 0, received: 0, conns: 0 };
        entry.bytes += c.bytes;
        entry[sent ? 'sent' : 'received'] += c.bytes;
        entry.conns += c.flows;
        peers.set(key, entry);
      }
      const sorted = [...peers.values()].sort((a, b) => b.bytes - a.bytes);
      const top = sorted.slice(0, PEERS).map((p, i) => ({ ...p, color: PALETTE[i % PALETTE.length] }));
      const rest = Math.max(0, t.bytes - top.reduce((sum, p) => sum + p.bytes, 0));
      return { ...t, top, rest, more: sorted.length - top.length, count, scale: t.bytes / max };
    });
  });
</script>

{#if groups.length}
  <div class="grid gap-2.5 lg:grid-cols-2">
    {#each groups as g, rank (g.ip)}
      <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
        <div class="flex items-baseline gap-2">
          <span class="text-ctp-overlay0 tabular-nums">#{rank + 1}</span>
          <button class="font-semibold hover:text-ctp-teal hover:underline {isPrivate(g.ip) ? 'text-ctp-sapphire' : 'text-ctp-text'}" onclick={() => onpick?.(g.ip)}>{g.ip}</button>
          {#if isPrivate(g.ip)}<span class="chip !py-0 text-[10px]">intern</span>{/if}
          <GeoTag geo={g.geo} org />
          <span class="ml-auto tabular-nums text-ctp-text">{fmtBytes(g.bytes)}</span>
          <span class="text-[11px] text-ctp-overlay0">{g.flows} flows</span>
        </div>

        <!-- Gesamtvolumen relativ zum stärksten Talker, aufgeteilt nach Gegenstellen -->
        <div class="mt-2 h-2.5 overflow-hidden rounded-full bg-ctp-surface0/60">
          <div class="flex h-full gap-px" style="width: {Math.max(2, g.scale * 100)}%">
            {#each g.top as p}
              <div class="h-full" style="flex: {p.bytes} 0 0; background: {p.color}" title="{p.peer} · {p.service} · {fmtBytes(p.bytes)}"></div>
            {/each}
            {#if g.rest > 0}
              <div class="h-full bg-ctp-overlay0/50" style="flex: {g.rest} 0 0" title="übrige: {fmtBytes(g.rest)}"></div>
            {/if}
          </div>
        </div>

        <div class="mt-2 grid gap-1">
          {#each g.top as p}
            <div class="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-2 text-[11px]">
              <span class="h-2 w-2 rounded-sm" style="background: {p.color}"></span>
              <div class="flex min-w-0 items-center gap-2">
                <button class="truncate hover:text-ctp-teal hover:underline {isPrivate(p.peer) ? 'text-ctp-sapphire' : 'text-ctp-subtext1'}" onclick={() => onpick?.(p.peer)}>{p.peer}</button>
                <GeoTag geo={p.geo} org />
                <span class="shrink-0 text-ctp-mauve">{p.service}</span>
                <div class="ml-auto hidden h-1 w-24 shrink-0 overflow-hidden rounded-full bg-ctp-surface0 sm:block" title="↑ gesendet / ↓ empfangen aus Sicht von {g.ip}">
                  <div class="flex h-full">
                    <div class="h-full bg-ctp-peach" style="width: {(p.sent / p.bytes) * 100}%"></div>
                    <div class="h-full bg-ctp-sapphire" style="width: {(p.received / p.bytes) * 100}%"></div>
                  </div>
                </div>
              </div>
              <span class="text-right tabular-nums text-ctp-text">
                {fmtBytes(p.bytes)}
                <span class="text-ctp-overlay0">· <span class="text-ctp-peach">↑{fmtBytes(p.sent)}</span> <span class="text-ctp-sapphire">↓{fmtBytes(p.received)}</span></span>
              </span>
            </div>
          {/each}
          {#if g.more > 0 || g.rest > 0}
            <div class="text-[11px] text-ctp-overlay0">
              {#if g.more > 0}+ {g.more} weitere gegenstellen{/if}{#if g.rest > 0} · übrige {fmtBytes(g.rest)}{/if}
            </div>
          {/if}
        </div>
      </div>
    {/each}
  </div>
{:else}
  <div class="py-10 text-center text-ctp-overlay0">keine Daten – Filter setzen und suchen</div>
{/if}
