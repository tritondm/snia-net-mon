<script>
  // Echtzeit-Durchsatz der letzten 5 Minuten (1 Punkt pro Sekunde, aus dem WebSocket-Stream).
  // Gespiegelt: Download (in) nach oben, Upload (out) nach unten – interner Verkehr als Linie.
  // Mit gedrückter Maus einen Bereich markieren: Chart hält an und ui.range filtert die aktiven Verbindungen.
  import { live } from '../lib/live.svelte.js';
  import { ui } from '../lib/state.svelte.js';
  import { DIRECTIONS, fmtBits, fmtTime } from '../lib/format.js';

  let width = $state(600);
  const height = 210;
  const pad = { l: 78, r: 16, t: 14, b: 22 };
  let hover = $state(null);

  const IN = DIRECTIONS.in.color;
  const OUT = DIRECTIONS.out.color;
  const INT = DIRECTIONS.internal.color;

  // Beim Markieren wird der Verlauf eingefroren, damit die Auswahl nicht mitwandert
  let frozen = $state(null);
  let drag = $state(null); // {a, b} Indizes während des Ziehens
  let selection = $state(null); // {a, b} Indizes der fertigen Auswahl in `frozen`
  const points = $derived(frozen ?? live.points);

  // Beim Verlassen des Dashboards die Auswahl aufheben – sonst bliebe die Tabelle ohne sichtbare Markierung angehalten
  $effect(() => () => (ui.range = null));

  // Auswahl wurde woanders aufgehoben (z. B. "live" in der Verbindungstabelle)
  $effect(() => {
    if (!ui.range) {
      frozen = null;
      selection = null;
    }
  });
  const internal = (p) => Math.max(0, p.bytes - (p.bytes_in ?? 0) - (p.bytes_out ?? 0));
  // Gemeinsame Skala für beide Hälften, damit Download und Upload direkt vergleichbar sind
  const maxBits = $derived(Math.max(1, ...points.map((p) => Math.max(p.bytes_in ?? 0, p.bytes_out ?? 0, internal(p)) * 8)) * 1.1);
  const innerW = $derived(Math.max(10, width - pad.l - pad.r));
  const half = (height - pad.t - pad.b) / 2;
  const mid = pad.t + half;
  const x = (i) => pad.l + (points.length < 2 ? 0 : (i / (points.length - 1)) * innerW);
  const up = (bits) => mid - (bits / maxBits) * half;
  const down = (bits) => mid + (bits / maxBits) * half;

  function line(value, y) {
    return points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(value(p) * 8).toFixed(1)}`).join('');
  }
  function area(path) {
    return points.length > 1 ? `${path}L${x(points.length - 1)},${mid}L${x(0)},${mid}Z` : '';
  }
  const inLine = $derived(line((p) => p.bytes_in ?? 0, up));
  const outLine = $derived(line((p) => p.bytes_out ?? 0, down));
  const intLine = $derived(line(internal, up));
  const ticks = $derived([1, 0.5].flatMap((f) => [
    { y: up(f * maxBits), label: fmtBits(f * maxBits) },
    { y: down(f * maxBits), label: fmtBits(f * maxBits) },
  ]));

  function indexAt(event) {
    const rect = event.currentTarget.getBoundingClientRect();
    const rel = (event.clientX - rect.left - pad.l) / innerW;
    return Math.round(Math.min(1, Math.max(0, rel)) * (points.length - 1));
  }

  function onMove(event) {
    if (points.length < 2) return;
    const i = indexAt(event);
    hover = { i, p: points[i] };
    if (drag) drag.b = i;
  }

  function onDown(event) {
    if (event.button !== 0 || points.length < 2) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    frozen ??= live.points;
    const i = indexAt(event);
    drag = { a: i, b: i, x: event.clientX };
  }

  function onUp(event) {
    if (!drag) return;
    const { a, b, x: startX } = drag;
    drag = null;
    if (Math.abs(event.clientX - startX) < 4) {
      // Einfacher Klick hebt die Auswahl auf
      clearRange();
      return;
    }
    const [lo, hi] = a < b ? [a, b] : [b, a];
    selection = { a: lo, b: hi };
    // Ein Punkt fasst die Sekunde vor seinem Zeitstempel zusammen
    ui.range = { from: points[lo].ts - 1000, to: points[hi].ts };
  }

  function clearRange() {
    ui.range = null;
    frozen = null;
    selection = null;
  }

  const band = $derived.by(() => {
    const s = drag ?? selection;
    if (!s || points.length < 2) return null;
    const [lo, hi] = s.a < s.b ? [s.a, s.b] : [s.b, s.a];
    return { x: x(lo), w: Math.max(1, x(hi) - x(lo)) };
  });
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && ui.range && clearRange()} />

<div class="relative h-full w-full select-none" bind:clientWidth={width}>
  <svg
    {width}
    {height}
    class="block cursor-crosshair"
    role="img"
    aria-label="Durchsatz Download/Upload – Bereich mit der Maus markieren"
    onpointermove={onMove}
    onpointerdown={onDown}
    onpointerup={onUp}
    onpointercancel={() => (drag = null)}
    onpointerleave={() => (hover = null)}
  >
    <defs>
      <linearGradient id="bw-in" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0" stop-color={IN} stop-opacity="0.5" /><stop offset="1" stop-color={IN} stop-opacity="0.02" />
      </linearGradient>
      <linearGradient id="bw-out" x1="0" x2="0" y1="1" y2="0">
        <stop offset="0" stop-color={OUT} stop-opacity="0.5" /><stop offset="1" stop-color={OUT} stop-opacity="0.02" />
      </linearGradient>
    </defs>
    {#each ticks as t}
      <line x1={pad.l} x2={width - pad.r} y1={t.y} y2={t.y} stroke="#313244" stroke-dasharray="2 4" />
      <text x={pad.l - 8} y={t.y + 4} text-anchor="end" class="fill-ctp-overlay0 text-[10px]">{t.label}</text>
    {/each}
    <line x1={pad.l} x2={width - pad.r} y1={mid} y2={mid} stroke="#45475a" />
    <text x={pad.l + 6} y={mid - 6} class="text-[10px]" fill={IN}>↓ download</text>
    <text x={pad.l + 6} y={mid + 14} class="text-[10px]" fill={OUT}>↑ upload</text>
    {#if points.length > 1}
      <path d={area(inLine)} fill="url(#bw-in)" />
      <path d={inLine} fill="none" stroke={IN} stroke-width="1.6" stroke-linejoin="round" />
      <path d={area(outLine)} fill="url(#bw-out)" />
      <path d={outLine} fill="none" stroke={OUT} stroke-width="1.6" stroke-linejoin="round" />
      <path d={intLine} fill="none" stroke={INT} stroke-width="1.1" stroke-dasharray="3 3" opacity="0.8" />
      <text x={pad.l} y={height - 4} class="fill-ctp-overlay0 text-[10px]">{fmtTime(points[0].ts)}</text>
      <text x={width - pad.r} y={height - 4} text-anchor="end" class="fill-ctp-overlay0 text-[10px]">{fmtTime(points.at(-1).ts)}</text>
    {:else}
      <text x={width / 2} y={mid - 8} text-anchor="middle" class="fill-ctp-overlay0 text-xs">warte auf Daten …</text>
    {/if}
    {#if band}
      <rect x={band.x} y={pad.t} width={band.w} height={height - pad.t - pad.b} fill="#f9e2af" fill-opacity="0.12" stroke="#f9e2af" stroke-opacity="0.6" />
    {/if}
    {#if hover}
      <line x1={x(hover.i)} x2={x(hover.i)} y1={pad.t} y2={height - pad.b} stroke="#cdd6f4" stroke-opacity="0.35" />
      <circle cx={x(hover.i)} cy={up((hover.p.bytes_in ?? 0) * 8)} r="3.5" fill={IN} />
      <circle cx={x(hover.i)} cy={down((hover.p.bytes_out ?? 0) * 8)} r="3.5" fill={OUT} />
    {/if}
  </svg>
  {#if hover}
    <div
      class="pointer-events-none absolute top-2 rounded-lg border border-ctp-surface1 bg-ctp-mantle/95 px-3 py-2 text-[11px] shadow-window"
      style="left: {Math.min(x(hover.i) + 12, width - 190)}px"
    >
      <div class="text-ctp-overlay1">{fmtTime(hover.p.ts)}</div>
      <div style="color: {IN}">↓ download {fmtBits((hover.p.bytes_in ?? 0) * 8)}</div>
      <div style="color: {OUT}">↑ upload {fmtBits((hover.p.bytes_out ?? 0) * 8)}</div>
      <div style="color: {INT}">⇄ intern {fmtBits(internal(hover.p) * 8)}</div>
      <div class="text-ctp-overlay1">{hover.p.flows} flows · {hover.p.packets} pakete</div>
    </div>
  {/if}
  <div class="absolute right-2 top-0 flex items-center gap-3 text-[10px] text-ctp-overlay1">
    {#if ui.range}
      <button class="chip !py-0 !border-ctp-yellow/60 text-ctp-yellow hover:bg-ctp-yellow/10" onclick={clearRange} title="Auswahl aufheben (Esc)">
        ❚❚ {fmtTime(ui.range.from)} – {fmtTime(ui.range.to)} · ▶ live
      </button>
    {/if}
    <span style="color: {IN}">━ download</span><span style="color: {OUT}">━ upload</span><span style="color: {INT}">┅ intern</span>
  </div>
</div>
