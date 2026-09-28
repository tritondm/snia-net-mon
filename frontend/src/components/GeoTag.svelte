<script>
  // Kompakte GeoIP-Anzeige neben einer IP: Flagge + Ländercode, optional die Organisation (ASN) dahinter.
  import { flag, geoTitle } from '../lib/format.js';

  let { geo = null, org = false } = $props();
</script>

{#if geo}
  <span class="inline-flex min-w-0 items-center gap-1 align-baseline text-[10.5px] text-ctp-overlay1" title={geoTitle(geo)}>
    {#if geo.cc}<span class="leading-none">{flag(geo.cc)}</span><span class="text-ctp-subtext0">{geo.cc}</span>{/if}
    {#if org && geo.org}<span class="truncate text-ctp-overlay0">{geo.org}</span>{/if}
  </span>
{/if}
