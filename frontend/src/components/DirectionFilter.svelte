<script>
  // Umschalter alle / ↓ download / ↑ upload / ⇄ intern. value ist bindbar.
  import { DIRECTIONS } from '../lib/format.js';
  let { value = $bindable(''), compact = false } = $props();
  const options = [['', 'alle'], ...['in', 'out', 'internal'].map((d) => [d, `${DIRECTIONS[d].icon} ${compact ? '' : DIRECTIONS[d].label}`.trim()])];
</script>

<div class="flex items-center gap-1 rounded-lg bg-ctp-mantle/60 p-1" title="Verkehrsrichtung">
  {#each options as [key, label]}
    <button
      type="button"
      class="rounded-md px-2 py-0.5 transition {value === key ? 'bg-ctp-surface0 shadow-glow-mauve' : 'text-ctp-overlay1 hover:text-ctp-text'}"
      style={value === key && key ? `color: ${DIRECTIONS[key].color}` : ''}
      title={key ? DIRECTIONS[key].title : 'alle Richtungen'}
      onclick={() => (value = key)}>{label}</button
    >
  {/each}
</div>
