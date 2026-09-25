<script>
  // "Fenster" im Hyprland-Stil. Fokus folgt der Maus (wie follow_mouse = 1): das Fenster unter dem Zeiger
  // bekommt die aktive Verlaufs-Kante.
  let { title, subtitle = '', class: klass = '', bodyClass = 'p-4', actions, children } = $props();
  let active = $state(false);
</script>

<section
  class="window flex min-h-0 flex-col {active ? 'window-active' : ''} {klass}"
  onmouseenter={() => (active = true)}
  onmouseleave={() => (active = false)}
>
  <header class="window-title">
    <span class="led {active ? 'bg-ctp-teal' : 'bg-ctp-surface2'}"></span>
    <span class="text-ctp-subtext1">{title}</span>
    {#if subtitle}<span class="normal-case tracking-normal text-ctp-overlay0">· {subtitle}</span>{/if}
    <div class="ml-auto flex items-center gap-2 normal-case tracking-normal">{@render actions?.()}</div>
  </header>
  <div class="min-h-0 flex-1 {bodyClass}">{@render children()}</div>
</section>
