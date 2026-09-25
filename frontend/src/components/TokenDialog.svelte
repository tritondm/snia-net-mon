<script>
  import { setToken } from '../lib/api.js';
  import { ui } from '../lib/state.svelte.js';
  import { live } from '../lib/live.svelte.js';
  let value = $state('');

  function save(event) {
    event.preventDefault();
    setToken(value.trim());
    ui.authRequired = false;
    live.restart();
  }
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-ctp-crust/70 backdrop-blur-sm">
  <form class="window window-active w-full max-w-sm p-5" onsubmit={save}>
    <div class="mb-3 text-ctp-subtext1">API-Token erforderlich</div>
    <input class="input" type="password" placeholder="api_token aus config.toml" bind:value autofocus />
    <button class="btn btn-primary mt-3 w-full justify-center" type="submit">anmelden</button>
  </form>
</div>
