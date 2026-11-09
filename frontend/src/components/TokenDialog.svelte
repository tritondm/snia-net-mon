<script>
  import { setToken } from '../lib/api.js';
  import { ui } from '../lib/state.svelte.js';
  import { live } from '../lib/live.svelte.js';
  import { t } from '../lib/i18n.svelte.js';
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
    <div class="mb-3 text-ctp-subtext1">{t('API-Token erforderlich', 'API token required')}</div>
    <input class="input" type="password" placeholder={t('api_token aus config.toml', 'api_token from config.toml')} bind:value autofocus />
    <button class="btn btn-primary mt-3 w-full justify-center" type="submit">{t('anmelden', 'sign in')}</button>
  </form>
</div>
