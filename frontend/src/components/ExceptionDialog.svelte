<script>
  // Ausnahme anlegen oder bearbeiten. Aus einer Auffälligkeit heraus sind Art, Host und Ziel vorausgefüllt; die Knöpfe
  // für den Umfang setzen Host und Ziel, beide Felder bleiben frei änderbar.
  import { untrack } from 'svelte';
  import { api } from '../lib/api.js';
  import { KINDS, TARGET_HINT } from '../lib/anomaly.js';
  import { t } from '../lib/i18n.svelte.js';

  // value: { id?, kind, host, target, comment, expires_ms }; targets: Vorschläge fürs Ziel; event: Auffälligkeit (optional)
  let { value, targets = [], event = null, onclose, onsaved } = $props();

  // Startwerte nur beim Öffnen übernehmen – danach gehören die Felder dem Formular
  const init = untrack(() => value);
  let form = $state({ kind: init.kind ?? 'dns', host: init.host ?? '', target: init.target ?? '', comment: init.comment ?? '' });
  let expires = $state(init.expires_ms ? toDateInput(init.expires_ms) : '');
  let error = $state('');
  let busy = $state(false);

  const hint = $derived(TARGET_HINT[form.kind]);
  const scopes = $derived(
    event && hint && targets.length
      ? [
          [t('nur dieser host', 'this host only'), event.host, ''],
          [t('host + ziel', 'host + target'), event.host, targets[0]],
          [t('alle hosts zu diesem ziel', 'all hosts to this target'), '', targets[0]],
        ]
      : [],
  );

  function toDateInput(ms) {
    const d = new Date(ms - 1);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  /** Ablauf: gilt bis einschließlich des gewählten Tages (Ortszeit). */
  function fromDateInput(text) {
    if (!text) return null;
    const [y, m, d] = text.split('-').map(Number);
    return new Date(y, m - 1, d + 1).getTime();
  }

  async function save(e) {
    e.preventDefault();
    busy = true;
    try {
      const body = { ...form, target: hint ? form.target : '', expires_ms: fromDateInput(expires) };
      const saved = value.id ? await api(`/anomalies/exceptions/${value.id}`, { method: 'PUT', body }) : await api('/anomalies/exceptions', { method: 'POST', body });
      onsaved?.(saved);
    } catch (err) {
      error = err.message;
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="fixed inset-0 z-50 flex items-center justify-center bg-ctp-crust/70 p-4 backdrop-blur-sm">
  <form class="window window-active grid w-full max-w-lg gap-3 p-5" onsubmit={save}>
    <div class="text-ctp-subtext1">{value.id ? t(`ausnahme #${value.id} bearbeiten`, `edit exception #${value.id}`) : t('ausnahme anlegen', 'create exception')}</div>
    {#if event}
      <div class="text-[11px] text-ctp-overlay0">{t('aus', 'from')}: {event.title}</div>
    {/if}

    <label>
      <span class="label">{t('art', 'kind')}</span>
      <select class="input" bind:value={form.kind}>
        {#each Object.entries(KINDS) as [k, v]}<option value={k}>{v.label}</option>{/each}
      </select>
    </label>

    {#if scopes.length}
      <div class="flex flex-wrap gap-2">
        {#each scopes as [label, host, target]}
          <button
            type="button"
            class="chip hover:text-ctp-text {form.host === host && form.target === target ? '!border-ctp-teal/60 text-ctp-teal' : ''}"
            onclick={() => ((form.host = host), (form.target = target))}>{label}</button
          >
        {/each}
      </div>
    {/if}

    <label>
      <span class="label">host</span>
      <input class="input" placeholder={t('ip oder netz, z. b. 10.4.3.200 oder 10.6.0.0/16 – leer = alle hosts', 'ip or network, e.g. 10.4.3.200 or 10.6.0.0/16 – empty = all hosts')} bind:value={form.host} />
    </label>

    {#if hint}
      <label>
        <span class="label">{t('ziel', 'target')}</span>
        <input class="input" placeholder={hint} list="exception-targets" bind:value={form.target} />
        <datalist id="exception-targets">{#each targets as tk}<option value={tk}></option>{/each}</datalist>
        <span class="mt-1 block text-[11px] text-ctp-overlay0">{t('leer = alle ziele dieses hosts', 'empty = all targets of this host')}</span>
      </label>
    {:else}
      <div class="text-[11px] text-ctp-overlay0">{t(`bei ${KINDS[form.kind].label} gilt die ausnahme nur für den host`, `for ${KINDS[form.kind].label} the exception applies to the host only`)}</div>
    {/if}

    <label>
      <span class="label">{t('kommentar', 'comment')}</span>
      <input class="input" placeholder={t('z. b. domain-controller, löst selbst extern auf', 'e.g. domain controller, resolves externally itself')} bind:value={form.comment} />
    </label>

    <label>
      <span class="label">{t('gilt bis (optional)', 'expires (optional)')}</span>
      <div class="flex gap-2">
        <input class="input" type="date" bind:value={expires} />
        {#if expires}<button type="button" class="btn" onclick={() => (expires = '')}>{t('unbefristet', 'never')}</button>{/if}
      </div>
    </label>

    {#if error}<div class="rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}

    <div class="flex justify-end gap-2">
      <button type="button" class="btn" onclick={onclose}>{t('abbrechen', 'cancel')}</button>
      <button type="submit" class="btn btn-primary" disabled={busy}>{t('speichern', 'save')}</button>
    </div>
  </form>
</div>
