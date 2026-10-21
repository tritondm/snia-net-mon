<script>
  // Ausnahmen der Anomalie-Erkennung: Liste mit Bearbeiten und Löschen, Export als JSON oder CSV, Import aus JSON.
  import Window from './Window.svelte';
  import { api } from '../lib/api.js';
  import { KINDS } from '../lib/anomaly.js';
  import { fmtDate } from '../lib/format.js';

  // list: Ausnahmen von GET /anomalies/exceptions; onedit(row | null): Dialog öffnen; onchanged(): neu laden
  let { list, retentionDays = 30, onedit, onchanged } = $props();
  let message = $state('');
  let fileInput;

  const now = Date.now();
  const expired = (x) => x.expires_ms != null && x.expires_ms <= now;
  const fmtUntil = (ms) => fmtDate(ms - 1).split(',')[0];

  async function remove(x) {
    if (!confirm(`ausnahme #${x.id} (${KINDS[x.kind]?.label ?? x.kind}${x.host ? ` · ${x.host}` : ''}${x.target ? ` · ${x.target}` : ''}) löschen?`)) return;
    try {
      await api(`/anomalies/exceptions/${x.id}`, { method: 'DELETE' });
      message = '';
      onchanged();
    } catch (err) {
      message = err.message;
    }
  }

  function download(name, type, text) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    a.click();
    URL.revokeObjectURL(url);
  }
  const stamp = () => new Date().toISOString().slice(0, 10);
  const iso = (ms) => (ms == null ? '' : new Date(ms).toISOString());

  function exportJson() {
    const rows = list.map(({ id, kind, host, target, comment, created_ms, updated_ms, expires_ms, hits, last_hit_ms }) => ({
      id,
      kind,
      host,
      target,
      comment,
      created_ms,
      updated_ms,
      expires_ms,
      hits,
      last_hit_ms,
    }));
    download(`snia-net-mon-ausnahmen-${stamp()}.json`, 'application/json', JSON.stringify(rows, null, 2) + '\n');
  }

  function exportCsv() {
    const cell = (v) => {
      const s = v == null ? '' : String(v);
      return /[";\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
    };
    const head = ['id', 'art', 'host', 'ziel', 'kommentar', 'angelegt', 'geändert', 'gilt_bis', 'treffer', 'letzter_treffer'];
    const rows = list.map((x) => [x.id, x.kind, x.host, x.target, x.comment, iso(x.created_ms), iso(x.updated_ms), iso(x.expires_ms), x.hits, iso(x.last_hit_ms)]);
    // Semikolon und BOM, damit Excel mit deutschen Einstellungen die Datei direkt richtig öffnet
    download(`snia-net-mon-ausnahmen-${stamp()}.csv`, 'text/csv', '﻿' + [head, ...rows].map((r) => r.map(cell).join(';')).join('\r\n') + '\r\n');
  }

  /** JSON-Export wieder einlesen; vorhandene Ausnahmen (gleiche Art, Host und Ziel) werden übersprungen. */
  async function importJson(e) {
    const file = e.currentTarget.files?.[0];
    e.currentTarget.value = '';
    if (!file) return;
    let rows;
    try {
      rows = JSON.parse(await file.text());
      if (!Array.isArray(rows)) throw new Error('erwartet eine liste');
    } catch (err) {
      message = `import: ${file.name} ist kein gültiger export (${err.message})`;
      return;
    }
    const key = (x) => `${x.kind}|${x.host ?? ''}|${x.target ?? ''}`;
    const known = new Set(list.map(key));
    let added = 0;
    let skipped = 0;
    const failed = [];
    for (const x of rows) {
      if (known.has(key(x))) {
        skipped++;
        continue;
      }
      try {
        await api('/anomalies/exceptions', { method: 'POST', body: { kind: x.kind, host: x.host, target: x.target, comment: x.comment ?? '', expires_ms: x.expires_ms ?? null } });
        known.add(key(x));
        added++;
      } catch (err) {
        failed.push(`${key(x)}: ${err.message}`);
      }
    }
    message = `import: ${added} angelegt, ${skipped} schon vorhanden${failed.length ? `, ${failed.length} fehlerhaft – ${failed.join(' · ')}` : ''}`;
    onchanged();
  }
</script>

<Window title="Ausnahmen" subtitle="ausgenommene auffälligkeiten werden gespeichert, aber ausgeblendet und nie gemailt" bodyClass="p-0 overflow-auto max-h-[50vh]">
  {#snippet actions()}
    <button class="chip hover:text-ctp-text" onclick={() => onedit(null)}>+ neu</button>
    <button class="chip hover:text-ctp-text" disabled={!list.length} onclick={exportJson}>export json</button>
    <button class="chip hover:text-ctp-text" disabled={!list.length} onclick={exportCsv}>export csv</button>
    <button class="chip hover:text-ctp-text" title="json-export wieder einlesen" onclick={() => fileInput.click()}>import</button>
    <input bind:this={fileInput} type="file" accept=".json,application/json" class="hidden" onchange={importJson} />
  {/snippet}
  {#if message}<div class="border-b border-ctp-surface0/60 px-3 py-2 text-[11px] text-ctp-subtext0">{message}</div>{/if}
  <table class="table-flows">
    <thead>
      <tr>
        <th>Art</th><th>Host</th><th>Ziel</th><th class="w-full">Kommentar</th><th>Gilt bis</th>
        <th title="ausgeblendete auffälligkeiten der letzten {retentionDays} tage">Treffer</th><th>Zuletzt</th><th></th>
      </tr>
    </thead>
    <tbody>
      {#each list as x (x.id)}
        {@const kind = KINDS[x.kind] ?? KINDS.stat}
        <tr class={expired(x) ? 'opacity-50' : ''}>
          <td><span class="chip !py-0 {kind.color}">{kind.label}</span></td>
          <td class="tabular-nums">{x.host ?? 'alle hosts'}</td>
          <td class="tabular-nums">{x.target ?? (x.kind === 'stat' || x.kind === 'ml' || x.kind === 'scan' ? '–' : 'alle ziele')}</td>
          <td class="whitespace-normal text-ctp-subtext0 [overflow-wrap:anywhere]">{x.comment}</td>
          <td class="tabular-nums text-ctp-subtext0">{x.expires_ms ? `${fmtUntil(x.expires_ms)}${expired(x) ? ' · abgelaufen' : ''}` : 'unbefristet'}</td>
          <td class="tabular-nums text-ctp-subtext0">{x.hits}</td>
          <td class="tabular-nums text-ctp-subtext0">{x.last_hit_ms ? fmtDate(x.last_hit_ms) : '–'}</td>
          <td>
            <button class="text-ctp-overlay1 hover:text-ctp-teal" title="bearbeiten" onclick={() => onedit(x)}>bearbeiten</button>
            <button class="ml-2 text-ctp-overlay1 hover:text-ctp-red" title="löschen" onclick={() => remove(x)}>löschen</button>
          </td>
        </tr>
      {:else}
        <tr>
          <td colspan="8" class="py-8 text-center text-ctp-overlay0">noch keine ausnahmen – in der liste oben eine auffälligkeit aufklappen und „ausnahme anlegen…“ wählen</td>
        </tr>
      {/each}
    </tbody>
  </table>
</Window>
