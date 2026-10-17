<script>
  // Anomalie-Erkennung: Status (Lernphase, Baseline, Isolation Forest) und Liste der Auffälligkeiten.
  import Window from './Window.svelte';
  import { api } from '../lib/api.js';
  import { searchFor } from '../lib/state.svelte.js';
  import { fmtBytes, fmtDate, fmtNum, flag } from '../lib/format.js';

  let status = $state(null);
  let rows = $state([]);
  let error = $state('');
  let disabled = $state(false);
  let filter = $state({ range: '24h', kind: '', severity: '', host: '' });
  let open = $state(null); // id der aufgeklappten Zeile

  const RANGES = [
    ['24h', '24 h', 86_400_000],
    ['7d', '7 tage', 7 * 86_400_000],
    ['30d', '30 tage', 30 * 86_400_000],
  ];
  const KINDS = {
    stat: { label: 'statistik', color: 'text-ctp-peach border-ctp-peach/50', title: 'Merkmale weit über der Baseline' },
    ml: { label: 'ml', color: 'text-ctp-mauve border-ctp-mauve/50', title: 'nur der Isolation Forest schlägt an' },
    scan: { label: 'portscan', color: 'text-ctp-red border-ctp-red/50', title: 'viele fehlgeschlagene TCP-Verbindungsversuche' },
    dns: { label: 'externes dns', color: 'text-ctp-yellow border-ctp-yellow/50', title: 'DNS an externe Resolver statt an die pfSense' },
    country: { label: 'neues land', color: 'text-ctp-sapphire border-ctp-sapphire/50', title: 'erste Verbindung der Gruppe in dieses Land' },
    policy: { label: 'netz-regel', color: 'text-ctp-pink border-ctp-pink/50', title: 'Verstoß gegen eine Netz-Regel aus [anomaly] rules' },
  };
  const SEVERITY = {
    info: ['bg-ctp-overlay0', 'info'],
    warn: ['bg-ctp-yellow', 'warnung'],
    high: ['bg-ctp-red animate-pulse-dot', 'hoch'],
  };

  async function load() {
    try {
      status = await api('/anomalies/status');
      const ms = RANGES.find((r) => r[0] === filter.range)?.[2] ?? RANGES[0][2];
      rows = await api('/anomalies', { query: { from: Date.now() - ms, kind: filter.kind, severity: filter.severity, host: filter.host.trim(), limit: 1000 } });
      error = '';
      disabled = false;
    } catch (err) {
      if (/abgeschaltet/.test(err.message)) disabled = true;
      else error = err.message;
    }
  }

  $effect(() => {
    filter.range, filter.kind, filter.severity, filter.host;
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  });

  const DAY = 86_400_000;
  const learnedDays = $derived(status ? (Date.now() - status.started_ms) / DAY : 0);
  const learnFill = $derived(status?.learning_days ? Math.min(1, learnedDays / status.learning_days) : 1);
  const ml = $derived(status?.ml);
  const fmtValue = (f) => (f.bytes ? fmtBytes(f.value) : f.percent ? `${Math.round(f.value * 100)} %` : fmtNum(f.value));
  const fmtTypical = (f) => (f.bytes ? fmtBytes(f.typical) : f.percent ? `${Math.round(f.typical * 100)} %` : fmtNum(f.typical));
</script>

<div class="grid gap-2.5">
  {#if disabled}
    <Window title="Anomalie-Erkennung">
      <div class="py-8 text-center text-ctp-overlay1">abgeschaltet – in config.toml unter <span class="text-ctp-text">[anomaly]</span> enabled = true setzen</div>
    </Window>
  {:else}
    <Window title="Erkennung" subtitle="baseline je netzgruppe und host · feste regeln · isolation forest als zweite meinung">
      {#if error}<div class="mb-3 rounded-lg border border-ctp-red/40 bg-ctp-red/10 px-3 py-2 text-ctp-red">{error}</div>{/if}
      {#if status}
        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">1 · lernphase</div>
            {#if status.learning}
              <div class="text-ctp-yellow">lernt noch · {learnedDays.toFixed(1)} von {status.learning_days} tagen</div>
            {:else}
              <div class="text-ctp-green">aktiv seit {fmtDate(status.started_ms + status.learning_days * DAY)}</div>
            {/if}
            <div class="mt-2 h-1.5 overflow-hidden rounded-full bg-ctp-surface0/70">
              <div class="h-full rounded-full" style="width: {Math.max(1, learnFill * 100)}%; background: linear-gradient(90deg, #94e2d5, #cba6f7)"></div>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">portscan, externes dns und netz-regeln melden sofort, statistik, ml und neue länder erst nach der lernphase</div>
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">2 · baseline (statistik)</div>
            <div class="text-ctp-text">{status.groups} gruppen · {status.host_profiles} host-profile</div>
            <div class="mt-1 text-[11px] text-ctp-overlay0">
              fenster {status.window_minutes} min · meldung ab z ≥ {status.z_threshold} und mindestwert · zeitzone {status.timezone}
            </div>
            {#if status.last_window}
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                letztes fenster {fmtDate(status.last_window.end_ms)} · {status.last_window.hosts} hosts{status.last_window.partial ? ' · unvollständig (nur regeln)' : ''}
              </div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">3 · isolation forest (ml)</div>
            {#if !ml.enabled}
              <div class="text-ctp-overlay1">abgeschaltet</div>
            {:else if ml.trained_ms}
              <div class="text-ctp-text">trainiert {fmtDate(ml.trained_ms)}</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">
                {fmtNum(ml.trained_vectors)} vektoren · {ml.trees} bäume · schwelle {ml.effective_threshold?.toFixed(2)}
                {#if ml.quantiles}· training median {ml.quantiles.p50.toFixed(2)}, p99 {ml.quantiles.p99.toFixed(2)}, max {ml.quantiles.max.toFixed(2)}{/if}
              </div>
            {:else}
              <div class="text-ctp-yellow">sammelt daten · {fmtNum(ml.stored_vectors)} / {fmtNum(ml.min_vectors)} vektoren</div>
              <div class="mt-1 text-[11px] text-ctp-overlay0">training nach der lernphase, danach täglich mit den letzten {ml.training_days} tagen (ohne ip-adressen)</div>
            {/if}
          </div>

          <div class="rounded-lg border border-ctp-surface0/70 bg-ctp-mantle/40 p-3">
            <div class="label">4 · letzte 24 h</div>
            <div class="flex flex-wrap gap-2">
              <span class="chip"><span class="led bg-ctp-red"></span>hoch {status.counts_24h.high}</span>
              <span class="chip"><span class="led bg-ctp-yellow"></span>warnung {status.counts_24h.warn}</span>
              <span class="chip"><span class="led bg-ctp-overlay0"></span>info {status.counts_24h.info}</span>
            </div>
            <div class="mt-2 text-[11px] text-ctp-overlay0">
              netz-regeln: {status.policy_rules ? `${status.policy_rules} regeln, ${status.policy_zones} zonen` : 'keine'} · mails {status.mail ? 'an' : 'aus'}
            </div>
          </div>
        </div>
      {/if}
    </Window>

    <Window title="Auffälligkeiten" subtitle="wiederholungen desselben hosts werden zusammengefasst" bodyClass="p-0 overflow-auto max-h-[70vh]">
      {#snippet actions()}
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.range}>{#each RANGES as [v, l]}<option value={v}>{l}</option>{/each}</select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.kind}>
          <option value="">alle arten</option>
          {#each Object.entries(KINDS) as [k, v]}<option value={k}>{v.label}</option>{/each}
        </select>
        <select class="input !w-auto !py-0.5 text-[11px]" bind:value={filter.severity}>
          <option value="">alle</option>
          <option value="warn">ab warnung</option>
          <option value="high">nur hoch</option>
        </select>
        <input class="input !w-36 !py-0.5 text-[11px]" placeholder="host-ip" bind:value={filter.host} />
      {/snippet}
      <table class="table-flows">
        <thead><tr><th></th><th>Zeit</th><th>Art</th><th>Host</th><th>Gruppe</th><th class="w-full">Befund</th></tr></thead>
        <tbody>
          {#each rows as r (r.id)}
            {@const kind = KINDS[r.kind] ?? KINDS.stat}
            <tr class="cursor-pointer" onclick={() => (open = open === r.id ? null : r.id)}>
              <td title={SEVERITY[r.severity]?.[1]}><span class="led {SEVERITY[r.severity]?.[0]}"></span></td>
              <td class="tabular-nums text-ctp-subtext0" title="erstes bis letztes fenster">
                {fmtDate(r.ts)}{#if r.count > 1}<span class="text-ctp-overlay0"> · {r.count}×</span>{/if}
              </td>
              <td><span class="chip !py-0 {kind.color}" title={kind.title}>{kind.label}</span></td>
              <td>
                <button class="text-ctp-teal hover:underline" title="in der flow-suche öffnen" onclick={(e) => (e.stopPropagation(), searchFor({ ip: r.host }))}>{r.host}</button>
              </td>
              <td class="text-ctp-overlay1">{r.group}</td>
              <td class="whitespace-normal text-ctp-text">
                {#if r.kind === 'country'}<span class="mr-1">{flag(r.detail?.cc)}</span>{/if}{r.title}
                {#if r.kind === 'stat' && r.detail?.ml_score != null}
                  <span
                    class="chip ml-1 !py-0 {r.detail.ml_agrees ? 'border-ctp-mauve/60 text-ctp-mauve' : 'text-ctp-overlay0'}"
                    title="zweite meinung des isolation forest">ml {r.detail.ml_score.toFixed(2)} {r.detail.ml_agrees ? '✓ stimmt zu' : '· unauffällig'}</span
                  >
                {/if}
              </td>
            </tr>
            {#if open === r.id}
              <tr class="!bg-ctp-mantle/50">
                <td></td>
                <td colspan="5" class="whitespace-normal text-[11px] text-ctp-subtext0">
                  {#if r.kind === 'stat'}
                    <div class="mb-1 text-ctp-overlay1">verglichen mit: {r.detail.slot ?? '–'}</div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.features ?? [] as f}
                        <span class="chip">{f.name} <span class="text-ctp-text">{fmtValue(f)}</span> · typisch {fmtTypical(f)} · z {f.z}</span>
                      {/each}
                    </div>
                  {:else if r.kind === 'ml'}
                    <div class="mb-1 text-ctp-overlay1">ml-score {r.detail.ml_score} – stärkste abweichungen vom median der trainingsdaten:</div>
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.deviations ?? [] as d}
                        <span class="chip">{d.name} <span class="text-ctp-text">{fmtValue(d)}</span> · typisch {fmtTypical(d)}</span>
                      {:else}
                        <span class="text-ctp-overlay0">keine einzelne kennzahl sticht heraus – die kombination (auch mit der uhrzeit) ist ungewöhnlich</span>
                      {/each}
                    </div>
                  {:else if r.kind === 'scan'}
                    <div>{r.detail.attempts} versuche · {r.detail.hosts} ziel-hosts · {r.detail.ports} ports</div>
                    <div class="mt-1 text-ctp-overlay1">ports: {(r.detail.sample_ports ?? []).join(', ')}</div>
                    <div class="mt-1 text-ctp-overlay1">ziele (auszug): {(r.detail.sample_hosts ?? []).join(', ')}</div>
                  {:else if r.kind === 'dns'}
                    <div class="flex flex-wrap gap-2">
                      {#each r.detail.resolvers ?? [] as res}<span class="chip">{res.ip} · {res.flows} flows</span>{/each}
                    </div>
                    <div class="mt-1 text-ctp-overlay0">erlaubte externe resolver: [anomaly] dns_servers</div>
                  {:else if r.kind === 'policy'}
                    <div>regel <span class="text-ctp-text">{r.detail.rule}</span> ({r.detail.from} → {r.detail.to}) · {r.detail.flows} verbindungen · {fmtBytes(r.detail.bytes)}</div>
                    {#if r.detail.ports?.length}<div class="mt-1 text-ctp-overlay1">ports: {r.detail.ports.join(', ')}</div>{/if}
                    <div class="mt-1 text-ctp-overlay1">ziele{r.detail.peers > 20 ? ' (auszug)' : ''}: {(r.detail.sample_peers ?? []).join(', ')}</div>
                  {:else if r.kind === 'country'}
                    <div>{flag(r.detail.cc)} {r.detail.cc} · {fmtBytes(r.detail.bytes)} hochgeladen im ersten fenster</div>
                  {/if}
                  <div class="mt-2 text-ctp-overlay0">zuletzt {fmtDate(r.last_ts)} · klick auf die ip öffnet die flow-suche</div>
                </td>
              </tr>
            {/if}
          {:else}
            <tr>
              <td colspan="6" class="py-12 text-center text-ctp-overlay0">
                {status?.learning ? 'keine auffälligkeiten – die erkennung lernt noch' : 'keine auffälligkeiten im gewählten zeitraum'}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Window>
  {/if}
</div>
