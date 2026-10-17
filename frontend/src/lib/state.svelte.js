// Globaler UI-Zustand (Svelte-5-Runes).

export const WINDOWS = [
  { key: '15m', label: '15m', ms: 15 * 60_000 },
  { key: '1h', label: '1h', ms: 3_600_000 },
  { key: '6h', label: '6h', ms: 6 * 3_600_000 },
  { key: '24h', label: '24h', ms: 24 * 3_600_000 },
  { key: '72h', label: '72h', ms: 72 * 3_600_000 },
];

export const ui = $state({
  workspace: 'dashboard', // dashboard | flows | pcap | archive | anomalies
  window: '1h',
  dir: '', // Richtungsfilter für die Statistiken: '' | in | out | internal | external
  // Im Durchsatz-Chart markierter Zeitbereich {from, to} in Unix-ms – friert Chart und Verbindungstabelle ein
  range: null,
  authRequired: false,
  // Vorbelegung für die Flow-Suche (z. B. Klick auf eine IP im Dashboard)
  search: { ip: '', port: '' },
  searchNonce: 0,
  // Datenquelle der Flow-Suche: '' = live, 'history' oder 'archive:<name>'; sourceInfo = { label, from, to }
  source: '',
  sourceInfo: null,
});

export function windowMs() {
  return (WINDOWS.find((w) => w.key === ui.window) ?? WINDOWS[1]).ms;
}

/** Zur Flow-Suche springen und dort sofort suchen (Klicks im Dashboard suchen immer in den Live-Daten). */
export function searchFor({ ip = '', port = '' } = {}) {
  ui.source = '';
  ui.sourceInfo = null;
  ui.search = { ip: String(ip), port: String(port) };
  ui.searchNonce += 1;
  ui.workspace = 'flows';
}

/** Historie oder ein entpacktes Archiv in der Flow-Suche öffnen. info = { label, from, to } (Zeitraum der Daten). */
export function browseSource(source, info) {
  ui.source = source;
  ui.sourceInfo = info;
  ui.search = { ip: '', port: '' };
  ui.searchNonce += 1;
  ui.workspace = 'flows';
}
