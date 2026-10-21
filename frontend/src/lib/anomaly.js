// Gemeinsame Beschreibungen der Anomalie-Erkennung für Liste, Ausnahmen und Dialog.

export const KINDS = {
  stat: { label: 'statistik', color: 'text-ctp-peach border-ctp-peach/50', title: 'Merkmale weit über der Baseline' },
  ml: { label: 'ml', color: 'text-ctp-mauve border-ctp-mauve/50', title: 'nur der Isolation Forest schlägt an' },
  scan: { label: 'portscan', color: 'text-ctp-red border-ctp-red/50', title: 'viele fehlgeschlagene TCP-Verbindungsversuche' },
  dns: { label: 'externes dns', color: 'text-ctp-yellow border-ctp-yellow/50', title: 'DNS an externe Resolver statt an den eigenen' },
  country: { label: 'neues land', color: 'text-ctp-sapphire border-ctp-sapphire/50', title: 'erste Verbindung der Gruppe in dieses Land' },
  policy: { label: 'netz-regel', color: 'text-ctp-pink border-ctp-pink/50', title: 'Verstoß gegen eine Netz-Regel aus [anomaly] rules' },
  beacon: { label: 'beaconing', color: 'text-ctp-lavender border-ctp-lavender/50', title: 'regelmäßige Verbindungen zum selben externen Ziel' },
};

export const SEVERITY = {
  info: ['bg-ctp-overlay0', 'info'],
  warn: ['bg-ctp-yellow', 'warnung'],
  high: ['bg-ctp-red animate-pulse-dot', 'hoch'],
};

/** Was bei einer Art als Ziel einer Ausnahme gilt (null = nur Host). */
export const TARGET_HINT = {
  dns: 'resolver: ip oder netz, z. b. 1.1.1.2',
  beacon: 'anbieter AS8075, anbieter und port AS8075:443 oder ip bzw. netz',
  policy: 'name der netz-regel',
  country: 'ländercode, z. b. CN',
  stat: null,
  ml: null,
  scan: null,
};

/** Mögliche Ziele einer Auffälligkeit für den Ausnahme-Dialog, das wahrscheinlichste zuerst. */
export function targetsOf(row) {
  const d = row.detail ?? {};
  switch (row.kind) {
    case 'dns':
      return (d.resolvers ?? []).map((r) => r.ip);
    case 'beacon':
      return [d.asn && `AS${d.asn}:${d.port}`, d.asn && `AS${d.asn}`, d.peer].filter(Boolean);
    case 'policy':
      return d.rule ? [d.rule] : [];
    case 'country':
      return d.cc ? [d.cc] : [];
    default:
      return [];
  }
}
