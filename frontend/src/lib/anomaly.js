// Gemeinsame Beschreibungen der Anomalie-Erkennung für Liste, Ausnahmen und Dialog.
// Texte als Getter, damit ein Sprachwechsel sofort greift.
import { t } from './i18n.svelte.js';

export const KINDS = {
  stat: { get label() { return t('statistik', 'statistics'); }, color: 'text-ctp-peach border-ctp-peach/50', get title() { return t('Merkmale weit über der Baseline', 'features far above the baseline'); } },
  ml: { label: 'ml', color: 'text-ctp-mauve border-ctp-mauve/50', get title() { return t('nur der Isolation Forest schlägt an', 'only the Isolation Forest fires'); } },
  scan: { label: 'portscan', color: 'text-ctp-red border-ctp-red/50', get title() { return t('viele fehlgeschlagene TCP-Verbindungsversuche', 'many failed TCP connection attempts'); } },
  dns: { get label() { return t('externes dns', 'external dns'); }, color: 'text-ctp-yellow border-ctp-yellow/50', get title() { return t('DNS an externe Resolver statt an den eigenen', 'DNS to external resolvers instead of your own'); } },
  country: { get label() { return t('neues land', 'new country'); }, color: 'text-ctp-sapphire border-ctp-sapphire/50', get title() { return t('erste Verbindung der Gruppe in dieses Land', 'first connection of the group to this country'); } },
  policy: { get label() { return t('netz-regel', 'network rule'); }, color: 'text-ctp-pink border-ctp-pink/50', get title() { return t('Verstoß gegen eine Netz-Regel aus [anomaly] rules', 'violation of a network rule from [anomaly] rules'); } },
  beacon: { label: 'beaconing', color: 'text-ctp-lavender border-ctp-lavender/50', get title() { return t('regelmäßige Verbindungen zum selben externen Ziel', 'regular connections to the same external destination'); } },
  drift: { get label() { return t('schleichend', 'creeping'); }, color: 'text-ctp-flamingo border-ctp-flamingo/50', get title() { return t('Upload über viele Fenster leicht erhöht (CUSUM)', 'upload slightly raised over many windows (CUSUM)'); } },
};

export const SEVERITY = {
  info: ['bg-ctp-overlay0', 'info'],
  warn: { 0: 'bg-ctp-yellow', get 1() { return t('warnung', 'warning'); } },
  high: { 0: 'bg-ctp-red animate-pulse-dot', get 1() { return t('hoch', 'high'); } },
};

/** Was bei einer Art als Ziel einer Ausnahme gilt (null = nur Host). */
export const TARGET_HINT = {
  get dns() { return t('resolver: ip oder netz, z. b. 1.1.1.2', 'resolver: ip or network, e.g. 1.1.1.2'); },
  get beacon() { return t('anbieter AS8075, anbieter und port AS8075:443 oder ip bzw. netz', 'provider AS8075, provider and port AS8075:443, or ip / network'); },
  get policy() { return t('name der netz-regel', 'name of the network rule'); },
  get country() { return t('ländercode, z. b. CN', 'country code, e.g. CN'); },
  stat: null,
  ml: null,
  scan: null,
  drift: null,
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
