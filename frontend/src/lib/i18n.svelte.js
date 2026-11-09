// Sprache der Web-UI (Deutsch / Englisch). Texte stehen direkt im Code als t('deutsch', 'english') –
// so bleiben beide Fassungen nebeneinander und es gibt keine Schlüssel-Dateien.
// Gewählt wird: gespeicherte Wahl des Browsers → Browsersprache (de* = Deutsch, sonst Englisch).

const KEY = 'snm-lang';

function initial() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'de' || saved === 'en') return saved;
  } catch {
    /* privater Modus */
  }
  return (navigator.language ?? '').toLowerCase().startsWith('de') ? 'de' : 'en';
}

export const i18n = $state({ lang: initial() });
document.documentElement.lang = i18n.lang;

/** Text in der aktuellen Sprache. Reaktiv: in Templates und $derived wird bei einem Sprachwechsel neu gerendert. */
export function t(de, en) {
  return i18n.lang === 'en' ? en : de;
}

/** Locale für Datum, Uhrzeit und Zahlen. */
export function locale() {
  return i18n.lang === 'en' ? 'en-GB' : 'de-AT';
}

export function setLang(lang) {
  i18n.lang = lang;
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(KEY, lang);
  } catch {
    /* privater Modus – gilt bis zum Neuladen */
  }
}
