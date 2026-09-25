import { ui } from './state.svelte.js';

const TOKEN_KEY = 'snm-api-token';

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setToken(token) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* privater Modus – Token gilt dann nur bis zum Neuladen */
  }
  memoryToken = token;
}

let memoryToken = '';
const token = () => getToken() || memoryToken;

/** URL mit Token als Query-Parameter – für WebSocket und Downloads, die keine Header setzen können. */
export function withToken(path) {
  const url = new URL(path, location.origin);
  if (token()) url.searchParams.set('token', token());
  return url;
}

export function wsUrl(path) {
  const url = withToken(path);
  url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString();
}

/** Fetch-Wrapper für /api. Leere Query-Werte werden weggelassen. */
export async function api(path, { method = 'GET', query, body } = {}) {
  const url = new URL('/api' + path, location.origin);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== '' && value !== null && value !== undefined) url.searchParams.set(key, value);
  }
  const headers = {};
  if (token()) headers.Authorization = `Bearer ${token()}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401) {
    ui.authRequired = true;
    throw new Error('API-Token erforderlich');
  }
  if (!res.ok) {
    let message = res.statusText;
    try {
      message = (await res.json()).error ?? message;
    } catch {
      /* keine JSON-Fehlermeldung */
    }
    throw new Error(message);
  }
  return res.status === 204 ? null : res.json();
}
