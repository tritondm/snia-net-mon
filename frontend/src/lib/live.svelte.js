// WebSocket-Anbindung an /api/live mit automatischem Neuverbinden.
import { wsUrl } from './api.js';

const MAX_POINTS = 300;

class LiveStream {
  connected = $state(false);
  points = $state([]); // [{ts, bytes, packets, flows}] je Sekunde
  connections = $state([]);
  active = $state(0);
  collector = $state(null);
  lastTick = $state(0);

  #socket = null;
  #retry = 0;

  start() {
    if (this.#socket) return;
    this.#connect();
  }

  #connect() {
    const socket = new WebSocket(wsUrl('/api/live'));
    this.#socket = socket;
    socket.onopen = () => {
      this.connected = true;
      this.#retry = 0;
    };
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'history') {
        this.points = msg.points.slice(-MAX_POINTS);
      } else if (msg.type === 'tick') {
        const next = this.points.length >= MAX_POINTS ? this.points.slice(1) : this.points.slice();
        next.push(msg.rate);
        this.points = next;
        this.connections = msg.connections;
        this.active = msg.active;
        this.collector = msg.collector;
        this.lastTick = msg.ts;
      }
    };
    socket.onclose = () => {
      this.connected = false;
      this.#socket = null;
      // Exponentielles Backoff bis 10 s
      const delay = Math.min(10_000, 500 * 2 ** this.#retry++);
      setTimeout(() => this.#connect(), delay);
    };
    socket.onerror = () => socket.close();
  }

  /** Aktuelle Rate (letzter Tick). */
  get current() {
    return this.points.at(-1) ?? { bytes: 0, packets: 0, flows: 0 };
  }

  /** Reconnect erzwingen (z. B. nach Token-Eingabe). */
  restart() {
    this.#socket?.close();
  }
}

export const live = new LiveStream();
