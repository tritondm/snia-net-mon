// Anzeigeformate und kleine Helfer.

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
const BIT_UNITS = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];

export function fmtBytes(value) {
  let v = Number(value) || 0;
  let i = 0;
  while (v >= 1024 && i < BYTE_UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${BYTE_UNITS[i]}`;
}

export function fmtBits(bitsPerSecond) {
  let v = Number(bitsPerSecond) || 0;
  let i = 0;
  while (v >= 1000 && i < BIT_UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${BIT_UNITS[i]}`;
}

export function fmtNum(value) {
  const v = Number(value) || 0;
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (v >= 1e4) return (v / 1e3).toFixed(1) + 'k';
  return String(Math.round(v));
}

export function fmtTime(ms, withDate = false) {
  const d = new Date(ms);
  const time = d.toLocaleTimeString('de-AT', { hour12: false });
  return withDate ? `${d.toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit' })} ${time}` : time;
}

export function fmtAgo(ms, now = Date.now()) {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const SERVICES = {
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp', 80: 'http',
  110: 'pop3', 123: 'ntp', 143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps',
  500: 'ike', 514: 'syslog', 587: 'submission', 853: 'dot', 993: 'imaps', 995: 'pop3s', 1194: 'openvpn',
  1433: 'mssql', 1883: 'mqtt', 2055: 'netflow', 3306: 'mysql', 3389: 'rdp', 3478: 'stun', 4500: 'ipsec-nat',
  5060: 'sip', 5432: 'postgres', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 51820: 'wireguard',
};

export function serviceName(port, proto) {
  if (proto === 1 || proto === 58) return 'icmp';
  if (proto === 17 && port === 443) return 'quic';
  return SERVICES[port] ?? '';
}

/** RFC1918, ULA, Link-Local, Loopback – für die Markierung "intern". */
export function isPrivate(ip = '') {
  return (
    /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip) ||
    /^(f[cd][0-9a-f]{2}:|fe80:|::1$)/i.test(ip) ||
    ip.startsWith('2001:db8:')
  );
}

/** Verkehrsrichtung relativ zu den internen Netzen (siehe network.local_networks in config.toml). */
export const DIRECTIONS = {
  in: { icon: '↓', label: 'download', title: 'eingehend: extern → intern', color: '#74c7ec' },
  out: { icon: '↑', label: 'upload', title: 'ausgehend: intern → extern', color: '#fab387' },
  internal: { icon: '⇄', label: 'intern', title: 'zwischen internen Netzen', color: '#cba6f7' },
  external: { icon: '⤳', label: 'extern', title: 'weder Quelle noch Ziel intern', color: '#9399b2' },
};

export const PROTO_COLORS = {
  TCP: '#94e2d5',
  UDP: '#cba6f7',
  ICMP: '#fab387',
  ICMPv6: '#f9e2af',
  GRE: '#f5c2e7',
  ESP: '#89b4fa',
  OTHER: '#9399b2',
};

export function protoColor(name) {
  return PROTO_COLORS[name] ?? PROTO_COLORS.OTHER;
}

/** Flaggen-Emoji aus einem ISO-Ländercode ("AT" → 🇦🇹). */
export function flag(cc) {
  if (!/^[A-Za-z]{2}$/.test(cc ?? '')) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

/** Tooltip-Text zu GeoIP-Daten: "Österreich · AS8447 A1 Telekom Austria AG". */
export function geoTitle(geo) {
  if (!geo) return '';
  return [geo.country ?? geo.cc, geo.asn ? `AS${geo.asn} ${geo.org ?? ''}`.trim() : ''].filter(Boolean).join(' · ');
}

/** Aus einem Unix-ms-Wert einen Wert für <input type="datetime-local"> (lokale Zeit) machen und zurück. */
export function toLocalInput(ms) {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000);
  return d.toISOString().slice(0, 16);
}

export function fromLocalInput(value) {
  return value ? new Date(value).getTime() : '';
}
