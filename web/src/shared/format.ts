/** Locale-independent display helpers; no deployment value is embedded here. */
const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'] as const;
const pad = (value: number) => String(Math.trunc(value)).padStart(2, '0');

export function bytes(value: number): string {
  let size = Number.isFinite(value) ? Math.max(0, value) : 0;
  let unit = 0;
  while (size >= 1024 && unit < UNITS.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(unit ? 1 : 0)} ${UNITS[unit]}`;
}

export function duration(ms: number): string {
  const seconds = Number.isFinite(ms) ? Math.max(0, Math.round(ms / 1000)) : 0;
  const hours = Math.floor(seconds / 3600);
  return `${hours ? `${hours}:` : ''}${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`;
}

export function timestamp(ms: number): string {
  const at = new Date(Number.isFinite(ms) ? ms : 0);
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}
