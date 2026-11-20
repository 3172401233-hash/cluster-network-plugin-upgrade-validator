// Minimal IPv4 CIDR helpers (no dependencies, Node 24 compatible).

export function parseCidr(cidr) {
  const [ip, prefixStr] = String(cidr).split('/');
  const prefix = Number(prefixStr);
  const parts = String(ip).split('.').map(Number);
  if (
    parts.length !== 4 ||
    parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255) ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32
  ) {
    throw new Error(`invalid CIDR: ${cidr}`);
  }
  const base = parts.reduce((acc, p) => (acc << 8) | p, 0) >>> 0;
  const size = 2 ** (32 - prefix);
  const start = base & (~(size - 1) >>> 0);
  return { cidr, start: start >>> 0, end: (start + size - 1) >>> 0, prefix };
}

export function parseIp(ip) {
  return parseCidr(`${ip}/32`).start;
}

export function overlaps(a, b) {
  return a.start <= b.end && b.start <= a.end;
}

export function containsIp(range, ip) {
  const value = parseIp(ip);
  return value >= range.start && value <= range.end;
}
