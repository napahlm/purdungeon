/** Helpers for the search box: IPv4 maths so a query like `10.0.0.0/25`
 *  can match host addresses by subnet. */

export function ipToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    value = value * 256 + n
  }
  return value >>> 0
}

export interface Cidr {
  base: number
  prefix: number
}

/** Parse `a.b.c.d/n` (or a bare `a.b.c.d` as /32). Returns null if it isn't one. */
export function parseCidr(token: string): Cidr | null {
  const [addr, prefixStr] = token.split('/')
  const base = ipToInt(addr)
  if (base === null) return null
  let prefix = 32
  if (prefixStr !== undefined) {
    const p = Number(prefixStr)
    if (!Number.isInteger(p) || p < 0 || p > 32) return null
    prefix = p
  } else if (!token.includes('/')) {
    // A bare full address only counts as a CIDR query when the user typed a
    // slash; otherwise let substring search handle partial addresses.
    return null
  }
  return { base, prefix }
}

export function ipInCidr(ip: string, cidr: Cidr): boolean {
  const value = ipToInt(ip)
  if (value === null) return false
  if (cidr.prefix === 0) return true
  const mask = cidr.prefix === 32 ? 0xffffffff : (~((1 << (32 - cidr.prefix)) - 1)) >>> 0
  return (value & mask) === (cidr.base & mask)
}

/** Transport-layer tokens the search treats as protocol filters. */
export const TRANSPORT_TOKENS = new Set(['tcp', 'udp', 'icmp'])
