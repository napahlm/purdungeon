/** Helpers for the search box: address maths so a query like `10.0.0.0/25`
 *  or `fe80::/64` can match host addresses by subnet, in either family. */

export interface ParsedIp {
  family: 4 | 6
  value: bigint
}

export function parseIp(text: string): ParsedIp | null {
  if (text.includes(':')) return parseIpv6(text)
  const v4 = parseIpv4(text)
  return v4 === null ? null : { family: 4, value: v4 }
}

function parseIpv4(ip: string): bigint | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let value = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    value = (value << 8n) | BigInt(n)
  }
  return value
}

/** RFC 4291 text form: eight hex groups, one optional `::` run, and an
 *  optional embedded IPv4 tail (`::ffff:10.0.0.1`). */
function parseIpv6(ip: string): ParsedIp | null {
  let text = ip
  const lastColon = text.lastIndexOf(':')
  if (text.includes('.', lastColon)) {
    const v4 = parseIpv4(text.slice(lastColon + 1))
    if (v4 === null) return null
    const hi = (v4 >> 16n).toString(16)
    const lo = (v4 & 0xffffn).toString(16)
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - tail.length
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail]
  let value = 0n
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null
    value = (value << 16n) | BigInt(parseInt(group, 16))
  }
  return { family: 6, value }
}

export interface Cidr {
  family: 4 | 6
  base: bigint
  prefix: number
}

/** Parse `addr/n`. Returns null unless the user typed a slash — bare
 *  addresses go through substring search so partial input still matches. */
export function parseCidr(token: string): Cidr | null {
  const slash = token.indexOf('/')
  if (slash < 0) return null
  const ip = parseIp(token.slice(0, slash))
  if (!ip) return null
  const prefixText = token.slice(slash + 1)
  if (!/^\d{1,3}$/.test(prefixText)) return null
  const prefix = Number(prefixText)
  if (prefix > (ip.family === 4 ? 32 : 128)) return null
  return { family: ip.family, base: ip.value, prefix }
}

export function ipInCidr(ip: string, cidr: Cidr): boolean {
  const parsed = parseIp(ip)
  if (!parsed || parsed.family !== cidr.family) return false
  const hostBits = BigInt((cidr.family === 4 ? 32 : 128) - cidr.prefix)
  return parsed.value >> hostBits === cidr.base >> hostBits
}

/** Sort order for addresses: IPv4 in numeric order, then IPv6, then anything
 *  that does not parse. */
export function compareAddresses(a: string, b: string): number {
  const ka = sortKey(a)
  const kb = sortKey(b)
  return ka < kb ? -1 : ka > kb ? 1 : 0
}

function sortKey(ip: string): bigint {
  const parsed = parseIp(ip)
  if (!parsed) return 1n << 129n
  return parsed.family === 4 ? parsed.value : (1n << 128n) + parsed.value
}

/** Transport-layer tokens the search treats as protocol filters. */
export const TRANSPORT_TOKENS = new Set(['tcp', 'udp', 'icmp', 'icmpv6', 'igmp'])
