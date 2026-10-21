import { protoFamily, type ProtoFamily } from '@/canvas/palette'

/** Protocol column values that name a transport or link layer, not an
 *  application: coloured as unnamed traffic, the way the topology does. */
const BARE = new Set([
  'tcp',
  'udp',
  'arp',
  'icmp',
  'icmpv6',
  'igmp',
  'lldp',
  'cdp',
  'llc',
  'other',
  'unsupported',
  'malformed',
  'truncated',
  'ipv4',
  'ipv6',
])

/** The colour family for a packet row or a protocol chip. The row carries
 *  its application tag when it has one; a chip only has the column text. */
export function familyForProtocol(protocol: string, appProtocol?: string | null): ProtoFamily {
  if (appProtocol) return protoFamily(appProtocol)
  const lower = protocol.toLowerCase()
  if (BARE.has(lower) || lower.startsWith('ip-')) return 'other'
  return protoFamily(lower)
}
