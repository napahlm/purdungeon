/** Helpers for the per-import frame accounting the backend reports. */

import type { LinkLayerCounts, SkippedPackets } from '@/types/network'

export function emptySkipped(): SkippedPackets {
  return {
    unsupported_link_type: 0,
    other_ethertype: 0,
    fragment: 0,
    truncated: 0,
    malformed: 0,
    no_timestamp: 0,
  }
}

export function emptyDecoded(): LinkLayerCounts {
  return { ipv4: 0, ipv6: 0, arp: 0, lldp: 0, cdp: 0 }
}

/** Field-wise sums, for stitching several captures into one session. */
export function addSkipped(a: SkippedPackets, b: SkippedPackets): SkippedPackets {
  return {
    unsupported_link_type: a.unsupported_link_type + b.unsupported_link_type,
    other_ethertype: a.other_ethertype + b.other_ethertype,
    fragment: a.fragment + b.fragment,
    truncated: a.truncated + b.truncated,
    malformed: a.malformed + b.malformed,
    no_timestamp: a.no_timestamp + b.no_timestamp,
  }
}

export function addDecoded(a: LinkLayerCounts, b: LinkLayerCounts): LinkLayerCounts {
  return {
    ipv4: a.ipv4 + b.ipv4,
    ipv6: a.ipv6 + b.ipv6,
    arp: a.arp + b.arp,
    lldp: a.lldp + b.lldp,
    cdp: a.cdp + b.cdp,
  }
}

export function totalSkipped(s: SkippedPackets): number {
  return (
    s.unsupported_link_type +
    s.other_ethertype +
    s.fragment +
    s.truncated +
    s.malformed +
    s.no_timestamp
  )
}

/** Frames decoded at the link layer only: they add devices, not links. */
export function linkLayerTotal(d: LinkLayerCounts): number {
  return d.arp + d.lldp + d.cdp
}

/** One plain-language line per non-zero reason, for tooltips and errors. */
export function describeSkipped(s: SkippedPackets): string[] {
  const n = (v: number) => v.toLocaleString()
  const lines: string[] = []
  if (s.unsupported_link_type > 0) {
    lines.push(
      `${n(s.unsupported_link_type)} on a link type purdungeon doesn’t read (Wi-Fi, USB, …)`,
    )
  }
  if (s.other_ethertype > 0) {
    lines.push(`${n(s.other_ethertype)} non-IP frames (spanning tree, PROFINET RT, EtherCAT, …)`)
  }
  if (s.fragment > 0) lines.push(`${n(s.fragment)} IP fragments (not reassembled)`)
  if (s.truncated > 0) lines.push(`${n(s.truncated)} cut short by the capture’s snapshot length`)
  if (s.malformed > 0) lines.push(`${n(s.malformed)} unreadable`)
  if (s.no_timestamp > 0) lines.push(`${n(s.no_timestamp)} without a timestamp`)
  return lines
}

/** `ARP 1,200 · LLDP 40 · CDP 12`, only the non-zero kinds. */
export function describeLinkLayer(d: LinkLayerCounts): string {
  const parts: string[] = []
  if (d.arp > 0) parts.push(`ARP ${d.arp.toLocaleString()}`)
  if (d.lldp > 0) parts.push(`LLDP ${d.lldp.toLocaleString()}`)
  if (d.cdp > 0) parts.push(`CDP ${d.cdp.toLocaleString()}`)
  return parts.join(' · ')
}
