import type { Host } from '@/types/network'
import { effectiveLevel, effectiveRole } from '@/types/network'

/** Mirrors the design tokens in style.css — Konva can't read CSS variables. */
export const LEVEL_COLORS: Record<string, string> = {
  '0': '#ef8e6d',
  '1': '#e8b15c',
  '2': '#d6c35e',
  '3': '#6fb8c9',
  '4': '#5b9dff',
  '5': '#9a8cff',
  unknown: '#6a7480',
}

export const PROTO_COLORS: Record<ProtoFamily, string> = {
  modbus: '#4cc2ff',
  ot: '#62c4ad',
  it: '#8f9aa8',
  other: '#4a545f',
}

export const ACCENT = '#5b9dff'
export const ALERT = '#f07a5f'
export const TEXT_SECONDARY = '#9aa4b1'
export const TEXT_MUTED = '#5f6975'
export const SELECTION = '#e7eaef'

export type ProtoFamily = 'modbus' | 'ot' | 'it' | 'other'

const OT_PROTOCOLS = new Set([
  's7comm',
  'iec104',
  'opcua',
  'dnp3',
  'enip',
  'enip-io',
  'bacnet',
  'fins',
  'fox',
  'ff-annunc',
])

export function protoFamily(appProtocol: string | null): ProtoFamily {
  if (!appProtocol) return 'other'
  if (appProtocol === 'modbus') return 'modbus'
  if (OT_PROTOCOLS.has(appProtocol)) return 'ot'
  return 'it'
}

export const PROTO_FAMILY_LABELS: Record<ProtoFamily, string> = {
  modbus: 'Modbus',
  ot: 'Other OT',
  it: 'IT',
  other: 'Unnamed',
}

export function levelColor(host: Host): string {
  const level = effectiveLevel(host)
  return LEVEL_COLORS[level === null ? 'unknown' : String(level)]
}

/** Horizontal bands of the Purdue-ordered view, top to bottom. */
export interface BandDef {
  key: string
  label: string
  level: number | null
}

export const BANDS: BandDef[] = [
  { key: 'external', label: 'External', level: 5 },
  { key: 'l4', label: 'Level 4 · Enterprise', level: 4 },
  { key: 'l3', label: 'Level 3 · Site Operations', level: 3 },
  { key: 'l2', label: 'Level 2 · Supervisory', level: 2 },
  { key: 'l1', label: 'Level 1 · Basic Control', level: 1 },
  { key: 'l0', label: 'Level 0 · Process', level: 0 },
  { key: 'unplaced', label: 'Unclassified', level: null },
]

/** Which band a host belongs in; null means it isn't drawn (broadcast noise). */
export function bandKeyForHost(host: Host): string | null {
  if (effectiveRole(host) === 'broadcast') return null
  const level = effectiveLevel(host)
  if (level === null) return 'unplaced'
  if (level >= 5) return 'external'
  return `l${level}`
}

/**
 * A conversation is a cross-zone conduit when it skips a Purdue level or
 * crosses the control/IT boundary between levels 2 and 3 — the flows a
 * consultant looks at first.
 */
export function isCrossZone(a: number | null, b: number | null): boolean {
  if (a === null || b === null) return false
  if (a === b) return false
  const [lo, hi] = a < b ? [a, b] : [b, a]
  return hi - lo >= 2 || (lo <= 2 && hi >= 3)
}
