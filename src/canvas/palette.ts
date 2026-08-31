import type { Host } from '@/types/network'
import { effectiveLevel, effectiveRole } from '@/types/network'

export type LevelKey = '0' | '1' | '2' | '3' | '4' | '5' | 'unknown'
export type ProtoFamily = 'modbus' | 'ot' | 'it' | 'other'

/**
 * Populated from the CSS design tokens by `initTokens()` before the app
 * mounts — style.css is the single source of color truth; nothing here
 * hard-codes a hex value.
 */
export const LEVEL_COLORS: Record<LevelKey, string> = {
  '0': '',
  '1': '',
  '2': '',
  '3': '',
  '4': '',
  '5': '',
  unknown: '',
}

/** Populated from the CSS design tokens by `initTokens()`. */
export const PROTO_COLORS: Record<ProtoFamily, string> = {
  modbus: '',
  ot: '',
  it: '',
  other: '',
}

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

export function levelColorFor(level: number | null | undefined): string {
  const key: LevelKey =
    level === null || level === undefined || level < 0 || level > 5
      ? 'unknown'
      : (String(level) as LevelKey)
  return LEVEL_COLORS[key]
}

export function levelColor(host: Host): string {
  return levelColorFor(effectiveLevel(host))
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
