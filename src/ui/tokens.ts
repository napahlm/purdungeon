/**
 * Runtime bridge to the design tokens in style.css — the single source of
 * truth for color, type, and motion. Konva draws to a canvas and can't read
 * CSS variables, so `initTokens()` (called once in main.ts, before mount)
 * copies them into these objects. Nothing outside style.css defines a color.
 */
import { LEVEL_COLORS, PROTO_COLORS } from '@/canvas/palette'

/** UI colors used by canvas drawing code. Populated from CSS variables. */
export const UI = {
  accent: '',
  alert: '',
  warn: '',
  textPrimary: '',
  textSecondary: '',
  textMuted: '',
  /** Selection outline — the brightest neutral, so it reads on any node color. */
  selection: '',
  bgPrimary: '',
  bgSecondary: '',
  border: '',
  bandFill: '',
  bandLine: '',
  badgeBg: '',
}

/** Font stacks, mirrored from the CSS `--font-*` variables. */
export const FONTS = {
  sans: 'system-ui, sans-serif',
  mono: 'ui-monospace, monospace',
}

/** Motion scale in milliseconds (+ easing), mirrored from `--duration-*`. */
export const MOTION = {
  fast: 140,
  base: 220,
  slow: 360,
  /** CSS easing string; Konva has its own easings, use Konva.Easings there. */
  easeOut: 'cubic-bezier(0.22, 1, 0.36, 1)',
}

function parseMs(value: string, fallback: number): number {
  const n = parseFloat(value)
  return Number.isFinite(n) && n > 0 ? n : fallback
}

export function initTokens() {
  const styles = getComputedStyle(document.documentElement)
  const read = (name: string) => styles.getPropertyValue(name).trim()

  // A colour token that is missing must still draw something: Konva paints
  // an empty string as fully transparent, and an invisible node is worse
  // than a grey one. Fall back to the muted text colour and say so.
  const missing: string[] = []
  const fallback = read('--color-text-muted') || 'gray' // only if style.css never loaded
  const readColor = (name: string) => {
    const value = read(name)
    if (value) return value
    missing.push(name)
    return fallback
  }

  for (const key of Object.keys(LEVEL_COLORS) as (keyof typeof LEVEL_COLORS)[]) {
    LEVEL_COLORS[key] = readColor(`--color-level-${key}`)
  }
  for (const key of Object.keys(PROTO_COLORS) as (keyof typeof PROTO_COLORS)[]) {
    PROTO_COLORS[key] = readColor(`--color-proto-${key}`)
  }

  UI.accent = readColor('--color-accent')
  UI.alert = readColor('--color-alert')
  UI.warn = readColor('--color-warn')
  UI.textPrimary = readColor('--color-text-primary')
  UI.textSecondary = readColor('--color-text-secondary')
  UI.textMuted = readColor('--color-text-muted')
  UI.selection = readColor('--color-text-primary')
  UI.bgPrimary = readColor('--color-bg-primary')
  UI.bgSecondary = readColor('--color-bg-secondary')
  UI.border = readColor('--color-border')
  UI.bandFill = readColor('--color-band-fill')
  UI.bandLine = readColor('--color-band-line')
  UI.badgeBg = readColor('--color-badge-bg')

  if (missing.length > 0) {
    console.warn(
      `design tokens missing from style.css, drawn in the fallback grey: ${missing.join(', ')}`,
    )
  }

  FONTS.sans = read('--font-sans') || FONTS.sans
  FONTS.mono = read('--font-mono') || FONTS.mono

  MOTION.fast = parseMs(read('--duration-fast'), MOTION.fast)
  MOTION.base = parseMs(read('--duration-base'), MOTION.base)
  MOTION.slow = parseMs(read('--duration-slow'), MOTION.slow)
  MOTION.easeOut = read('--ease-out') || MOTION.easeOut

  return { UI, FONTS, MOTION }
}
