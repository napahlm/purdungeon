/** Shared display formatters used across the detail panels. */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

/** Full date + time, for the detail panels. */
export function formatTime(ts: number): string {
  if (ts <= 0) return '-'
  return new Date(ts * 1000).toLocaleString()
}

/** Time of day only, for the timeline where the date would be noise. */
export function formatClock(ts: number): string {
  if (ts <= 0) return '-'
  return new Date(ts * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Node labels have about 130 px; a full IPv6 address does not fit. Keep the
 *  first group and the last two so neighbours stay distinguishable - the
 *  panels always show the full address. */
export function shortAddress(ip: string): string {
  if (!ip.includes(':') || ip.length <= 17) return ip
  const groups = ip.split(':')
  const first = groups[0] || '0'
  const last = groups.slice(-2).join(':')
  return `${first}:…:${last}`
}

export function formatCadence(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

/** Packets per second, for the live counters. */
export function formatRate(pps: number): string {
  if (pps >= 10000) return `${(pps / 1000).toFixed(1)}k pkt/s`
  if (pps >= 100) return `${Math.round(pps)} pkt/s`
  return `${pps.toFixed(1)} pkt/s`
}

/** Elapsed seconds as `m:ss` or `h:mm:ss`. */
export function formatElapsed(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const rest = s % 60
  const mm = h > 0 ? String(m).padStart(2, '0') : String(m)
  return `${h > 0 ? `${h}:` : ''}${mm}:${String(rest).padStart(2, '0')}`
}
