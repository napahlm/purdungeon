/** Shared display formatters used across the detail panels. */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

/** Full date + time, for the detail panels. */
export function formatTime(ts: number): string {
  if (ts <= 0) return '—'
  return new Date(ts * 1000).toLocaleString()
}

/** Time of day only, for the timeline where the date would be noise. */
export function formatClock(ts: number): string {
  if (ts <= 0) return '—'
  return new Date(ts * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatCadence(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}
