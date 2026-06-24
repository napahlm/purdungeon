/** Shared display formatters used across the detail panels. */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

export function formatTime(ts: number): string {
  if (ts <= 0) return '—'
  return new Date(ts * 1000).toLocaleString()
}

export function formatCadence(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}
