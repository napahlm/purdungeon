import { onMounted, onUnmounted } from 'vue'
import { listen } from '@tauri-apps/api/event'
import type { CaptureStatus } from '@/types/capture'
import { useCaptureStore } from '@/stores/capture'
import { useAppStore } from '@/stores/app'
import { useTauri } from '@/composables/useTauri'

/** The topology refreshes at most this often while a capture runs. */
const REFRESH_INTERVAL_MS = 1000
/** The histogram scans every packet row; refresh it every Nth time. */
const HISTOGRAM_EVERY = 5

/**
 * Listens for the capture's ticks and keeps the topology, timeline and
 * header in step with them: at most one refresh a second, one more after a
 * refresh that a tick arrived during, and a final one (histogram included)
 * when the capture stops.
 */
export function useLiveCapture() {
  const captureStore = useCaptureStore()
  const appStore = useAppStore()
  const { refreshLive, captureStatus } = useTauri()

  let unlisten: (() => void) | null = null
  let timer: ReturnType<typeof setTimeout> | null = null
  let inFlight = false
  let tickedMeanwhile = false
  let lastRefresh = 0
  let refreshes = 0

  async function refresh(final: boolean) {
    inFlight = true
    tickedMeanwhile = false
    try {
      refreshes += 1
      await refreshLive(final || refreshes % HISTOGRAM_EVERY === 1)
    } catch (e) {
      console.warn('live refresh failed', e)
    } finally {
      inFlight = false
      lastRefresh = Date.now()
      if (tickedMeanwhile) schedule(false)
    }
  }

  function schedule(final: boolean) {
    if (inFlight) {
      tickedMeanwhile = true
      return
    }
    if (final) {
      if (timer !== null) {
        clearTimeout(timer)
        timer = null
      }
      void refresh(true)
      return
    }
    if (timer !== null) return
    const wait = Math.max(0, REFRESH_INTERVAL_MS - (Date.now() - lastRefresh))
    timer = setTimeout(() => {
      timer = null
      void refresh(false)
    }, wait)
  }

  function onTick(status: CaptureStatus) {
    captureStore.applyStatus(status)
    captureStore.invalidatePages()
    appStore.liveCounts = status.counts
    if (status.state === 'running') {
      schedule(false)
      return
    }
    // The run is over: fold its counts into the session totals as a source
    // of its own, then refresh everything one last time.
    appStore.finishLiveSource(status.interface, status.counts)
    schedule(true)
  }

  onMounted(async () => {
    unlisten = await listen<CaptureStatus>('capture-tick', (event) => onTick(event.payload))
    // A capture may already be running (the window reloaded in dev).
    try {
      const status = await captureStatus()
      if (status) captureStore.applyStatus(status)
    } catch {
      // No backend status is not an error worth surfacing.
    }
  })

  onUnmounted(() => {
    unlisten?.()
    if (timer !== null) clearTimeout(timer)
  })
}
