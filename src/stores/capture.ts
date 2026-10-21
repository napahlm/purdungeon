import { computed, ref, shallowRef } from 'vue'
import { defineStore } from 'pinia'
import type { CaptureFailure, CaptureStatus, InterfaceInfo, PacketRow } from '@/types/capture'

/** The capture tab's state: what the backend reports and what the user set. */
export const useCaptureStore = defineStore('capture', () => {
  const interfaces = ref<InterfaceInfo[]>([])
  const selectedInterface = ref<string | null>(null)
  const filter = ref('')
  const promiscuous = ref(true)
  /** The latest status the backend published; null before any capture. */
  const status = shallowRef<CaptureStatus | null>(null)
  /** Why the last start (or the capture itself) failed. */
  const error = ref<CaptureFailure | null>(null)
  /** True from the moment Start is pressed until the backend has opened the interface. */
  const starting = ref(false)
  const stopping = ref(false)

  // The packet list: a quick text filter, the selected row, and whether the
  // list follows the newest frame.
  const query = ref('')
  const selectedNo = ref<number | null>(null)
  const follow = ref(true)
  /** Pages of rows by page index, invalidated on every tick. */
  const pages = shallowRef(new Map<number, PacketRow[]>())
  const total = ref(0)
  const firstNo = ref(1)

  const running = computed(() => status.value?.state === 'running')
  /** A capture exists (running or stopped) whose packets can be listed and saved. */
  const hasCapture = computed(() => status.value !== null)

  function applyStatus(next: CaptureStatus) {
    status.value = next
    if (next.state === 'failed' && next.error) {
      error.value = { code: 'capture', message: next.error }
    }
  }

  function invalidatePages() {
    pages.value = new Map()
  }

  function reset() {
    status.value = null
    error.value = null
    starting.value = false
    stopping.value = false
    query.value = ''
    selectedNo.value = null
    follow.value = true
    pages.value = new Map()
    total.value = 0
    firstNo.value = 1
  }

  return {
    interfaces,
    selectedInterface,
    filter,
    promiscuous,
    status,
    error,
    starting,
    stopping,
    query,
    selectedNo,
    follow,
    pages,
    total,
    firstNo,
    running,
    hasCapture,
    applyStatus,
    invalidatePages,
    reset,
  }
})
