import { ref } from 'vue'
import { defineStore } from 'pinia'

/** Backend stages arrive over the `import-stage` event; `building-view`
 *  is the frontend's own final stage while the graph is assembled. */
export type ImportStage =
  | 'reading-packets'
  | 'identifying-devices'
  | 'mapping-conversations'
  | 'inferring-roles'
  | 'surfacing-findings'
  | 'building-view'

export const IMPORT_STAGES: { id: ImportStage; label: string }[] = [
  { id: 'reading-packets', label: 'Reading packets' },
  { id: 'identifying-devices', label: 'Identifying devices' },
  { id: 'mapping-conversations', label: 'Mapping conversations' },
  { id: 'inferring-roles', label: 'Inferring roles' },
  { id: 'surfacing-findings', label: 'Looking for findings' },
  { id: 'building-view', label: 'Building the view' },
]

/** Minimum on-screen time for each import step, so every stage is briefly
 *  visible even when the backend blows through it. A slow stage shows for as
 *  long as it actually takes; this only sets the floor. */
export const IMPORT_STEP_MIN_MS = 220

/** How long the fully-checkmarked list lingers before the view opens. */
const IMPORT_DONE_HOLD_MS = 450

const STAGE_COUNT = IMPORT_STAGES.length

/** One capture that has been stitched into the current session. */
export interface CaptureSource {
  path: string
  packets: number
}

export const useAppStore = defineStore('app', () => {
  const loading = ref(false)
  const loadedFile = ref<string | null>(null)
  // Every capture merged into the session, in load order. The first is the
  // one `loadedFile` names; the rest were appended.
  const sources = ref<CaptureSource[]>([])
  const error = ref<string | null>(null)
  const importProgress = ref(0) // 0.0 – 1.0, within the reading stage
  const stage = ref<ImportStage | null>(null)
  const dragHovering = ref(false)
  // Position of the file being imported within a multi-file batch (1-based),
  // and the batch size — drives the "File 2 of 3" line.
  const currentFile = ref(0)
  const totalFiles = ref(0)

  // Step pacing: `displayStage` is the index of the step currently shown as
  // active. It advances toward the real backend stage (`targetStage`) at most
  // one step per IMPORT_STEP_MIN_MS, so each step is on screen for at least
  // that long. When work is done it climbs to STAGE_COUNT — one past the last
  // step — so every item, including the last, ends with a checkmark.
  const displayStage = ref(0)
  let targetStage = 0
  let workDone = false
  let ticker: ReturnType<typeof setInterval> | null = null
  let holdTimer: ReturnType<typeof setTimeout> | null = null
  let drainResolve: (() => void) | null = null

  function clearTimers() {
    if (ticker !== null) {
      clearInterval(ticker)
      ticker = null
    }
    if (holdTimer !== null) {
      clearTimeout(holdTimer)
      holdTimer = null
    }
  }

  function finishDrain() {
    loading.value = false
    const resolve = drainResolve
    drainResolve = null
    resolve?.()
  }

  function tick() {
    if (displayStage.value < targetStage) displayStage.value++
    // Reached the end with every step checkmarked: hold the completed list a
    // moment, then open the view.
    if (workDone && displayStage.value >= STAGE_COUNT && holdTimer === null) {
      if (ticker !== null) {
        clearInterval(ticker)
        ticker = null
      }
      holdTimer = setTimeout(finishDrain, IMPORT_DONE_HOLD_MS)
    }
  }

  /** Begin importing one file of a batch. */
  function startLoading(fileIndex: number, fileCount: number) {
    loading.value = true
    currentFile.value = fileIndex
    totalFiles.value = fileCount
    importProgress.value = 0
    stage.value = null
    error.value = null
    displayStage.value = 0
    targetStage = 0
    workDone = false
    clearTimers()
    ticker = setInterval(tick, IMPORT_STEP_MIN_MS)
  }

  /** Mark the work complete and resolve once the stepper has drained to the
   *  end (all checkmarks) and the brief completed-state hold has elapsed. */
  function finishLoading(): Promise<void> {
    workDone = true
    targetStage = STAGE_COUNT
    if (!loading.value) {
      clearTimers()
      return Promise.resolve()
    }
    return new Promise((resolve) => {
      drainResolve = resolve
    })
  }

  function setStage(value: ImportStage) {
    stage.value = value
    const i = IMPORT_STAGES.findIndex((s) => s.id === value)
    if (i > targetStage) targetStage = i
  }

  /** A fresh capture replaces the session: it becomes the first source. */
  function setLoadedFile(path: string, packets: number) {
    loadedFile.value = path
    sources.value = [{ path, packets }]
    error.value = null
  }

  /** An appended capture joins the existing source list. */
  function addSource(path: string, packets: number) {
    sources.value = [...sources.value, { path, packets }]
  }

  function setError(message: string) {
    error.value = message
    loading.value = false
    stage.value = null
    clearTimers()
    const resolve = drainResolve
    drainResolve = null
    resolve?.()
  }

  function clearError() {
    error.value = null
  }

  function reset() {
    clearTimers()
    loading.value = false
    loadedFile.value = null
    sources.value = []
    error.value = null
    importProgress.value = 0
    stage.value = null
    currentFile.value = 0
    totalFiles.value = 0
    displayStage.value = 0
    targetStage = 0
    workDone = false
  }

  return {
    loading,
    loadedFile,
    sources,
    error,
    importProgress,
    stage,
    dragHovering,
    currentFile,
    totalFiles,
    displayStage,
    startLoading,
    finishLoading,
    setStage,
    setLoadedFile,
    addSource,
    setError,
    clearError,
    reset,
  }
})
