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

  function setLoading(value: boolean) {
    loading.value = value
    if (value) {
      importProgress.value = 0
      stage.value = null
      error.value = null
    }
  }

  function setStage(value: ImportStage) {
    stage.value = value
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
  }

  function reset() {
    loading.value = false
    loadedFile.value = null
    sources.value = []
    error.value = null
    importProgress.value = 0
    stage.value = null
  }

  return {
    loading,
    loadedFile,
    sources,
    error,
    importProgress,
    stage,
    dragHovering,
    setLoading,
    setStage,
    setLoadedFile,
    addSource,
    setError,
    reset,
  }
})
