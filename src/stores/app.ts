import { ref } from 'vue'
import { defineStore } from 'pinia'

/** Backend stages arrive over the `import-stage` event; `building-view`
 *  is the frontend's own final stage while the graph is assembled. */
export type ImportStage =
  | 'reading-packets'
  | 'identifying-devices'
  | 'mapping-conversations'
  | 'inferring-roles'
  | 'building-view'

export const IMPORT_STAGES: { id: ImportStage; label: string }[] = [
  { id: 'reading-packets', label: 'Reading packets' },
  { id: 'identifying-devices', label: 'Identifying devices' },
  { id: 'mapping-conversations', label: 'Mapping conversations' },
  { id: 'inferring-roles', label: 'Inferring roles' },
  { id: 'building-view', label: 'Building the view' },
]

export const useAppStore = defineStore('app', () => {
  const loading = ref(false)
  const loadedFile = ref<string | null>(null)
  const error = ref<string | null>(null)
  const importProgress = ref(0) // 0.0 – 1.0, within the reading stage
  const stage = ref<ImportStage | null>(null)

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

  function setLoadedFile(path: string) {
    loadedFile.value = path
    error.value = null
  }

  function setError(message: string) {
    error.value = message
    loading.value = false
    stage.value = null
  }

  function reset() {
    loading.value = false
    loadedFile.value = null
    error.value = null
    importProgress.value = 0
    stage.value = null
  }

  return {
    loading,
    loadedFile,
    error,
    importProgress,
    stage,
    setLoading,
    setStage,
    setLoadedFile,
    setError,
    reset,
  }
})
