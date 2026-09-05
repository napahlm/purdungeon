import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type { LinkLayerCounts, SkippedPackets } from '@/types/network'
import { addDecoded, addSkipped, emptyDecoded, emptySkipped } from '@/utils/skipped'

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

export type ImportJobStatus = 'queued' | 'running' | 'done' | 'failed'

/** One capture in the import queue: a row with its own progress bar. */
export interface ImportJob {
  id: number
  path: string
  status: ImportJobStatus
  /** Backend stage while running. */
  stage: ImportStage | null
  /** 0–1 through the file while reading packets. */
  progress: number
  /** Decoded frames once done. */
  packets: number
  /** Why it failed. */
  message: string | null
}

/** Share of a job's bar given to reading the file; the analysis stages split
 *  the rest evenly, so the bar keeps moving through a big capture's analysis. */
const READ_SHARE = 0.7

export function jobBarWidth(job: ImportJob): number {
  switch (job.status) {
    case 'queued':
      return 0
    case 'done':
    case 'failed':
      return 100
    case 'running': {
      const index = job.stage ? IMPORT_STAGES.findIndex((s) => s.id === job.stage) : 0
      if (index <= 0) return job.progress * READ_SHARE * 100
      const analysisSteps = IMPORT_STAGES.length - 1
      return (READ_SHARE + (1 - READ_SHARE) * (index / analysisSteps)) * 100
    }
  }
}

/** The short text beside a job's bar: stage while running, outcome after. */
export function jobStatusText(job: ImportJob): string {
  switch (job.status) {
    case 'queued':
      return 'Waiting'
    case 'failed':
      return job.message ?? 'Failed'
    case 'done':
      return job.packets > 0 ? `${job.packets.toLocaleString()} packets` : 'Nothing readable'
    case 'running': {
      const label = IMPORT_STAGES.find((s) => s.id === job.stage)?.label ?? 'Starting'
      const reading = job.stage === null || job.stage === 'reading-packets'
      return reading ? `${label} · ${Math.round(job.progress * 100)}%` : label
    }
  }
}

/** One capture that has been stitched into the current session. */
export interface CaptureSource {
  path: string
  packets: number
}

/** The per-file frame accounting an import returns. */
export interface ImportCounts {
  frames_read: number
  decoded: LinkLayerCounts
  skipped: SkippedPackets
}

export const useAppStore = defineStore('app', () => {
  const loadedFile = ref<string | null>(null)
  // Every capture merged into the session, in load order. The first is the
  // one `loadedFile` names; the rest were appended.
  const sources = ref<CaptureSource[]>([])
  // A batch-level problem that produced no jobs (nothing droppable, say).
  const error = ref<string | null>(null)
  const dragHovering = ref(false)
  // The findings panel's collapsed state lives here (not in the panel) so the
  // canvas can frame content into the actually-visible area.
  const findingsCollapsed = ref(false)
  // Frame accounting summed across every capture stitched into the session:
  // what could not be decoded (by reason) and what was decoded at the link
  // layer only. Surfaces why a view looks thin.
  const skipped = ref<SkippedPackets>(emptySkipped())
  const decoded = ref<LinkLayerCounts>(emptyDecoded())
  const framesRead = ref(0)

  // The import queue. Each dropped file is a job with its own bar; one worker
  // (useTauri.loadFiles) drains the queue in order, so at most one job runs.
  const jobs = ref<ImportJob[]>([])
  let nextJobId = 1
  // True while a batch that started on an empty window is still running, so
  // the full-screen overlay stays up until the whole batch has landed.
  const freshBatch = ref(false)

  const loading = computed(() =>
    jobs.value.some((j) => j.status === 'queued' || j.status === 'running'),
  )

  function enqueue(paths: string[]): ImportJob[] {
    const created: ImportJob[] = paths.map((path) => ({
      id: nextJobId++,
      path,
      status: 'queued',
      stage: null,
      progress: 0,
      packets: 0,
      message: null,
    }))
    jobs.value = [...jobs.value, ...created]
    error.value = null
    return created
  }

  function updateJob(id: number, patch: Partial<ImportJob>) {
    jobs.value = jobs.value.map((j) => (j.id === id ? { ...j, ...patch } : j))
  }

  function startJob(id: number) {
    updateJob(id, { status: 'running', stage: 'reading-packets', progress: 0 })
  }

  function setJobProgress(id: number, fraction: number) {
    updateJob(id, { progress: Math.max(0, Math.min(1, fraction)) })
  }

  function setJobStage(id: number, stage: ImportStage) {
    // Past the reading stage the file has been read in full.
    const patch: Partial<ImportJob> = { status: 'running', stage }
    if (stage !== 'reading-packets') patch.progress = 1
    updateJob(id, patch)
  }

  function finishJob(id: number, packets: number) {
    updateJob(id, { status: 'done', stage: null, progress: 1, packets })
  }

  function failJob(id: number, message: string) {
    updateJob(id, { status: 'failed', stage: null, message })
  }

  /** Drop finished rows; anything still queued or running stays. */
  function clearFinishedJobs() {
    jobs.value = jobs.value.filter((j) => j.status === 'queued' || j.status === 'running')
  }

  /** A fresh capture replaces the session: it becomes the first source. */
  function setLoadedFile(path: string, packets: number, counts?: ImportCounts) {
    loadedFile.value = path
    sources.value = [{ path, packets }]
    skipped.value = counts?.skipped ?? emptySkipped()
    decoded.value = counts?.decoded ?? emptyDecoded()
    framesRead.value = counts?.frames_read ?? 0
    error.value = null
  }

  /** An appended capture joins the existing source list. */
  function addSource(path: string, packets: number, counts?: ImportCounts) {
    sources.value = [...sources.value, { path, packets }]
    if (counts) {
      skipped.value = addSkipped(skipped.value, counts.skipped)
      decoded.value = addDecoded(decoded.value, counts.decoded)
      framesRead.value += counts.frames_read
    }
  }

  function setError(message: string) {
    error.value = message
  }

  function clearError() {
    error.value = null
  }

  function reset() {
    loadedFile.value = null
    sources.value = []
    skipped.value = emptySkipped()
    decoded.value = emptyDecoded()
    framesRead.value = 0
    findingsCollapsed.value = false
    error.value = null
    jobs.value = []
    freshBatch.value = false
  }

  return {
    loading,
    loadedFile,
    sources,
    error,
    dragHovering,
    findingsCollapsed,
    skipped,
    decoded,
    framesRead,
    jobs,
    freshBatch,
    enqueue,
    startJob,
    setJobProgress,
    setJobStage,
    finishJob,
    failJob,
    clearFinishedJobs,
    setLoadedFile,
    addSource,
    setError,
    clearError,
    reset,
  }
})
