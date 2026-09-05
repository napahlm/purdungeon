import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import type {
  Host,
  Connection,
  ImportResult,
  HistogramBucket,
  HostDetail,
  ModbusHostActivity,
  ModbusConversation,
  Finding,
  Role,
} from '@/types/network'
import { useAppStore, type ImportStage } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useTimelineStore } from '@/stores/timeline'
import { describeSkipped } from '@/utils/skipped'

const ACCEPTED_EXTENSIONS = ['pcap', 'pcapng', 'cap']

/** Resolution of the timeline's traffic sparkline. */
const HISTOGRAM_BUCKETS = 120

export function isCaptureFile(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  return ACCEPTED_EXTENSIONS.includes(ext)
}

/** Turn backend errors into something a person can act on. */
function humanizeError(raw: string): string {
  const msg = raw.toLowerCase()
  // The backend's link-type message is specific and actionable; keep it.
  if (msg.includes('link type')) return raw.replace(/^parse error: /i, '')
  if (msg.includes('file too small') || msg.includes('reader') || msg.includes('parse error')) {
    return 'This file doesn’t look like a packet capture. purdungeon reads .pcap and .pcapng files.'
  }
  if (msg.includes('io error') || msg.includes('no such file') || msg.includes('os error')) {
    return 'Couldn’t open that file. Check that it still exists and is readable.'
  }
  return raw
}

/** Why a fresh import produced nothing, with the reasons the backend counted. */
function noTrafficMessage(result: ImportResult): string {
  const reasons = describeSkipped(result.skipped)
  const detail =
    reasons.length > 0
      ? ` (${result.frames_read.toLocaleString()} frames read: ${reasons.join(', ')})`
      : ''
  return (
    `No readable network traffic in this capture${detail}. purdungeon reads IPv4, IPv6 and ARP ` +
    'over Ethernet, VLAN-tagged, Linux cooked, raw-IP and loopback captures.'
  )
}

export function useTauri() {
  async function importPcap(path: string): Promise<ImportResult> {
    return invoke<ImportResult>('import_pcap', { path })
  }

  async function addPcap(path: string): Promise<ImportResult> {
    return invoke<ImportResult>('add_pcap', { path })
  }

  async function getHosts(): Promise<Host[]> {
    return invoke<Host[]>('get_hosts')
  }

  async function getConnections(): Promise<Connection[]> {
    return invoke<Connection[]>('get_connections')
  }

  async function getTimeRange(): Promise<[number, number]> {
    return invoke<[number, number]>('get_time_range')
  }

  async function getTrafficHistogram(buckets: number): Promise<HistogramBucket[]> {
    return invoke<HistogramBucket[]>('get_traffic_histogram', { buckets })
  }

  async function saveNodePosition(hostId: number, x: number, y: number): Promise<void> {
    return invoke<void>('save_node_position', { hostId, x, y })
  }

  async function getNodePositions(): Promise<[number, number, number][]> {
    return invoke<[number, number, number][]>('get_node_positions')
  }

  async function getHostDetail(hostId: number): Promise<HostDetail> {
    return invoke<HostDetail>('get_host_detail', { hostId })
  }

  async function getFindings(): Promise<Finding[]> {
    return invoke<Finding[]>('get_findings')
  }

  async function getModbusHostActivity(hostId: number): Promise<ModbusHostActivity> {
    return invoke<ModbusHostActivity>('get_modbus_host_activity', { hostId })
  }

  async function getModbusConversation(connectionId: number): Promise<ModbusConversation> {
    return invoke<ModbusConversation>('get_modbus_conversation', { connectionId })
  }

  async function setRoleOverride(hostId: number, role: Role | null): Promise<void> {
    return invoke<void>('set_role_override', { hostId, role })
  }

  async function setLevelOverride(hostId: number, level: number | null): Promise<void> {
    return invoke<void>('set_level_override', { hostId, level })
  }

  /** Fetch the (possibly merged) session and rebuild the topology from it. */
  async function refreshView(reset: boolean) {
    const topologyStore = useTopologyStore()
    const timelineStore = useTimelineStore()
    const [hosts, connections, timeRange, findings, positions, histogram] = await Promise.all([
      getHosts(),
      getConnections(),
      getTimeRange(),
      getFindings(),
      getNodePositions(),
      getTrafficHistogram(HISTOGRAM_BUCKETS),
    ])
    if (reset) {
      // Clear selection, filters, and findings left over from a previous capture
      topologyStore.reset()
    }
    timelineStore.setFullRange(timeRange[0], timeRange[1])
    timelineStore.histogram = histogram
    topologyStore.buildGraph(hosts, connections, positions)
    topologyStore.findings = findings
  }

  /** One worker drains the import queue; a drop during a batch only adds to it. */
  let workerRunning = false

  async function runQueue() {
    const appStore = useAppStore()
    if (workerRunning) return
    workerRunning = true
    const startedFresh = appStore.loadedFile === null
    appStore.freshBatch = startedFresh

    // The backend's events name no file; the worker never overlaps imports,
    // so whatever is running is the target.
    let running: number | null = null
    const unlistenProgress = await listen<{ bytes_done: number; bytes_total: number }>(
      'import-progress',
      (event) => {
        if (running !== null && event.payload.bytes_total > 0) {
          appStore.setJobProgress(running, event.payload.bytes_done / event.payload.bytes_total)
        }
      },
    )
    const unlistenStage = await listen<ImportStage>('import-stage', (event) => {
      if (running !== null) appStore.setJobStage(running, event.payload)
    })

    // The last file that loaded keeps its row "running" until the view is
    // built, so the final stage reads honestly.
    let pending: { id: number; packets: number } | null = null
    let loadedAny = false
    try {
      for (;;) {
        const job = appStore.jobs.find((j) => j.status === 'queued')
        if (!job) break
        if (pending) {
          appStore.finishJob(pending.id, pending.packets)
          pending = null
        }
        running = job.id
        appStore.startJob(job.id)
        // The first file into an empty session replaces; everything after
        // stitches in. Decided per job, so a failed first file is not fatal.
        const mode = appStore.loadedFile === null ? 'replace' : 'append'
        try {
          const result = mode === 'append' ? await addPcap(job.path) : await importPcap(job.path)
          if (result.packet_count === 0 && mode === 'replace') {
            appStore.failJob(job.id, noTrafficMessage(result))
          } else {
            if (mode === 'replace') appStore.setLoadedFile(job.path, result.packet_count, result)
            else appStore.addSource(job.path, result.packet_count, result)
            pending = { id: job.id, packets: result.packet_count }
            loadedAny = true
          }
        } catch (e) {
          appStore.failJob(job.id, humanizeError(e instanceof Error ? e.message : String(e)))
        }
        running = null
      }
      if (pending) appStore.setJobStage(pending.id, 'building-view')
      if (loadedAny) await refreshView(startedFresh)
      if (pending) appStore.finishJob(pending.id, pending.packets)
    } finally {
      unlistenProgress()
      unlistenStage()
      appStore.freshBatch = false
      workerRunning = false
    }
  }

  /**
   * Queue captures for import. On an empty window the first one starts the
   * session; over a loaded view they stitch in; during a running batch they
   * join the queue. The view is rebuilt once when the queue drains.
   */
  async function loadFiles(paths: string[]) {
    const appStore = useAppStore()
    const captures = paths.filter(isCaptureFile)
    if (captures.length === 0) {
      appStore.setError('No capture files here. Drop a .pcap or .pcapng instead.')
      return
    }
    appStore.enqueue(captures)
    await runQueue()
  }

  /** Open the native capture picker and load whatever the user selects. */
  async function pickAndLoadFiles() {
    const selected = await open({
      multiple: true,
      filters: [{ name: 'Packet captures', extensions: ACCEPTED_EXTENSIONS }],
    })
    if (!selected) return
    await loadFiles(Array.isArray(selected) ? selected : [selected])
  }

  return {
    importPcap,
    addPcap,
    getHosts,
    getConnections,
    getTimeRange,
    getTrafficHistogram,
    saveNodePosition,
    getNodePositions,
    getHostDetail,
    getFindings,
    getModbusHostActivity,
    getModbusConversation,
    setRoleOverride,
    setLevelOverride,
    loadFiles,
    pickAndLoadFiles,
  }
}
