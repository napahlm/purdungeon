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
    const appStore = useAppStore()
    const topologyStore = useTopologyStore()
    const timelineStore = useTimelineStore()
    appStore.setStage('building-view')
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

  type LoadOutcome = 'failed' | 'loaded' | 'refreshed'

  /**
   * Load a capture. `replace` starts a fresh session; `append` stitches the
   * file into the current one. With `refresh` (the default) the graph is
   * rebuilt afterwards; a multi-file batch turns it off for all but the last
   * file so the view is built once, not once per file.
   */
  async function loadFile(
    path: string,
    mode: 'replace' | 'append' = 'replace',
    fileIndex = 1,
    fileCount = 1,
    refresh = true,
  ): Promise<LoadOutcome> {
    const appStore = useAppStore()

    if (!isCaptureFile(path)) {
      appStore.setError('That isn’t a capture file. Drop a .pcap or .pcapng instead.')
      return 'failed'
    }

    appStore.startLoading(fileIndex, fileCount)
    const unlistenProgress = await listen<{ bytes_done: number; bytes_total: number }>(
      'import-progress',
      (event) => {
        if (event.payload.bytes_total > 0) {
          appStore.importProgress = event.payload.bytes_done / event.payload.bytes_total
        }
      },
    )
    const unlistenStage = await listen<ImportStage>('import-stage', (event) => {
      appStore.setStage(event.payload)
    })
    let outcome: LoadOutcome = 'failed'
    try {
      const result = mode === 'append' ? await addPcap(path) : await importPcap(path)
      if (result.packet_count === 0) {
        // On a fresh load that's an error; on an append it just means this file
        // added nothing — leave the existing view in place.
        if (mode === 'replace') {
          appStore.setError(noTrafficMessage(result))
        } else {
          appStore.addSource(path, 0, result)
          outcome = 'loaded'
        }
      } else {
        if (mode === 'replace') appStore.setLoadedFile(path, result.packet_count, result)
        else appStore.addSource(path, result.packet_count, result)
        if (refresh) {
          await refreshView(mode === 'replace')
          outcome = 'refreshed'
        } else {
          outcome = 'loaded'
        }
      }
    } catch (e) {
      appStore.setError(humanizeError(e instanceof Error ? e.message : String(e)))
    } finally {
      unlistenProgress()
      unlistenStage()
    }
    // Drain the step animation to the end (honouring each step's minimum screen
    // time) before the overlay closes. On error the overlay stays for the ack.
    if (outcome !== 'failed') await appStore.finishLoading()
    return outcome
  }

  /**
   * Load several captures in one gesture: the first replaces the session (or
   * appends if one is already open), the rest stitch in, so the network grows
   * file by file. Stops if a file fails. The view is rebuilt once at the end,
   * not after every file.
   */
  async function loadFiles(paths: string[]) {
    const appStore = useAppStore()
    const captures = paths.filter(isCaptureFile)
    if (captures.length === 0) {
      appStore.setError('No capture files here. Drop a .pcap or .pcapng instead.')
      return
    }
    const startingFresh = appStore.loadedFile === null
    let loadedAny = false
    let refreshed = false
    for (let i = 0; i < captures.length; i++) {
      const mode = i === 0 && startingFresh ? 'replace' : 'append'
      const isLast = i === captures.length - 1
      const outcome = await loadFile(captures[i], mode, i + 1, captures.length, isLast)
      if (outcome !== 'failed') loadedAny = true
      if (outcome === 'refreshed') refreshed = true
      if (appStore.error) break
    }
    // A mid-batch failure or an empty last file can leave imported data
    // unrendered — build the view for whatever did load.
    if (loadedAny && !refreshed) await refreshView(startingFresh)
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
    loadFile,
    loadFiles,
    pickAndLoadFiles,
  }
}
