import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type {
  Host,
  Connection,
  ImportResult,
  HostDetail,
  Packet,
  ModbusHostActivity,
  ModbusConversation,
  Finding,
  Role,
} from '@/types/network'
import { useAppStore, type ImportStage } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useTimelineStore } from '@/stores/timeline'

const ACCEPTED_EXTENSIONS = ['pcap', 'pcapng', 'cap']

export function isCaptureFile(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  return ACCEPTED_EXTENSIONS.includes(ext)
}

/** Turn backend errors into something a person can act on. */
function humanizeError(raw: string): string {
  const msg = raw.toLowerCase()
  if (msg.includes('file too small') || msg.includes('reader') || msg.includes('parse error')) {
    return "This file doesn't look like a packet capture. purdungeon reads .pcap and .pcapng files."
  }
  if (msg.includes('io error') || msg.includes('no such file') || msg.includes('os error')) {
    return "Couldn't open that file. Check that it still exists and is readable."
  }
  return raw
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

  async function saveNodePosition(hostId: number, x: number, y: number): Promise<void> {
    return invoke<void>('save_node_position', { hostId, x, y })
  }

  async function getNodePositions(): Promise<[number, number, number][]> {
    return invoke<[number, number, number][]>('get_node_positions')
  }

  async function getHostDetail(hostId: number): Promise<HostDetail> {
    return invoke<HostDetail>('get_host_detail', { hostId })
  }

  async function getConnectionPackets(connectionId: number, limit: number): Promise<Packet[]> {
    return invoke<Packet[]>('get_connection_packets', { connectionId, limit })
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

  /**
   * Load a capture. `replace` starts a fresh session; `append` stitches the
   * file into the current one. Either way the graph is rebuilt from the
   * (possibly merged) session.
   */
  async function loadFile(
    path: string,
    mode: 'replace' | 'append' = 'replace',
    fileIndex = 1,
    fileCount = 1,
  ) {
    const appStore = useAppStore()
    const topologyStore = useTopologyStore()
    const timelineStore = useTimelineStore()

    if (!isCaptureFile(path)) {
      appStore.setError('That isn’t a capture file. Drop a .pcap or .pcapng instead.')
      return
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
    let ok = false
    try {
      const result = mode === 'append' ? await addPcap(path) : await importPcap(path)
      if (result.packet_count === 0) {
        // On a fresh load that's an error; on an append it just means this file
        // added nothing — leave the existing view in place.
        if (mode === 'replace') {
          appStore.setError(
            'No readable network traffic in this capture. purdungeon currently reads IPv4 over Ethernet.',
          )
        } else {
          appStore.addSource(path, 0)
          ok = true
        }
      } else {
        appStore.setStage('building-view')
        const [hosts, connections, timeRange, findings, positions] = await Promise.all([
          getHosts(),
          getConnections(),
          getTimeRange(),
          getFindings(),
          getNodePositions(),
        ])
        if (mode === 'replace') {
          // Clear selection, filters, and findings left over from a previous capture
          topologyStore.reset()
        }
        timelineStore.setFullRange(timeRange[0], timeRange[1])
        topologyStore.buildGraph(hosts, connections, positions)
        topologyStore.findings = findings
        if (mode === 'replace') appStore.setLoadedFile(path, result.packet_count)
        else appStore.addSource(path, result.packet_count)
        ok = true
      }
    } catch (e) {
      appStore.setError(humanizeError(e instanceof Error ? e.message : String(e)))
    } finally {
      unlistenProgress()
      unlistenStage()
    }
    // Drain the step animation to the end (honouring each step's minimum screen
    // time) before the overlay closes. On error the overlay stays for the ack.
    if (ok) await appStore.finishLoading()
  }

  /**
   * Load several captures in one gesture: the first replaces the session (or
   * appends if one is already open), the rest stitch in, so the network grows
   * file by file. Stops if a file fails.
   */
  async function loadFiles(paths: string[]) {
    const appStore = useAppStore()
    const captures = paths.filter(isCaptureFile)
    if (captures.length === 0) {
      appStore.setError('No capture files here. Drop a .pcap or .pcapng instead.')
      return
    }
    for (let i = 0; i < captures.length; i++) {
      const mode = i === 0 && appStore.loadedFile === null ? 'replace' : 'append'
      await loadFile(captures[i], mode, i + 1, captures.length)
      if (appStore.error) break
    }
  }

  return {
    importPcap,
    addPcap,
    getHosts,
    getConnections,
    getTimeRange,
    saveNodePosition,
    getNodePositions,
    getHostDetail,
    getConnectionPackets,
    getFindings,
    getModbusHostActivity,
    getModbusConversation,
    setRoleOverride,
    setLevelOverride,
    loadFile,
    loadFiles,
  }
}
