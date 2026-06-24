import { ref, computed, shallowRef } from 'vue'
import { defineStore } from 'pinia'
import type { Host, Connection, Finding } from '@/types/network'
import { effectiveLevel, effectiveRole } from '@/types/network'
import type { CanvasNode, CanvasEdge, CanvasLink, BandLayout } from '@/types/canvas'
import {
  BANDS,
  bandKeyForHost,
  isCrossZone,
  levelColor,
  protoFamily,
  PROTO_COLORS,
  ALERT,
  type ProtoFamily,
} from '@/canvas/palette'
import { useTimelineStore } from './timeline'

const BAND_HEIGHT = 220
const NODE_SPACING = 130
const BARYCENTER_SWEEPS = 4

function nodeShape(host: Host): CanvasNode['shape'] {
  const role = effectiveRole(host)
  if (role === 'plc' || role === 'field-device') return 'square'
  if (role === 'network-gear') return 'diamond'
  return 'circle'
}

/** Link thickness from the pair's total bytes: floored so a thin link stays
 *  visible, capped so a busy one can't bully its neighbours. */
function linkWidth(totalBytes: number): number {
  const base = Math.log2(totalBytes / 512 + 2)
  return Math.max(1.5, Math.min(base, 8))
}

function ipSortKey(ip: string): number {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(Number.isNaN)) return Number.MAX_SAFE_INTEGER
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]
}

function pairKey(a: number, b: number): string {
  return a < b ? `${a}-${b}` : `${b}-${a}`
}

function addAdjacency(adjacency: Map<number, number[]>, a: number, b: number): void {
  const list = adjacency.get(a)
  if (list) list.push(b)
  else adjacency.set(a, [b])
}

/** Collapse every conversation between a host pair into one straight link. */
function buildLinks(edgeList: CanvasEdge[]): CanvasLink[] {
  const groups = new Map<string, CanvasEdge[]>()
  for (const e of edgeList) {
    const key = pairKey(e.source.host.id, e.target.host.id)
    const arr = groups.get(key)
    if (arr) arr.push(e)
    else groups.set(key, [e])
  }

  const links: CanvasLink[] = []
  for (const [key, edges] of groups) {
    const bytesByFamily = new Map<ProtoFamily, number>()
    let totalBytes = 0
    let crossZone = false
    for (const e of edges) {
      totalBytes += e.connection.byte_count
      bytesByFamily.set(e.family, (bytesByFamily.get(e.family) ?? 0) + e.connection.byte_count)
      if (e.crossZone) crossZone = true
    }
    // Dominant protocol family by volume drives the link colour, unless the
    // pair crosses a zone — a security signal that always wins.
    let dominantFamily = edges[0].family
    let max = -1
    for (const [family, bytes] of bytesByFamily) {
      if (bytes > max) {
        max = bytes
        dominantFamily = family
      }
    }
    links.push({
      key,
      source: edges[0].source,
      target: edges[0].target,
      edges,
      crossZone,
      dominantFamily,
      conversationCount: edges.length,
      color: crossZone ? ALERT : PROTO_COLORS[dominantFamily],
      width: linkWidth(totalBytes),
    })
  }
  return links
}

/**
 * Static Purdue-banded layout. Hosts sit in horizontal bands by level
 * (process at the bottom, enterprise at the top). Within a band, a few
 * barycenter sweeps pull connected nodes toward their peers in other
 * bands, then nodes are spaced evenly — deterministic and overlap-free.
 */
function layoutBands(nodes: CanvasNode[], adjacency: Map<number, number[]>): BandLayout[] {
  const byBand = new Map<string, CanvasNode[]>()
  for (const node of nodes) {
    let arr = byBand.get(node.bandKey)
    if (!arr) {
      arr = []
      byBand.set(node.bandKey, arr)
    }
    arr.push(node)
  }

  // Only bands that have hosts, in Purdue order (top → bottom)
  const populated = BANDS.filter((b) => byBand.has(b.key))
  const layouts: BandLayout[] = populated.map((b, i) => ({
    key: b.key,
    label: b.label,
    y: i * BAND_HEIGHT,
    height: BAND_HEIGHT,
    index: i,
  }))

  const nodeById = new Map<number, CanvasNode>()
  for (const node of nodes) nodeById.set(node.host.id, node)

  // Initial order: by IP, spaced around x = 0
  for (const layout of layouts) {
    const band = byBand.get(layout.key)!
    band.sort((a, b) => ipSortKey(a.host.ip_address) - ipSortKey(b.host.ip_address))
    respace(band, layout)
  }

  // Barycenter sweeps: pull nodes under their neighbors, keep even spacing
  for (let sweep = 0; sweep < BARYCENTER_SWEEPS; sweep++) {
    for (const layout of layouts) {
      const band = byBand.get(layout.key)!
      const desired = new Map<number, number>()
      for (const node of band) {
        const peers = adjacency.get(node.host.id) ?? []
        const xs = peers
          .map((id) => nodeById.get(id))
          .filter((n): n is CanvasNode => !!n && n.bandKey !== node.bandKey)
          .map((n) => n.x)
        desired.set(
          node.host.id,
          xs.length > 0 ? xs.reduce((a, b) => a + b, 0) / xs.length : node.x,
        )
      }
      band.sort((a, b) => desired.get(a.host.id)! - desired.get(b.host.id)!)
      respace(band, layout)
    }
  }

  return layouts
}

function respace(band: CanvasNode[], layout: BandLayout): void {
  const n = band.length
  for (let i = 0; i < n; i++) {
    band[i].x = (i - (n - 1) / 2) * NODE_SPACING
    band[i].y = layout.y + layout.height / 2
  }
}

export const useTopologyStore = defineStore('topology', () => {
  const nodes = shallowRef<CanvasNode[]>([])
  const edges = shallowRef<CanvasEdge[]>([])
  const bands = shallowRef<BandLayout[]>([])
  // Every host and connection from the capture, including broadcast/multicast
  // pseudo-hosts and self-loops that never become canvas nodes or edges. The
  // detail panels resolve from these so a selection is never a dead end.
  const hostsById = shallowRef(new Map<number, Host>())
  const connectionsById = shallowRef(new Map<number, Connection>())
  const layoutVersion = ref(0)
  const selectedNodeId = ref<number | null>(null)
  const selectedEdgeId = ref<number | null>(null)
  const selectedLinkKey = ref<string | null>(null)
  const searchQuery = ref('')

  // Filters: empty sets mean "show everything"
  const hiddenFamilies = ref(new Set<ProtoFamily>())
  const hiddenBands = ref(new Set<string>())
  const crossZoneOnly = ref(false)

  // Findings and the highlight they drive on the canvas
  const findings = ref<Finding[]>([])
  const activeFindingId = ref<number | null>(null)

  const activeFinding = computed(
    () => findings.value.find((f) => f.id === activeFindingId.value) ?? null,
  )

  function toggleFinding(finding: Finding) {
    if (activeFindingId.value === finding.id) {
      activeFindingId.value = null
      return
    }
    activeFindingId.value = finding.id
    // A finding about exactly one conversation opens its detail directly; one
    // about several conversations between the same pair opens their link list.
    if (finding.connection_ids.length === 1) {
      selectEdge(finding.connection_ids[0])
    } else if (finding.connection_ids.length > 1) {
      const key = sharedLinkKey(finding.connection_ids)
      if (key) selectLink(key)
    } else if (finding.host_ids.length === 1) {
      selectNode(finding.host_ids[0])
    }
  }

  /** The link key shared by these conversations, or null if they span more
   *  than one host pair (or no link is currently visible for them). */
  function sharedLinkKey(connectionIds: number[]): string | null {
    let key: string | null = null
    for (const id of connectionIds) {
      const c = connectionsById.value.get(id)
      if (!c) return null
      const k = pairKey(c.src_host_id, c.dst_host_id)
      if (key === null) key = k
      else if (key !== k) return null
    }
    return key && links.value.some((l) => l.key === key) ? key : null
  }

  const timelineStore = useTimelineStore()

  const visibleNodes = computed(() => {
    if (hiddenBands.value.size === 0) return nodes.value
    return nodes.value.filter((n) => !hiddenBands.value.has(n.bandKey))
  })

  const filteredEdges = computed(() => {
    let result = edges.value
    if (hiddenBands.value.size > 0) {
      result = result.filter(
        (e) => !hiddenBands.value.has(e.source.bandKey) && !hiddenBands.value.has(e.target.bandKey),
      )
    }
    if (hiddenFamilies.value.size > 0) {
      result = result.filter((e) => !hiddenFamilies.value.has(e.family))
    }
    if (crossZoneOnly.value) {
      result = result.filter((e) => e.crossZone)
    }
    if (timelineStore.filtering) {
      const { start, end } = timelineStore.filterRange
      result = result.filter(
        (e) => e.connection.last_seen >= start && e.connection.first_seen <= end,
      )
    }
    return result
  })

  const filteredNodes = computed(() => {
    if (!timelineStore.filtering && !crossZoneOnly.value) return visibleNodes.value
    const activeHostIds = new Set<number>()
    for (const edge of filteredEdges.value) {
      activeHostIds.add(edge.source.host.id)
      activeHostIds.add(edge.target.host.id)
    }
    return visibleNodes.value.filter((n) => activeHostIds.has(n.host.id))
  })

  /** One straight link per host pair, derived from the visible conversations. */
  const links = computed<CanvasLink[]>(() => buildLinks(filteredEdges.value))

  const selectedLink = computed(
    () => links.value.find((l) => l.key === selectedLinkKey.value) ?? null,
  )

  /** Protocol families present in the capture, for the filter bar. */
  const presentFamilies = computed<ProtoFamily[]>(() => {
    const found = new Set<ProtoFamily>()
    for (const e of edges.value) found.add(e.family)
    return (['modbus', 'ot', 'it', 'other'] as ProtoFamily[]).filter((f) => found.has(f))
  })

  const crossZoneCount = computed(() => edges.value.filter((e) => e.crossZone).length)

  const matchedNodeIds = computed<Set<number>>(() => {
    const q = searchQuery.value.trim().toLowerCase()
    if (!q) return new Set()
    const matched = new Set<number>()
    for (const node of nodes.value) {
      const h = node.host
      if (
        h.ip_address.toLowerCase().includes(q) ||
        h.mac_address.toLowerCase().includes(q) ||
        effectiveRole(h).toLowerCase().includes(q) ||
        (h.vendor ?? '').toLowerCase().includes(q) ||
        h.protocols.toLowerCase().includes(q)
      ) {
        matched.add(h.id)
      }
    }
    return matched
  })

  function buildGraph(hosts: Host[], connections: Connection[]) {
    hostsById.value = new Map(hosts.map((h) => [h.id, h]))
    connectionsById.value = new Map(connections.map((c) => [c.id, c]))

    const nodeMap = new Map<number, CanvasNode>()
    const built: CanvasNode[] = []

    for (const host of hosts) {
      const bandKey = bandKeyForHost(host)
      if (!bandKey) continue // broadcast/multicast pseudo-hosts stay out of the view
      const node: CanvasNode = {
        host,
        x: 0,
        y: 0,
        bandKey,
        color: levelColor(host),
        label: host.ip_address,
        shape: nodeShape(host),
        dashed: host.is_external,
      }
      nodeMap.set(host.id, node)
      built.push(node)
    }

    const adjacency = new Map<number, number[]>()
    const builtEdges: CanvasEdge[] = []
    for (const conn of connections) {
      const source = nodeMap.get(conn.src_host_id)
      const target = nodeMap.get(conn.dst_host_id)
      if (!source || !target || source === target) continue

      const family = protoFamily(conn.app_protocol)
      const crossZone = isCrossZone(effectiveLevel(source.host), effectiveLevel(target.host))
      builtEdges.push({
        connection: conn,
        source,
        target,
        color: crossZone ? ALERT : PROTO_COLORS[family],
        width: linkWidth(conn.byte_count),
        family,
        crossZone,
      })
      addAdjacency(adjacency, conn.src_host_id, conn.dst_host_id)
      addAdjacency(adjacency, conn.dst_host_id, conn.src_host_id)
    }

    bands.value = layoutBands(built, adjacency)
    nodes.value = built
    edges.value = builtEdges
    layoutVersion.value++
  }

  /** Re-derive band, color, and shape after a role/level override. */
  function refreshHost(updated: Host) {
    hostsById.value.set(updated.id, updated)
    const node = nodes.value.find((n) => n.host.id === updated.id)
    if (!node) return
    node.host = updated
    node.color = levelColor(updated)
    node.shape = nodeShape(updated)
    const newBand = bandKeyForHost(updated)
    if (newBand && newBand !== node.bandKey) {
      // Band changed: relayout everything so the node moves to its level
      const adjacency = new Map<number, number[]>()
      for (const e of edges.value) {
        addAdjacency(adjacency, e.source.host.id, e.target.host.id)
        addAdjacency(adjacency, e.target.host.id, e.source.host.id)
      }
      node.bandKey = newBand
      bands.value = layoutBands(nodes.value, adjacency)
    }
    for (const e of edges.value) {
      if (e.source.host.id === updated.id || e.target.host.id === updated.id) {
        e.crossZone = isCrossZone(effectiveLevel(e.source.host), effectiveLevel(e.target.host))
        e.color = e.crossZone ? ALERT : PROTO_COLORS[e.family]
      }
    }
    layoutVersion.value++
  }

  /** Drag: free horizontally, clamped to the node's band vertically. */
  function moveNode(hostId: number, x: number, y: number) {
    const node = nodes.value.find((n) => n.host.id === hostId)
    if (!node) return
    const band = bands.value.find((b) => b.key === node.bandKey)
    node.x = x
    if (band) {
      const pad = 28
      node.y = Math.max(band.y + pad, Math.min(band.y + band.height - pad, y))
    } else {
      node.y = y
    }
  }

  function toggleFamily(family: ProtoFamily) {
    const s = new Set(hiddenFamilies.value)
    if (s.has(family)) s.delete(family)
    else s.add(family)
    hiddenFamilies.value = s
  }

  function toggleBand(key: string) {
    const s = new Set(hiddenBands.value)
    if (s.has(key)) s.delete(key)
    else s.add(key)
    hiddenBands.value = s
  }

  function selectNode(hostId: number | null) {
    selectedNodeId.value = hostId
    if (hostId !== null) {
      selectedEdgeId.value = null
      selectedLinkKey.value = null
    }
  }

  /** Select a single conversation. The parent link stays selected so closing
   *  the conversation panel returns to its list. */
  function selectEdge(edgeId: number | null) {
    selectedEdgeId.value = edgeId
    if (edgeId !== null) selectedNodeId.value = null
  }

  function selectLink(key: string | null) {
    selectedLinkKey.value = key
    if (key !== null) {
      selectedNodeId.value = null
      selectedEdgeId.value = null
    }
  }

  function clearSelection() {
    selectedNodeId.value = null
    selectedEdgeId.value = null
    selectedLinkKey.value = null
    activeFindingId.value = null
  }

  function reset() {
    nodes.value = []
    edges.value = []
    bands.value = []
    hostsById.value = new Map()
    connectionsById.value = new Map()
    selectedNodeId.value = null
    selectedEdgeId.value = null
    selectedLinkKey.value = null
    searchQuery.value = ''
    hiddenFamilies.value = new Set()
    hiddenBands.value = new Set()
    crossZoneOnly.value = false
    findings.value = []
    activeFindingId.value = null
  }

  return {
    nodes,
    edges,
    bands,
    hostsById,
    connectionsById,
    layoutVersion,
    selectedNodeId,
    selectedEdgeId,
    selectedLinkKey,
    searchQuery,
    hiddenFamilies,
    hiddenBands,
    crossZoneOnly,
    findings,
    activeFindingId,
    activeFinding,
    toggleFinding,
    presentFamilies,
    crossZoneCount,
    filteredNodes,
    filteredEdges,
    links,
    selectedLink,
    matchedNodeIds,
    buildGraph,
    refreshHost,
    moveNode,
    toggleFamily,
    toggleBand,
    selectNode,
    selectEdge,
    selectLink,
    clearSelection,
    reset,
  }
})
