import { ref, computed, shallowRef, triggerRef } from 'vue'
import { defineStore } from 'pinia'
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  type Simulation,
  type SimulationNodeDatum,
} from 'd3-force'
import type { Host, Connection } from '@/types/network'
import type { CanvasNode, CanvasEdge, LayoutConfig } from '@/types/canvas'
import { useTimelineStore } from './timeline'

type SimNode = CanvasNode & SimulationNodeDatum

const EDGE_COLORS: Record<string, string> = {
  TCP: '#6b7280',
  UDP: '#3b82f6',
  Modbus: '#39ff14',
}

const DEFAULT_LAYOUT: LayoutConfig = {
  linkDistance: 120,
  chargeStrength: -300,
  centerX: 640,
  centerY: 400,
}

const CLUSTER_THRESHOLD = 200

function edgeColor(conn: Connection): string {
  if (conn.app_protocol) return EDGE_COLORS[conn.app_protocol] ?? '#6b7280'
  return EDGE_COLORS[conn.protocol] ?? '#6b7280'
}

function edgeWidth(conn: Connection): number {
  const base = Math.log2(conn.packet_count + 1)
  return Math.max(1, Math.min(base, 6))
}

function getSubnet(ip: string): string {
  const parts = ip.split('.')
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}` : ip
}

function pairKey(a: number, b: number): string {
  return a < b ? `${a}-${b}` : `${b}-${a}`
}

const CURVE_SPACING = 30

function assignCurveOffsets(edgeList: CanvasEdge[]): void {
  const groups = new Map<string, CanvasEdge[]>()
  for (const e of edgeList) {
    const key = pairKey(e.source.host.id, e.target.host.id)
    let arr = groups.get(key)
    if (!arr) { arr = []; groups.set(key, arr) }
    arr.push(e)
  }
  for (const group of groups.values()) {
    if (group.length === 1) {
      group[0].curveOffset = 0
      continue
    }
    const n = group.length
    for (let i = 0; i < n; i++) {
      group[i].curveOffset = (i - (n - 1) / 2) * CURVE_SPACING
    }
  }
}

export const useTopologyStore = defineStore('topology', () => {
  const nodes = shallowRef<CanvasNode[]>([])
  const edges = shallowRef<CanvasEdge[]>([])
  const selectedNodeId = ref<number | null>(null)
  const selectedEdgeId = ref<number | null>(null)
  const searchQuery = ref('')
  const layout = ref<LayoutConfig>({ ...DEFAULT_LAYOUT })
  const expandedSubnets = ref(new Set<string>())
  const clustered = ref(false)
  const trafficMin = ref(0)
  const trafficMax = ref(Infinity)

  let simulation: Simulation<SimNode, undefined> | null = null
  let onTickCallback: (() => void) | null = null
  let rawHosts: Host[] = []
  let rawConnections: Connection[] = []

  const timelineStore = useTimelineStore()

  const filteredEdges = computed(() => {
    let result = edges.value
    if (timelineStore.filtering) {
      const { start, end } = timelineStore.filterRange
      result = result.filter((e) => e.connection.last_seen >= start && e.connection.first_seen <= end)
    }
    if (trafficMin.value > 0 || trafficMax.value < Infinity) {
      result = result.filter((e) => {
        const pc = e.connection.packet_count
        return pc >= trafficMin.value && pc <= trafficMax.value
      })
    }
    return result
  })

  const filteredNodes = computed(() => {
    if (!timelineStore.filtering) return nodes.value
    const activeHostIds = new Set<number>()
    for (const edge of filteredEdges.value) {
      activeHostIds.add(edge.source.host.id)
      activeHostIds.add(edge.target.host.id)
    }
    return nodes.value.filter((n) => activeHostIds.has(n.host.id))
  })

  const matchedNodeIds = computed<Set<number>>(() => {
    const q = searchQuery.value.trim().toLowerCase()
    if (!q) return new Set()
    const matched = new Set<number>()
    for (const node of nodes.value) {
      const h = node.host
      if (
        h.ip_address.toLowerCase().includes(q) ||
        h.mac_address.toLowerCase().includes(q) ||
        h.role.toLowerCase().includes(q) ||
        (h.vendor ?? '').toLowerCase().includes(q)
      ) {
        matched.add(h.id)
      }
    }
    for (const edge of edges.value) {
      const c = edge.connection
      const proto = (c.app_protocol ?? c.protocol).toLowerCase()
      if (proto.includes(q)) {
        matched.add(c.src_host_id)
        matched.add(c.dst_host_id)
      }
    }
    return matched
  })

  const packetCountRange = computed(() => {
    if (edges.value.length === 0) return { min: 0, max: 0 }
    let lo = Infinity
    let hi = 0
    for (const e of edges.value) {
      const pc = e.connection.packet_count
      if (pc < lo) lo = pc
      if (pc > hi) hi = pc
    }
    return { min: lo, max: hi }
  })

  function setTrafficFilter(min: number, max: number) {
    trafficMin.value = min
    trafficMax.value = max
  }

  function buildGraph(hosts: Host[], connections: Connection[]) {
    rawHosts = hosts
    rawConnections = connections
    expandedSubnets.value.clear()
    trafficMin.value = 0
    trafficMax.value = Infinity

    if (hosts.length > CLUSTER_THRESHOLD) {
      clustered.value = true
      rebuildClusteredGraph()
    } else {
      clustered.value = false
      buildFlatGraph(hosts, connections)
    }
  }

  function buildFlatGraph(hosts: Host[], connections: Connection[]) {
    const nodeMap = new Map<number, CanvasNode>()

    nodes.value = hosts.map((host) => {
      const node: CanvasNode = {
        host,
        x: layout.value.centerX + (Math.random() - 0.5) * 200,
        y: layout.value.centerY + (Math.random() - 0.5) * 200,
        vx: 0,
        vy: 0,
        radius: 18,
        color: '#39ff14',
        label: host.ip_address,
        pinned: false,
      }
      nodeMap.set(host.id, node)
      return node
    })

    edges.value = connections
      .filter((c) => nodeMap.has(c.src_host_id) && nodeMap.has(c.dst_host_id))
      .map((conn) => ({
        connection: conn,
        source: nodeMap.get(conn.src_host_id)!,
        target: nodeMap.get(conn.dst_host_id)!,
        color: edgeColor(conn),
        width: edgeWidth(conn),
        curveOffset: 0,
      }))

    assignCurveOffsets(edges.value)
    runSimulation()
  }

  function rebuildClusteredGraph() {
    const subnetMap = new Map<string, Host[]>()
    for (const h of rawHosts) {
      const s = getSubnet(h.ip_address)
      let arr = subnetMap.get(s)
      if (!arr) { arr = []; subnetMap.set(s, arr) }
      arr.push(h)
    }

    const nodeMap = new Map<number, CanvasNode>()
    const hostToNodeId = new Map<number, number>()
    let nextClusterId = -1

    for (const [subnet, hosts] of subnetMap) {
      if (hosts.length <= 1 || expandedSubnets.value.has(subnet)) {
        for (const host of hosts) {
          const node: CanvasNode = {
            host,
            x: layout.value.centerX + (Math.random() - 0.5) * 200,
            y: layout.value.centerY + (Math.random() - 0.5) * 200,
            vx: 0, vy: 0,
            radius: 18,
            color: '#39ff14',
            label: host.ip_address,
            pinned: false,
          }
          nodeMap.set(host.id, node)
          hostToNodeId.set(host.id, host.id)
        }
      } else {
        const cId = nextClusterId--
        const fakeHost: Host = {
          id: cId,
          mac_address: '',
          ip_address: `${subnet}.0/24`,
          hostname: null,
          vendor: null,
          role: 'subnet',
          role_confidence: 1,
          role_evidence: null,
          purdue_level: null,
          role_override: null,
          level_override: null,
          protocols: '',
          is_external: false,
          first_seen: Math.min(...hosts.map((h) => h.first_seen)),
          last_seen: Math.max(...hosts.map((h) => h.last_seen)),
        }
        const node: CanvasNode = {
          host: fakeHost,
          x: layout.value.centerX + (Math.random() - 0.5) * 200,
          y: layout.value.centerY + (Math.random() - 0.5) * 200,
          vx: 0, vy: 0,
          radius: Math.min(40, 18 + Math.sqrt(hosts.length) * 3),
          color: '#6366f1',
          label: `${subnet}.0/24 (${hosts.length})`,
          pinned: false,
          cluster: { subnet, hostCount: hosts.length, hostIds: hosts.map((h) => h.id) },
        }
        nodeMap.set(cId, node)
        for (const h of hosts) hostToNodeId.set(h.id, cId)
      }
    }

    nodes.value = Array.from(nodeMap.values())

    // Build edges: keep originals between individual nodes, aggregate for clusters
    const newEdges: CanvasEdge[] = []
    const aggKey = (a: number, b: number) => `${Math.min(a, b)}-${Math.max(a, b)}`
    const aggregated = new Map<string, { src: number; dst: number; packets: number; bytes: number; firstSeen: number; lastSeen: number; protocol: string; appProtocol: string | null }>()

    for (const conn of rawConnections) {
      const srcId = hostToNodeId.get(conn.src_host_id)
      const dstId = hostToNodeId.get(conn.dst_host_id)
      if (srcId === undefined || dstId === undefined || srcId === dstId) continue

      if (srcId === conn.src_host_id && dstId === conn.dst_host_id) {
        // Both endpoints are individual — keep original connection
        newEdges.push({
          connection: conn,
          source: nodeMap.get(srcId)!,
          target: nodeMap.get(dstId)!,
          color: edgeColor(conn),
          width: edgeWidth(conn),
          curveOffset: 0,
        })
      } else {
        // At least one endpoint is a cluster — aggregate
        const key = aggKey(srcId, dstId)
        const ex = aggregated.get(key)
        if (ex) {
          ex.packets += conn.packet_count
          ex.bytes += conn.byte_count
          ex.firstSeen = Math.min(ex.firstSeen, conn.first_seen)
          ex.lastSeen = Math.max(ex.lastSeen, conn.last_seen)
        } else {
          aggregated.set(key, {
            src: srcId, dst: dstId,
            packets: conn.packet_count, bytes: conn.byte_count,
            firstSeen: conn.first_seen, lastSeen: conn.last_seen,
            protocol: conn.protocol, appProtocol: conn.app_protocol,
          })
        }
      }
    }

    let syntheticId = -1
    for (const agg of aggregated.values()) {
      const synConn: Connection = {
        id: syntheticId--,
        src_host_id: agg.src, dst_host_id: agg.dst,
        src_port: 0, dst_port: 0,
        protocol: agg.protocol, app_protocol: agg.appProtocol,
        packet_count: agg.packets, byte_count: agg.bytes,
        first_seen: agg.firstSeen, last_seen: agg.lastSeen,
      }
      newEdges.push({
        connection: synConn,
        source: nodeMap.get(agg.src)!,
        target: nodeMap.get(agg.dst)!,
        color: edgeColor(synConn),
        width: edgeWidth(synConn),
        curveOffset: 0,
      })
    }

    edges.value = newEdges
    assignCurveOffsets(edges.value)
    runSimulation()
  }

  function toggleCluster(subnet: string) {
    const s = expandedSubnets.value
    if (s.has(subnet)) {
      s.delete(subnet)
    } else {
      s.add(subnet)
    }
    rebuildClusteredGraph()
  }

  function runSimulation() {
    if (simulation) simulation.stop()

    const simNodes = nodes.value as SimNode[]
    const simLinks = edges.value.map((e) => ({
      source: simNodes.indexOf(e.source as SimNode),
      target: simNodes.indexOf(e.target as SimNode),
    }))

    const nodeCount = simNodes.length
    const charge = nodeCount > 200 ? -150 : layout.value.chargeStrength
    const alphaDecay = nodeCount > 200 ? 0.05 : 0.0228

    simulation = forceSimulation(simNodes)
      .force(
        'link',
        forceLink(simLinks).distance(layout.value.linkDistance),
      )
      .force('charge', forceManyBody().strength(charge))
      .force('center', forceCenter(layout.value.centerX, layout.value.centerY))
      .force('collide', forceCollide(24))
      .alphaDecay(alphaDecay)
      .on('tick', () => {
        triggerRef(nodes)
        onTickCallback?.()
      })
  }

  function setOnTick(cb: () => void) {
    onTickCallback = cb
  }

  function pinNode(hostId: number, x: number, y: number) {
    const node = nodes.value.find((n) => n.host.id === hostId)
    if (!node) return
    node.pinned = true
    node.x = x
    node.y = y
    const simNode = node as SimNode
    simNode.fx = x
    simNode.fy = y
  }

  function unpinNode(hostId: number) {
    const node = nodes.value.find((n) => n.host.id === hostId)
    if (!node) return
    node.pinned = false
    const simNode = node as SimNode
    simNode.fx = null
    simNode.fy = null
  }

  function selectNode(hostId: number | null) {
    selectedNodeId.value = hostId
    if (hostId !== null) selectedEdgeId.value = null
  }

  function selectEdge(edgeId: number | null) {
    selectedEdgeId.value = edgeId
    if (edgeId !== null) selectedNodeId.value = null
  }

  function clearSelection() {
    selectedNodeId.value = null
    selectedEdgeId.value = null
  }

  function reset() {
    if (simulation) simulation.stop()
    simulation = null
    nodes.value = []
    edges.value = []
    selectedNodeId.value = null
    selectedEdgeId.value = null
    searchQuery.value = ''
    expandedSubnets.value.clear()
    clustered.value = false
    trafficMin.value = 0
    trafficMax.value = Infinity
    rawHosts = []
    rawConnections = []
    onTickCallback = null
  }

  function updateCenter(cx: number, cy: number) {
    layout.value.centerX = cx
    layout.value.centerY = cy
    if (simulation) {
      simulation.force('center', forceCenter(cx, cy))
      simulation.alpha(0.3).restart()
    }
  }

  return {
    nodes,
    edges,
    selectedNodeId,
    selectedEdgeId,
    searchQuery,
    layout,
    clustered,
    filteredNodes,
    filteredEdges,
    matchedNodeIds,
    packetCountRange,
    trafficMin,
    trafficMax,
    buildGraph,
    setOnTick,
    pinNode,
    unpinNode,
    selectNode,
    selectEdge,
    clearSelection,
    setTrafficFilter,
    reset,
    updateCenter,
    toggleCluster,
  }
})
