<script setup lang="ts">
import { ref, watch, nextTick, onMounted } from 'vue'
import Konva from 'konva'
import { useCanvas } from '@/composables/useCanvas'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import { createNodeGroup, updateNodeGroup } from '@/canvas/CanvasNode'
import {
  createLinkLine,
  updateLinkLine,
  createLinkBadge,
  updateLinkBadge,
} from '@/canvas/CanvasLink'
import { TEXT_MUTED } from '@/canvas/palette'

const containerRef = ref<HTMLDivElement | null>(null)
const { stage, bandLayer, mainLayer, fitToContent } = useCanvas(containerRef)

const topology = useTopologyStore()
const { saveNodePosition } = useTauri()

const nodeGroups = new Map<number, Konva.Group>()
const linkLines = new Map<string, Konva.Line>()
const linkBadges = new Map<string, Konva.Label>()

function contentBounds() {
  let minX = Infinity
  let maxX = -Infinity
  for (const node of topology.nodes) {
    if (node.x < minX) minX = node.x
    if (node.x > maxX) maxX = node.x
  }
  if (!Number.isFinite(minX)) {
    minX = 0
    maxX = 0
  }
  const height = topology.bands.length * (topology.bands[0]?.height ?? 220)
  return { minX, maxX, height }
}

function renderBands() {
  const layer = bandLayer.value
  if (!layer) return
  layer.destroyChildren()

  const { minX, maxX } = contentBounds()
  const x = minX - 400
  const width = maxX - minX + 800

  for (const band of topology.bands) {
    if (band.index % 2 === 1) {
      layer.add(
        new Konva.Rect({
          x,
          y: band.y,
          width,
          height: band.height,
          fill: 'rgba(255,255,255,0.022)',
        }),
      )
    }
    layer.add(
      new Konva.Line({
        points: [x, band.y, x + width, band.y],
        stroke: 'rgba(255,255,255,0.05)',
        strokeWidth: 1,
      }),
    )
    layer.add(
      new Konva.Text({
        x: x + 16,
        y: band.y + 12,
        text: band.label.toUpperCase(),
        fontSize: 10,
        letterSpacing: 1.2,
        fontFamily: '-apple-system, BlinkMacSystemFont, system-ui, sans-serif',
        fill: TEXT_MUTED,
      }),
    )
  }
  layer.batchDraw()
}

function renderGraph() {
  const layer = mainLayer.value
  if (!layer) return

  for (const g of nodeGroups.values()) g.destroy()
  for (const l of linkLines.values()) l.destroy()
  for (const b of linkBadges.values()) b.destroy()
  nodeGroups.clear()
  linkLines.clear()
  linkBadges.clear()

  // Links first (below nodes), then their count badges on top of the lines
  for (const link of topology.links) {
    const line = createLinkLine(link, {
      onClick(key) {
        topology.selectLink(key === topology.selectedLinkKey ? null : key)
      },
    })
    layer.add(line)
    linkLines.set(link.key, line)
    if (link.conversationCount > 1) {
      const badge = createLinkBadge(link)
      layer.add(badge)
      linkBadges.set(link.key, badge)
    }
  }

  for (const node of topology.filteredNodes) {
    const group = createNodeGroup(node, {
      onDragMove(hostId, x, y) {
        topology.moveNode(hostId, x, y)
        updateLinksFor(hostId)
      },
      onDragEnd(hostId, x, y) {
        saveNodePosition(hostId, x, y)
      },
      onClick(hostId) {
        topology.selectNode(hostId === topology.selectedNodeId ? null : hostId)
      },
    })
    layer.add(group)
    nodeGroups.set(node.host.id, group)
  }

  renderBands()
  updateStyles()
  layer.batchDraw()
}

function updateLinksFor(hostId: number) {
  for (const link of topology.links) {
    if (link.source.host.id === hostId || link.target.host.id === hostId) {
      const line = linkLines.get(link.key)
      if (line) updateLinkLine(line, link, link.key === topology.selectedLinkKey)
      const badge = linkBadges.get(link.key)
      if (badge) updateLinkBadge(badge, link)
    }
  }
  mainLayer.value?.batchDraw()
}

function updateStyles() {
  const searching = topology.searchQuery.trim().length > 0
  const matched = topology.matchedNodeIds
  const finding = topology.activeFinding
  const findingHosts = new Set(finding?.host_ids ?? [])
  const findingConns = new Set(finding?.connection_ids ?? [])

  for (const node of topology.filteredNodes) {
    const group = nodeGroups.get(node.host.id)
    if (!group) continue
    let state: 'match' | 'dim' | 'none' = 'none'
    if (finding && findingHosts.size > 0) {
      state = findingHosts.has(node.host.id) ? 'match' : 'dim'
    } else if (searching) {
      state = matched.has(node.host.id) ? 'match' : 'dim'
    }
    updateNodeGroup(group, node, node.host.id === topology.selectedNodeId, state)
  }

  for (const link of topology.links) {
    const line = linkLines.get(link.key)
    if (!line) continue
    updateLinkLine(line, link, link.key === topology.selectedLinkKey)
    if (finding && findingConns.size > 0) {
      const inFinding = link.edges.some((e) => findingConns.has(e.connection.id))
      line.opacity(inFinding ? 1 : 0.06)
      const badge = linkBadges.get(link.key)
      if (badge) badge.opacity(inFinding ? 1 : 0.06)
    } else {
      const badge = linkBadges.get(link.key)
      if (badge) badge.opacity(1)
    }
  }

  mainLayer.value?.batchDraw()
}

function fitView() {
  const { minX, maxX, height } = contentBounds()
  fitToContent({ x: minX - 80, y: -40, width: maxX - minX + 160, height: height + 80 })
}

// The canvas mounts after the capture is imported (v-if in App.vue), so the
// store is already populated and no watcher fires for that initial state —
// draw it now. useCanvas registered its onMounted first, so the stage exists.
onMounted(() => {
  renderGraph()
  fitView()
})

// Full re-render when the visible graph changes
watch(
  () => [topology.filteredNodes, topology.links],
  () => renderGraph(),
)

// New layout (fresh import or level override): re-render and fit the view
watch(
  () => topology.layoutVersion,
  async () => {
    await nextTick()
    renderGraph()
    fitView()
  },
)

watch(
  () => [topology.selectedNodeId, topology.selectedEdgeId, topology.selectedLinkKey],
  () => updateStyles(),
)
watch(
  () => topology.searchQuery,
  () => updateStyles(),
)
watch(
  () => topology.activeFindingId,
  () => updateStyles(),
)

// Click on empty canvas clears the selection
watch(stage, (s) => {
  s?.on('click tap', (e) => {
    if (e.target === s) topology.clearSelection()
  })
})
</script>

<template>
  <!-- min-w-0: the Konva stage sets a fixed pixel width on its content div,
       which would otherwise act as a min-width and stop this flex item from
       shrinking when a detail panel opens — pushing the panel out of view. -->
  <div ref="containerRef" class="h-full min-w-0 flex-1 overflow-hidden bg-bg-primary" />
</template>
