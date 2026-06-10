<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'
import Konva from 'konva'
import { useCanvas } from '@/composables/useCanvas'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import { createNodeGroup, updateNodeGroup } from '@/canvas/CanvasNode'
import { createEdgeLine, updateEdgeLine } from '@/canvas/CanvasEdge'
import { TEXT_MUTED } from '@/canvas/palette'

const containerRef = ref<HTMLDivElement | null>(null)
const { stage, bandLayer, mainLayer, fitToContent } = useCanvas(containerRef)

const topology = useTopologyStore()
const { saveNodePosition } = useTauri()

const nodeGroups = new Map<number, Konva.Group>()
const edgeLines = new Map<number, Konva.Line>()

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
  for (const l of edgeLines.values()) l.destroy()
  nodeGroups.clear()
  edgeLines.clear()

  // Edges first (below nodes)
  for (const edge of topology.filteredEdges) {
    const line = createEdgeLine(edge, {
      onClick(connectionId) {
        topology.selectEdge(connectionId === topology.selectedEdgeId ? null : connectionId)
      },
    })
    layer.add(line)
    edgeLines.set(edge.connection.id, line)
  }

  for (const node of topology.filteredNodes) {
    const group = createNodeGroup(node, {
      onDragMove(hostId, x, y) {
        topology.moveNode(hostId, x, y)
        updateEdgesFor(hostId)
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

function updateEdgesFor(hostId: number) {
  for (const edge of topology.filteredEdges) {
    if (edge.source.host.id === hostId || edge.target.host.id === hostId) {
      const line = edgeLines.get(edge.connection.id)
      if (line) updateEdgeLine(line, edge, edge.connection.id === topology.selectedEdgeId)
    }
  }
  mainLayer.value?.batchDraw()
}

function updateStyles() {
  const searching = topology.searchQuery.trim().length > 0
  const matched = topology.matchedNodeIds

  for (const node of topology.filteredNodes) {
    const group = nodeGroups.get(node.host.id)
    if (group) {
      let searchState: 'match' | 'dim' | 'none' = 'none'
      if (searching) {
        searchState = matched.has(node.host.id) ? 'match' : 'dim'
      }
      updateNodeGroup(group, node, node.host.id === topology.selectedNodeId, searchState)
    }
  }

  for (const edge of topology.filteredEdges) {
    const line = edgeLines.get(edge.connection.id)
    if (line) {
      updateEdgeLine(line, edge, edge.connection.id === topology.selectedEdgeId)
    }
  }

  mainLayer.value?.batchDraw()
}

// Full re-render when the visible graph changes
watch(
  () => [topology.filteredNodes, topology.filteredEdges],
  () => renderGraph(),
)

// New layout (fresh import or level override): re-render and fit the view
watch(
  () => topology.layoutVersion,
  async () => {
    await nextTick()
    renderGraph()
    const { minX, maxX, height } = contentBounds()
    fitToContent({ x: minX - 80, y: -40, width: maxX - minX + 160, height: height + 80 })
  },
)

watch(() => [topology.selectedNodeId, topology.selectedEdgeId], () => updateStyles())
watch(() => topology.searchQuery, () => updateStyles())

// Click on empty canvas clears the selection
watch(stage, (s) => {
  s?.on('click tap', (e) => {
    if (e.target === s) topology.clearSelection()
  })
})
</script>

<template>
  <div ref="containerRef" class="h-full w-full bg-bg-primary" />
</template>
