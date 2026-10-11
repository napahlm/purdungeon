<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted } from 'vue'
import Konva from 'konva'
import { useCanvas } from '@/composables/useCanvas'
import { useTopologyStore } from '@/stores/topology'
import { useAppStore } from '@/stores/app'
import { useTimelineStore } from '@/stores/timeline'
import { useTauri } from '@/composables/useTauri'
import { FINDINGS_PANEL_WIDTH, FINDINGS_RAIL_WIDTH } from '@/ui/layout'
import { createNodeGroup, updateNodeGroup } from '@/canvas/CanvasNode'
import {
  createLinkLine,
  updateLinkLine,
  createLinkBadge,
  updateLinkBadge,
} from '@/canvas/CanvasLink'
import { UI, FONTS } from '@/ui/tokens'
import { BANDS, levelColorFor } from '@/canvas/palette'

const containerRef = ref<HTMLDivElement | null>(null)
const { stage, bandLayer, mainLayer, scale, fitToContent, zoomBy } = useCanvas(containerRef)

const topology = useTopologyStore()
const appStore = useAppStore()
const timelineStore = useTimelineStore()
const { saveNodePosition } = useTauri()

// Filters or the time window can hide the whole graph - say so instead of
// showing an unexplained blank canvas.
const allHidden = computed(() => topology.nodes.length > 0 && topology.filteredNodes.length === 0)

function showEverything() {
  topology.hiddenFamilies = new Set()
  topology.hiddenBands = new Set()
  topology.crossZoneOnly = false
  timelineStore.resetFilter()
}

const nodeGroups = new Map<number, Konva.Group>()
const linkLines = new Map<string, Konva.Line>()
const linkBadges = new Map<string, Konva.Label>()

// Sub-groups inside the main layer keep z-order stable while the diff adds
// and removes children: links under badges under nodes.
let linksGroup: Konva.Group | null = null
let badgesGroup: Konva.Group | null = null
let nodesGroup: Konva.Group | null = null

function ensureGroups(layer: Konva.Layer) {
  if (linksGroup) return
  linksGroup = new Konva.Group()
  badgesGroup = new Konva.Group({ listening: false })
  nodesGroup = new Konva.Group()
  layer.add(linksGroup, badgesGroup, nodesGroup)
}

// Labels are unreadable when zoomed far out; hiding them keeps the far view
// clean and skips rasterizing hundreds of tiny text nodes.
const LABEL_MIN_SCALE = 0.45

// Bands run well past the outermost device so panning never finds their edge;
// the band labels sit a fixed distance left of the devices, inside the fitted
// view.
const BAND_OVERHANG = 2400
const BAND_LABEL_INSET = 130
let labelsVisible = true

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
  const x = minX - BAND_OVERHANG
  const width = maxX - minX + BAND_OVERHANG * 2
  const labelX = minX - BAND_LABEL_INSET

  const counts = new Map<string, number>()
  for (const node of topology.filteredNodes) {
    counts.set(node.bandKey, (counts.get(node.bandKey) ?? 0) + 1)
  }

  let boundaryDrawn = false
  for (const band of topology.bands) {
    const level = BANDS.find((b) => b.key === band.key)?.level ?? null
    const color = levelColorFor(level)

    // A faint wash of the level colour, so the zones read as zones even where
    // no device sits, alternating so neighbouring bands stay distinct.
    layer.add(
      new Konva.Rect({
        x,
        y: band.y,
        width,
        height: band.height,
        fill: color,
        opacity: band.index % 2 === 1 ? 0.06 : 0.035,
      }),
    )

    // The control/IT boundary (levels 2 and 3) is the line a consultant
    // draws first; mark it instead of a plain band edge.
    const above =
      band.index > 0 ? BANDS.find((b) => b.key === topology.bands[band.index - 1].key)?.level : null
    const isBoundary =
      !boundaryDrawn &&
      level !== null &&
      level <= 2 &&
      above !== null &&
      above !== undefined &&
      above >= 3
    if (isBoundary) {
      boundaryDrawn = true
      layer.add(
        new Konva.Line({
          points: [x, band.y, x + width, band.y],
          stroke: UI.warn,
          strokeWidth: 1.2,
          dash: [7, 5],
          opacity: 0.6,
        }),
      )
      layer.add(
        new Konva.Text({
          x: labelX,
          y: band.y - 16,
          text: 'IT / OT BOUNDARY',
          fontSize: 9,
          letterSpacing: 1.2,
          fontFamily: FONTS.sans,
          fill: UI.warn,
          opacity: 0.85,
        }),
      )
    } else {
      layer.add(
        new Konva.Line({
          points: [x, band.y, x + width, band.y],
          stroke: UI.bandLine,
          strokeWidth: 1,
        }),
      )
    }

    // Level accent bar, name and device count at the label edge.
    layer.add(
      new Konva.Rect({
        x: labelX - 12,
        y: band.y + 16,
        width: 3,
        height: band.height - 32,
        cornerRadius: 1.5,
        fill: color,
        opacity: 0.85,
      }),
    )
    layer.add(
      new Konva.Text({
        x: labelX,
        y: band.y + 16,
        text: band.label.toUpperCase(),
        fontSize: 10,
        letterSpacing: 1.2,
        fontFamily: FONTS.sans,
        fill: color,
      }),
    )
    const n = counts.get(band.key) ?? 0
    layer.add(
      new Konva.Text({
        x: labelX,
        y: band.y + 32,
        text: `${n} ${n === 1 ? 'device' : 'devices'}`,
        fontSize: 10,
        fontFamily: FONTS.sans,
        fill: UI.textMuted,
      }),
    )
  }
  layer.batchDraw()
}

const nodeCallbacks = {
  onDragMove(hostId: number, x: number, y: number) {
    topology.moveNode(hostId, x, y)
    updateLinksFor(hostId)
  },
  onDragEnd(hostId: number, x: number, y: number) {
    // Position saving is a convenience, not critical state - don't interrupt
    // the user over it, but leave a trace for debugging.
    saveNodePosition(hostId, x, y).catch((e) => console.warn('failed to save node position', e))
  },
  onClick(hostId: number) {
    topology.selectNode(hostId === topology.selectedNodeId ? null : hostId)
  },
}

/**
 * Reconcile the Konva scene with the store: create what's new, keep what
 * stayed, destroy what's gone. Filter and timeline changes touch only the
 * delta - never a full teardown, which made scrubbing unusable.
 */
function syncGraph() {
  const layer = mainLayer.value
  if (!layer) return
  ensureGroups(layer)

  const liveLinks = new Set<string>()
  for (const link of topology.links) {
    liveLinks.add(link.key)
    if (!linkLines.has(link.key)) {
      const line = createLinkLine(link, {
        onClick(key) {
          topology.selectLink(key === topology.selectedLinkKey ? null : key)
        },
      })
      linksGroup!.add(line)
      linkLines.set(link.key, line)
    }
    const badge = linkBadges.get(link.key)
    if (link.conversationCount > 1 && !badge) {
      const created = createLinkBadge(link)
      badgesGroup!.add(created)
      linkBadges.set(link.key, created)
    } else if (link.conversationCount <= 1 && badge) {
      badge.destroy()
      linkBadges.delete(link.key)
    }
  }
  for (const [key, line] of linkLines) {
    if (!liveLinks.has(key)) {
      line.destroy()
      linkLines.delete(key)
    }
  }
  for (const [key, badge] of linkBadges) {
    if (!liveLinks.has(key)) {
      badge.destroy()
      linkBadges.delete(key)
    }
  }

  const liveNodes = new Set<number>()
  for (const node of topology.filteredNodes) {
    liveNodes.add(node.host.id)
    // A changed shape kind, hollow style, color (role/level override) or label
    // (a name learnt from a stitched capture) rebuilds the group; position and
    // highlight changes update in place.
    const visual = `${node.shape}|${node.dashed}|${node.color}|${node.label}|${node.sublabel ?? ''}`
    const existing = nodeGroups.get(node.host.id)
    if (existing && existing.getAttr('visualKey') !== visual) {
      existing.destroy()
      nodeGroups.delete(node.host.id)
    }
    if (!nodeGroups.has(node.host.id)) {
      const group = createNodeGroup(node, nodeCallbacks)
      group.setAttr('visualKey', visual)
      group.findOne('.node-label')?.visible(labelsVisible)
      nodesGroup!.add(group)
      nodeGroups.set(node.host.id, group)
    }
  }
  for (const [id, group] of nodeGroups) {
    if (!liveNodes.has(id)) {
      group.destroy()
      nodeGroups.delete(id)
    }
  }

  renderBands()
  updateStyles()
}

function updateLinksFor(hostId: number) {
  for (const link of topology.linksByHostId.get(hostId) ?? []) {
    const line = linkLines.get(link.key)
    if (line) updateLinkLine(line, link, link.key === topology.selectedLinkKey)
    const badge = linkBadges.get(link.key)
    if (badge) updateLinkBadge(badge, link)
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

  const matchedLinks = topology.matchedLinkKeys
  for (const link of topology.links) {
    const line = linkLines.get(link.key)
    if (!line) continue
    // A finding or search dims the links it is not about; the renderer keeps
    // that dimming through hover and drag.
    let opacity: number | null = null
    if (finding && findingConns.size > 0) {
      opacity = link.edges.some((e) => findingConns.has(e.connection.id)) ? 1 : 0.06
    } else if (searching) {
      opacity = matchedLinks.has(link.key) ? 1 : 0.06
    }
    updateLinkLine(line, link, link.key === topology.selectedLinkKey, opacity)
    const badge = linkBadges.get(link.key)
    if (badge) {
      updateLinkBadge(badge, link)
      badge.opacity(opacity ?? 1)
    }
  }

  mainLayer.value?.batchDraw()
}

// The findings panel overlays the canvas on the left; frame content into
// the clear area beside it (narrower when it's collapsed to the rail).
function fitView() {
  const { minX, maxX, height } = contentBounds()
  fitToContent(
    {
      x: minX - BAND_LABEL_INSET - 24,
      y: -40,
      width: maxX - minX + BAND_LABEL_INSET + 24 + 80,
      height: height + 80,
    },
    appStore.findingsCollapsed ? FINDINGS_RAIL_WIDTH : FINDINGS_PANEL_WIDTH,
  )
}

// Which layout generation the scene currently shows. Lets the graph watcher
// stand down when a fresh import is about to trigger the layoutVersion
// watcher anyway - without this, every import rendered twice.
let renderedVersion = 0

// The canvas mounts after the capture is imported (v-if in App.vue), so the
// store is already populated and no watcher fires for that initial state -
// draw it now. useCanvas registered its onMounted first, so the stage exists.
onMounted(() => {
  renderedVersion = topology.layoutVersion
  syncGraph()
  fitView()
})

// Reconcile when the visible graph changes (filters, timeline, overrides)
watch(
  () => [topology.filteredNodes, topology.links],
  () => {
    if (topology.layoutVersion !== renderedVersion) return
    syncGraph()
  },
)

// New layout (fresh import or stitched capture): reconcile and fit the view
watch(
  () => topology.layoutVersion,
  async (version) => {
    await nextTick()
    renderedVersion = version
    syncGraph()
    fitView()
  },
)

// Re-frame when the findings panel opens or collapses, so content settles
// into the newly available space.
watch(
  () => appStore.findingsCollapsed,
  () => fitView(),
)

// Zoomed far out, labels become noise - toggle them with the zoom level.
watch(scale, (s) => {
  const show = s >= LABEL_MIN_SCALE
  if (show === labelsVisible) return
  labelsVisible = show
  for (const group of nodeGroups.values()) {
    group.findOne('.node-label')?.visible(show)
  }
  mainLayer.value?.batchDraw()
})

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
       shrinking when a detail panel opens - pushing the panel out of view. -->
  <div class="relative h-full min-w-0 flex-1 overflow-hidden">
    <div ref="containerRef" class="h-full w-full bg-bg-primary" />

    <!-- View controls -->
    <div
      class="absolute right-3 bottom-3 z-10 flex flex-col overflow-hidden rounded-lg border border-border bg-bg-secondary/90 backdrop-blur"
    >
      <button
        class="p-1.5 text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        title="Zoom in"
        @click="zoomBy(1.3)"
      >
        <svg
          viewBox="0 0 16 16"
          class="h-4 w-4"
          fill="none"
          stroke="currentColor"
          stroke-width="1.6"
        >
          <path d="M8 3.5v9M3.5 8h9" stroke-linecap="round" />
        </svg>
      </button>
      <button
        class="p-1.5 text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        title="Zoom out"
        @click="zoomBy(1 / 1.3)"
      >
        <svg
          viewBox="0 0 16 16"
          class="h-4 w-4"
          fill="none"
          stroke="currentColor"
          stroke-width="1.6"
        >
          <path d="M3.5 8h9" stroke-linecap="round" />
        </svg>
      </button>
      <button
        class="p-1.5 text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        title="Fit the network in view"
        @click="fitView"
      >
        <svg
          viewBox="0 0 16 16"
          class="h-4 w-4"
          fill="none"
          stroke="currentColor"
          stroke-width="1.6"
        >
          <path
            d="M6 2.5H2.5V6M10 2.5h3.5V6M6 13.5H2.5V10M10 13.5h3.5V10"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
    </div>

    <!-- Everything filtered out -->
    <div
      v-if="allHidden"
      class="pointer-events-none absolute inset-0 z-10 flex items-center justify-center"
    >
      <div
        class="pointer-events-auto flex flex-col items-center gap-3 rounded-xl border border-border bg-bg-secondary/95 px-8 py-6 text-center backdrop-blur"
      >
        <p class="text-sm text-text-primary">
          {{
            timelineStore.filtering ? 'Nothing in this time window' : 'Everything is filtered out'
          }}
        </p>
        <p class="max-w-60 text-xs text-text-muted">
          The capture is still loaded - the current filters just hide all of it.
        </p>
        <button
          class="rounded-md bg-bg-elevated px-3 py-1.5 text-xs text-text-primary transition-colors hover:bg-border"
          @click="showEverything"
        >
          Show everything
        </button>
      </div>
    </div>
  </div>
</template>
