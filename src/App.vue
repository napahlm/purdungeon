<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import { useAppStore } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import FileDropZone from '@/components/FileDropZone.vue'
import AppHeader from '@/components/AppHeader.vue'
import TopologyCanvas from '@/components/TopologyCanvas.vue'
import TimelineBar from '@/components/TimelineBar.vue'
import NodeDetailPanel from '@/components/NodeDetailPanel.vue'
import EdgeDetailPanel from '@/components/EdgeDetailPanel.vue'
import LinkDetailPanel from '@/components/LinkDetailPanel.vue'
import SearchBar from '@/components/SearchBar.vue'
import FilterBar from '@/components/FilterBar.vue'
import FindingsPanel from '@/components/FindingsPanel.vue'
import LevelLegend from '@/components/LevelLegend.vue'
import LoadingOverlay from '@/components/LoadingOverlay.vue'
import ImportCard from '@/components/ImportCard.vue'
import { FINDINGS_PANEL_WIDTH, FINDINGS_RAIL_WIDTH, DETAIL_PANEL_WIDTH } from '@/ui/layout'

const appStore = useAppStore()
const topology = useTopologyStore()
const { loadFiles } = useTauri()

// A detail panel sits on the right; the legend tucks in beside it when open.
const panelOpen = computed(
  () =>
    topology.selectedNodeId !== null ||
    topology.selectedEdgeId !== null ||
    topology.selectedLinkKey !== null,
)

// Floating controls sit beside the overlaying panels — one shared set of
// widths (ui/layout.ts) keeps them aligned as panels open and collapse.
const filterBarLeft = computed(
  () => (appStore.findingsCollapsed ? FINDINGS_RAIL_WIDTH : FINDINGS_PANEL_WIDTH) + 12 + 'px',
)
const legendRight = computed(() => (panelOpen.value ? DETAIL_PANEL_WIDTH + 12 : 12) + 'px')

// The full-screen overlay belongs to a window with nothing loaded yet: it
// stays up for the whole first batch, and afterwards only to show a batch
// that produced nothing. Once a session is open, imports run in the card.
const showOverlay = computed(
  () =>
    appStore.freshBatch ||
    (appStore.loadedFile === null && (appStore.jobs.length > 0 || appStore.error !== null)),
)
const showImportCard = computed(
  () => !appStore.freshBatch && appStore.loadedFile !== null && appStore.jobs.length > 0,
)

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    topology.clearSelection()
  }
}

// Dropping captures works anywhere, anytime: on an empty window the first one
// starts the session, over a loaded view they stitch in, and during a batch
// they join the queue.
let unlistenDrop: (() => void) | null = null

onMounted(async () => {
  window.addEventListener('keydown', onKeydown)
  const appWindow = getCurrentWebviewWindow()
  unlistenDrop = await appWindow.onDragDropEvent((event) => {
    if (event.payload.type === 'over') {
      appStore.dragHovering = true
    } else if (event.payload.type === 'drop') {
      appStore.dragHovering = false
      if (event.payload.paths.length > 0) loadFiles(event.payload.paths)
    } else {
      appStore.dragHovering = false
    }
  })
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  unlistenDrop?.()
})
</script>

<template>
  <div class="relative flex h-screen w-screen flex-col bg-bg-primary">
    <template v-if="appStore.loadedFile">
      <AppHeader />
      <div class="relative flex flex-1 overflow-hidden">
        <FindingsPanel />
        <TopologyCanvas />
        <Transition name="panel">
          <NodeDetailPanel v-if="topology.selectedNodeId !== null" />
        </Transition>
        <Transition name="panel">
          <EdgeDetailPanel v-if="topology.selectedEdgeId !== null" />
        </Transition>
        <Transition name="panel">
          <LinkDetailPanel
            v-if="topology.selectedEdgeId === null && topology.selectedLinkKey !== null"
          />
        </Transition>
        <div class="absolute bottom-3 z-10" :style="{ left: filterBarLeft }">
          <FilterBar />
        </div>
        <div class="absolute top-3 z-10" :style="{ right: legendRight }">
          <LevelLegend />
        </div>
      </div>
      <TimelineBar />
      <SearchBar />
      <!-- Drop target feedback over a loaded view -->
      <Transition name="overlay">
        <div
          v-if="appStore.dragHovering"
          class="pointer-events-none absolute inset-0 z-50 flex items-center justify-center bg-bg-primary/70 backdrop-blur-sm"
        >
          <div
            class="rounded-2xl border border-dashed border-accent bg-bg-secondary px-10 py-6 text-sm text-text-primary"
          >
            Drop to add to this network
          </div>
        </div>
      </Transition>
    </template>
    <FileDropZone v-else />

    <LoadingOverlay v-if="showOverlay" />
    <Transition name="overlay">
      <ImportCard v-if="showImportCard" />
    </Transition>
  </div>
</template>
