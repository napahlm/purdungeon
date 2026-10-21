<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import { listen } from '@tauri-apps/api/event'
import { useAppStore } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useCaptureStore } from '@/stores/capture'
import { useTauri } from '@/composables/useTauri'
import { useLiveCapture } from '@/composables/useLiveCapture'
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
import CaptureView from '@/components/capture/CaptureView.vue'
import { FINDINGS_PANEL_WIDTH, FINDINGS_RAIL_WIDTH, DETAIL_PANEL_WIDTH } from '@/ui/layout'

const appStore = useAppStore()
const topology = useTopologyStore()
const captureStore = useCaptureStore()
const { loadFiles, initialCaptures } = useTauri()
useLiveCapture()

const hasSession = computed(() => appStore.sessionName !== null)
const onTopology = computed(() => appStore.activeView === 'topology')

// A detail panel sits on the right; the legend tucks in beside it when open.
const panelOpen = computed(
  () =>
    topology.selectedNodeId !== null ||
    topology.selectedEdgeId !== null ||
    topology.selectedLinkKey !== null,
)

// Floating controls sit beside the overlaying panels - one shared set of
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
    (!hasSession.value && (appStore.jobs.length > 0 || appStore.error !== null)),
)
const showImportCard = computed(
  () => !appStore.freshBatch && hasSession.value && appStore.jobs.length > 0,
)

function onKeydown(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  if (onTopology.value) topology.clearSelection()
  else captureStore.selectedNo = null
}

// Dropping captures works anywhere, anytime: on an empty window the first one
// starts the session, over a loaded view they stitch in, and during a batch
// they join the queue. While an interface feeds the session the backend
// refuses the file, and the drop hint says so first.
let unlistenDrop: (() => void) | null = null
let unlistenOpen: (() => void) | null = null

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

  // Captures also arrive from the command line and from the OS (a double-
  // clicked file, "Open with"). Listen first, then drain what queued up before
  // the window was ready, so nothing falls in the gap between the two.
  unlistenOpen = await listen<string[]>('open-captures', (event) => loadFiles(event.payload))
  const initial = await initialCaptures()
  if (initial.length > 0) loadFiles(initial)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  unlistenDrop?.()
  unlistenOpen?.()
})
</script>

<template>
  <div class="relative flex h-screen w-screen flex-col bg-bg-primary">
    <AppHeader v-if="hasSession || !onTopology" />

    <!-- The topology stays mounted behind the capture tab: its Konva stage,
         pan and zoom would otherwise be rebuilt on every switch. -->
    <div v-show="onTopology" class="relative flex min-h-0 flex-1 flex-col">
      <template v-if="hasSession">
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
      </template>
      <FileDropZone v-else />
    </div>

    <CaptureView v-show="!onTopology" />

    <!-- Drop target feedback -->
    <Transition name="overlay">
      <div
        v-if="appStore.dragHovering && (hasSession || !onTopology)"
        class="pointer-events-none absolute inset-0 z-50 flex items-center justify-center bg-bg-primary/70 backdrop-blur-sm"
      >
        <div
          class="rounded-2xl border border-dashed border-accent bg-bg-secondary px-10 py-6 text-sm text-text-primary"
        >
          {{
            captureStore.running
              ? 'Stop the capture before adding files'
              : hasSession
                ? 'Drop to add to this network'
                : 'Drop to open'
          }}
        </div>
      </div>
    </Transition>

    <LoadingOverlay v-if="showOverlay" />
    <Transition name="overlay">
      <ImportCard v-if="showImportCard" />
    </Transition>
  </div>
</template>
