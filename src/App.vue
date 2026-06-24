<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import { useAppStore, IMPORT_STAGES } from '@/stores/app'
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

// Label for the in-progress stage, shown in the append overlay.
const stageLabel = computed(
  () => IMPORT_STAGES.find((s) => s.id === appStore.stage)?.label ?? 'Reading packets',
)

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    topology.clearSelection()
  }
}

// Dropping a capture works anywhere, anytime — including over a loaded view,
// where it replaces the current capture.
let unlistenDrop: (() => void) | null = null

onMounted(async () => {
  window.addEventListener('keydown', onKeydown)
  const appWindow = getCurrentWebviewWindow()
  unlistenDrop = await appWindow.onDragDropEvent((event) => {
    if (appStore.loading) return
    if (event.payload.type === 'over') {
      appStore.dragHovering = true
    } else if (event.payload.type === 'drop') {
      appStore.dragHovering = false
      // Dropping onto a loaded view stitches the files in; the first file on a
      // fresh window starts the session. loadFiles handles that distinction.
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
        <NodeDetailPanel v-if="topology.selectedNodeId !== null" />
        <EdgeDetailPanel v-if="topology.selectedEdgeId !== null" />
        <LinkDetailPanel
          v-if="topology.selectedEdgeId === null && topology.selectedLinkKey !== null"
        />
        <div class="absolute bottom-3 left-83 z-10">
          <FilterBar />
        </div>
        <div class="absolute top-3 z-10" :class="panelOpen ? 'right-89' : 'right-3'">
          <LevelLegend />
        </div>
      </div>
      <TimelineBar />
      <SearchBar />
      <!-- Drop target feedback over a loaded view -->
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

      <!-- Stitching a capture into the open session -->
      <div
        v-if="appStore.loading"
        class="pointer-events-none absolute inset-0 z-50 flex items-center justify-center bg-bg-primary/70 backdrop-blur-sm"
      >
        <div
          class="flex items-center gap-3 rounded-2xl border border-border bg-bg-secondary px-6 py-4 text-sm text-text-primary"
        >
          <span class="h-2 w-2 animate-pulse rounded-full bg-accent" />
          <span>{{ stageLabel }}</span>
        </div>
      </div>
    </template>
    <FileDropZone v-else />
  </div>
</template>
