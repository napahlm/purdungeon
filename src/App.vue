<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
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
import SearchBar from '@/components/SearchBar.vue'
import FilterBar from '@/components/FilterBar.vue'
import FindingsPanel from '@/components/FindingsPanel.vue'
import LevelLegend from '@/components/LevelLegend.vue'

const appStore = useAppStore()
const topology = useTopologyStore()
const { loadFile } = useTauri()

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
      if (event.payload.paths.length > 0) loadFile(event.payload.paths[0])
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
        <div class="absolute bottom-3 left-83 z-10">
          <FilterBar />
        </div>
        <div
          class="absolute right-3 top-3 z-10"
          :class="{
            'right-89': topology.selectedNodeId !== null || topology.selectedEdgeId !== null,
          }"
        >
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
          Drop to open this capture
        </div>
      </div>
    </template>
    <FileDropZone v-else />
  </div>
</template>
