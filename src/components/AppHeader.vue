<script setup lang="ts">
import { ref } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { useAppStore } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useTimelineStore } from '@/stores/timeline'
import { useTauri } from '@/composables/useTauri'

const appStore = useAppStore()
const topologyStore = useTopologyStore()
const timelineStore = useTimelineStore()
const { loadFiles } = useTauri()

const showSources = ref(false)

function fileName(path: string): string {
  const sep = path.includes('\\') ? '\\' : '/'
  return path.split(sep).pop() ?? path
}

async function addFiles() {
  const selected = await open({
    multiple: true,
    filters: [{ name: 'Packet captures', extensions: ['pcap', 'pcapng', 'cap'] }],
  })
  if (!selected) return
  await loadFiles(Array.isArray(selected) ? selected : [selected])
}

function closeCapture() {
  showSources.value = false
  topologyStore.reset()
  timelineStore.reset()
  appStore.reset()
}
</script>

<template>
  <header
    class="relative flex h-11 shrink-0 items-center justify-between border-b border-border bg-bg-secondary px-4"
  >
    <div class="flex items-baseline gap-4">
      <span class="text-sm font-semibold tracking-tight text-text-primary">purdungeon</span>
      <span v-if="appStore.loadedFile" class="flex items-baseline gap-1.5 text-xs text-text-muted">
        <!-- Single capture: just its name. Several: a count that opens the list. -->
        <span v-if="appStore.sources.length <= 1">{{ fileName(appStore.loadedFile) }}</span>
        <button
          v-else
          class="text-text-secondary transition-colors hover:text-text-primary"
          @click="showSources = !showSources"
        >
          {{ appStore.sources.length }} captures ▾
        </button>
        <span class="mx-1.5 text-border-strong">·</span>
        {{ topologyStore.nodes.length }} assets
        <span class="mx-1.5 text-border-strong">·</span>
        {{ topologyStore.edges.length }} conversations
      </span>
    </div>
    <div class="flex items-center gap-1">
      <span class="mr-2 hidden text-xs text-text-muted sm:inline">⌘K to search</span>
      <button
        class="rounded-md px-2.5 py-1 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        @click="addFiles"
      >
        Add…
      </button>
      <button
        class="rounded-md px-2.5 py-1 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        @click="closeCapture"
      >
        Close
      </button>
    </div>

    <!-- Sources list -->
    <template v-if="showSources">
      <div class="fixed inset-0 z-30" @click="showSources = false" />
      <div
        class="absolute left-4 top-11 z-40 mt-1 w-72 rounded-lg border border-border bg-bg-elevated p-1 shadow-lg"
      >
        <div class="px-2 py-1.5 text-xs font-medium uppercase tracking-wider text-text-muted">
          Stitched captures
        </div>
        <div
          v-for="(src, i) in appStore.sources"
          :key="i"
          class="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm"
        >
          <span class="truncate font-mono text-xs text-text-primary">{{ fileName(src.path) }}</span>
          <span class="shrink-0 text-xs tabular-nums text-text-muted"
            >{{ src.packets.toLocaleString() }} pkts</span
          >
        </div>
      </div>
    </template>
  </header>
</template>
