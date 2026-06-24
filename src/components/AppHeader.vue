<script setup lang="ts">
import { open } from '@tauri-apps/plugin-dialog'
import { useAppStore } from '@/stores/app'
import { useTopologyStore } from '@/stores/topology'
import { useTimelineStore } from '@/stores/timeline'
import { useTauri } from '@/composables/useTauri'

const appStore = useAppStore()
const topologyStore = useTopologyStore()
const timelineStore = useTimelineStore()
const { loadFile } = useTauri()

function fileName(path: string): string {
  const sep = path.includes('\\') ? '\\' : '/'
  return path.split(sep).pop() ?? path
}

async function openFile() {
  const selected = await open({
    multiple: false,
    filters: [{ name: 'Packet captures', extensions: ['pcap', 'pcapng', 'cap'] }],
  })
  if (!selected) return
  await loadFile(selected)
}

function closeCapture() {
  topologyStore.reset()
  timelineStore.reset()
  appStore.reset()
}
</script>

<template>
  <header
    class="flex h-11 shrink-0 items-center justify-between border-b border-border bg-bg-secondary px-4"
  >
    <div class="flex items-baseline gap-4">
      <span class="text-sm font-semibold tracking-tight text-text-primary">purdungeon</span>
      <span v-if="appStore.loadedFile" class="text-xs text-text-muted">
        {{ fileName(appStore.loadedFile) }}
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
        @click="openFile"
      >
        Open…
      </button>
      <button
        class="rounded-md px-2.5 py-1 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
        @click="closeCapture"
      >
        Close
      </button>
    </div>
  </header>
</template>
