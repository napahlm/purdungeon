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
    filters: [{ name: 'PCAP files', extensions: ['pcap', 'pcapng', 'cap'] }],
  })
  if (!selected) return
  await loadFile(selected)
}

function closeInvestigation() {
  topologyStore.reset()
  timelineStore.reset()
  appStore.reset()
}
</script>

<template>
  <header class="flex h-10 shrink-0 items-center justify-between border-b border-border bg-bg-secondary px-4">
    <div class="flex items-center gap-4">
      <span class="text-sm font-bold tracking-wider text-accent">coil-sniffer</span>
      <div class="flex items-center gap-1">
        <button
          class="rounded px-2 py-0.5 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
          @click="openFile"
        >
          Open File
        </button>
        <button
          class="rounded px-2 py-0.5 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary"
          @click="closeInvestigation"
        >
          Close
        </button>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <span v-if="appStore.loading" class="text-xs text-accent-dim">
        importing... {{ Math.round(appStore.importProgress * 100) }}%
      </span>
      <span v-if="appStore.loadedFile" class="text-xs text-text-secondary">
        {{ fileName(appStore.loadedFile) }}
      </span>
    </div>
  </header>
</template>
