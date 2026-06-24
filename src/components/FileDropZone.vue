<script setup lang="ts">
import { computed } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { useTauri } from '@/composables/useTauri'
import { useAppStore } from '@/stores/app'

const appStore = useAppStore()
const { loadFiles } = useTauri()

// Drag-drop events are handled at the app root; this only mirrors the hover.
// Loading and error feedback live in LoadingOverlay.
const hovering = computed(() => appStore.dragHovering)

async function openFilePicker() {
  const selected = await open({
    multiple: true,
    filters: [{ name: 'Packet captures', extensions: ['pcap', 'pcapng', 'cap'] }],
  })
  if (!selected) return
  await loadFiles(Array.isArray(selected) ? selected : [selected])
}
</script>

<template>
  <div
    class="flex h-full w-full flex-col items-center justify-center transition-colors duration-200"
    :class="hovering ? 'bg-bg-secondary' : ''"
  >
    <div class="flex flex-col items-center gap-8">
      <div class="flex flex-col items-center gap-2 text-center">
        <h1 class="text-2xl font-semibold tracking-tight text-text-primary">purdungeon</h1>
        <p class="text-sm text-text-secondary">See the OT network inside a packet capture.</p>
      </div>

      <div
        class="flex w-96 flex-col items-center gap-4 rounded-2xl border border-dashed px-10 py-12 transition-colors duration-200"
        :class="hovering ? 'border-accent bg-bg-secondary' : 'border-border-strong'"
      >
        <svg
          viewBox="0 0 24 24"
          class="h-10 w-10"
          :class="hovering ? 'text-accent' : 'text-text-muted'"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 16V4m0 0L8 8m4-4 4 4M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"
          />
        </svg>
        <p class="text-sm text-text-secondary">Drop one or more captures</p>
        <p class="text-xs text-text-muted">.pcap or .pcapng · several files stitch together</p>
        <button
          class="mt-2 rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
          @click="openFilePicker"
        >
          Choose files
        </button>
      </div>
    </div>
  </div>
</template>
