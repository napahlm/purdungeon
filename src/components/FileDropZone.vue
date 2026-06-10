<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import { open } from '@tauri-apps/plugin-dialog'
import { useTauri } from '@/composables/useTauri'
import { useAppStore, IMPORT_STAGES } from '@/stores/app'

const appStore = useAppStore()
const { loadFile } = useTauri()

const hovering = ref(false)
const progressPct = computed(() => Math.round(appStore.importProgress * 100))

const currentStageIndex = computed(() => IMPORT_STAGES.findIndex((s) => s.id === appStore.stage))

function stageState(index: number): 'done' | 'active' | 'pending' {
  if (currentStageIndex.value < 0) return 'pending'
  if (index < currentStageIndex.value) return 'done'
  if (index === currentStageIndex.value) return 'active'
  return 'pending'
}

async function openFilePicker() {
  const selected = await open({
    multiple: false,
    filters: [{ name: 'Packet captures', extensions: ['pcap', 'pcapng', 'cap'] }],
  })
  if (selected) await loadFile(selected)
}

let unlisten: (() => void) | null = null

onMounted(async () => {
  const appWindow = getCurrentWebviewWindow()
  unlisten = await appWindow.onDragDropEvent((event) => {
    if (appStore.loading) return
    if (event.payload.type === 'over') {
      hovering.value = true
    } else if (event.payload.type === 'drop') {
      hovering.value = false
      const paths = event.payload.paths
      if (paths.length > 0) loadFile(paths[0])
    } else {
      hovering.value = false
    }
  })
})

onUnmounted(() => {
  unlisten?.()
})
</script>

<template>
  <div
    class="flex h-full w-full flex-col items-center justify-center transition-colors duration-200"
    :class="hovering ? 'bg-bg-secondary' : ''"
  >
    <!-- Loading: honest stages -->
    <div v-if="appStore.loading" class="flex w-72 flex-col gap-6">
      <div>
        <h1 class="text-lg font-semibold text-text-primary">Reading capture</h1>
        <p class="mt-1 text-sm text-text-muted">This stays on your machine.</p>
      </div>

      <ol class="flex flex-col gap-3">
        <li
          v-for="(s, i) in IMPORT_STAGES"
          :key="s.id"
          class="flex items-center gap-3 text-sm transition-colors duration-200"
          :class="{
            'text-text-muted': stageState(i) === 'pending',
            'text-text-primary': stageState(i) === 'active',
            'text-text-secondary': stageState(i) === 'done',
          }"
        >
          <span class="flex h-4 w-4 items-center justify-center" aria-hidden="true">
            <svg
              v-if="stageState(i) === 'done'"
              viewBox="0 0 16 16"
              class="h-3.5 w-3.5 text-accent"
            >
              <path
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M3 8.5 6.5 12 13 4.5"
              />
            </svg>
            <span
              v-else-if="stageState(i) === 'active'"
              class="h-2 w-2 animate-pulse rounded-full bg-accent"
            />
            <span v-else class="h-1.5 w-1.5 rounded-full bg-border-strong" />
          </span>
          <span class="flex-1">{{ s.label }}</span>
          <span
            v-if="s.id === 'reading-packets' && stageState(i) === 'active'"
            class="text-xs tabular-nums text-text-muted"
            >{{ progressPct }}%</span
          >
        </li>
      </ol>

      <div class="h-0.5 w-full overflow-hidden rounded-full bg-bg-elevated">
        <div
          class="h-full rounded-full bg-accent transition-all duration-200"
          :style="{
            width:
              currentStageIndex <= 0
                ? progressPct * 0.6 + '%'
                : 60 + (currentStageIndex / (IMPORT_STAGES.length - 1)) * 40 + '%',
          }"
        />
      </div>
    </div>

    <!-- Idle: drop target -->
    <div v-else class="flex flex-col items-center gap-8">
      <div class="flex flex-col items-center gap-2 text-center">
        <h1 class="text-2xl font-semibold tracking-tight text-text-primary">coil-sniffer</h1>
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
        <p class="text-sm text-text-secondary">Drop a capture anywhere</p>
        <p class="text-xs text-text-muted">.pcap or .pcapng</p>
        <button
          class="mt-2 rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
          @click="openFilePicker"
        >
          Choose a file
        </button>
      </div>

      <p v-if="appStore.error" class="max-w-sm text-center text-sm text-alert">
        {{ appStore.error }}
      </p>
    </div>
  </div>
</template>
