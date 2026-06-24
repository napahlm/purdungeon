<script setup lang="ts">
import { computed } from 'vue'
import { useAppStore, IMPORT_STAGES } from '@/stores/app'

const appStore = useAppStore()

// The displayed step is paced in the store so each stage gets a minimum screen
// time; here we just read it.
function stageState(i: number): 'done' | 'active' | 'pending' {
  if (i < appStore.displayStage) return 'done'
  if (i === appStore.displayStage) return 'active'
  return 'pending'
}

const progressPct = computed(() => Math.round(appStore.importProgress * 100))

const barWidth = computed(() => {
  const steps = IMPORT_STAGES.length - 1
  const within = appStore.displayStage === 0 ? appStore.importProgress * 0.6 : 0
  return Math.min(100, ((appStore.displayStage + within) / steps) * 100)
})

const fileLabel = computed(() =>
  appStore.totalFiles > 1 ? `File ${appStore.currentFile} of ${appStore.totalFiles}` : null,
)
</script>

<template>
  <div
    class="absolute inset-0 z-50 flex items-center justify-center bg-bg-primary/80 backdrop-blur-sm"
  >
    <!-- Error: stop and ask for acknowledgement rather than failing silently -->
    <div
      v-if="appStore.error"
      class="flex w-80 flex-col gap-4 rounded-2xl border border-border bg-bg-secondary px-6 py-5"
    >
      <div class="flex items-center gap-2.5">
        <span class="flex h-6 w-6 items-center justify-center rounded-full bg-alert/15">
          <svg viewBox="0 0 16 16" class="h-3.5 w-3.5 text-alert" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 4.5v4M8 11h.01" stroke-linecap="round" />
          </svg>
        </span>
        <h2 class="text-sm font-semibold text-text-primary">Couldn't read that capture</h2>
      </div>
      <p class="text-sm leading-relaxed text-text-secondary">{{ appStore.error }}</p>
      <button
        class="self-end rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
        @click="appStore.clearError()"
      >
        OK
      </button>
    </div>

    <!-- Loading: honest, paced steps -->
    <div v-else class="flex w-72 flex-col gap-6">
      <div>
        <h1 class="text-lg font-semibold text-text-primary">Reading capture</h1>
        <p class="mt-1 text-sm text-text-muted">
          <template v-if="fileLabel">{{ fileLabel }} · stays on your machine.</template>
          <template v-else>This stays on your machine.</template>
        </p>
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
            <svg v-if="stageState(i) === 'done'" viewBox="0 0 16 16" class="h-3.5 w-3.5 text-accent">
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
          :style="{ width: barWidth + '%' }"
        />
      </div>
    </div>
  </div>
</template>
