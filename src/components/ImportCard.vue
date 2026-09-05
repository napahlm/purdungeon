<script setup lang="ts">
import { computed, onUnmounted, watch } from 'vue'
import { useAppStore } from '@/stores/app'
import ImportJobList from './ImportJobList.vue'

const appStore = useAppStore()

/** How long the finished rows stay on screen before the card closes itself. */
const CLOSE_AFTER_MS = 1500
let closeTimer: ReturnType<typeof setTimeout> | null = null

const title = computed(() => {
  const n = appStore.jobs.length
  return n === 1 ? 'Adding a capture' : `Adding ${n} captures`
})

// Leave the completed rows up a moment so each outcome can be seen, then
// close. A new drop restarts the batch and cancels the close.
watch(
  () => appStore.loading,
  (loading) => {
    if (closeTimer !== null) {
      clearTimeout(closeTimer)
      closeTimer = null
    }
    if (!loading && appStore.jobs.length > 0) {
      closeTimer = setTimeout(() => appStore.clearFinishedJobs(), CLOSE_AFTER_MS)
    }
  },
  { immediate: true },
)

onUnmounted(() => {
  if (closeTimer !== null) clearTimeout(closeTimer)
})
</script>

<!-- Captures being added to an open session. Blocks the canvas until the
     batch is done; the graph rebuilds once at the end. -->
<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-bg-primary/40 backdrop-blur-sm"
  >
    <div
      class="flex w-80 flex-col gap-4 rounded-2xl border border-border bg-bg-secondary px-6 py-5 shadow-2xl"
    >
      <div class="flex items-baseline justify-between gap-3">
        <h2 class="text-sm font-semibold text-text-primary">{{ title }}</h2>
        <span v-if="appStore.loading" class="text-xs text-text-muted">Drop more to add them</span>
      </div>
      <ImportJobList />
      <button
        v-if="!appStore.loading"
        class="self-end rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
        @click="appStore.clearFinishedJobs()"
      >
        Done
      </button>
    </div>
  </div>
</template>
