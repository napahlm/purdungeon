<script setup lang="ts">
import { computed } from 'vue'
import { useAppStore } from '@/stores/app'
import ImportJobList from './ImportJobList.vue'

const appStore = useAppStore()

const title = computed(() =>
  appStore.jobs.length > 1 ? `Reading ${appStore.jobs.length} captures` : 'Reading capture',
)

// Every file failed and there is no session to show: keep the rows up with
// their messages until acknowledged.
const allFailed = computed(
  () =>
    !appStore.loading &&
    appStore.jobs.length > 0 &&
    appStore.jobs.every((j) => j.status === 'failed'),
)
</script>

<!-- Import progress on a fresh window. Closes the instant the batch lands. -->
<template>
  <div
    class="absolute inset-0 z-50 flex items-center justify-center bg-bg-primary/80 backdrop-blur-sm"
  >
    <!-- A batch-level problem with nothing to load: say so and ask for an ack -->
    <div
      v-if="appStore.error"
      class="flex w-80 flex-col gap-4 rounded-2xl border border-border bg-bg-secondary px-6 py-5"
    >
      <div class="flex items-center gap-2.5">
        <span class="flex h-6 w-6 items-center justify-center rounded-full bg-alert/15">
          <svg
            viewBox="0 0 16 16"
            class="h-3.5 w-3.5 text-alert"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
          >
            <path d="M8 4.5v4M8 11h.01" stroke-linecap="round" />
          </svg>
        </span>
        <h2 class="text-sm font-semibold text-text-primary">Couldn’t read that capture</h2>
      </div>
      <p class="text-sm leading-relaxed text-text-secondary">{{ appStore.error }}</p>
      <button
        class="self-end rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
        @click="appStore.clearError()"
      >
        OK
      </button>
    </div>

    <!-- Loading: one bar per file, stage text beside it -->
    <div v-else class="flex w-80 flex-col gap-5">
      <div>
        <h1 class="text-lg font-semibold text-text-primary">
          {{ allFailed ? 'Couldn’t read these captures' : title }}
        </h1>
        <p class="mt-1 text-sm text-text-muted">This stays on your machine.</p>
      </div>
      <ImportJobList />
      <button
        v-if="allFailed"
        class="self-end rounded-lg bg-bg-elevated px-4 py-1.5 text-sm text-text-primary transition-colors hover:bg-border"
        @click="appStore.clearFinishedJobs()"
      >
        OK
      </button>
    </div>
  </div>
</template>
