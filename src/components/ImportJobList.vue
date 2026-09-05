<script setup lang="ts">
import { useAppStore, jobBarWidth, jobStatusText } from '@/stores/app'

const appStore = useAppStore()

function fileName(path: string): string {
  const sep = path.includes('\\') ? '\\' : '/'
  return path.split(sep).pop() ?? path
}
</script>

<!-- One row per capture in the import queue: name, a bar that tracks bytes
     read and then the analysis stages, and the stage or outcome beside it. -->
<template>
  <ul class="flex flex-col gap-3">
    <li v-for="job in appStore.jobs" :key="job.id" class="flex flex-col gap-1.5">
      <div class="flex items-baseline justify-between gap-3">
        <span class="truncate font-mono text-xs text-text-primary" :title="job.path">
          {{ fileName(job.path) }}
        </span>
        <span
          class="flex shrink-0 items-center gap-1 text-xs tabular-nums"
          :class="job.status === 'failed' ? 'text-alert' : 'text-text-muted'"
        >
          <svg
            v-if="job.status === 'done'"
            viewBox="0 0 16 16"
            class="h-3 w-3 text-accent"
            aria-hidden="true"
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
          <!-- A failure's message goes under the bar so the name stays readable -->
          {{ job.status === 'failed' ? 'Failed' : jobStatusText(job) }}
        </span>
      </div>
      <div class="h-1 w-full overflow-hidden rounded-full bg-bg-elevated">
        <div
          class="h-full rounded-full transition-[width] duration-150 ease-out"
          :class="job.status === 'failed' ? 'bg-alert' : 'bg-accent'"
          :style="{ width: jobBarWidth(job) + '%' }"
        />
      </div>
      <p v-if="job.status === 'failed' && job.message" class="text-xs leading-relaxed text-alert">
        {{ job.message }}
      </p>
    </li>
  </ul>
</template>
