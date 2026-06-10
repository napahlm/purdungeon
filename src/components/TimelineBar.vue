<script setup lang="ts">
import { ref, computed } from 'vue'
import { useTimelineStore } from '@/stores/timeline'

const timelineStore = useTimelineStore()

const containerRef = ref<HTMLDivElement | null>(null)
const dragging = ref<'start' | 'end' | null>(null)

const range = computed(() => timelineStore.fullRange)
const filter = computed(() => timelineStore.filterRange)
const span = computed(() => range.value.end - range.value.start || 1)

const startPct = computed(() => ((filter.value.start - range.value.start) / span.value) * 100)
const endPct = computed(() => ((filter.value.end - range.value.start) / span.value) * 100)

function formatTime(ts: number): string {
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function pctToValue(pct: number): number {
  return range.value.start + (pct / 100) * span.value
}

function pointerToPercent(clientX: number): number {
  if (!containerRef.value) return 0
  const rect = containerRef.value.getBoundingClientRect()
  return Math.max(0, Math.min(100, ((clientX - rect.left) / rect.width) * 100))
}

function onPointerDown(handle: 'start' | 'end', e: PointerEvent) {
  dragging.value = handle
  ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
}

function onPointerMove(e: PointerEvent) {
  if (!dragging.value) return
  const pct = pointerToPercent(e.clientX)
  const val = pctToValue(pct)

  if (dragging.value === 'start') {
    const clamped = Math.min(val, filter.value.end)
    timelineStore.setFilterRange(clamped, filter.value.end)
  } else {
    const clamped = Math.max(val, filter.value.start)
    timelineStore.setFilterRange(filter.value.start, clamped)
  }
}

function onPointerUp() {
  dragging.value = null
}

function resetFilter() {
  timelineStore.resetFilter()
}
</script>

<template>
  <div class="flex shrink-0 items-center gap-3 border-t border-border bg-bg-secondary px-4 py-2">
    <span class="text-xs text-text-muted whitespace-nowrap">{{ formatTime(filter.start) }}</span>

    <div
      ref="containerRef"
      class="relative h-6 flex-1 cursor-pointer select-none"
      @pointermove="onPointerMove"
      @pointerup="onPointerUp"
    >
      <!-- Track background -->
      <div class="absolute top-2.5 h-1 w-full rounded bg-bg-elevated" />

      <!-- Active region -->
      <div
        class="absolute top-2.5 h-1 rounded bg-accent/60"
        :style="{ left: startPct + '%', width: endPct - startPct + '%' }"
      />

      <!-- Start handle -->
      <div
        class="absolute top-1 h-4 w-2 cursor-ew-resize rounded-sm bg-accent transition-colors hover:bg-accent-dim"
        :style="{ left: 'calc(' + startPct + '% - 4px)' }"
        @pointerdown="onPointerDown('start', $event)"
      />

      <!-- End handle -->
      <div
        class="absolute top-1 h-4 w-2 cursor-ew-resize rounded-sm bg-accent transition-colors hover:bg-accent-dim"
        :style="{ left: 'calc(' + endPct + '% - 4px)' }"
        @pointerdown="onPointerDown('end', $event)"
      />
    </div>

    <span class="text-xs text-text-muted whitespace-nowrap">{{ formatTime(filter.end) }}</span>

    <button
      v-if="timelineStore.filtering"
      class="ml-1 rounded px-2 py-0.5 text-xs text-accent-dim transition-colors hover:bg-bg-elevated hover:text-accent"
      @click="resetFilter"
    >
      reset
    </button>
  </div>
</template>
