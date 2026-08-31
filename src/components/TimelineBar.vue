<script setup lang="ts">
import { ref, computed } from 'vue'
import { useTimelineStore } from '@/stores/timeline'
import { formatClock } from '@/utils/format'

const timelineStore = useTimelineStore()

const containerRef = ref<HTMLDivElement | null>(null)
const dragging = ref<'start' | 'end' | null>(null)

const range = computed(() => timelineStore.fullRange)
const filter = computed(() => timelineStore.filterRange)
const span = computed(() => range.value.end - range.value.start || 1)

const startPct = computed(() => ((filter.value.start - range.value.start) / span.value) * 100)
const endPct = computed(() => ((filter.value.end - range.value.start) / span.value) * 100)

// Traffic sparkline behind the track: shows where the packets are, so the
// slider explains itself. Square-root scaling keeps quiet periods visible
// next to bursts.
const histogram = computed(() => timelineStore.histogram)
const maxCount = computed(() =>
  histogram.value.reduce((max, b) => Math.max(max, b.packet_count), 0),
)

function barHeight(count: number): number {
  if (count <= 0 || maxCount.value <= 0) return 0
  return Math.max(6, Math.sqrt(count / maxCount.value) * 100)
}

function bucketInRange(index: number): boolean {
  const width = span.value / (histogram.value.length || 1)
  const center = range.value.start + (index + 0.5) * width
  return center >= filter.value.start && center <= filter.value.end
}

function pctToValue(pct: number): number {
  return range.value.start + (pct / 100) * span.value
}

function pointerToPercent(clientX: number): number {
  if (!containerRef.value) return 0
  const rect = containerRef.value.getBoundingClientRect()
  return Math.max(0, Math.min(100, ((clientX - rect.left) / rect.width) * 100))
}

// Scrubbing emits pointermove far faster than the canvas can usefully update;
// coalesce range changes to one store write per animation frame.
let pendingRange: { start: number; end: number } | null = null
let rafId = 0

function scheduleRange(start: number, end: number) {
  pendingRange = { start, end }
  if (rafId) return
  rafId = requestAnimationFrame(() => {
    rafId = 0
    if (pendingRange) {
      timelineStore.setFilterRange(pendingRange.start, pendingRange.end)
      pendingRange = null
    }
  })
}

function onPointerDown(handle: 'start' | 'end', e: PointerEvent) {
  dragging.value = handle
  ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
}

/** Pressing the bare track jumps the nearer handle there and starts dragging
 *  it, so the whole strip is interactive — not just the two thin handles. */
function onTrackPointerDown(e: PointerEvent) {
  if (dragging.value) return // a handle already claimed this press
  const val = pctToValue(pointerToPercent(e.clientX))
  const nearerStart = Math.abs(val - filter.value.start) <= Math.abs(val - filter.value.end)
  dragging.value = nearerStart ? 'start' : 'end'
  containerRef.value?.setPointerCapture(e.pointerId)
  onPointerMove(e)
}

function onPointerMove(e: PointerEvent) {
  if (!dragging.value) return
  const val = pctToValue(pointerToPercent(e.clientX))

  if (dragging.value === 'start') {
    scheduleRange(Math.min(val, filter.value.end), filter.value.end)
  } else {
    scheduleRange(filter.value.start, Math.max(val, filter.value.start))
  }
}

function onPointerUp() {
  dragging.value = null
  // Apply the last position immediately rather than waiting a frame.
  if (rafId) {
    cancelAnimationFrame(rafId)
    rafId = 0
  }
  if (pendingRange) {
    timelineStore.setFilterRange(pendingRange.start, pendingRange.end)
    pendingRange = null
  }
}

function resetFilter() {
  timelineStore.resetFilter()
}
</script>

<template>
  <div class="flex shrink-0 items-center gap-3 border-t border-border bg-bg-secondary px-4 py-2">
    <span class="text-xs text-text-muted whitespace-nowrap">{{ formatClock(filter.start) }}</span>

    <div
      ref="containerRef"
      class="relative h-10 flex-1 cursor-pointer select-none"
      @pointerdown="onTrackPointerDown"
      @pointermove="onPointerMove"
      @pointerup="onPointerUp"
      @pointercancel="onPointerUp"
    >
      <!-- Traffic sparkline: dimmed outside the selected window -->
      <svg
        v-if="histogram.length"
        class="pointer-events-none absolute inset-x-0 top-0 h-6.5 w-full"
        :viewBox="`0 0 ${histogram.length} 100`"
        preserveAspectRatio="none"
      >
        <rect
          v-for="(bucket, i) in histogram"
          :key="i"
          :x="i + 0.1"
          :y="100 - barHeight(bucket.packet_count)"
          width="0.8"
          :height="barHeight(bucket.packet_count)"
          :class="bucketInRange(i) ? 'fill-accent/45' : 'fill-text-muted/20'"
        />
      </svg>

      <!-- Track background -->
      <div class="absolute bottom-1 h-1 w-full rounded bg-bg-elevated" />

      <!-- Active region -->
      <div
        class="absolute bottom-1 h-1 rounded bg-accent/60"
        :style="{ left: startPct + '%', width: endPct - startPct + '%' }"
      />

      <!-- Start handle -->
      <div
        class="group absolute top-0 h-full w-2.5 cursor-ew-resize"
        :style="{ left: 'calc(' + startPct + '% - 5px)' }"
        @pointerdown="onPointerDown('start', $event)"
      >
        <div
          class="absolute inset-y-0 left-1/2 w-0.75 -translate-x-1/2 rounded-full bg-accent transition-colors group-hover:bg-accent-dim"
        />
      </div>

      <!-- End handle -->
      <div
        class="group absolute top-0 h-full w-2.5 cursor-ew-resize"
        :style="{ left: 'calc(' + endPct + '% - 5px)' }"
        @pointerdown="onPointerDown('end', $event)"
      >
        <div
          class="absolute inset-y-0 left-1/2 w-0.75 -translate-x-1/2 rounded-full bg-accent transition-colors group-hover:bg-accent-dim"
        />
      </div>
    </div>

    <span class="text-xs text-text-muted whitespace-nowrap">{{ formatClock(filter.end) }}</span>

    <button
      v-if="timelineStore.filtering"
      class="ml-1 rounded px-2 py-0.5 text-xs text-accent-dim transition-colors hover:bg-bg-elevated hover:text-accent"
      @click="resetFilter"
    >
      reset
    </button>
  </div>
</template>
