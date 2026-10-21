<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useCaptureStore } from '@/stores/capture'
import { useTauri } from '@/composables/useTauri'
import { PROTO_COLORS } from '@/canvas/palette'
import { formatClock } from '@/utils/format'
import type { PacketRow } from '@/types/capture'
import { familyForProtocol } from './protocolFamily'

const captureStore = useCaptureStore()
const { getPackets } = useTauri()

/** Rows are fixed-height so any row's position is arithmetic. */
const ROW_HEIGHT = 22
const PAGE_SIZE = 200
const OVERSCAN = 20
/** Within this many rows of the end counts as "at the end". */
const FOLLOW_SLACK_ROWS = 2

const viewportRef = ref<HTMLDivElement | null>(null)
const scrollTop = ref(0)
const viewportHeight = ref(0)
const timeMode = ref<'clock' | 'relative'>('clock')

const total = computed(() => captureStore.total)
const spacerHeight = computed(() => total.value * ROW_HEIGHT)

const firstVisible = computed(() =>
  Math.max(0, Math.floor(scrollTop.value / ROW_HEIGHT) - OVERSCAN),
)
const lastVisible = computed(() =>
  Math.min(
    total.value - 1,
    Math.ceil((scrollTop.value + viewportHeight.value) / ROW_HEIGHT) + OVERSCAN,
  ),
)

const visibleIndexes = computed(() => {
  const out: number[] = []
  for (let i = firstVisible.value; i <= lastVisible.value; i++) out.push(i)
  return out
})

function rowAt(index: number): PacketRow | null {
  const page = captureStore.pages.get(Math.floor(index / PAGE_SIZE))
  return page?.[index % PAGE_SIZE] ?? null
}

// ── Fetching ────────────────────────────────────────────────────────────────

const inFlight = new Set<number>()
let fetchGeneration = 0

async function fetchPage(index: number, generation: number) {
  if (inFlight.has(index)) return
  inFlight.add(index)
  try {
    const page = await getPackets(index * PAGE_SIZE, PAGE_SIZE, captureStore.query || null)
    if (generation !== fetchGeneration) return
    const next = new Map(captureStore.pages)
    next.set(index, page.rows)
    captureStore.pages = next
    captureStore.total = page.total
    captureStore.firstNo = page.first_no
  } catch (e) {
    console.warn('packet page unavailable', e)
  } finally {
    inFlight.delete(index)
  }
}

/** Fetch whatever the viewport needs that is not loaded. */
function fetchVisible() {
  if (!captureStore.hasCapture) return
  const generation = fetchGeneration
  const first = Math.floor(firstVisible.value / PAGE_SIZE)
  const last = Math.floor(Math.max(firstVisible.value, lastVisible.value) / PAGE_SIZE)
  for (let p = first; p <= last; p++) {
    if (!captureStore.pages.has(p)) void fetchPage(p, generation)
  }
  // The newest page keeps the total honest even when the view is elsewhere.
  if (total.value === 0) void fetchPage(0, generation)
}

// Pages are dropped on every tick (the ring moved) and on a query change;
// refetch what is on screen. The generation guards against a stale page
// landing after the drop.
watch(
  () => captureStore.pages,
  (pages) => {
    if (pages.size === 0) {
      fetchGeneration += 1
      inFlight.clear()
      fetchVisible()
    }
  },
)
watch(
  () => captureStore.query,
  () => {
    captureStore.invalidatePages()
    captureStore.total = 0
    captureStore.follow = true
  },
)
watch([firstVisible, lastVisible], () => fetchVisible())

// ── Follow mode ─────────────────────────────────────────────────────────────

function atEnd(): boolean {
  const el = viewportRef.value
  if (!el) return true
  return el.scrollHeight - el.scrollTop - el.clientHeight <= FOLLOW_SLACK_ROWS * ROW_HEIGHT
}

function scrollToEnd() {
  const el = viewportRef.value
  if (!el) return
  el.scrollTop = el.scrollHeight
  scrollTop.value = el.scrollTop
}

let scrollFrame = 0
function onScroll() {
  if (scrollFrame) return
  scrollFrame = requestAnimationFrame(() => {
    scrollFrame = 0
    const el = viewportRef.value
    if (!el) return
    scrollTop.value = el.scrollTop
    captureStore.follow = atEnd()
  })
}

watch(total, async () => {
  if (!captureStore.follow) return
  // Let the spacer grow before scrolling to its new end.
  await Promise.resolve()
  scrollToEnd()
})

function jumpToLatest() {
  captureStore.follow = true
  scrollToEnd()
}

// ── Selection ───────────────────────────────────────────────────────────────

function select(row: PacketRow | null) {
  if (!row) return
  captureStore.selectedNo = row.no === captureStore.selectedNo ? null : row.no
}

function indexOfSelected(): number | null {
  const no = captureStore.selectedNo
  if (no === null) return null
  for (const [page, rows] of captureStore.pages) {
    const i = rows.findIndex((r) => r.no === no)
    if (i >= 0) return page * PAGE_SIZE + i
  }
  return null
}

function onKeydown(e: KeyboardEvent) {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
  e.preventDefault()
  const current = indexOfSelected()
  const next =
    current === null
      ? e.key === 'ArrowDown'
        ? firstVisible.value
        : lastVisible.value
      : current + (e.key === 'ArrowDown' ? 1 : -1)
  const row = rowAt(Math.max(0, Math.min(total.value - 1, next)))
  if (row) {
    captureStore.selectedNo = row.no
    captureStore.follow = false
    const el = viewportRef.value
    if (el) {
      const top = next * ROW_HEIGHT
      if (top < el.scrollTop) el.scrollTop = top
      else if (top + ROW_HEIGHT > el.scrollTop + el.clientHeight) {
        el.scrollTop = top + ROW_HEIGHT - el.clientHeight
      }
    }
  }
}

// ── Formatting ──────────────────────────────────────────────────────────────

const startedAt = computed(() => captureStore.status?.started_at ?? 0)

function formatRowTime(ts: number): string {
  if (timeMode.value === 'relative') return (ts - startedAt.value).toFixed(3)
  return formatClock(ts)
}

function protocolColor(row: PacketRow): string {
  return PROTO_COLORS[familyForProtocol(row.protocol, row.app_protocol)]
}

let resizeObserver: ResizeObserver | null = null
onMounted(() => {
  resizeObserver = new ResizeObserver(() => {
    viewportHeight.value = viewportRef.value?.clientHeight ?? 0
    if (captureStore.follow) scrollToEnd()
  })
  if (viewportRef.value) resizeObserver.observe(viewportRef.value)
  fetchVisible()
})
onUnmounted(() => {
  resizeObserver?.disconnect()
  if (scrollFrame) cancelAnimationFrame(scrollFrame)
})
</script>

<template>
  <div class="relative flex min-h-0 flex-1 flex-col">
    <!-- Column headers -->
    <div
      class="grid shrink-0 grid-cols-[72px_104px_minmax(120px,1fr)_minmax(120px,1fr)_88px_64px_minmax(200px,2fr)] gap-x-3 border-b border-border bg-bg-secondary px-3 py-1 text-[11px] font-medium uppercase tracking-wider text-text-muted"
    >
      <span class="text-right">No.</span>
      <button
        class="text-left transition-colors hover:text-text-secondary"
        :title="
          timeMode === 'clock' ? 'Show seconds since the capture started' : 'Show the time of day'
        "
        @click="timeMode = timeMode === 'clock' ? 'relative' : 'clock'"
      >
        {{ timeMode === 'clock' ? 'Time' : 'Seconds' }}
      </button>
      <span>Source</span>
      <span>Destination</span>
      <span>Protocol</span>
      <span class="text-right">Length</span>
      <span>Info</span>
    </div>

    <!-- Rows: a spacer the height of every row, with only the visible ones drawn -->
    <div
      ref="viewportRef"
      class="min-h-0 flex-1 overflow-y-auto overflow-x-hidden outline-none"
      tabindex="0"
      @scroll="onScroll"
      @keydown="onKeydown"
    >
      <div
        v-if="total === 0"
        class="flex h-full items-center justify-center text-sm text-text-muted"
      >
        {{
          captureStore.hasCapture
            ? captureStore.query
              ? 'No packets match'
              : 'Waiting for packets…'
            : 'Packets appear here once a capture starts.'
        }}
      </div>
      <div v-else class="relative" :style="{ height: spacerHeight + 'px' }">
        <div
          v-for="index in visibleIndexes"
          :key="index"
          class="absolute inset-x-0 grid cursor-default select-none grid-cols-[72px_104px_minmax(120px,1fr)_minmax(120px,1fr)_88px_64px_minmax(200px,2fr)] items-center gap-x-3 px-3 text-xs"
          :class="[
            rowAt(index)?.no === captureStore.selectedNo
              ? 'bg-accent/20 text-text-primary'
              : index % 2 === 1
                ? 'bg-bg-secondary/40 hover:bg-bg-elevated'
                : 'hover:bg-bg-elevated',
          ]"
          :style="{ top: index * ROW_HEIGHT + 'px', height: ROW_HEIGHT + 'px' }"
          @click="select(rowAt(index))"
        >
          <template v-if="rowAt(index)">
            <span class="text-right font-mono tabular-nums text-text-muted">{{
              rowAt(index)!.no.toLocaleString()
            }}</span>
            <span class="font-mono tabular-nums text-text-secondary">{{
              formatRowTime(rowAt(index)!.timestamp)
            }}</span>
            <span class="truncate font-mono text-text-primary">{{ rowAt(index)!.src }}</span>
            <span class="truncate font-mono text-text-primary">{{ rowAt(index)!.dst }}</span>
            <span class="truncate font-medium" :style="{ color: protocolColor(rowAt(index)!) }">{{
              rowAt(index)!.protocol
            }}</span>
            <span class="text-right font-mono tabular-nums text-text-secondary">{{
              rowAt(index)!.length
            }}</span>
            <span class="truncate text-text-secondary" :title="rowAt(index)!.info">{{
              rowAt(index)!.info
            }}</span>
          </template>
          <span v-else class="col-span-7 text-text-muted">…</span>
        </div>
      </div>
    </div>

    <!-- Scrolled away from the newest frames -->
    <Transition name="overlay">
      <button
        v-if="!captureStore.follow && total > 0"
        class="absolute bottom-3 left-1/2 -translate-x-1/2 rounded-full border border-border bg-bg-elevated/95 px-3 py-1 text-xs text-text-primary shadow-lg backdrop-blur transition-colors hover:bg-border"
        @click="jumpToLatest"
      >
        Jump to latest
      </button>
    </Transition>
  </div>
</template>
