<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useCaptureStore } from '@/stores/capture'
import { PROTO_COLORS } from '@/canvas/palette'
import { formatBytes, formatElapsed, formatRate } from '@/utils/format'
import { familyForProtocol } from './protocolFamily'

const captureStore = useCaptureStore()
const status = computed(() => captureStore.status)

// Elapsed time ticks on its own clock while the capture runs; the backend
// only speaks when a batch lands.
const now = ref(Date.now() / 1000)
let clock: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  clock = setInterval(() => (now.value = Date.now() / 1000), 1000)
})
onUnmounted(() => {
  if (clock !== null) clearInterval(clock)
})

const elapsed = computed(() => {
  const s = status.value
  if (!s) return 0
  const end = s.stopped_at ?? now.value
  return Math.max(0, end - s.started_at)
})

const dropped = computed(() => {
  const s = status.value
  return s ? s.kernel_dropped + s.if_dropped + s.app_dropped : 0
})

const chips = computed(() => (status.value?.protocol_counts ?? []).slice(0, 6))

const stateLabel = computed(() => {
  switch (status.value?.state) {
    case 'running':
      return 'Capturing'
    case 'stopped':
      return 'Stopped'
    case 'failed':
      return 'Failed'
    default:
      return 'Idle'
  }
})
</script>

<template>
  <div
    class="flex shrink-0 items-center gap-5 border-b border-border bg-bg-secondary/60 px-4 py-1.5 text-xs"
  >
    <span class="flex items-center gap-1.5 text-text-secondary">
      <span
        class="inline-block h-1.5 w-1.5 rounded-full"
        :class="
          status?.state === 'running'
            ? 'bg-alert'
            : status?.state === 'failed'
              ? 'bg-warn'
              : 'bg-text-muted'
        "
      />
      {{ stateLabel }}
      <span v-if="status" class="font-mono text-text-muted">{{ status.linktype }}</span>
      <span
        v-if="status && !status.promiscuous"
        class="text-text-muted"
        title="The interface refused promiscuous mode; only traffic to and from this machine is seen"
      >
        · not promiscuous
      </span>
    </span>

    <template v-if="status">
      <span class="tabular-nums text-text-secondary"
        ><span class="text-text-primary">{{ status.counts.frames_read.toLocaleString() }}</span>
        frames</span
      >
      <span class="tabular-nums text-text-secondary">{{ formatRate(status.pps) }}</span>
      <span class="tabular-nums text-text-secondary">{{ formatBytes(status.bytes) }}</span>
      <span class="tabular-nums text-text-secondary">{{ formatElapsed(elapsed) }}</span>
      <span
        class="tabular-nums"
        :class="dropped > 0 ? 'text-warn' : 'text-text-muted'"
        :title="`OS buffer ${status.kernel_dropped.toLocaleString()} · interface ${status.if_dropped.toLocaleString()} · purdungeon ${status.app_dropped.toLocaleString()}`"
        >{{ dropped.toLocaleString() }} dropped</span
      >
      <span class="tabular-nums text-text-secondary"
        ><span class="text-text-primary">{{ status.counts.host_count.toLocaleString() }}</span>
        devices ·
        <span class="text-text-primary">{{ status.counts.connection_count.toLocaleString() }}</span>
        conversations</span
      >
      <span class="ml-auto flex items-center gap-1.5">
        <span
          v-for="[name, count] in chips"
          :key="name"
          class="flex items-center gap-1 rounded-md bg-bg-elevated px-1.5 py-0.5 tabular-nums text-text-secondary"
        >
          <span
            class="inline-block h-1.5 w-1.5 rounded-full"
            :style="{ backgroundColor: PROTO_COLORS[familyForProtocol(name)] }"
          />
          {{ name }}
          <span class="text-text-muted">{{ count.toLocaleString() }}</span>
        </span>
      </span>
    </template>
    <span v-else class="text-text-muted">Pick an interface and press Start.</span>
  </div>
</template>
