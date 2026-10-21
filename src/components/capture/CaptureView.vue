<script setup lang="ts">
import { computed } from 'vue'
import { useCaptureStore } from '@/stores/capture'
import { captureAdvice } from '@/composables/useCaptureControls'
import CaptureToolbar from './CaptureToolbar.vue'
import CaptureCounters from './CaptureCounters.vue'
import PacketList from './PacketList.vue'
import PacketDetail from './PacketDetail.vue'

const captureStore = useCaptureStore()
const advice = computed(() => (captureStore.error ? captureAdvice(captureStore.error) : null))
</script>

<!-- The capture tab: enough of Wireshark to see that the tap is live and
     what is flowing, while the topology tab draws the network it implies. -->
<template>
  <div class="flex min-h-0 flex-1 flex-col">
    <CaptureToolbar />
    <CaptureCounters />

    <Transition name="overlay">
      <div
        v-if="captureStore.error"
        class="flex shrink-0 items-start gap-2.5 border-b border-border bg-alert/10 px-4 py-2 text-sm"
      >
        <span
          class="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-alert/20"
        >
          <svg
            viewBox="0 0 16 16"
            class="h-3 w-3 text-alert"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
          >
            <path d="M8 4.5v4M8 11h.01" stroke-linecap="round" />
          </svg>
        </span>
        <div class="min-w-0 flex-1">
          <p class="text-text-primary">{{ advice }}</p>
          <p
            v-if="advice !== captureStore.error.message"
            class="mt-0.5 truncate font-mono text-xs text-text-muted"
            :title="captureStore.error.message"
          >
            {{ captureStore.error.message }}
          </p>
        </div>
        <button
          class="shrink-0 rounded px-1.5 py-0.5 text-xs text-text-muted transition-colors hover:text-text-primary"
          @click="captureStore.error = null"
        >
          Dismiss
        </button>
      </div>
    </Transition>

    <div class="flex shrink-0 items-center gap-2 border-b border-border px-4 py-1.5">
      <svg
        viewBox="0 0 16 16"
        class="h-3.5 w-3.5 shrink-0 text-text-muted"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
      >
        <circle cx="7" cy="7" r="4.5" />
        <path d="M10.5 10.5L14 14" stroke-linecap="round" />
      </svg>
      <input
        v-model.trim="captureStore.query"
        type="text"
        spellcheck="false"
        placeholder="Filter the list: an address, a protocol, or anything in Info"
        class="min-w-0 flex-1 bg-transparent text-xs text-text-primary outline-none placeholder:text-text-muted"
      />
      <span v-if="captureStore.query" class="text-xs tabular-nums text-text-muted">
        {{ captureStore.total.toLocaleString() }} matching
      </span>
    </div>

    <div class="flex min-h-0 flex-1">
      <PacketList />
      <Transition name="panel">
        <PacketDetail v-if="captureStore.selectedNo !== null" />
      </Transition>
    </div>
  </div>
</template>
