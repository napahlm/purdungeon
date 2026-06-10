<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import type { ModbusConversation } from '@/types/network'

const topology = useTopologyStore()
const { getModbusConversation } = useTauri()

const modbus = ref<ModbusConversation | null>(null)
const loading = ref(false)

const edge = computed(() => {
  if (topology.selectedEdgeId === null) return null
  return topology.edges.find((e) => e.connection.id === topology.selectedEdgeId) ?? null
})

const connection = computed(() => edge.value?.connection ?? null)
const srcHost = computed(() => edge.value?.source.host ?? null)
const dstHost = computed(() => edge.value?.target.host ?? null)

watch(
  () => topology.selectedEdgeId,
  async (edgeId) => {
    modbus.value = null
    if (edgeId === null) return
    if (connection.value?.app_protocol !== 'modbus') return
    loading.value = true
    try {
      modbus.value = await getModbusConversation(edgeId)
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

function formatTime(ts: number): string {
  if (ts <= 0) return '—'
  return new Date(ts * 1000).toLocaleString()
}

function formatCadence(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

function close() {
  topology.selectEdge(null)
}

function openHost(hostId: number) {
  topology.selectNode(hostId)
}
</script>

<template>
  <div class="flex h-full w-86 flex-col border-l border-border bg-bg-secondary">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-border px-4 py-3">
      <div class="flex items-center gap-2.5">
        <span
          v-if="edge"
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: edge.color }"
        />
        <h2 class="text-sm font-semibold text-text-primary">Conversation</h2>
        <span
          v-if="edge?.crossZone"
          class="rounded bg-alert/15 px-1.5 py-0.5 text-xs font-medium text-alert"
          >cross-zone</span
        >
      </div>
      <button
        class="rounded p-1 text-text-muted transition-colors hover:text-text-primary"
        aria-label="Close panel"
        @click="close"
      >
        <svg
          viewBox="0 0 16 16"
          class="h-3.5 w-3.5"
          fill="none"
          stroke="currentColor"
          stroke-width="1.8"
        >
          <path d="M3 3l10 10M13 3L3 13" stroke-linecap="round" />
        </svg>
      </button>
    </div>

    <div v-if="connection" class="flex-1 overflow-y-auto">
      <!-- Endpoints -->
      <div class="border-b border-border px-4 py-3">
        <div class="space-y-1 text-sm">
          <button
            v-if="srcHost"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(srcHost.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{ srcHost.ip_address }}</span>
            <span class="font-mono text-xs text-text-muted">:{{ connection.src_port }}</span>
          </button>
          <div class="pl-2 text-xs text-text-muted">
            ↓ {{ connection.app_protocol ?? connection.protocol.toLowerCase() }}
          </div>
          <button
            v-if="dstHost"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(dstHost.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{ dstHost.ip_address }}</span>
            <span class="font-mono text-xs text-text-muted">:{{ connection.dst_port }}</span>
          </button>
        </div>
      </div>

      <!-- Traffic -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Traffic</div>
        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">Packets</span>
            <span class="text-text-primary">{{ connection.packet_count.toLocaleString() }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Bytes</span>
            <span class="text-text-primary">{{ formatBytes(connection.byte_count) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">First seen</span>
            <span class="text-text-primary">{{ formatTime(connection.first_seen) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Last seen</span>
            <span class="text-text-primary">{{ formatTime(connection.last_seen) }}</span>
          </div>
        </div>
      </div>

      <!-- Modbus -->
      <div v-if="loading" class="px-4 py-3 text-sm text-text-muted">Loading Modbus detail…</div>
      <div v-else-if="modbus" class="px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Modbus</div>

        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">Requests</span>
            <span class="text-text-primary">{{ modbus.requests.toLocaleString() }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Reads / writes</span>
            <span class="text-text-primary">
              {{ modbus.reads.toLocaleString() }} /
              <span :class="modbus.writes > 0 ? 'font-medium text-alert' : ''">
                {{ modbus.writes.toLocaleString() }}
              </span>
            </span>
          </div>
          <div v-if="modbus.poll_interval_ms !== null" class="flex justify-between">
            <span class="text-text-secondary">Polling cadence</span>
            <span class="text-text-primary"
              >every {{ formatCadence(modbus.poll_interval_ms) }}</span
            >
          </div>
          <div v-if="modbus.unit_ids.length" class="flex justify-between">
            <span class="text-text-secondary">Unit IDs</span>
            <span class="font-mono text-text-primary">{{ modbus.unit_ids.join(', ') }}</span>
          </div>
          <div v-if="modbus.exceptions > 0" class="flex justify-between">
            <span class="text-text-secondary">Exceptions</span>
            <span class="text-warn">{{ modbus.exceptions }}</span>
          </div>
        </div>

        <div v-if="modbus.functions.length" class="mt-3">
          <div class="mb-1 text-xs text-text-muted">Function codes</div>
          <div class="space-y-0.5">
            <div
              v-for="fn in modbus.functions"
              :key="fn.function_code"
              class="flex items-center justify-between text-xs"
            >
              <span class="flex items-center gap-1.5 text-text-primary">
                <span
                  v-if="fn.is_write"
                  class="rounded bg-alert/15 px-1 py-px font-medium text-alert"
                  >W</span
                >
                <span class="font-mono text-text-muted">{{
                  '0x' + fn.function_code.toString(16).padStart(2, '0')
                }}</span>
                {{ fn.function_name }}
              </span>
              <span class="tabular-nums text-text-secondary">{{ fn.count.toLocaleString() }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
