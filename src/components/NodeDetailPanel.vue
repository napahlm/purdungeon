<script setup lang="ts">
import { ref, watch } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import type { HostDetail } from '@/types/network'

const topology = useTopologyStore()
const { getHostDetail } = useTauri()

const detail = ref<HostDetail | null>(null)
const loading = ref(false)

watch(
  () => topology.selectedNodeId,
  async (hostId) => {
    if (hostId === null) {
      detail.value = null
      return
    }
    loading.value = true
    try {
      detail.value = await getHostDetail(hostId)
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

function openEdge(connectionId: number) {
  topology.selectEdge(connectionId)
}

function close() {
  topology.selectNode(null)
}
</script>

<template>
  <div
    class="flex h-full w-80 flex-col border-l border-border bg-bg-secondary"
    @keydown.escape="close"
  >
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-border px-4 py-3">
      <h2 class="text-sm font-semibold text-text-primary">Host Detail</h2>
      <button
        class="text-text-secondary hover:text-text-primary"
        @click="close"
      >
        ✕
      </button>
    </div>

    <div v-if="loading" class="flex flex-1 items-center justify-center text-text-muted">
      Loading…
    </div>

    <div v-else-if="detail" class="flex-1 overflow-y-auto">
      <!-- Host info -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Identity</div>
        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">IP</span>
            <span class="font-mono text-text-primary">{{ detail.host.ip_address }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">MAC</span>
            <span class="font-mono text-text-primary">{{ detail.host.mac_address }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Vendor</span>
            <span class="text-text-primary">{{ detail.host.vendor ?? '—' }}</span>
          </div>
        </div>
      </div>

      <!-- Stats -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Statistics</div>
        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">Packets</span>
            <span class="text-text-primary">{{ detail.total_packets.toLocaleString() }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Bytes</span>
            <span class="text-text-primary">{{ formatBytes(detail.total_bytes) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">First seen</span>
            <span class="text-text-primary">{{ formatTime(detail.host.first_seen) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Last seen</span>
            <span class="text-text-primary">{{ formatTime(detail.host.last_seen) }}</span>
          </div>
        </div>
      </div>

      <!-- Connections -->
      <div class="px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
          Connections ({{ detail.connections.length }})
        </div>
        <div class="space-y-1">
          <button
            v-for="conn in detail.connections"
            :key="conn.connection_id"
            class="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-bg-elevated"
            @click="openEdge(conn.connection_id)"
          >
            <span
              class="inline-block h-2 w-2 rounded-full"
              :class="{
                'bg-accent': conn.app_protocol,
                'bg-edge-tcp': conn.protocol === 'TCP' && !conn.app_protocol,
                'bg-edge-udp': conn.protocol === 'UDP',
              }"
            />
            <span class="flex-1 truncate font-mono text-text-primary">
              {{ conn.peer_ip }}
            </span>
            <span class="text-xs text-text-muted">
              {{ conn.app_protocol ?? conn.protocol }}
            </span>
            <span class="text-xs text-text-secondary">
              {{ conn.packet_count }}p
            </span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
