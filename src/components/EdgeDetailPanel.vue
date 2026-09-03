<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import type { ModbusConversation } from '@/types/network'
import { formatBytes, formatTime, formatCadence } from '@/utils/format'
import DetailPanel from './ui/DetailPanel.vue'
import PanelSection from './ui/PanelSection.vue'
import DetailRow from './ui/DetailRow.vue'
import CrossZoneBadge from './ui/CrossZoneBadge.vue'
import WriteBadge from './ui/WriteBadge.vue'

const topology = useTopologyStore()
const { getModbusConversation } = useTauri()

const modbus = ref<ModbusConversation | null>(null)
const loading = ref(false)

const edge = computed(() => {
  if (topology.selectedEdgeId === null) return null
  return topology.edges.find((e) => e.connection.id === topology.selectedEdgeId) ?? null
})

// Selections from the node panel or a finding can point at conversations that
// have no canvas edge (broadcast/multicast peers, self-loops) — fall back to
// the raw capture data so the panel never opens empty.
const connection = computed(() => {
  if (topology.selectedEdgeId === null) return null
  return edge.value?.connection ?? topology.connectionsById.get(topology.selectedEdgeId) ?? null
})
const srcHost = computed(
  () =>
    edge.value?.source.host ??
    (connection.value ? (topology.hostsById.get(connection.value.src_host_id) ?? null) : null),
)
const dstHost = computed(
  () =>
    edge.value?.target.host ??
    (connection.value ? (topology.hostsById.get(connection.value.dst_host_id) ?? null) : null),
)

let requestSeq = 0
watch(
  () => topology.selectedEdgeId,
  async (edgeId) => {
    const seq = ++requestSeq
    modbus.value = null
    loading.value = false
    if (edgeId === null) return
    if (connection.value?.app_protocol !== 'modbus') return
    loading.value = true
    try {
      const result = await getModbusConversation(edgeId)
      if (seq === requestSeq) modbus.value = result
    } catch (e) {
      // Traffic stats still show; only the Modbus depth is unavailable.
      console.error('modbus conversation unavailable', e)
    } finally {
      if (seq === requestSeq) loading.value = false
    }
  },
  { immediate: true },
)

function close() {
  topology.selectEdge(null)
}

function openHost(hostId: number) {
  topology.selectNode(hostId)
}
</script>

<template>
  <DetailPanel @close="close">
    <template #header>
      <div class="flex items-center gap-2.5">
        <span
          v-if="edge"
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: edge.color }"
        />
        <h2 class="text-sm font-semibold text-text-primary">Conversation</h2>
        <CrossZoneBadge v-if="edge?.crossZone" />
      </div>
    </template>

    <div v-if="connection" class="flex-1 overflow-y-auto">
      <PanelSection>
        <div class="space-y-1 text-sm">
          <button
            v-if="srcHost"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(srcHost.id)"
          >
            <span class="flex-1 truncate font-mono text-text-primary">{{
              srcHost.ip_address
            }}</span>
            <span class="font-mono text-xs text-text-muted">:{{ connection.src_port }}</span>
          </button>
          <div class="flex items-center gap-1 pl-2 text-xs text-text-muted">
            <svg
              viewBox="0 0 16 16"
              class="h-3 w-3"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
            >
              <path
                d="M8 3v10M4.5 9.5L8 13l3.5-3.5"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
            {{ connection.app_protocol ?? connection.protocol.toLowerCase() }}
          </div>
          <button
            v-if="dstHost"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(dstHost.id)"
          >
            <span class="flex-1 truncate font-mono text-text-primary">{{
              dstHost.ip_address
            }}</span>
            <span class="font-mono text-xs text-text-muted">:{{ connection.dst_port }}</span>
          </button>
        </div>
      </PanelSection>

      <PanelSection label="Traffic">
        <div class="space-y-1.5 text-sm">
          <DetailRow label="Packets">
            {{ connection.packet_count.toLocaleString() }}
          </DetailRow>
          <DetailRow label="Bytes">
            {{ formatBytes(connection.byte_count) }}
          </DetailRow>
          <DetailRow label="First seen">
            {{ formatTime(connection.first_seen) }}
          </DetailRow>
          <DetailRow label="Last seen">
            {{ formatTime(connection.last_seen) }}
          </DetailRow>
          <DetailRow v-if="connection.vlan_id !== null" label="VLAN" mono>
            {{ connection.vlan_id }}
          </DetailRow>
        </div>
      </PanelSection>

      <div v-if="loading" class="px-4 py-3 text-sm text-text-muted">Loading Modbus detail…</div>
      <PanelSection v-else-if="modbus" label="Modbus" :divider="false">
        <div class="space-y-1.5 text-sm">
          <DetailRow label="Requests">
            {{ modbus.requests.toLocaleString() }}
          </DetailRow>
          <DetailRow label="Reads / writes">
            {{ modbus.reads.toLocaleString() }} /
            <span :class="modbus.writes > 0 ? 'font-medium text-alert' : ''">
              {{ modbus.writes.toLocaleString() }}
            </span>
          </DetailRow>
          <DetailRow v-if="modbus.poll_interval_ms !== null" label="Polling cadence">
            every {{ formatCadence(modbus.poll_interval_ms) }}
          </DetailRow>
          <DetailRow v-if="modbus.unit_ids.length" label="Unit IDs" mono>
            {{ modbus.unit_ids.join(', ') }}
          </DetailRow>
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
                <WriteBadge v-if="fn.is_write" />
                <span class="font-mono text-text-muted">{{
                  '0x' + fn.function_code.toString(16).padStart(2, '0')
                }}</span>
                {{ fn.function_name }}
              </span>
              <span class="tabular-nums text-text-secondary">{{ fn.count.toLocaleString() }}</span>
            </div>
          </div>
        </div>
      </PanelSection>
    </div>

    <div
      v-else
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      No data for this conversation.
    </div>
  </DetailPanel>
</template>
