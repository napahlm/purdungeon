<script setup lang="ts">
import { computed } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { effectiveRole, ROLE_LABELS, type Host } from '@/types/network'
import { PROTO_FAMILY_LABELS, PROTO_COLORS, type ProtoFamily } from '@/canvas/palette'
import { formatBytes, formatTime } from '@/utils/format'
import DetailPanel from './ui/DetailPanel.vue'
import PanelSection from './ui/PanelSection.vue'
import DetailRow from './ui/DetailRow.vue'
import CrossZoneBadge from './ui/CrossZoneBadge.vue'

const topology = useTopologyStore()

const link = computed(() => topology.selectedLink)

/** Conversations, busiest first. */
const conversations = computed(() =>
  [...(link.value?.edges ?? [])].sort((a, b) => b.connection.byte_count - a.connection.byte_count),
)

const aggregate = computed(() => {
  const edges = link.value?.edges ?? []
  let packets = 0
  let bytes = 0
  let firstSeen = Infinity
  let lastSeen = -Infinity
  for (const e of edges) {
    packets += e.connection.packet_count
    bytes += e.connection.byte_count
    firstSeen = Math.min(firstSeen, e.connection.first_seen)
    lastSeen = Math.max(lastSeen, e.connection.last_seen)
  }
  return {
    packets,
    bytes,
    firstSeen: Number.isFinite(firstSeen) ? firstSeen : 0,
    lastSeen: Number.isFinite(lastSeen) ? lastSeen : 0,
  }
})

/** Protocol families on this link with their share of bytes, busiest first. */
const familyMix = computed(() => {
  const byFamily = new Map<ProtoFamily, number>()
  for (const e of link.value?.edges ?? []) {
    byFamily.set(e.family, (byFamily.get(e.family) ?? 0) + e.connection.byte_count)
  }
  return [...byFamily.entries()].sort((a, b) => b[1] - a[1]).map(([family]) => family)
})

function endpointLabel(host: Host): string {
  return ROLE_LABELS[effectiveRole(host)]
}

function protoLabel(appProtocol: string | null, protocol: string): string {
  return appProtocol ?? protocol.toLowerCase()
}

function openHost(hostId: number) {
  topology.selectNode(hostId)
}

function openConversation(connectionId: number) {
  topology.selectEdge(connectionId)
}

function close() {
  topology.selectLink(null)
}
</script>

<template>
  <DetailPanel @close="close">
    <template #header>
      <div class="flex items-center gap-2.5">
        <span
          v-if="link"
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: link.color }"
        />
        <h2 class="text-sm font-semibold text-text-primary">Link</h2>
        <CrossZoneBadge v-if="link?.crossZone" />
      </div>
    </template>

    <div v-if="link" class="flex-1 overflow-y-auto">
      <PanelSection>
        <div class="space-y-1 text-sm">
          <button
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(link.source.host.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{
              link.source.host.ip_address
            }}</span>
            <span class="text-xs text-text-muted">{{ endpointLabel(link.source.host) }}</span>
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
                d="M8 2.5v11M4.5 6L8 2.5 11.5 6M4.5 10L8 13.5 11.5 10"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
            {{ link.conversationCount }} conversations
          </div>
          <button
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(link.target.host.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{
              link.target.host.ip_address
            }}</span>
            <span class="text-xs text-text-muted">{{ endpointLabel(link.target.host) }}</span>
          </button>
        </div>
      </PanelSection>

      <PanelSection label="Traffic">
        <div class="space-y-1.5 text-sm">
          <DetailRow label="Packets">
            {{ aggregate.packets.toLocaleString() }}
          </DetailRow>
          <DetailRow label="Bytes">
            {{ formatBytes(aggregate.bytes) }}
          </DetailRow>
          <DetailRow label="First seen">
            {{ formatTime(aggregate.firstSeen) }}
          </DetailRow>
          <DetailRow label="Last seen">
            {{ formatTime(aggregate.lastSeen) }}
          </DetailRow>
          <div class="flex items-center justify-between gap-3 pt-0.5">
            <span class="text-text-secondary">Protocols</span>
            <span class="flex flex-wrap justify-end gap-1.5">
              <span
                v-for="family in familyMix"
                :key="family"
                class="inline-flex items-center gap-1 text-xs text-text-primary"
              >
                <span
                  class="inline-block h-2 w-2 rounded-full"
                  :style="{ backgroundColor: PROTO_COLORS[family] }"
                />
                {{ PROTO_FAMILY_LABELS[family] }}
              </span>
            </span>
          </div>
        </div>
      </PanelSection>

      <PanelSection :label="`Conversations (${conversations.length})`" :divider="false">
        <div class="space-y-0.5">
          <button
            v-for="edge in conversations"
            :key="edge.connection.id"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openConversation(edge.connection.id)"
          >
            <span
              class="inline-block h-2 w-2 shrink-0 rounded-full"
              :style="{ backgroundColor: edge.color }"
            />
            <span class="text-xs text-text-primary">{{
              protoLabel(edge.connection.app_protocol, edge.connection.protocol)
            }}</span>
            <span class="flex-1 truncate font-mono text-xs text-text-muted">
              :{{ edge.connection.src_port }} → :{{ edge.connection.dst_port }}
            </span>
            <span class="text-xs tabular-nums text-text-secondary">{{
              formatBytes(edge.connection.byte_count)
            }}</span>
          </button>
        </div>
      </PanelSection>
    </div>

    <div
      v-else
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      No data for this link.
    </div>
  </DetailPanel>
</template>
