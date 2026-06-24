<script setup lang="ts">
import { computed } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { effectiveRole, ROLE_LABELS, type Host } from '@/types/network'
import { PROTO_FAMILY_LABELS, PROTO_COLORS, type ProtoFamily } from '@/canvas/palette'
import { formatBytes, formatTime } from '@/utils/format'

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
  <div class="flex h-full w-86 shrink-0 flex-col border-l border-border bg-bg-secondary">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-border px-4 py-3">
      <div class="flex items-center gap-2.5">
        <span
          v-if="link"
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: link.color }"
        />
        <h2 class="text-sm font-semibold text-text-primary">Link</h2>
        <span
          v-if="link?.crossZone"
          class="rounded bg-alert/15 px-1.5 py-0.5 text-xs font-medium text-alert"
          >cross-zone</span
        >
      </div>
      <button
        class="rounded p-1 text-text-muted transition-colors hover:text-text-primary"
        aria-label="Close panel"
        @click="close"
      >
        <svg viewBox="0 0 16 16" class="h-3.5 w-3.5" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M3 3l10 10M13 3L3 13" stroke-linecap="round" />
        </svg>
      </button>
    </div>

    <div v-if="link" class="flex-1 overflow-y-auto">
      <!-- Endpoints -->
      <div class="border-b border-border px-4 py-3">
        <div class="space-y-1 text-sm">
          <button
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(link.source.host.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{ link.source.host.ip_address }}</span>
            <span class="text-xs text-text-muted">{{ endpointLabel(link.source.host) }}</span>
          </button>
          <div class="pl-2 text-xs text-text-muted">↕ {{ link.conversationCount }} conversations</div>
          <button
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-bg-elevated"
            @click="openHost(link.target.host.id)"
          >
            <span class="flex-1 font-mono text-text-primary">{{ link.target.host.ip_address }}</span>
            <span class="text-xs text-text-muted">{{ endpointLabel(link.target.host) }}</span>
          </button>
        </div>
      </div>

      <!-- Aggregate traffic -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Traffic</div>
        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">Packets</span>
            <span class="text-text-primary">{{ aggregate.packets.toLocaleString() }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Bytes</span>
            <span class="text-text-primary">{{ formatBytes(aggregate.bytes) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">First seen</span>
            <span class="text-text-primary">{{ formatTime(aggregate.firstSeen) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Last seen</span>
            <span class="text-text-primary">{{ formatTime(aggregate.lastSeen) }}</span>
          </div>
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
      </div>

      <!-- Conversations -->
      <div class="px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
          Conversations ({{ conversations.length }})
        </div>
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
      </div>
    </div>

    <div
      v-else
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      No data for this link.
    </div>
  </div>
</template>
