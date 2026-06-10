<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import type { HostDetail, ModbusHostActivity, Role } from '@/types/network'
import { ROLE_LABELS, ASSIGNABLE_ROLES, effectiveLevel } from '@/types/network'
import { LEVEL_COLORS } from '@/canvas/palette'

const topology = useTopologyStore()
const { getHostDetail, getModbusHostActivity, setRoleOverride, setLevelOverride } = useTauri()

const detail = ref<HostDetail | null>(null)
const modbus = ref<ModbusHostActivity | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

const host = computed(() => detail.value?.host ?? null)
const speaksModbus = computed(() => host.value?.protocols.includes('modbus') ?? false)

const levelBadgeColor = computed(() => {
  if (!host.value) return LEVEL_COLORS.unknown
  const level = effectiveLevel(host.value)
  return LEVEL_COLORS[level === null ? 'unknown' : String(level)]
})

let requestSeq = 0
watch(
  () => topology.selectedNodeId,
  async (hostId) => {
    if (hostId === null) {
      detail.value = null
      modbus.value = null
      return
    }
    const seq = ++requestSeq
    loading.value = true
    error.value = null
    try {
      const result = await getHostDetail(hostId)
      const activity = result.host.protocols.includes('modbus')
        ? await getModbusHostActivity(hostId)
        : null
      if (seq !== requestSeq) return
      detail.value = result
      modbus.value = activity
    } catch (e) {
      if (seq !== requestSeq) return
      detail.value = null
      modbus.value = null
      error.value = e instanceof Error ? e.message : String(e)
    } finally {
      if (seq === requestSeq) loading.value = false
    }
  },
  { immediate: true },
)

async function onRoleChange(e: Event) {
  if (!host.value) return
  const value = (e.target as HTMLSelectElement).value
  const role = value === 'auto' ? null : (value as Role)
  await setRoleOverride(host.value.id, role)
  host.value.role_override = role
  topology.refreshHost({ ...host.value })
}

async function onLevelChange(e: Event) {
  if (!host.value) return
  const value = (e.target as HTMLSelectElement).value
  const level = value === 'auto' ? null : Number(value)
  await setLevelOverride(host.value.id, level)
  host.value.level_override = level
  topology.refreshHost({ ...host.value })
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

function formatTime(ts: number): string {
  if (ts <= 0) return '—'
  return new Date(ts * 1000).toLocaleString()
}

function registerRange(start: number, quantity: number): string {
  return quantity > 1 ? `${start}–${start + quantity - 1}` : String(start)
}

function openEdge(connectionId: number) {
  topology.selectEdge(connectionId)
}

function close() {
  topology.selectNode(null)
}
</script>

<template>
  <div class="flex h-full w-86 shrink-0 flex-col border-l border-border bg-bg-secondary">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-border px-4 py-3">
      <div class="flex items-center gap-2.5">
        <span
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: levelBadgeColor }"
        />
        <h2 class="font-mono text-sm font-semibold text-text-primary">
          {{ host?.ip_address ?? 'Asset' }}
        </h2>
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

    <div v-if="loading" class="flex flex-1 items-center justify-center text-sm text-text-muted">
      Loading…
    </div>

    <div
      v-else-if="error"
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      Couldn't load this asset: {{ error }}
    </div>

    <div v-else-if="detail && host" class="flex-1 overflow-y-auto">
      <!-- Classification -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
          Classification
        </div>
        <div class="space-y-2 text-sm">
          <div class="flex items-center justify-between gap-2">
            <span class="text-text-secondary">Role</span>
            <select
              class="rounded-md border border-border bg-bg-elevated px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
              :value="host.role_override ?? 'auto'"
              @change="onRoleChange"
            >
              <option value="auto">
                Auto — {{ ROLE_LABELS[host.role] }}
                {{ host.role !== 'unknown' ? `(${Math.round(host.role_confidence * 100)}%)` : '' }}
              </option>
              <option v-for="r in ASSIGNABLE_ROLES" :key="r" :value="r">
                {{ ROLE_LABELS[r] }}
              </option>
            </select>
          </div>
          <div class="flex items-center justify-between gap-2">
            <span class="text-text-secondary">Purdue level</span>
            <select
              class="rounded-md border border-border bg-bg-elevated px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
              :value="host.level_override ?? 'auto'"
              @change="onLevelChange"
            >
              <option value="auto">
                Auto — {{ host.purdue_level === null ? 'unplaced' : `Level ${host.purdue_level}` }}
              </option>
              <option v-for="l in [0, 1, 2, 3, 4, 5]" :key="l" :value="l">Level {{ l }}</option>
            </select>
          </div>
          <p v-if="host.role_evidence" class="text-xs leading-relaxed text-text-muted">
            {{ host.role_evidence }}
          </p>
        </div>
      </div>

      <!-- Identity -->
      <div class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
          Identity
        </div>
        <div class="space-y-1.5 text-sm">
          <div class="flex justify-between">
            <span class="text-text-secondary">MAC</span>
            <span class="font-mono text-text-primary">{{ host.mac_address || '—' }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Vendor</span>
            <span class="text-text-primary">{{ host.vendor ?? '—' }}</span>
          </div>
          <div v-if="host.protocols" class="flex items-start justify-between gap-3">
            <span class="text-text-secondary">Protocols</span>
            <span class="text-right font-mono text-xs leading-relaxed text-text-primary">
              {{ host.protocols.split(',').join(' · ') }}
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">First seen</span>
            <span class="text-text-primary">{{ formatTime(host.first_seen) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Last seen</span>
            <span class="text-text-primary">{{ formatTime(host.last_seen) }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-text-secondary">Traffic</span>
            <span class="text-text-primary">
              {{ detail.total_packets.toLocaleString() }} packets ·
              {{ formatBytes(detail.total_bytes) }}
            </span>
          </div>
        </div>
      </div>

      <!-- Modbus -->
      <div v-if="speaksModbus && modbus" class="border-b border-border px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">Modbus</div>

        <div v-if="modbus.unit_ids_served.length" class="mb-2 flex justify-between text-sm">
          <span class="text-text-secondary">Unit IDs served</span>
          <span class="font-mono text-text-primary">{{ modbus.unit_ids_served.join(', ') }}</span>
        </div>
        <div v-if="modbus.exceptions_returned > 0" class="mb-2 flex justify-between text-sm">
          <span class="text-text-secondary">Exceptions returned</span>
          <span class="text-warn">{{ modbus.exceptions_returned }}</span>
        </div>

        <template
          v-for="(stats, kind) in { Receives: modbus.as_server, Sends: modbus.as_client }"
          :key="kind"
        >
          <div v-if="stats.length" class="mt-2">
            <div class="mb-1 text-xs text-text-muted">
              {{ kind }}
            </div>
            <div class="space-y-0.5">
              <div
                v-for="fn in stats"
                :key="fn.function_code"
                class="flex items-center justify-between text-xs"
              >
                <span class="flex items-center gap-1.5 text-text-primary">
                  <span
                    v-if="fn.is_write"
                    class="rounded bg-alert/15 px-1 py-px font-medium text-alert"
                    >W</span
                  >
                  {{ fn.function_name }}
                </span>
                <span class="tabular-nums text-text-secondary">{{
                  fn.count.toLocaleString()
                }}</span>
              </div>
            </div>
          </div>
        </template>

        <template
          v-for="(regs, title) in {
            'Data points on this device': modbus.registers,
            'Data points it touches elsewhere': modbus.registers_remote,
          }"
          :key="title"
        >
          <div v-if="regs.length" class="mt-3">
            <div class="mb-1 text-xs text-text-muted">
              {{ title }}
            </div>
            <table class="w-full text-xs">
              <thead>
                <tr class="text-left text-text-muted">
                  <th class="pb-1 font-normal">Type</th>
                  <th class="pb-1 font-normal">Address</th>
                  <th class="pb-1 text-right font-normal">R</th>
                  <th class="pb-1 text-right font-normal">W</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(r, i) in regs.slice(0, 12)" :key="i" class="border-t border-border/40">
                  <td class="py-0.5 text-text-secondary">
                    {{ r.kind }}
                  </td>
                  <td class="py-0.5 font-mono text-text-primary">
                    {{ registerRange(r.start, r.quantity) }}
                  </td>
                  <td class="py-0.5 text-right tabular-nums text-text-secondary">
                    {{ r.reads }}
                  </td>
                  <td
                    class="py-0.5 text-right tabular-nums"
                    :class="r.writes > 0 ? 'font-medium text-alert' : 'text-text-secondary'"
                  >
                    {{ r.writes }}
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-if="regs.length > 12" class="mt-1 text-xs text-text-muted">
              and {{ regs.length - 12 }} more
            </p>
          </div>
        </template>
      </div>

      <!-- Connections -->
      <div class="px-4 py-3">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
          Conversations ({{ detail.connections.length }})
        </div>
        <div class="space-y-0.5">
          <button
            v-for="conn in detail.connections"
            :key="conn.connection_id"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-bg-elevated"
            @click="openEdge(conn.connection_id)"
          >
            <span class="w-7 text-xs text-text-muted">{{
              conn.direction === 'outbound' ? '→' : '←'
            }}</span>
            <span class="flex-1 truncate font-mono text-text-primary">{{ conn.peer_ip }}</span>
            <span class="text-xs text-text-muted">{{
              conn.app_protocol ?? conn.protocol.toLowerCase()
            }}</span>
            <span class="text-xs tabular-nums text-text-secondary">{{
              conn.packet_count.toLocaleString()
            }}</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
