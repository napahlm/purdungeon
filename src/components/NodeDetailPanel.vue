<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useTopologyStore } from '@/stores/topology'
import { useTauri } from '@/composables/useTauri'
import type { HostDetail, ModbusHostActivity, Role } from '@/types/network'
import { ROLE_LABELS, ASSIGNABLE_ROLES, effectiveLevel } from '@/types/network'
import { levelColorFor } from '@/canvas/palette'
import { formatBytes, formatTime } from '@/utils/format'
import DetailPanel from './ui/DetailPanel.vue'
import PanelSection from './ui/PanelSection.vue'
import DetailRow from './ui/DetailRow.vue'
import SelectMenu from './ui/SelectMenu.vue'
import WriteBadge from './ui/WriteBadge.vue'

const topology = useTopologyStore()
const { getHostDetail, getModbusHostActivity, setRoleOverride, setLevelOverride } = useTauri()

const detail = ref<HostDetail | null>(null)
const modbus = ref<ModbusHostActivity | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

const host = computed(() => detail.value?.host ?? null)
const speaksModbus = computed(() => host.value?.protocols.includes('modbus') ?? false)

const levelBadgeColor = computed(() =>
  host.value ? levelColorFor(effectiveLevel(host.value)) : levelColorFor(null),
)

const roleOptions = computed(() => {
  if (!host.value) return []
  const auto =
    host.value.role !== 'unknown'
      ? `Auto — ${ROLE_LABELS[host.value.role]} (${Math.round(host.value.role_confidence * 100)}%)`
      : `Auto — ${ROLE_LABELS[host.value.role]}`
  return [
    { value: 'auto', label: auto },
    ...ASSIGNABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })),
  ]
})

const levelOptions = computed(() => {
  if (!host.value) return []
  const auto =
    host.value.purdue_level === null ? 'Auto — unplaced' : `Auto — Level ${host.value.purdue_level}`
  return [
    { value: 'auto', label: auto },
    ...[0, 1, 2, 3, 4, 5].map((l) => ({ value: String(l), label: `Level ${l}` })),
  ]
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

async function onRoleChange(value: string) {
  if (!host.value) return
  const role = value === 'auto' ? null : (value as Role)
  try {
    await setRoleOverride(host.value.id, role)
  } catch (err) {
    // The session didn't record it — don't update the view as if it had.
    error.value = err instanceof Error ? err.message : String(err)
    return
  }
  host.value.role_override = role
  topology.refreshHost({ ...host.value })
}

async function onLevelChange(value: string) {
  if (!host.value) return
  const level = value === 'auto' ? null : Number(value)
  try {
    await setLevelOverride(host.value.id, level)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
    return
  }
  host.value.level_override = level
  topology.refreshHost({ ...host.value })
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
  <DetailPanel @close="close">
    <template #header>
      <div class="flex items-center gap-2.5">
        <span
          class="inline-block h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: levelBadgeColor }"
        />
        <h2 class="font-mono text-sm font-semibold text-text-primary">
          {{ host?.ip_address ?? 'Device' }}
        </h2>
      </div>
    </template>

    <div v-if="loading" class="flex flex-1 items-center justify-center text-sm text-text-muted">
      Loading…
    </div>

    <div
      v-else-if="error"
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      Couldn’t load this device: {{ error }}
    </div>

    <div v-else-if="detail && host" class="flex-1 overflow-y-auto">
      <PanelSection label="Classification">
        <div class="space-y-2 text-sm">
          <div class="flex items-center justify-between gap-2">
            <span class="text-text-secondary">Role</span>
            <SelectMenu
              :model-value="host.role_override ?? 'auto'"
              :options="roleOptions"
              @update:model-value="onRoleChange"
            />
          </div>
          <div class="flex items-center justify-between gap-2">
            <span class="text-text-secondary">Purdue level</span>
            <SelectMenu
              :model-value="host.level_override === null ? 'auto' : String(host.level_override)"
              :options="levelOptions"
              @update:model-value="onLevelChange"
            />
          </div>
          <p v-if="host.role_evidence" class="text-xs leading-relaxed text-text-muted">
            {{ host.role_evidence }}
          </p>
        </div>
      </PanelSection>

      <PanelSection label="Identity">
        <div class="space-y-1.5 text-sm">
          <DetailRow label="MAC" mono>
            {{ host.mac_address || '—' }}
          </DetailRow>
          <DetailRow label="Vendor">
            {{ host.vendor ?? '—' }}
          </DetailRow>
          <div v-if="host.protocols" class="flex items-start justify-between gap-3">
            <span class="text-text-secondary">Protocols</span>
            <span class="text-right font-mono text-xs leading-relaxed text-text-primary">
              {{ host.protocols.split(',').join(' · ') }}
            </span>
          </div>
          <DetailRow label="First seen">
            {{ formatTime(host.first_seen) }}
          </DetailRow>
          <DetailRow label="Last seen">
            {{ formatTime(host.last_seen) }}
          </DetailRow>
          <DetailRow label="Traffic">
            {{ detail.total_packets.toLocaleString() }} packets ·
            {{ formatBytes(detail.total_bytes) }}
          </DetailRow>
        </div>
      </PanelSection>

      <PanelSection v-if="speaksModbus && modbus" label="Modbus">
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
                  <WriteBadge v-if="fn.is_write" />
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
      </PanelSection>

      <PanelSection :label="`Conversations (${detail.connections.length})`" :divider="false">
        <div class="space-y-0.5">
          <button
            v-for="conn in detail.connections"
            :key="conn.connection_id"
            class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-bg-elevated"
            @click="openEdge(conn.connection_id)"
          >
            <span class="w-7 text-xs text-text-muted">
              <svg
                v-if="conn.direction === 'outbound'"
                viewBox="0 0 16 16"
                class="h-3 w-3"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
              >
                <path
                  d="M3 8h10M9.5 4.5L13 8l-3.5 3.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              <svg
                v-else
                viewBox="0 0 16 16"
                class="h-3 w-3"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
              >
                <path
                  d="M13 8H3M6.5 4.5L3 8l3.5 3.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </span>
            <span class="flex-1 truncate font-mono text-text-primary">{{ conn.peer_ip }}</span>
            <span class="text-xs text-text-muted">{{
              conn.app_protocol ?? conn.protocol.toLowerCase()
            }}</span>
            <span class="text-xs tabular-nums text-text-secondary">{{
              conn.packet_count.toLocaleString()
            }}</span>
          </button>
        </div>
      </PanelSection>
    </div>
  </DetailPanel>
</template>
