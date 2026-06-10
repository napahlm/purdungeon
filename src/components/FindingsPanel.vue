<script setup lang="ts">
import { computed } from 'vue'
import { useTopologyStore } from '@/stores/topology'

const topology = useTopologyStore()

const SEVERITY_ORDER = ['high', 'medium', 'info'] as const
const SEVERITY_COLOR: Record<string, string> = {
  high: 'bg-alert',
  medium: 'bg-warn',
  info: 'bg-text-muted',
}

const counts = computed(() => {
  const c = { high: 0, medium: 0, info: 0 }
  for (const f of topology.findings) c[f.severity]++
  return c
})

const summary = computed(() =>
  SEVERITY_ORDER.filter((s) => counts.value[s] > 0)
    .map((s) => `${counts.value[s]} ${s}`)
    .join(' · '),
)
</script>

<template>
  <aside class="flex w-80 shrink-0 flex-col border-r border-border bg-bg-secondary">
    <div class="border-b border-border px-4 py-3">
      <h2 class="text-sm font-semibold text-text-primary">What to look at</h2>
      <p class="mt-0.5 text-xs text-text-muted">
        {{ topology.findings.length ? summary : 'Nothing flagged in this capture' }}
      </p>
    </div>

    <div class="flex-1 overflow-y-auto">
      <button
        v-for="finding in topology.findings"
        :key="finding.id"
        class="block w-full border-b border-border/50 px-4 py-3 text-left transition-colors"
        :class="topology.activeFindingId === finding.id ? 'bg-bg-elevated' : 'hover:bg-bg-surface'"
        @click="topology.toggleFinding(finding)"
      >
        <div class="flex items-start gap-2.5">
          <span
            class="mt-1.25 inline-block h-2 w-2 shrink-0 rounded-full"
            :class="SEVERITY_COLOR[finding.severity]"
          />
          <div class="min-w-0">
            <div class="text-sm leading-snug text-text-primary">
              {{ finding.title }}
            </div>
            <div class="mt-1 text-xs leading-relaxed text-text-secondary">
              {{ finding.detail }}
            </div>
          </div>
        </div>
      </button>
    </div>
  </aside>
</template>
