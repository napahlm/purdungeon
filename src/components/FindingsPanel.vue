<script setup lang="ts">
import { computed, ref } from 'vue'
import { useTopologyStore } from '@/stores/topology'

const topology = useTopologyStore()

// Open by default — it's the first thing to skim — but collapsible so it isn't
// permanently in the way once you've read it.
const collapsed = ref(false)

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

// Dot colour for the collapsed rail: the most severe thing present.
const topSeverity = computed(
  () => SEVERITY_ORDER.find((s) => counts.value[s] > 0) ?? 'info',
)
</script>

<template>
  <!-- Collapsed: a thin rail that reopens the panel -->
  <aside
    v-if="collapsed"
    class="absolute inset-y-0 left-0 z-20 flex w-11 flex-col items-center border-r border-border bg-bg-secondary py-3"
  >
    <button
      class="flex flex-col items-center gap-2 text-text-muted transition-colors hover:text-text-primary"
      title="Show what to look at"
      @click="collapsed = false"
    >
      <svg viewBox="0 0 16 16" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="1.8">
        <path d="M6 4l4 4-4 4" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
      <span
        v-if="topology.findings.length"
        class="inline-flex h-5 min-w-5 items-center justify-center rounded-full px-1 text-xs font-medium text-bg-primary"
        :class="SEVERITY_COLOR[topSeverity]"
        >{{ topology.findings.length }}</span
      >
    </button>
    <span
      class="mt-3 text-[10px] font-medium uppercase tracking-wider text-text-muted [writing-mode:vertical-rl]"
    >
      What to look at
    </span>
  </aside>

  <aside
    v-else
    class="absolute inset-y-0 left-0 z-20 flex w-80 flex-col border-r border-border bg-bg-secondary shadow-xl shadow-black/20"
  >
    <div class="flex items-start justify-between border-b border-border px-4 py-3">
      <div>
        <h2 class="text-sm font-semibold text-text-primary">What to look at</h2>
        <p class="mt-0.5 text-xs text-text-muted">
          {{ topology.findings.length ? summary : 'Nothing flagged in this capture' }}
        </p>
      </div>
      <button
        class="-mr-1 rounded p-1 text-text-muted transition-colors hover:text-text-primary"
        title="Collapse"
        @click="collapsed = true"
      >
        <svg viewBox="0 0 16 16" class="h-4 w-4" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M10 4L6 8l4 4" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </button>
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
