<script setup lang="ts">
import { useTopologyStore } from '@/stores/topology'
import { LEVEL_COLORS, BANDS } from '@/canvas/palette'

const topology = useTopologyStore()

function colorFor(key: string): string {
  const band = BANDS.find((b) => b.key === key)
  const level = band?.level
  return LEVEL_COLORS[level === null || level === undefined ? 'unknown' : String(level)]
}
</script>

<template>
  <div
    v-if="topology.bands.length"
    class="flex flex-col gap-0.5 rounded-lg border border-border bg-bg-secondary/90 p-1.5 backdrop-blur"
  >
    <button
      v-for="band in topology.bands"
      :key="band.key"
      class="flex items-center gap-2 rounded-md px-2 py-1 text-left text-xs transition-colors hover:bg-bg-elevated"
      :class="topology.hiddenBands.has(band.key) ? 'text-text-muted' : 'text-text-secondary'"
      :title="topology.hiddenBands.has(band.key) ? 'Show this level' : 'Hide this level'"
      @click="topology.toggleBand(band.key)"
    >
      <span
        class="inline-block h-2 w-2 rounded-full transition-opacity"
        :style="{
          backgroundColor: colorFor(band.key),
          opacity: topology.hiddenBands.has(band.key) ? 0.25 : 1,
        }"
      />
      <span :class="{ 'line-through opacity-60': topology.hiddenBands.has(band.key) }">
        {{ band.label }}
      </span>
    </button>
  </div>
</template>
