<script setup lang="ts">
import { useTopologyStore } from '@/stores/topology'
import { PROTO_COLORS, PROTO_FAMILY_LABELS, ALERT } from '@/canvas/palette'

const topology = useTopologyStore()
</script>

<template>
  <div
    class="flex items-center gap-1.5 rounded-lg border border-border bg-bg-secondary/90 px-2 py-1.5 backdrop-blur"
  >
    <!-- Protocol families -->
    <button
      v-for="family in topology.presentFamilies"
      :key="family"
      class="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs transition-colors"
      :class="
        topology.hiddenFamilies.has(family)
          ? 'text-text-muted hover:text-text-secondary'
          : 'bg-bg-elevated text-text-primary'
      "
      :title="
        topology.hiddenFamilies.has(family)
          ? `Show ${PROTO_FAMILY_LABELS[family]} traffic`
          : `Hide ${PROTO_FAMILY_LABELS[family]} traffic`
      "
      @click="topology.toggleFamily(family)"
    >
      <span
        class="inline-block h-2 w-2 rounded-full transition-opacity"
        :style="{
          backgroundColor: PROTO_COLORS[family],
          opacity: topology.hiddenFamilies.has(family) ? 0.3 : 1,
        }"
      />
      {{ PROTO_FAMILY_LABELS[family] }}
    </button>

    <div v-if="topology.crossZoneCount > 0" class="mx-1 h-4 w-px bg-border" />

    <!-- Cross-zone toggle -->
    <button
      v-if="topology.crossZoneCount > 0"
      class="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs transition-colors"
      :class="
        topology.crossZoneOnly
          ? 'bg-bg-elevated text-text-primary'
          : 'text-text-secondary hover:text-text-primary'
      "
      title="Show only conversations that cross a Purdue boundary"
      @click="topology.crossZoneOnly = !topology.crossZoneOnly"
    >
      <span class="inline-block h-2 w-2 rounded-full" :style="{ backgroundColor: ALERT }" />
      Cross-zone · {{ topology.crossZoneCount }}
    </button>
  </div>
</template>
