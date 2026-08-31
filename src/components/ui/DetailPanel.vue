<script setup lang="ts">
import { DETAIL_PANEL_WIDTH } from '@/ui/layout'
import IconClose from './IconClose.vue'

defineEmits<{ close: [] }>()
</script>

<template>
  <aside
    class="flex h-full shrink-0 flex-col border-l border-border bg-bg-secondary"
    :style="{ width: DETAIL_PANEL_WIDTH + 'px' }"
  >
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-border px-4 py-3">
      <slot name="header" />
      <button
        class="rounded p-1 text-text-muted transition-colors hover:text-text-primary"
        aria-label="Close panel"
        @click="$emit('close')"
      >
        <IconClose />
      </button>
    </div>
    <slot />
  </aside>
</template>
