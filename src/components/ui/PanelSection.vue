<script setup lang="ts">
withDefaults(defineProps<{ label?: string; divider?: boolean }>(), { label: '', divider: true })
</script>

<template>
  <div class="px-4 py-3" :class="divider ? 'border-b border-border' : ''">
    <div v-if="label" class="mb-2 text-xs font-medium uppercase tracking-wider text-text-muted">
      {{ label }}
    </div>
    <slot />
  </div>
</template>
