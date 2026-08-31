<script setup lang="ts">
defineProps<{ label: string; mono?: boolean }>()
</script>

<template>
  <div class="flex justify-between">
    <span class="text-text-secondary">{{ label }}</span>
    <span :class="mono ? 'font-mono text-text-primary' : 'text-text-primary'">
      <slot />
    </span>
  </div>
</template>
