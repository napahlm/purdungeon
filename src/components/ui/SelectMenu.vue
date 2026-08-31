<script setup lang="ts">
import { ref, computed } from 'vue'

const props = defineProps<{
  modelValue: string
  options: { value: string; label: string }[]
}>()

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const open = ref(false)
const activeIndex = ref(0)

const selectedLabel = computed(
  () => props.options.find((o) => o.value === props.modelValue)?.label ?? props.modelValue,
)

function openMenu() {
  const selected = props.options.findIndex((o) => o.value === props.modelValue)
  activeIndex.value = Math.max(0, selected)
  open.value = true
}

function closeMenu() {
  open.value = false
}

function toggle() {
  if (open.value) closeMenu()
  else openMenu()
}

function select(value: string) {
  closeMenu()
  if (value !== props.modelValue) emit('update:modelValue', value)
}

// Enter/Space on the closed button already toggle via the native click; this
// only adds arrow-key opening plus navigation inside the open listbox.
function onKeydown(e: KeyboardEvent) {
  if (!open.value) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      openMenu()
    }
    return
  }
  if (e.key === 'Escape') {
    e.preventDefault()
    closeMenu()
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    activeIndex.value = Math.min(props.options.length - 1, activeIndex.value + 1)
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    activeIndex.value = Math.max(0, activeIndex.value - 1)
  } else if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault()
    const option = props.options[activeIndex.value]
    if (option) select(option.value)
  }
}
</script>

<template>
  <div class="relative" @keydown="onKeydown">
    <button
      type="button"
      class="flex items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2 py-1 text-xs text-text-primary outline-none transition-colors focus:border-accent"
      aria-haspopup="listbox"
      :aria-expanded="open"
      @click="toggle"
    >
      <span class="truncate">{{ selectedLabel }}</span>
      <svg
        viewBox="0 0 16 16"
        class="h-3 w-3 shrink-0 text-text-muted"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
      >
        <path d="M4 6l4 4 4-4" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
    </button>

    <template v-if="open">
      <div class="fixed inset-0 z-30" @click="closeMenu" />
      <div
        class="absolute right-0 top-full z-40 mt-1 min-w-full rounded-lg border border-border bg-bg-elevated p-1 shadow-lg"
        role="listbox"
      >
        <button
          v-for="(option, i) in options"
          :key="option.value"
          type="button"
          class="flex w-full items-center justify-between gap-3 whitespace-nowrap rounded-md px-2 py-1.5 text-left text-sm transition-colors"
          :class="[
            option.value === modelValue ? 'text-accent' : 'text-text-primary',
            i === activeIndex ? 'bg-bg-surface' : '',
          ]"
          role="option"
          :aria-selected="option.value === modelValue"
          @mouseenter="activeIndex = i"
          @click="select(option.value)"
        >
          {{ option.label }}
          <svg
            v-if="option.value === modelValue"
            viewBox="0 0 16 16"
            class="h-3.5 w-3.5 shrink-0"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
          >
            <path d="M3 8.5l3.5 3.5L13 5" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </button>
      </div>
    </template>
  </div>
</template>
