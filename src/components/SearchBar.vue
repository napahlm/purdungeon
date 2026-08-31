<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { useTopologyStore } from '@/stores/topology'

const topology = useTopologyStore()
const visible = ref(false)
const inputRef = ref<HTMLInputElement | null>(null)
const query = ref('')

function onKeydown(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault()
    visible.value = !visible.value
    if (visible.value) {
      setTimeout(() => inputRef.value?.focus(), 0)
    } else {
      query.value = ''
      clearDebounce()
      topology.searchQuery = ''
    }
  }
  if (e.key === 'Escape' && visible.value) {
    e.stopPropagation()
    close()
  }
}

function close() {
  visible.value = false
  query.value = ''
  clearDebounce()
  topology.searchQuery = ''
}

// Each keystroke recomputes the match over every node and link; debounce so
// fast typing settles before the canvas re-highlights.
let debounceTimer: ReturnType<typeof setTimeout> | null = null

function clearDebounce() {
  if (debounceTimer !== null) {
    clearTimeout(debounceTimer)
    debounceTimer = null
  }
}

watch(query, (v) => {
  clearDebounce()
  debounceTimer = setTimeout(() => {
    debounceTimer = null
    topology.searchQuery = v
  }, 150)
})

onMounted(() => window.addEventListener('keydown', onKeydown, true))
onUnmounted(() => window.removeEventListener('keydown', onKeydown, true))
</script>

<template>
  <Teleport to="body">
    <Transition name="overlay">
      <div
        v-if="visible"
        class="fixed inset-0 z-50 flex items-start justify-center bg-bg-primary/40 pt-24 backdrop-blur-sm"
        @click.self="close"
      >
        <div class="w-96 rounded-lg border border-border bg-bg-elevated shadow-2xl">
          <div class="flex items-center gap-2 px-4 py-3">
            <svg
              viewBox="0 0 16 16"
              class="h-4 w-4 shrink-0 text-text-muted"
              fill="none"
              stroke="currentColor"
              stroke-width="1.6"
            >
              <circle cx="7" cy="7" r="4.5" />
              <path d="M10.5 10.5L14 14" stroke-linecap="round" />
            </svg>
            <input
              ref="inputRef"
              v-model="query"
              type="text"
              placeholder="IP, MAC, vendor, protocol (tcp, modbus), or subnet (10.0.0.0/24)…"
              class="flex-1 bg-transparent text-sm text-text-primary outline-none placeholder:text-text-muted"
            />
            <kbd class="rounded border border-border px-1.5 py-0.5 text-xs text-text-muted"
              >Esc</kbd
            >
          </div>
          <div
            v-if="query && (topology.matchedNodeIds.size > 0 || topology.matchedLinkKeys.size > 0)"
            class="border-t border-border px-4 py-2 text-xs text-text-secondary"
          >
            <span v-if="topology.matchedNodeIds.size > 0"
              >{{ topology.matchedNodeIds.size }} device{{
                topology.matchedNodeIds.size === 1 ? '' : 's'
              }}</span
            >
            <span v-if="topology.matchedNodeIds.size > 0 && topology.matchedLinkKeys.size > 0">
              ·
            </span>
            <span v-if="topology.matchedLinkKeys.size > 0"
              >{{ topology.matchedLinkKeys.size }} link{{
                topology.matchedLinkKeys.size === 1 ? '' : 's'
              }}</span
            >
            highlighted
          </div>
          <div v-else-if="query" class="border-t border-border px-4 py-2 text-xs text-text-muted">
            No matches
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
