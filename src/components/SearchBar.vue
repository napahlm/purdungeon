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
  topology.searchQuery = ''
}

watch(query, (v) => {
  topology.searchQuery = v
})

onMounted(() => window.addEventListener('keydown', onKeydown, true))
onUnmounted(() => window.removeEventListener('keydown', onKeydown, true))
</script>

<template>
  <Teleport to="body">
    <div
      v-if="visible"
      class="fixed inset-0 z-50 flex items-start justify-center pt-24"
      @click.self="close"
    >
      <div class="w-96 rounded-lg border border-border bg-bg-elevated shadow-2xl">
        <div class="flex items-center gap-2 px-4 py-3">
          <span class="text-text-muted">⌘</span>
          <input
            ref="inputRef"
            v-model="query"
            type="text"
            placeholder="Search by IP, MAC, vendor, protocol…"
            class="flex-1 bg-transparent text-sm text-text-primary outline-none placeholder:text-text-muted"
          />
          <kbd class="rounded border border-border px-1.5 py-0.5 text-xs text-text-muted">Esc</kbd>
        </div>
        <div
          v-if="query && topology.matchedNodeIds.size > 0"
          class="border-t border-border px-4 py-2 text-xs text-text-secondary"
        >
          {{ topology.matchedNodeIds.size }} match{{
            topology.matchedNodeIds.size === 1 ? '' : 'es'
          }}
          highlighted
        </div>
        <div
          v-else-if="query && topology.matchedNodeIds.size === 0"
          class="border-t border-border px-4 py-2 text-xs text-text-muted"
        >
          No matches
        </div>
      </div>
    </div>
  </Teleport>
</template>
