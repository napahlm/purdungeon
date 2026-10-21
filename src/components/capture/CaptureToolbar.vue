<script setup lang="ts">
import { computed, ref } from 'vue'
import { useCaptureStore } from '@/stores/capture'
import { useCaptureControls } from '@/composables/useCaptureControls'
import { formatBytes } from '@/utils/format'
import SelectMenu from '@/components/ui/SelectMenu.vue'

const captureStore = useCaptureStore()
const { start, stop, saveAs, loadInterfaces } = useCaptureControls()

const interfaceOptions = computed(() =>
  captureStore.interfaces.map((i) => ({
    value: i.name,
    label: i.addresses.length > 0 ? `${i.name}  ${i.addresses[0]}` : i.name,
  })),
)

const saved = ref<string | null>(null)
let savedTimer: ReturnType<typeof setTimeout> | null = null

async function onSave() {
  const result = await saveAs()
  if (!result) return
  const name = result.path.split(/[\\/]/).pop() ?? result.path
  saved.value = `Saved ${formatBytes(result.bytes)} to ${name}`
  if (savedTimer !== null) clearTimeout(savedTimer)
  savedTimer = setTimeout(() => (saved.value = null), 4000)
}

function onSelectInterface(value: string) {
  captureStore.selectedInterface = value
}

function onFilterKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !captureStore.running) void start()
}
</script>

<template>
  <div class="flex shrink-0 items-center gap-3 border-b border-border bg-bg-secondary px-4 py-2">
    <div class="flex items-center gap-2">
      <span class="text-xs text-text-muted">Interface</span>
      <SelectMenu
        v-if="interfaceOptions.length > 0"
        :model-value="captureStore.selectedInterface ?? ''"
        :options="interfaceOptions"
        @update:model-value="onSelectInterface"
      />
      <button
        v-else
        class="rounded-md border border-border bg-bg-elevated px-2 py-1 text-xs text-text-secondary transition-colors hover:text-text-primary"
        @click="loadInterfaces"
      >
        No interfaces found · retry
      </button>
    </div>

    <label class="flex min-w-0 flex-1 items-center gap-2">
      <span class="text-xs text-text-muted">Filter</span>
      <input
        v-model="captureStore.filter"
        type="text"
        spellcheck="false"
        placeholder="tcp port 502"
        :disabled="captureStore.running"
        class="min-w-0 flex-1 rounded-md border border-border bg-bg-primary px-2 py-1 font-mono text-xs text-text-primary outline-none transition-colors placeholder:text-text-muted focus:border-accent disabled:opacity-60"
        :class="captureStore.error?.code === 'bad-filter' ? 'border-alert' : ''"
        title="A BPF capture filter, as tcpdump and Wireshark take it"
        @keydown="onFilterKeydown"
      />
    </label>

    <label
      class="flex items-center gap-1.5 text-xs text-text-secondary"
      title="Receive every frame on the segment, not only those addressed to this machine"
    >
      <input
        v-model="captureStore.promiscuous"
        type="checkbox"
        :disabled="captureStore.running"
        class="accent-accent"
      />
      Promiscuous
    </label>

    <div class="flex items-center gap-1">
      <button
        v-if="!captureStore.running"
        class="rounded-md bg-accent px-3 py-1 text-xs font-medium text-bg-primary transition-colors hover:bg-accent-dim disabled:cursor-not-allowed disabled:opacity-40"
        :disabled="captureStore.starting || captureStore.selectedInterface === null"
        @click="start"
      >
        {{ captureStore.starting ? 'Starting…' : 'Start' }}
      </button>
      <button
        v-else
        class="rounded-md bg-alert px-3 py-1 text-xs font-medium text-bg-primary transition-colors hover:opacity-90 disabled:cursor-wait disabled:opacity-60"
        :disabled="captureStore.stopping"
        @click="stop"
      >
        {{ captureStore.stopping ? 'Stopping…' : 'Stop' }}
      </button>
      <button
        class="rounded-md px-2.5 py-1 text-xs text-text-secondary transition-colors hover:bg-bg-elevated hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
        :disabled="!captureStore.hasCapture || captureStore.running"
        :title="
          captureStore.running
            ? 'Stop the capture to save it'
            : captureStore.hasCapture
              ? 'Save the capture as a pcap file'
              : 'Nothing captured yet'
        "
        @click="onSave"
      >
        Save as pcap…
      </button>
      <Transition name="overlay">
        <span v-if="saved" class="ml-1 text-xs text-text-muted">{{ saved }}</span>
      </Transition>
    </div>
  </div>
</template>
