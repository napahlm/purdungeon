<script setup lang="ts">
import { ref, watch } from 'vue'
import { useCaptureStore } from '@/stores/capture'
import { useTauri } from '@/composables/useTauri'
import type { PacketDetail } from '@/types/capture'
import { isCaptureFailure } from '@/types/capture'
import { formatTime } from '@/utils/format'
import DetailPanel from '@/components/ui/DetailPanel.vue'
import PanelSection from '@/components/ui/PanelSection.vue'
import DetailRow from '@/components/ui/DetailRow.vue'
import WriteBadge from '@/components/ui/WriteBadge.vue'

const captureStore = useCaptureStore()
const { getPacketDetail } = useTauri()

const detail = ref<PacketDetail | null>(null)
const error = ref<string | null>(null)

let requestSeq = 0
watch(
  () => captureStore.selectedNo,
  async (no) => {
    const seq = ++requestSeq
    error.value = null
    if (no === null) {
      detail.value = null
      return
    }
    try {
      const result = await getPacketDetail(no)
      if (seq === requestSeq) detail.value = result
    } catch (e) {
      if (seq !== requestSeq) return
      detail.value = null
      error.value =
        isCaptureFailure(e) && e.message.includes('left the buffer')
          ? 'This packet has left the buffer. The list keeps the newest 200,000 frames; the saved pcap keeps them all.'
          : isCaptureFailure(e)
            ? e.message
            : String(e)
    }
  },
  { immediate: true },
)

function isWriteRow(section: string, label: string, value: string): boolean {
  return section.startsWith('Modbus') && label === 'Writes' && value === 'yes'
}

function close() {
  captureStore.selectedNo = null
}
</script>

<template>
  <DetailPanel @close="close">
    <template #header>
      <div class="flex min-w-0 items-center gap-2.5">
        <h2 class="truncate text-sm font-semibold text-text-primary">
          <template v-if="detail">Frame {{ detail.no.toLocaleString() }}</template>
          <template v-else>Packet</template>
        </h2>
        <span v-if="detail" class="shrink-0 text-xs text-text-muted">{{ detail.protocol }}</span>
      </div>
    </template>

    <div
      v-if="error"
      class="flex flex-1 items-center justify-center px-6 text-center text-sm text-text-muted"
    >
      {{ error }}
    </div>

    <div v-else-if="detail" class="flex-1 overflow-y-auto">
      <PanelSection>
        <p class="text-sm leading-relaxed text-text-primary">{{ detail.info }}</p>
        <p class="mt-1 text-xs text-text-muted">{{ formatTime(detail.timestamp) }}</p>
      </PanelSection>
      <PanelSection
        v-for="(section, i) in detail.sections"
        :key="section.title"
        :label="section.title"
        :divider="i < detail.sections.length - 1"
      >
        <div class="space-y-1.5 text-sm">
          <DetailRow v-for="[label, value] in section.rows" :key="label" :label="label" mono>
            <WriteBadge v-if="isWriteRow(section.title, label, value)" />
            <template v-else>{{ value }}</template>
          </DetailRow>
        </div>
      </PanelSection>
    </div>

    <div v-else class="flex flex-1 items-center justify-center text-sm text-text-muted">
      Loading…
    </div>
  </DetailPanel>
</template>
