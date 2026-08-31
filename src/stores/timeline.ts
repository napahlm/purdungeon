import { ref, shallowRef } from 'vue'
import { defineStore } from 'pinia'
import type { HistogramBucket } from '@/types/network'

export interface TimeWindow {
  start: number
  end: number
}

export const useTimelineStore = defineStore('timeline', () => {
  const fullRange = ref<TimeWindow>({ start: 0, end: 0 })
  const filterRange = ref<TimeWindow>({ start: 0, end: 0 })
  const filtering = ref(false)
  /** Traffic volume per bucket, drawn behind the timeline track. */
  const histogram = shallowRef<HistogramBucket[]>([])

  function setFullRange(start: number, end: number) {
    fullRange.value = { start, end }
    filterRange.value = { start, end }
    filtering.value = false
  }

  function setFilterRange(start: number, end: number) {
    filterRange.value = { start, end }
    filtering.value = start !== fullRange.value.start || end !== fullRange.value.end
  }

  function resetFilter() {
    filterRange.value = { ...fullRange.value }
    filtering.value = false
  }

  function reset() {
    fullRange.value = { start: 0, end: 0 }
    filterRange.value = { start: 0, end: 0 }
    filtering.value = false
    histogram.value = []
  }

  return {
    fullRange,
    filterRange,
    filtering,
    histogram,
    setFullRange,
    setFilterRange,
    resetFilter,
    reset,
  }
})
