import { ref, onMounted, onUnmounted, type Ref } from 'vue'
import Konva from 'konva'

export function useCanvas(containerRef: Ref<HTMLDivElement | null>) {
  const stage = ref<Konva.Stage | null>(null)
  const bandLayer = ref<Konva.Layer | null>(null)
  const mainLayer = ref<Konva.Layer | null>(null)
  const scale = ref(1)

  const MIN_SCALE = 0.1
  const MAX_SCALE = 5

  function init() {
    const el = containerRef.value
    if (!el) return

    const s = new Konva.Stage({
      container: el,
      width: el.clientWidth,
      height: el.clientHeight,
      draggable: true,
    })

    const bands = new Konva.Layer({ listening: false })
    const layer = new Konva.Layer()
    s.add(bands)
    s.add(layer)

    s.on('wheel', (e) => {
      e.evt.preventDefault()
      const oldScale = s.scaleX()
      const pointer = s.getPointerPosition()
      if (!pointer) return

      const direction = e.evt.deltaY > 0 ? -1 : 1
      const factor = 1.08
      const newScale = Math.max(
        MIN_SCALE,
        Math.min(MAX_SCALE, direction > 0 ? oldScale * factor : oldScale / factor),
      )

      const mousePointTo = {
        x: (pointer.x - s.x()) / oldScale,
        y: (pointer.y - s.y()) / oldScale,
      }

      s.scale({ x: newScale, y: newScale })
      s.position({
        x: pointer.x - mousePointTo.x * newScale,
        y: pointer.y - mousePointTo.y * newScale,
      })

      scale.value = newScale
    })

    stage.value = s
    bandLayer.value = bands
    mainLayer.value = layer
  }

  function resize() {
    const el = containerRef.value
    const s = stage.value
    if (!el || !s) return
    s.width(el.clientWidth)
    s.height(el.clientHeight)
  }

  /** Center the given content rect in the viewport, zoomed to fit. */
  function fitToContent(bounds: { x: number; y: number; width: number; height: number }) {
    const s = stage.value
    if (!s || bounds.width <= 0 || bounds.height <= 0) return
    const pad = 70
    const fit = Math.min(
      (s.width() - pad * 2) / bounds.width,
      (s.height() - pad * 2) / bounds.height,
      1.4,
    )
    const newScale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, fit))
    s.scale({ x: newScale, y: newScale })
    s.position({
      x: s.width() / 2 - (bounds.x + bounds.width / 2) * newScale,
      y: s.height() / 2 - (bounds.y + bounds.height / 2) * newScale,
    })
    scale.value = newScale
  }

  onMounted(() => {
    init()
    window.addEventListener('resize', resize)
  })

  onUnmounted(() => {
    window.removeEventListener('resize', resize)
    stage.value?.destroy()
    stage.value = null
    bandLayer.value = null
    mainLayer.value = null
  })

  return { stage, bandLayer, mainLayer, scale, resize, fitToContent }
}
