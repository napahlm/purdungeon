import { ref, shallowRef, markRaw, onMounted, onUnmounted, type Ref } from 'vue'
import Konva from 'konva'
import { MOTION } from '@/ui/tokens'

export function useCanvas(containerRef: Ref<HTMLDivElement | null>) {
  // Konva objects must never be wrapped in Vue's reactive proxies: a proxied
  // scene graph pays proxy traps on every draw, and a proxied stage breaks
  // identity checks against raw event targets (e.target === stage).
  const stage = shallowRef<Konva.Stage | null>(null)
  const bandLayer = shallowRef<Konva.Layer | null>(null)
  const mainLayer = shallowRef<Konva.Layer | null>(null)
  const scale = ref(1)

  const MIN_SCALE = 0.1
  const MAX_SCALE = 5

  function init() {
    const el = containerRef.value
    if (!el) return

    // A pixel of jitter during a click must stay a click, not become a
    // stage pan or node drag that swallows the click event.
    Konva.dragDistance = 3

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
      // Manual zoom takes over from any running fit/zoom animation.
      viewTween?.destroy()
      viewTween = null
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

    stage.value = markRaw(s)
    bandLayer.value = markRaw(bands)
    mainLayer.value = markRaw(layer)
  }

  function resize() {
    const el = containerRef.value
    const s = stage.value
    if (!el || !s) return
    s.width(el.clientWidth)
    s.height(el.clientHeight)
  }

  // One viewport tween at a time; a new fit or zoom replaces the running one.
  let viewTween: Konva.Tween | null = null

  function tweenViewport(s: Konva.Stage, newScale: number, x: number, y: number, animate: boolean) {
    viewTween?.destroy()
    viewTween = null
    if (!animate) {
      s.scale({ x: newScale, y: newScale })
      s.position({ x, y })
    } else {
      viewTween = new Konva.Tween({
        node: s,
        duration: MOTION.slow / 1000,
        easing: Konva.Easings.EaseInOut,
        scaleX: newScale,
        scaleY: newScale,
        x,
        y,
      })
      viewTween.play()
    }
    scale.value = newScale
  }

  /**
   * Center the given content rect in the viewport, zoomed to fit. `insetLeft`
   * reserves space on the left for the findings panel, which overlays the
   * canvas, so content frames into the clear area beside it.
   */
  function fitToContent(
    bounds: { x: number; y: number; width: number; height: number },
    insetLeft = 0,
    animate = true,
  ) {
    const s = stage.value
    if (!s || bounds.width <= 0 || bounds.height <= 0) return
    const pad = 70
    const availWidth = Math.max(1, s.width() - insetLeft)
    const fit = Math.min(
      (availWidth - pad * 2) / bounds.width,
      (s.height() - pad * 2) / bounds.height,
      1.4,
    )
    const newScale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, fit))
    tweenViewport(
      s,
      newScale,
      insetLeft + availWidth / 2 - (bounds.x + bounds.width / 2) * newScale,
      s.height() / 2 - (bounds.y + bounds.height / 2) * newScale,
      animate,
    )
  }

  /** Zoom by a factor around the viewport centre (the +/− buttons). */
  function zoomBy(factor: number) {
    const s = stage.value
    if (!s) return
    const oldScale = s.scaleX()
    const newScale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, oldScale * factor))
    if (newScale === oldScale) return
    const center = { x: s.width() / 2, y: s.height() / 2 }
    const anchor = {
      x: (center.x - s.x()) / oldScale,
      y: (center.y - s.y()) / oldScale,
    }
    tweenViewport(s, newScale, center.x - anchor.x * newScale, center.y - anchor.y * newScale, true)
  }

  // The container resizes when sibling panels open and close, not just with
  // the window, so observe the element itself.
  let resizeObserver: ResizeObserver | null = null

  onMounted(() => {
    init()
    resizeObserver = new ResizeObserver(() => resize())
    if (containerRef.value) resizeObserver.observe(containerRef.value)
  })

  onUnmounted(() => {
    resizeObserver?.disconnect()
    resizeObserver = null
    viewTween?.destroy()
    viewTween = null
    stage.value?.destroy()
    stage.value = null
    bandLayer.value = null
    mainLayer.value = null
  })

  return { stage, bandLayer, mainLayer, scale, fitToContent, zoomBy }
}
