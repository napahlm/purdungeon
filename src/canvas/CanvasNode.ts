import Konva from 'konva'
import type { CanvasNode } from '@/types/canvas'
import { UI, FONTS, MOTION } from '@/ui/tokens'

const RADIUS = 13

/**
 * The visual for one device. Groups are centered on the node's position with
 * the shape child named 'node-shape' — future pixel-art sprites swap in here
 * as a `Konva.Image` with `offsetX/Y` at half its size, keeping the same
 * centered-origin contract; the ring, label, drag, and hit behavior on the
 * parent group stay untouched.
 */
function makeShape(node: CanvasNode): Konva.Shape {
  const common = {
    fill: node.color,
    // A thin halo in the background colour separates a node from the links
    // passing under it; external hosts keep their dashed outline instead.
    stroke: node.dashed ? node.color : UI.bgPrimary,
    strokeWidth: 1.5,
    dash: node.dashed ? [4, 3] : undefined,
    name: 'node-shape',
    // Skip Konva's buffer-canvas pass; these simple fills don't need it.
    perfectDrawEnabled: false,
  }
  if (node.shape === 'square') {
    return new Konva.Rect({
      ...common,
      x: -RADIUS,
      y: -RADIUS,
      width: RADIUS * 2,
      height: RADIUS * 2,
      cornerRadius: 3,
    })
  }
  if (node.shape === 'diamond') {
    return new Konva.Rect({
      ...common,
      width: RADIUS * 1.8,
      height: RADIUS * 1.8,
      offsetX: RADIUS * 0.9,
      offsetY: RADIUS * 0.9,
      rotation: 45,
      cornerRadius: 2,
    })
  }
  if (node.dashed) {
    // External hosts: hollow dashed circle
    return new Konva.Circle({
      radius: RADIUS,
      fill: UI.bgPrimary,
      stroke: node.color,
      strokeWidth: 1.5,
      dash: [4, 3],
      name: 'node-shape',
      perfectDrawEnabled: false,
    })
  }
  return new Konva.Circle({ ...common, radius: RADIUS })
}

export function createNodeGroup(
  node: CanvasNode,
  callbacks: {
    onDragMove: (hostId: number, x: number, y: number) => void
    onDragEnd: (hostId: number, x: number, y: number) => void
    onClick: (hostId: number) => void
  },
): Konva.Group {
  const group = new Konva.Group({
    x: node.x,
    y: node.y,
    draggable: true,
    id: `node-${node.host.id}`,
  })

  // Selection ring, hidden until selected
  const ring = new Konva.Circle({
    radius: RADIUS + 5,
    stroke: UI.selection,
    strokeWidth: 1.5,
    visible: false,
    name: 'node-ring',
    listening: false,
    perfectDrawEnabled: false,
  })

  const label = new Konva.Text({
    text: node.label,
    fontSize: 10.5,
    fontFamily: FONTS.mono,
    fill: UI.textSecondary,
    align: 'center',
    y: RADIUS + 8,
    name: 'node-label',
    listening: false,
    perfectDrawEnabled: false,
  })
  label.x(-label.width() / 2)

  group.add(ring)
  group.add(makeShape(node))
  group.add(label)

  group.on('dragmove', () => {
    callbacks.onDragMove(node.host.id, group.x(), group.y())
    // The store may clamp y to the band; reflect it immediately
    group.x(node.x)
    group.y(node.y)
  })

  group.on('dragend', () => {
    callbacks.onDragEnd(node.host.id, group.x(), group.y())
  })

  group.on('click tap', (e) => {
    e.cancelBubble = true
    callbacks.onClick(node.host.id)
  })

  group.on('mouseenter', () => {
    const stage = group.getStage()
    if (stage) stage.container().style.cursor = 'pointer'
  })
  group.on('mouseleave', () => {
    const stage = group.getStage()
    if (stage) stage.container().style.cursor = 'default'
  })

  return group
}

export function updateNodeGroup(
  group: Konva.Group,
  node: CanvasNode,
  selected: boolean,
  searchState: 'match' | 'dim' | 'none' = 'none',
) {
  group.x(node.x)
  group.y(node.y)

  const ring = group.findOne('.node-ring') as Konva.Circle | undefined
  if (ring) {
    const show = selected || searchState === 'match'
    const appearing = show && !ring.visible()
    ring.visible(show)
    ring.stroke(searchState === 'match' ? UI.accent : UI.selection)
    if (appearing) {
      // A quick settle-in so selection feels acknowledged, not switched.
      ring.scale({ x: 0.6, y: 0.6 })
      ring.opacity(0)
      new Konva.Tween({
        node: ring,
        duration: MOTION.fast / 1000,
        easing: Konva.Easings.EaseOut,
        scaleX: 1,
        scaleY: 1,
        opacity: 1,
      }).play()
    }
  }
  group.opacity(searchState === 'dim' ? 0.18 : 1)
}
