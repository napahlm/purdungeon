import Konva from 'konva'
import type { CanvasNode } from '@/types/canvas'
import { ACCENT, SELECTION, TEXT_SECONDARY } from './palette'

const RADIUS = 13

function makeShape(node: CanvasNode): Konva.Shape {
  const common = {
    fill: node.color,
    stroke: node.dashed ? node.color : undefined,
    dash: node.dashed ? [4, 3] : undefined,
    name: 'node-shape',
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
      fill: '#0e1116',
      stroke: node.color,
      strokeWidth: 1.5,
      dash: [4, 3],
      name: 'node-shape',
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
    stroke: SELECTION,
    strokeWidth: 1.5,
    visible: false,
    name: 'node-ring',
  })

  const label = new Konva.Text({
    text: node.label,
    fontSize: 10.5,
    fontFamily: 'ui-monospace, SF Mono, Menlo, monospace',
    fill: TEXT_SECONDARY,
    align: 'center',
    y: RADIUS + 8,
    name: 'node-label',
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
    ring.visible(selected || searchState === 'match')
    ring.stroke(searchState === 'match' ? ACCENT : SELECTION)
  }
  group.opacity(searchState === 'dim' ? 0.18 : 1)
}
