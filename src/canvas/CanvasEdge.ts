import Konva from 'konva'
import type { CanvasEdge } from '@/types/canvas'
import { SELECTION } from './palette'

const BASE_OPACITY = 0.45
const CROSS_ZONE_OPACITY = 0.85

function curvedPoints(edge: CanvasEdge): number[] {
  const { x: x1, y: y1 } = edge.source
  const { x: x2, y: y2 } = edge.target
  if (edge.curveOffset === 0) return [x1, y1, x2, y2]

  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2
  const dx = x2 - x1
  const dy = y2 - y1
  const len = Math.sqrt(dx * dx + dy * dy) || 1
  // Perpendicular unit vector
  const nx = -dy / len
  const ny = dx / len
  const cx = mx + nx * edge.curveOffset
  const cy = my + ny * edge.curveOffset
  return [x1, y1, cx, cy, x2, y2]
}

function baseOpacity(edge: CanvasEdge): number {
  return edge.crossZone ? CROSS_ZONE_OPACITY : BASE_OPACITY
}

export function createEdgeLine(
  edge: CanvasEdge,
  callbacks?: { onClick?: (connectionId: number) => void },
): Konva.Line {
  const line = new Konva.Line({
    points: curvedPoints(edge),
    stroke: edge.color,
    strokeWidth: edge.width,
    opacity: baseOpacity(edge),
    hitStrokeWidth: 14,
    tension: edge.curveOffset !== 0 ? 0.5 : 0,
    id: `edge-${edge.connection.id}`,
  })

  if (callbacks?.onClick) {
    const cb = callbacks.onClick
    line.on('click tap', (e) => {
      e.cancelBubble = true
      cb(edge.connection.id)
    })
    line.on('mouseenter', () => {
      const stage = line.getStage()
      if (stage) stage.container().style.cursor = 'pointer'
    })
    line.on('mouseleave', () => {
      const stage = line.getStage()
      if (stage) stage.container().style.cursor = 'default'
    })
  }

  return line
}

export function updateEdgeLine(line: Konva.Line, edge: CanvasEdge, selected: boolean) {
  line.points(curvedPoints(edge))
  line.tension(edge.curveOffset !== 0 ? 0.5 : 0)
  line.stroke(selected ? SELECTION : edge.color)
  line.strokeWidth(selected ? edge.width + 1.5 : edge.width)
  line.opacity(selected ? 1 : baseOpacity(edge))
}
