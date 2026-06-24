import Konva from 'konva'
import type { CanvasLink } from '@/types/canvas'
import { SELECTION, TEXT_SECONDARY } from './palette'

const BASE_OPACITY = 0.5
const CROSS_ZONE_OPACITY = 0.9

function endpoints(link: CanvasLink): number[] {
  return [link.source.x, link.source.y, link.target.x, link.target.y]
}

function midpoint(link: CanvasLink): { x: number; y: number } {
  return {
    x: (link.source.x + link.target.x) / 2,
    y: (link.source.y + link.target.y) / 2,
  }
}

function baseOpacity(link: CanvasLink): number {
  return link.crossZone ? CROSS_ZONE_OPACITY : BASE_OPACITY
}

export function createLinkLine(
  link: CanvasLink,
  callbacks?: { onClick?: (key: string) => void },
): Konva.Line {
  const line = new Konva.Line({
    points: endpoints(link),
    stroke: link.color,
    strokeWidth: link.width,
    opacity: baseOpacity(link),
    hitStrokeWidth: 14,
    id: `link-${link.key}`,
  })

  if (callbacks?.onClick) {
    const cb = callbacks.onClick
    line.on('click tap', (e) => {
      e.cancelBubble = true
      cb(link.key)
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

export function updateLinkLine(line: Konva.Line, link: CanvasLink, selected: boolean) {
  line.points(endpoints(link))
  line.stroke(selected ? SELECTION : link.color)
  line.strokeWidth(selected ? link.width + 1.5 : link.width)
  line.opacity(selected ? 1 : baseOpacity(link))
}

/** A small pill at the link midpoint showing how many conversations it carries.
 *  Only created for links with more than one conversation. */
export function createLinkBadge(link: CanvasLink): Konva.Label {
  const label = new Konva.Label({ id: `badge-${link.key}`, listening: false })
  label.add(
    new Konva.Tag({
      fill: 'rgba(18,22,27,0.88)',
      stroke: link.color,
      strokeWidth: 1,
      cornerRadius: 8,
    }),
  )
  label.add(
    new Konva.Text({
      text: String(link.conversationCount),
      fontSize: 10,
      fontFamily: '-apple-system, BlinkMacSystemFont, system-ui, sans-serif',
      fill: TEXT_SECONDARY,
      padding: 3,
    }),
  )
  positionBadge(label, link)
  return label
}

export function updateLinkBadge(label: Konva.Label, link: CanvasLink) {
  positionBadge(label, link)
}

function positionBadge(label: Konva.Label, link: CanvasLink) {
  const m = midpoint(link)
  label.position(m)
  label.offsetX(label.width() / 2)
  label.offsetY(label.height() / 2)
}
