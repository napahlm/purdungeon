import Konva from 'konva'
import type { CanvasLink } from '@/types/canvas'
import { UI, FONTS } from '@/ui/tokens'

const BASE_OPACITY = 0.72
const CROSS_ZONE_OPACITY = 0.92
const EMPHASIS_WIDTH = 1.5

/**
 * Control points of the cubic curve that draws a link. A link between bands
 * leaves and enters its devices vertically, so the links fanning into one
 * device converge there instead of crossing each other; a link inside a band
 * arcs over the band, clear of the devices and labels between its endpoints.
 */
export function linkCurve(link: CanvasLink): number[] {
  const { x: x0, y: y0 } = link.source
  const { x: x1, y: y1 } = link.target
  if (link.source.bandKey === link.target.bandKey) {
    const dx = x1 - x0
    const lift = Math.min(64, Math.max(28, Math.abs(dx) * 0.22))
    return [x0, y0, x0 + dx * 0.25, y0 - lift, x0 + dx * 0.75, y1 - lift, x1, y1]
  }
  const ym = (y0 + y1) / 2
  return [x0, y0, x0, ym, x1, ym, x1, y1]
}

/** The point halfway along the curve (t = 0.5), where the badge sits. */
function curveMidpoint(p: number[]): { x: number; y: number } {
  return {
    x: (p[0] + 3 * p[2] + 3 * p[4] + p[6]) / 8,
    y: (p[1] + 3 * p[3] + 3 * p[5] + p[7]) / 8,
  }
}

function baseOpacity(link: CanvasLink): number {
  return link.crossZone ? CROSS_ZONE_OPACITY : BASE_OPACITY
}

/** Selection and hover are stored on the shape, so either can be restyled
 *  without the other's caller having to know about it. */
function applyLinkStyle(line: Konva.Line, link: CanvasLink) {
  const selected = line.getAttr('selected') === true
  const hovered = line.getAttr('hovered') === true
  const forced = line.getAttr('forcedOpacity') as number | null
  line.stroke(selected ? UI.selection : link.color)
  line.strokeWidth(selected || hovered ? link.width + EMPHASIS_WIDTH : link.width)
  if (selected || hovered) line.opacity(1)
  else line.opacity(forced ?? baseOpacity(link))
}

export function createLinkLine(
  link: CanvasLink,
  callbacks?: { onClick?: (key: string) => void },
): Konva.Line {
  const line = new Konva.Line({
    points: linkCurve(link),
    bezier: true,
    lineCap: 'round',
    stroke: link.color,
    strokeWidth: link.width,
    opacity: baseOpacity(link),
    hitStrokeWidth: 14,
    id: `link-${link.key}`,
    perfectDrawEnabled: false,
    forcedOpacity: null,
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
      line.setAttr('hovered', true)
      applyLinkStyle(line, link)
      line.getLayer()?.batchDraw()
    })
    line.on('mouseleave', () => {
      const stage = line.getStage()
      if (stage) stage.container().style.cursor = 'default'
      line.setAttr('hovered', false)
      applyLinkStyle(line, link)
      line.getLayer()?.batchDraw()
    })
  }

  return line
}

/**
 * Re-point and restyle a link. `forcedOpacity` is what a search or an active
 * finding wants (dimmed or lit); `undefined` keeps whatever was set last, so a
 * drag mid-search does not undo the dimming.
 */
export function updateLinkLine(
  line: Konva.Line,
  link: CanvasLink,
  selected: boolean,
  forcedOpacity?: number | null,
) {
  line.points(linkCurve(link))
  line.setAttr('selected', selected)
  if (forcedOpacity !== undefined) line.setAttr('forcedOpacity', forcedOpacity)
  applyLinkStyle(line, link)
}

/** A small pill at the link midpoint showing how many conversations it carries.
 *  Only created for links with more than one conversation. */
export function createLinkBadge(link: CanvasLink): Konva.Label {
  const label = new Konva.Label({ id: `badge-${link.key}`, listening: false })
  label.add(
    new Konva.Tag({
      fill: UI.badgeBg,
      stroke: link.color,
      strokeWidth: 1,
      cornerRadius: 8,
    }),
  )
  label.add(
    new Konva.Text({
      text: String(link.conversationCount),
      fontSize: 10,
      fontFamily: FONTS.sans,
      fill: UI.textSecondary,
      padding: 3,
    }),
  )
  positionBadge(label, link)
  return label
}

export function updateLinkBadge(label: Konva.Label, link: CanvasLink) {
  // A stitched capture can change how many conversations a pair carries.
  const text = label.getText() as Konva.Text | undefined
  if (text && text.text() !== String(link.conversationCount)) {
    text.text(String(link.conversationCount))
  }
  const tag = label.getTag() as Konva.Tag | undefined
  if (tag) tag.stroke(link.color)
  positionBadge(label, link)
}

function positionBadge(label: Konva.Label, link: CanvasLink) {
  label.position(curveMidpoint(linkCurve(link)))
  label.offsetX(label.width() / 2)
  label.offsetY(label.height() / 2)
}
