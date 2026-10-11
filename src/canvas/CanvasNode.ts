import Konva from 'konva'
import type { CanvasNode } from '@/types/canvas'
import { effectiveRole, type Role } from '@/types/network'
import { UI, FONTS, MOTION } from '@/ui/tokens'

export const NODE_RADIUS = 14
const LABEL_GAP = 9
const LABEL_PAD_X = 5
const LABEL_PAD_Y = 2

/** Three letters inside the shape, so a role reads at a glance without the
 *  legend. Empty for a device the analysis could not place. */
const ROLE_GLYPH: Record<Role, string> = {
  plc: 'PLC',
  scada: 'SCA',
  hmi: 'HMI',
  'engineering-workstation': 'EWS',
  historian: 'HIS',
  'field-device': 'I/O',
  'network-gear': 'NET',
  server: 'SRV',
  workstation: 'WKS',
  external: 'EXT',
  broadcast: '',
  unknown: '',
  subnet: 'NET',
}

/**
 * The visual for one device. Groups are centered on the node's position with
 * the shape child named 'node-shape' - future pixel-art sprites swap in here
 * as a `Konva.Image` with `offsetX/Y` at half its size, keeping the same
 * centered-origin contract; the ring, glyph, label, drag, and hit behavior on
 * the parent group stay untouched.
 */
function makeShape(node: CanvasNode): Konva.Shape {
  const common = {
    fill: node.color,
    // A halo in the background colour separates a node from the links
    // passing under it; external hosts keep their dashed outline instead.
    stroke: node.dashed ? node.color : UI.bgPrimary,
    strokeWidth: 2,
    dash: node.dashed ? [4, 3] : undefined,
    name: 'node-shape',
    // Skip Konva's buffer-canvas pass; these simple fills don't need it.
    perfectDrawEnabled: false,
  }
  if (node.shape === 'square') {
    return new Konva.Rect({
      ...common,
      x: -NODE_RADIUS,
      y: -NODE_RADIUS,
      width: NODE_RADIUS * 2,
      height: NODE_RADIUS * 2,
      cornerRadius: 4,
    })
  }
  if (node.shape === 'diamond') {
    return new Konva.Rect({
      ...common,
      width: NODE_RADIUS * 1.85,
      height: NODE_RADIUS * 1.85,
      offsetX: NODE_RADIUS * 0.925,
      offsetY: NODE_RADIUS * 0.925,
      rotation: 45,
      cornerRadius: 3,
    })
  }
  if (node.dashed) {
    // External hosts: hollow dashed circle
    return new Konva.Circle({
      radius: NODE_RADIUS,
      fill: UI.bgPrimary,
      stroke: node.color,
      strokeWidth: 1.5,
      dash: [4, 3],
      name: 'node-shape',
      perfectDrawEnabled: false,
    })
  }
  return new Konva.Circle({ ...common, radius: NODE_RADIUS })
}

function makeGlyph(node: CanvasNode): Konva.Text | null {
  const glyph = ROLE_GLYPH[effectiveRole(node.host)]
  if (!glyph) return null
  return new Konva.Text({
    text: glyph,
    fontSize: 8,
    fontStyle: 'bold',
    fontFamily: FONTS.sans,
    letterSpacing: 0.2,
    // Dark on a filled shape; the level colour on a hollow external one.
    fill: node.dashed ? node.color : UI.bgPrimary,
    align: 'center',
    verticalAlign: 'middle',
    x: -NODE_RADIUS,
    y: -NODE_RADIUS,
    width: NODE_RADIUS * 2,
    height: NODE_RADIUS * 2,
    name: 'node-glyph',
    listening: false,
    perfectDrawEnabled: false,
  })
}

/** Address on the first line, name or role on the second, on a plate so the
 *  text stays readable over band tints and the links passing beneath. */
function makeLabel(node: CanvasNode): Konva.Group {
  const group = new Konva.Group({
    y: NODE_RADIUS + LABEL_GAP,
    name: 'node-label',
    listening: false,
  })
  const lines = [
    new Konva.Text({
      text: node.label,
      fontSize: 10.5,
      fontFamily: FONTS.mono,
      fill: UI.textPrimary,
      perfectDrawEnabled: false,
    }),
  ]
  if (node.sublabel) {
    lines.push(
      new Konva.Text({
        text: node.sublabel,
        fontSize: 9.5,
        fontFamily: FONTS.sans,
        fill: UI.textMuted,
        perfectDrawEnabled: false,
      }),
    )
  }
  let width = 0
  for (const line of lines) width = Math.max(width, line.width())
  let y = LABEL_PAD_Y
  for (const line of lines) {
    line.x(-line.width() / 2)
    line.y(y)
    y += line.height() + 1
  }
  const plate = new Konva.Rect({
    x: -width / 2 - LABEL_PAD_X,
    y: 0,
    width: width + LABEL_PAD_X * 2,
    height: y + LABEL_PAD_Y - 1,
    cornerRadius: 4,
    fill: UI.badgeBg,
    perfectDrawEnabled: false,
  })
  group.add(plate, ...lines)
  return group
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
    radius: NODE_RADIUS + 6,
    stroke: UI.selection,
    strokeWidth: 1.5,
    visible: false,
    name: 'node-ring',
    listening: false,
    perfectDrawEnabled: false,
  })

  group.add(ring)
  group.add(makeShape(node))
  const glyph = makeGlyph(node)
  if (glyph) group.add(glyph)
  group.add(makeLabel(node))

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
