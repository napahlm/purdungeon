import type { Host, Connection } from './network'
import type { ProtoFamily } from '@/canvas/palette'

export interface CanvasNode {
  host: Host
  x: number
  y: number
  bandKey: string
  color: string
  label: string
  shape: 'circle' | 'square' | 'diamond'
  dashed: boolean
}

export interface CanvasEdge {
  connection: Connection
  source: CanvasNode
  target: CanvasNode
  color: string
  width: number
  family: ProtoFamily
  crossZone: boolean
}

/**
 * All conversations between one unordered pair of hosts, collapsed into a
 * single straight link. The canvas draws links, not individual edges; the
 * underlying `edges` drive the conversations list and finding highlights.
 */
export interface CanvasLink {
  key: string // pairKey(source.host.id, target.host.id)
  source: CanvasNode
  target: CanvasNode
  edges: CanvasEdge[]
  color: string
  width: number
  crossZone: boolean
  dominantFamily: ProtoFamily
  conversationCount: number
}

/** A populated horizontal band in the laid-out view. */
export interface BandLayout {
  key: string
  label: string
  y: number
  height: number
  index: number
}
