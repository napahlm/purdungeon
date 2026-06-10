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
  curveOffset: number // 0 = straight, nonzero = perpendicular offset for parallel edges
}

/** A populated horizontal band in the laid-out view. */
export interface BandLayout {
  key: string
  label: string
  y: number
  height: number
  index: number
}
