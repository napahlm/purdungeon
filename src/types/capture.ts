/** What the live capture commands return; mirrors `crates/core/src/live/types.rs`. */

import type { ImportResult } from './network'

export interface PacketRow {
  /** 1-based frame number, monotonic for the capture run. */
  no: number
  /** Epoch seconds. */
  timestamp: number
  src: string
  dst: string
  /** The Protocol column: `Modbus`, `TCP`, `ARP`, `LLDP`, ... */
  protocol: string
  /** Lowercase application tag the topology colours by, when there is one. */
  app_protocol: string | null
  /** Length on the wire. */
  length: number
  info: string
}

export interface PacketPage {
  /** Rows matching the query across the whole ring. */
  total: number
  /** The oldest frame number still in the ring. */
  first_no: number
  offset: number
  rows: PacketRow[]
}

export interface DetailSection {
  title: string
  rows: [string, string][]
}

export interface PacketDetail {
  no: number
  timestamp: number
  length: number
  captured: number
  protocol: string
  info: string
  sections: DetailSection[]
}

export type CaptureState = 'running' | 'stopped' | 'failed'

export interface CaptureStatus {
  seq: number
  state: CaptureState
  interface: string
  linktype: string
  promiscuous: boolean
  started_at: number
  counts: ImportResult
  bytes: number
  pps: number
  kernel_received: number
  kernel_dropped: number
  if_dropped: number
  app_dropped: number
  ring_total: number
  ring_first_no: number
  protocol_counts: [string, number][]
  last_analysis_ms: number
  error: string | null
}

export interface InterfaceInfo {
  name: string
  description: string | null
  addresses: string[]
  is_up: boolean
  is_loopback: boolean
}

export interface CaptureOptions {
  interface: string
  filter: string | null
  promiscuous: boolean
}

/** A capture command's rejection: advice is picked by `code`, the message quoted. */
export interface CaptureFailure {
  code: string
  message: string
}

export function isCaptureFailure(e: unknown): e is CaptureFailure {
  return (
    typeof e === 'object' &&
    e !== null &&
    typeof (e as CaptureFailure).code === 'string' &&
    typeof (e as CaptureFailure).message === 'string'
  )
}
