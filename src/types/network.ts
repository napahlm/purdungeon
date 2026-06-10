export type Role =
  | 'plc'
  | 'scada'
  | 'hmi'
  | 'engineering-workstation'
  | 'historian'
  | 'field-device'
  | 'network-gear'
  | 'server'
  | 'workstation'
  | 'external'
  | 'broadcast'
  | 'unknown'
  | 'subnet'

export interface Host {
  id: number
  mac_address: string
  ip_address: string
  hostname: string | null
  vendor: string | null
  role: Role
  role_confidence: number
  role_evidence: string | null
  purdue_level: number | null
  role_override: Role | null
  level_override: number | null
  protocols: string
  is_external: boolean
  first_seen: number
  last_seen: number
}

export const ROLE_LABELS: Record<Role, string> = {
  plc: 'PLC',
  scada: 'SCADA / Master',
  hmi: 'HMI',
  'engineering-workstation': 'Engineering Workstation',
  historian: 'Historian',
  'field-device': 'Field Device',
  'network-gear': 'Network Gear',
  server: 'Server',
  workstation: 'Workstation',
  external: 'External',
  broadcast: 'Broadcast',
  unknown: 'Unknown',
  subnet: 'Subnet',
}

/** Roles a user can assign manually. */
export const ASSIGNABLE_ROLES: Role[] = [
  'plc',
  'scada',
  'hmi',
  'engineering-workstation',
  'historian',
  'field-device',
  'network-gear',
  'server',
  'workstation',
  'external',
  'unknown',
]

/** Role after any user override. */
export function effectiveRole(host: Host): Role {
  return host.role_override ?? host.role
}

/** Purdue level after any user override; null means unplaced. */
export function effectiveLevel(host: Host): number | null {
  return host.level_override ?? host.purdue_level
}

export interface Connection {
  id: number
  src_host_id: number
  dst_host_id: number
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string | null
  packet_count: number
  byte_count: number
  first_seen: number
  last_seen: number
}

export interface HostConnection {
  connection_id: number
  peer_ip: string
  peer_mac: string
  direction: string
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string | null
  packet_count: number
  byte_count: number
  first_seen: number
  last_seen: number
}

export interface HostDetail {
  host: Host
  connections: HostConnection[]
  total_packets: number
  total_bytes: number
}

export interface Packet {
  id: number
  timestamp: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  length: number
}

export interface ModbusFunctionStat {
  function_code: number
  function_name: string
  count: number
  is_write: boolean
}

export interface RegisterAccess {
  kind: string
  start: number
  quantity: number
  reads: number
  writes: number
}

export interface ModbusHostActivity {
  as_client: ModbusFunctionStat[]
  as_server: ModbusFunctionStat[]
  unit_ids_served: number[]
  registers: RegisterAccess[]
  registers_remote: RegisterAccess[]
  exceptions_returned: number
}

export interface ModbusConversation {
  functions: ModbusFunctionStat[]
  unit_ids: number[]
  requests: number
  reads: number
  writes: number
  exceptions: number
  poll_interval_ms: number | null
}

export interface ImportResult {
  host_count: number
  connection_count: number
  packet_count: number
  time_range: [number, number]
}

export interface TimeRange {
  start: number
  end: number
}
