// Network types (Hub-and-Spoke VPN)
export interface Network {
  id: string;
  name: string;
  cidr: string;
  server_public_key?: string;  // Hub's public key
  server_endpoint?: string;    // Hub's endpoint (IP:Port)
  listen_port?: number;        // UDP Port
  interface_name?: string;     // WireGuard Interface (wg0, etc)
  created_at: string;
  updated_at: string;
  node_count?: number;
  online_nodes?: number;
}

// Node types (Peers/Spokes)
export type NodeStatus = 'pending' | 'online' | 'offline' | 'expired';

export interface NodeInfo {
  os: string;
  arch: string;
  hostname: string;
}

export interface Node {
  id: string;
  network_id: string;
  name: string;
  virtual_ip: string;
  public_key: string;
  labels: Record<string, string>;
  status: NodeStatus;
  last_seen: string;
  public_ip?: string;
  transfer_rx?: number;
  transfer_tx?: number;
  expires_at?: string;
  node_info?: NodeInfo;
  endpoints?: string[];
  created_at: string;
}

// API response types
export interface ApiError {
  error: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}

// Dashboard specific types
export interface NetworkStats {
  total_nodes: number;
  online_nodes: number;
}

export interface NetworkTopology {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export interface TopologyNode {
  id: string;
  type: 'node';
  position: { x: number; y: number };
  data: {
    label: string;
    status: NodeStatus;
    ip: string;
  };
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  data?: {
    latency?: number;
    connected: boolean;
  };
}

// WebSocket event types
export type EventType = 
  | 'node_status'
  | 'peer_added'
  | 'peer_removed';

export interface WebSocketEvent {
  type: EventType;
  payload: any;
  timestamp: string;
}

export interface NodeStatusEvent {
  type: 'node_status';
  node_id: string;
  status: NodeStatus;
  timestamp: string;
}

// Form types
export interface CreateNetworkForm {
  name: string;
  cidr: string;
}

export interface CreateNodeForm {
  name: string;
  labels?: Record<string, string>;
}


// System Info types
export interface SystemInfo {
  cpu_cores: number;
  cpu_model?: string;
  load_1m?: string;
  load_5m?: string;
  load_15m?: string;
  memory_total: number;
  memory_free: number;
  memory_available: number;
  memory_used: number;
  memory_buffers?: number;
  memory_cached?: number;
  disk_total: number;
  disk_used: number;
  disk_free: number;
  uptime_seconds: number;
  hostname: string;
}

// Fail2Ban types
export interface Fail2BanJail {
  name: string;
  banned_count?: number;
  total_banned?: number;
  banned_ips?: string[];
  failed_count?: number;
  total_failed?: number;
}

export interface Fail2BanStatus {
  installed: boolean;
  running: boolean;
  jails: Fail2BanJail[];
}

export interface Fail2BanLogEntry {
  raw: string;
  timestamp?: string;
  action?: 'ban' | 'unban' | 'found';
}

export interface Fail2BanLogs {
  logs: Fail2BanLogEntry[];
  count: number;
  error?: string;
}

// Stats Overview types
export interface NetworkStats {
  id: string;
  name: string;
  cidr: string;
  interface: string;
  total_nodes: number;
  online_nodes: number;
  offline_nodes: number;
  pending_nodes: number;
  expired_nodes: number;
  transfer_rx: number;
  transfer_tx: number;
}

export interface StatsOverview {
  total_networks: number;
  total_nodes: number;
  online_nodes: number;
  offline_nodes: number;
  pending_nodes: number;
  expired_nodes: number;
  total_rx: number;
  total_tx: number;
  networks: NetworkStats[];
}

// Firewall types
export interface FirewallRule {
  number: number;
  chain: string;
  target: string;
  protocol: string;
  source: string;
  destination: string;
  port: string;
  interface: string;
  in_interface?: string;
  out_interface?: string;
  options?: string;
  protected: boolean;
}

export interface ChainInfo {
  name: string;
  policy: string;
  rules: FirewallRule[];
}

export interface FirewallStatus {
  chains: ChainInfo[];
  total_rules: number;
  blocked_ips: number;
  open_ports: number;
}

export interface OpenPortRequest {
  port: number;
  protocol: string;
  source?: string;
}

export interface ClosePortRequest {
  port: number;
  protocol: string;
  force?: boolean;
}

export interface BlockIPRequest {
  ip: string;
  ports?: string;
}

export interface AllowIPRequest {
  ip: string;
  ports?: string;
}

export interface DeleteRuleRequest {
  chain: string;
  line_number: number;
  force?: boolean;
}

export interface ImportRulesRequest {
  rules: string;
}

// VPN Firewall types
export type VPNEndpointType = 'any' | 'network' | 'node' | 'custom';
export type VPNFirewallAction = 'accept' | 'drop' | 'reject';
export type VPNFirewallProtocol = 'tcp' | 'udp' | 'icmp' | 'all';

export interface VPNFirewallRule {
  id: string;
  name: string;
  description?: string;
  source_type: VPNEndpointType;
  source_network_id?: string;
  source_node_id?: string;
  source_ip?: string;
  source_network_name?: string;
  source_node_name?: string;
  dest_type: VPNEndpointType;
  dest_network_id?: string;
  dest_node_id?: string;
  dest_ip?: string;
  dest_network_name?: string;
  dest_node_name?: string;
  protocol: VPNFirewallProtocol;
  port?: string;
  action: VPNFirewallAction;
  priority: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface VPNFirewallRuleRequest {
  name: string;
  description?: string;
  source_type: VPNEndpointType;
  source_network_id?: string;
  source_node_id?: string;
  source_ip?: string;
  dest_type: VPNEndpointType;
  dest_network_id?: string;
  dest_node_id?: string;
  dest_ip?: string;
  protocol: VPNFirewallProtocol;
  port?: string;
  action: VPNFirewallAction;
  priority: number;
  enabled: boolean;
}
