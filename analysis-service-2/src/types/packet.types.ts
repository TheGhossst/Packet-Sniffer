export interface PacketData {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  packet_size: number;
  packet_type: string;
  timestamp: string;
}

export interface BatchData {
  batchId: string;
  timestamp: string;
  packets: PacketData[];
}

export interface MaliciousCheckResult {
  isMalicious: boolean;
  reasons?: string[];
  threatLevel?: string;
  timestamp?: string;
  score?: number;
  details?: Record<string, any>;
}
