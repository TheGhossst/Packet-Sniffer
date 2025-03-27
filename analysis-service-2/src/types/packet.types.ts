export interface PacketData {
  id?: string;                // Unique identifier for the packet
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  packet_size: number;
  packet_type?: string;       // Made optional since not all packets have this
  timestamp: string;
  payload?: string;
  headers?: Record<string, string>;
  timestamp_start?: number;   // Start timestamp in milliseconds
  timestamp_end?: number;     // End timestamp in milliseconds
  status?: "Safe" | "Unsafe"; // Packet status for frontend display
  threat_level?: "trusted" | "low" | "medium" | "high"; // Threat level for frontend display
  threat_details?: Array<{    // Details about threats detected
    type: string;
    description: string;
    severity: 'low' | 'medium' | 'high';
    confidence?: number;
  }>;
  dpi_results?: {             // DPI analysis results
    protocol?: string;
    isSuspicious?: boolean;
    findings?: Array<{
      type: string;
      description: string;
      severity: 'low' | 'medium' | 'high';
      evidence?: string;
    }>;
    confidence?: number;
  };
  behavioral_results?: {      // Behavioral analysis results
    anomalies?: Array<{
      type: string;
      description: string;
      severity: 'low' | 'medium' | 'high';
      confidence?: number;
    }>;
  };
}

export interface ProtocolAnalysisResult {
  protocol: string;
  isSuspicious: boolean;
  findings: ProtocolFinding[];
  confidence: number;
}

export interface ProtocolFinding {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  evidence: string;
}

export interface BatchData {
  batchId: string;
  timestamp: string;
  packets: PacketData[];
}

export interface MaliciousReason {
  source: string;
  category: string;
  description: string;
}

export interface BehavioralAnalysisResult {
  anomalies: BehavioralAnomaly[];
  connectionInfo: ConnectionStats | null;
  sourceInfo: IPBehaviorStats | null;
  destinationInfo: IPBehaviorStats | null;
}

export interface BehavioralAnomaly {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface ConnectionStats {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  packetCount: number;
  firstSeen: number;
  lastSeen: number;
  bytesSent: number;
  recentActivity: Array<{timestamp: number, size: number}>;
}

export interface IPBehaviorStats {
  ip: string;
  packetCount: number;
  firstSeen: number;
  lastSeen: number;
  bytesSent: number;
  bytesReceived: number;
  uniqueConnections: Set<string>;
  uniquePorts: Set<number>;
  protocols: Set<string>;
  recentActivity: Array<{timestamp: number, size: number}>;
  portScanScore: number;
  isSuspicious: boolean;
}

export interface MaliciousCheckResult {
  isMalicious: boolean;
  reasons?: MaliciousReason[] | string[];
  threatLevel?: string;
  timestamp?: string;
  score?: number;
  details?: {
    source?: string;
    sourceCount?: number;
    enrichment?: any;
    results?: any;
    behavioralAnomalies?: BehavioralAnomaly[];
  };
  protocolAnalysis?: ProtocolAnalysisResult;
}