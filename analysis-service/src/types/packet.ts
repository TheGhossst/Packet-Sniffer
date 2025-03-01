export interface PacketData {
    source: string;
    destination: string;
    protocol: string;
    size: number;
    type: string;
    timestamp: string;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    packet_size: number;
    packet_type: string;
    payload_size: number;
}

export interface PacketAnalysisResult {
    packet: PacketData;
    score: number;
    causes: Array<{
        reason: string;
        score: number;
    }>;
    timestamp: string;
} 