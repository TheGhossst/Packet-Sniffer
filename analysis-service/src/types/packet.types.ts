export interface PacketData {
    timestamp: string;
    src_ip: string;
    dst_ip: string;
    protocol: string;
    src_port: number;
    dst_port: number;
    packet_size: number;
    packet_type: string;
    payload_size: number;
}

export interface BatchData {
    batchId: string;
    packets: PacketData[];
    timestamp: string;
} 