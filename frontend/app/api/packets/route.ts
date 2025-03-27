import { NextRequest, NextResponse } from 'next/server';

// Mock packets for testing
const mockPackets = Array.from({ length: 50 }).map((_, i) => {
  const status = Math.random() > 0.7 ? "Unsafe" : "Safe";
  const threatLevel = status === "Unsafe" 
    ? (Math.random() > 0.5 ? "high" : "medium") 
    : (Math.random() > 0.5 ? "low" : "trusted");
  
  // Generate timestamps with a small difference between start and end
  const now = Math.floor(Date.now() / 1000);
  const timestamp_start = now - Math.floor(Math.random() * 15); // 0-15 seconds ago
  const timestamp_end = timestamp_start + Math.floor(Math.random() * 5) + 1; // 1-5 seconds duration
  
  return {
    id: i.toString(),
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
    timestamp_start,
    timestamp_end,
    src_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    dst_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    src_port: Math.floor(Math.random() * 65535),
    dst_port: [80, 443, 22, 53, 3389][Math.floor(Math.random() * 5)],
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)],
    packet_size: Math.floor(Math.random() * 1500),
    threat_level: threatLevel,
    status: status,
    threat_details: status === "Unsafe" ? [
      {
        type: ["SQL_INJECTION", "XSS", "SUSPICIOUS_DOMAIN", "PORT_SCAN"][Math.floor(Math.random() * 4)],
        description: "Potential security threat detected",
        severity: threatLevel === "high" ? "high" : "medium",
        confidence: 0.7 + Math.random() * 0.3
      }
    ] : [],
    dpi_results: status === "Unsafe" ? {
      protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(Math.random() * 4)],
      isSuspicious: true,
      findings: [
        {
          type: ["SUSPICIOUS_USER_AGENT", "MALICIOUS_PAYLOAD", "WEAK_CIPHER_SUITE"][Math.floor(Math.random() * 3)],
          description: "Suspicious patterns detected in packet payload",
          severity: threatLevel === "high" ? "high" : "medium",
          evidence: "Pattern match in payload data"
        }
      ],
      confidence: 0.7 + Math.random() * 0.3
    } : {
      protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(Math.random() * 4)],
      isSuspicious: false,
      findings: [],
      confidence: 0
    },
    behavioral_results: {
      anomalies: status === "Unsafe" ? [
        {
          type: ["PORT_SCAN", "HIGH_TRAFFIC_VOLUME", "EXCESSIVE_CONNECTIONS"][Math.floor(Math.random() * 3)],
          description: "Unusual network behavior detected",
          severity: threatLevel === "high" ? "high" : "medium",
          confidence: 0.7 + Math.random() * 0.3
        }
      ] : []
    }
  };
});

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const limit = parseInt(searchParams.get('limit') || '50', 10);
  
  // Return a subset of mock packets
  const packets = mockPackets.slice(0, Math.min(limit, mockPackets.length));
  
  return NextResponse.json(packets);
} 