import { NextRequest, NextResponse } from 'next/server';

export async function GET(
  request: NextRequest,
  context: { params: { id: string } }
) {
  const { id } = context.params;
  
  // Create a seed from the ID for deterministic random generation
  const seed = Array.from(id).reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const random = () => {
    const x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
  };

  const status = random() > 0.7 ? "Unsafe" : "Safe";
  const threatLevel = status === "Unsafe" 
    ? (random() > 0.5 ? "high" : "medium") 
    : (random() > 0.5 ? "low" : "trusted");
  
  // Generate timestamps with a small difference between start and end
  const now = Math.floor(Date.now() / 1000);
  const timestamp_start = now - Math.floor(random() * 15); // 0-15 seconds ago
  const timestamp_end = timestamp_start + Math.floor(random() * 5) + 1; // 1-5 seconds duration
  
  const packet = {
    id,
    timestamp: new Date(Date.now() - random() * 86400000).toISOString(),
    timestamp_start,
    timestamp_end,
    src_ip: `192.168.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
    dst_ip: `10.0.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
    src_port: Math.floor(random() * 65535),
    dst_port: [80, 443, 22, 53, 3389][Math.floor(random() * 5)],
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(random() * 3)],
    packet_size: Math.floor(random() * 1500),
    threat_level: threatLevel,
    status: status,
    threat_details: status === "Unsafe" ? [
      {
        type: ["SQL_INJECTION", "XSS", "SUSPICIOUS_DOMAIN", "PORT_SCAN"][Math.floor(random() * 4)],
        description: "Potential security threat detected",
        severity: threatLevel === "high" ? "high" : "medium",
        confidence: 0.7 + random() * 0.3
      },
      ...(random() > 0.6 ? [{
        type: ["MALICIOUS_PAYLOAD", "SUSPICIOUS_PATTERN", "DATA_EXFILTRATION"][Math.floor(random() * 3)],
        description: "Secondary threat pattern identified",
        severity: "medium",
        confidence: 0.6 + random() * 0.2
      }] : [])
    ] : [],
    dpi_results: {
      protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(random() * 4)],
      isSuspicious: status === "Unsafe",
      findings: status === "Unsafe" ? [
        {
          type: ["SUSPICIOUS_USER_AGENT", "MALICIOUS_PAYLOAD", "WEAK_CIPHER_SUITE"][Math.floor(random() * 3)],
          description: "Suspicious patterns detected in packet payload",
          severity: threatLevel === "high" ? "high" : "medium",
          evidence: "Pattern match in payload data: " + Array(Math.floor(random() * 30) + 10).fill(0).map(() => String.fromCharCode(97 + Math.floor(random() * 26))).join('')
        },
        ...(random() > 0.5 ? [{
          type: ["SUSPICIOUS_HEADER", "OBFUSCATED_CONTENT", "ANOMALOUS_PATTERN"][Math.floor(random() * 3)],
          description: "Additional suspicious pattern detected",
          severity: "medium",
          evidence: "Secondary pattern: " + Array(Math.floor(random() * 20) + 5).fill(0).map(() => String.fromCharCode(97 + Math.floor(random() * 26))).join('')
        }] : [])
      ] : [],
      confidence: status === "Unsafe" ? 0.7 + random() * 0.3 : 0
    },
    behavioral_results: {
      anomalies: status === "Unsafe" ? [
        {
          type: ["PORT_SCAN", "HIGH_TRAFFIC_VOLUME", "EXCESSIVE_CONNECTIONS"][Math.floor(random() * 3)],
          description: "Unusual network behavior detected",
          severity: threatLevel === "high" ? "high" : "medium",
          confidence: 0.7 + random() * 0.3
        },
        ...(random() > 0.7 ? [{
          type: "UNCOMMON_PORT",
          description: `Connection to uncommon port ${Math.floor(random() * 10000) + 10000}`,
          severity: "low",
          confidence: 0.5 + random() * 0.3
        }] : [])
      ] : []
    }
  };
  
  return NextResponse.json(packet);
} 