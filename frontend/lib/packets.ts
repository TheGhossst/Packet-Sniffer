import { z } from "zod";

// Define the packet schema for type safety
export const packetSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  src_ip: z.string(),
  dst_ip: z.string(),
  src_port: z.number(),
  dst_port: z.number(),
  protocol: z.string(),
  packet_size: z.number(),
  threat_level: z.enum(["trusted", "low", "medium", "high"]),
  status: z.enum(["Safe", "Unsafe"]),
  timestamp_start: z.number().optional(),
  timestamp_end: z.number().optional(),
  payload: z.string().optional(),
  threat_details: z.array(z.object({
    type: z.string(),
    description: z.string(),
    severity: z.enum(["low", "medium", "high"]),
    confidence: z.number().optional()
  })).optional(),
  dpi_results: z.object({
    protocol: z.string().optional(),
    isSuspicious: z.boolean().optional(),
    findings: z.array(z.object({
      type: z.string(),
      description: z.string(),
      severity: z.enum(["low", "medium", "high"]),
      evidence: z.string().optional()
    })).optional(),
    confidence: z.number().optional()
  }).optional(),
  behavioral_results: z.object({
    anomalies: z.array(z.object({
      type: z.string(),
      description: z.string(),
      severity: z.enum(["low", "medium", "high"]),
      confidence: z.number().optional()
    })).optional()
  }).optional()
});

export type Packet = z.infer<typeof packetSchema>;

const API_URL = process.env.NEXT_PUBLIC_ANALYSIS_SERVICE_URL || 'http://localhost:3001';

/**
 * Fetch a list of packets from the analysis service
 */
export async function getPackets(limit = 50): Promise<Packet[]> {
  try {
    const response = await fetch(`${API_URL}/api/packets?limit=${limit}`, {
      cache: 'no-store'
    });
    
    if (!response.ok) {
      throw new Error(`Failed to fetch packets: ${response.status}`);
    }
    
    const data = await response.json();
    
    const normalizedData = data.map((packet: Record<string, unknown>) => {
      if (typeof packet.timestamp === 'number') {
        packet.timestamp = new Date(packet.timestamp * 1000).toISOString();
      } else if (packet.timestamp && typeof packet.timestamp === 'string' && !isNaN(parseInt(packet.timestamp))) {
        packet.timestamp = new Date(parseInt(packet.timestamp) * 1000).toISOString();
      }
      
      return packet;
    });
    
    return packetSchema.array().parse(normalizedData);
  } catch (error) {
    console.error('Error fetching packets from analysis service:', error);
    
    // Fall back to frontend API if analysis service is unavailable
    try {
      const fallbackResponse = await fetch(`/api/packets?limit=${limit}`, {
        cache: 'no-store'
      });
      
      if (!fallbackResponse.ok) {
        throw new Error(`Failed to fetch packets from fallback: ${fallbackResponse.status}`);
      }
      
      const fallbackData = await fallbackResponse.json();
      console.log('Using fallback mock data from frontend API');
      return packetSchema.array().parse(fallbackData);
    } catch (fallbackError) {
      console.error('Error fetching packets from fallback:', fallbackError);
      // Last resort: generate mock data directly
      return Array.from({ length: limit }).map((_, i) => generateMockPacket(i));
    }
  }
}

/**
 * Fetch a single packet by ID
 */
export async function getPacketById(id: string): Promise<Packet | null> {
  try {
    // Add timestamp parameter to cache-bust the URL and ensure fresh data
    const timestamp = Date.now();
    // First try to get data from the analysis service
    const response = await fetch(`${API_URL}/api/packets/${id}?_t=${timestamp}`, {
      cache: 'no-store',
      next: { revalidate: 0 } // Disable caching in Next.js
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        console.warn(`Packet with ID ${id} not found in analysis service, trying fallback`);
        // Fall back to frontend API
        return getPacketByIdFallback(id);
      }
      throw new Error(`Failed to fetch packet: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Normalize packet data to ensure proper timestamp format
    if (typeof data.timestamp === 'number') {
      data.timestamp = new Date(data.timestamp * 1000).toISOString();
    } else if (data.timestamp && typeof data.timestamp === 'string' && !isNaN(parseInt(data.timestamp))) {
      data.timestamp = new Date(parseInt(data.timestamp) * 1000).toISOString();
    }
    
    // Ensure payload is properly set if it's missing
    if (!data.payload) {
      console.warn(`Packet payload missing from analysis service for ID ${id}, using placeholder`);
      data.payload = Buffer.from(`Packet ID: ${id} - Payload data not available from analysis service.`).toString('base64');
    }
    
    return packetSchema.parse(data);
  } catch (error) {
    console.error('Error fetching packet from analysis service:', error);
    // Fall back to frontend API
    return getPacketByIdFallback(id);
  }
}

/**
 * Fallback function to get a packet by ID from the frontend API or generate mock data
 */
async function getPacketByIdFallback(id: string): Promise<Packet | null> {
  try {
    // Add timestamp parameter to cache-bust the URL
    const timestamp = Date.now();
    const fallbackResponse = await fetch(`/api/packets/${id}?_t=${timestamp}`, {
      cache: 'no-store',
      next: { revalidate: 0 } // Disable caching in Next.js
    });
    
    if (!fallbackResponse.ok) {
      if (fallbackResponse.status === 404) {
        console.warn(`Packet with ID ${id} not found in fallback API, generating mock data`);
        // Generate a deterministic mock packet
        return generateDeterministicMockPacket(id);
      }
      throw new Error(`Failed to fetch packet from fallback: ${fallbackResponse.status}`);
    }
    
    const fallbackData = await fallbackResponse.json();
    console.log('Using fallback mock data from frontend API');
    return packetSchema.parse(fallbackData);
  } catch (fallbackError) {
    console.error('Error fetching packet from fallback:', fallbackError);
    // Last resort: generate mock data
    return generateDeterministicMockPacket(id);
  }
}

/**
 * Generate a deterministic mock packet based on ID
 */
function generateDeterministicMockPacket(id: string): Packet {
  // Create a seed from the ID for deterministic random generation
  const seed = Array.from(id).reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const seededRandom = () => {
    const x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
  };
  
  const status = seededRandom() > 0.7 ? "Unsafe" : "Safe";
  const threatLevel = status === "Unsafe" 
    ? (seededRandom() > 0.5 ? "high" : "medium") 
    : (seededRandom() > 0.5 ? "low" : "trusted");
  
  const now = Date.now();
  const timestamp = new Date(now - seededRandom() * 86400000).toISOString();
  const timestamp_start = Math.floor(now / 1000) - Math.floor(seededRandom() * 15);
  const timestamp_end = timestamp_start + Math.floor(seededRandom() * 5) + 1;
  
  // Generate a mock payload (base64 encoded)
  const dummyText = `Packet ID: ${id} with threat level: ${threatLevel}. This is a ${status} packet.`;
  const payload = Buffer.from(dummyText).toString('base64');
  
  return {
    id,
    timestamp,
    timestamp_start,
    timestamp_end,
    src_ip: `192.168.${Math.floor(seededRandom() * 255)}.${Math.floor(seededRandom() * 255)}`,
    dst_ip: `10.0.${Math.floor(seededRandom() * 255)}.${Math.floor(seededRandom() * 255)}`,
    src_port: Math.floor(seededRandom() * 65535),
    dst_port: [80, 443, 22, 53, 3389][Math.floor(seededRandom() * 5)],
    protocol: ["TCP", "UDP", "ICMP"][Math.floor(seededRandom() * 3)],
    packet_size: Math.floor(seededRandom() * 1500),
    threat_level: threatLevel,
    status: status,
    payload,
    threat_details: status === "Unsafe" ? [
      {
        type: ["SQL_INJECTION", "XSS", "SUSPICIOUS_DOMAIN", "PORT_SCAN"][Math.floor(seededRandom() * 4)],
        description: "Potential security threat detected",
        severity: threatLevel === "high" ? "high" : "medium",
        confidence: 0.7 + seededRandom() * 0.3
      }
    ] : [],
    dpi_results: status === "Unsafe" ? {
      protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(seededRandom() * 4)],
      isSuspicious: true,
      findings: [
        {
          type: ["SUSPICIOUS_USER_AGENT", "MALICIOUS_PAYLOAD", "WEAK_CIPHER_SUITE"][Math.floor(seededRandom() * 3)],
          description: "Suspicious patterns detected in packet payload",
          severity: threatLevel === "high" ? "high" : "medium",
          evidence: "Pattern match in payload data"
        }
      ],
      confidence: 0.7 + seededRandom() * 0.3
    } : {
      protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(seededRandom() * 4)],
      isSuspicious: false,
      findings: [],
      confidence: 0
    },
    behavioral_results: {
      anomalies: status === "Unsafe" ? [
        {
          type: ["PORT_SCAN", "HIGH_TRAFFIC_VOLUME", "EXCESSIVE_CONNECTIONS"][Math.floor(seededRandom() * 3)],
          description: "Unusual network behavior detected",
          severity: threatLevel === "high" ? "high" : "medium",
          confidence: 0.7 + seededRandom() * 0.3
        }
      ] : []
    }
  };
}

/**
 * Generate a mock packet for testing
 */
function generateMockPacket(id: number): Packet {
  const status = Math.random() > 0.7 ? "Unsafe" : "Safe";
  const threatLevel = status === "Unsafe" 
    ? (Math.random() > 0.5 ? "high" : "medium") 
    : (Math.random() > 0.5 ? "low" : "trusted");
  
  const now = Date.now();
  const timestamp = new Date(now - Math.random() * 86400000).toISOString();
  const timestamp_start = Math.floor(now / 1000) - Math.floor(Math.random() * 15);
  const timestamp_end = timestamp_start + Math.floor(Math.random() * 5) + 1;
  
  // Generate a mock payload (base64 encoded)
  const dummyText = `Packet ID: ${id} with threat level: ${threatLevel}. This is a ${status} packet.`;
  const payload = Buffer.from(dummyText).toString('base64');
  
  return {
    id: id.toString(),
    timestamp,
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
    payload,
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
} 