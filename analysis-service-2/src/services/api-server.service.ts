import * as http from 'http';
import { behavioralAnalysisService } from './behavioral-analysis.service.js';
import { dpiService } from './dpi.service.js';
import { maliciousCheckService } from './malicious-check.service.js';
import { PacketData } from '../types/packet.types.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * APIServerService provides an HTTP server to expose API endpoints
 * for accessing packet data and analysis results
 */
class APIServerService {
  private server: http.Server | null = null;
  private port: number = 3001;
  
  // Live packets with frequent updates
  private livePackets: PacketData[] = [];
  private packetIdCounter = 0;
  private refreshInterval: NodeJS.Timeout | null = null;
  
  // Available protocols
  private protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"];
  
  constructor() {
    // Generate initial packet data
    this.generateInitialPackets();
    
    // Start the refresh timer to continuously generate new packets
    this.startRefreshTimer();
  }
  
  /**
   * Generate initial packet data
   */
  private generateInitialPackets(): void {
    // Clear existing packets
    this.livePackets = [];
    
    // Create 20 initial packets (more will be added by the refresh timer)
    for (let i = 0; i < 20; i++) {
      this.addNewPacket();
    }
  }
  
  /**
   * Generate a random IP address
   */
  private generateRandomIp(): string {
    // 50% chance to generate a private IP
    if (Math.random() < 0.5) {
      // Generate a private IP (192.168.x.x or 10.0.x.x)
      if (Math.random() < 0.5) {
        return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      } else {
        return `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      }
    } else {
      // Generate a public IP
      return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }
  }
  
  /**
   * Check if an IP address is private
   */
  private isPrivateIp(ip: string): boolean {
    return ip.startsWith('192.168.') || 
           ip.startsWith('10.') || 
           (ip.startsWith('172.') && 
            parseInt(ip.split('.')[1]) >= 16 && 
            parseInt(ip.split('.')[1]) <= 31);
  }
  
  /**
   * Add a new packet to the list with the current timestamp
   */
  private addNewPacket(): void {
    const now = Math.floor(Date.now() / 1000);
    const src_ip = this.generateRandomIp();
    const dst_ip = this.generateRandomIp();
    const isPrivateSource = this.isPrivateIp(src_ip);
    const isPrivateDestination = this.isPrivateIp(dst_ip);
    
    // Generate timestamps with a small difference between start and end
    const timestamp_start = now - Math.floor(Math.random() * 15); // 0-15 seconds ago
    const timestamp_end = timestamp_start + Math.floor(Math.random() * 5) + 1; // 1-5 seconds duration
    
    // For private IPs, only flag as malicious if DPI detects something suspicious
    const hasSuspiciousPayload = Math.random() < 0.1; // 10% chance
    const hasSuspiciousBehavior = Math.random() < 0.05; // 5% chance
    
    // Only flag private IPs as unsafe if something suspicious is detected
    let shouldFlagMalicious = false;
    
    if ((isPrivateSource || isPrivateDestination) && (hasSuspiciousPayload || hasSuspiciousBehavior)) {
      shouldFlagMalicious = true;
    } else if (!isPrivateSource && !isPrivateDestination && Math.random() < 0.2) {
      // For public IP to public IP traffic, keep the 20% chance of being unsafe
      shouldFlagMalicious = true;
    }
    
    // Generate threat level as a string value
    const threatLevelMap: Array<"trusted" | "low" | "medium" | "high"> = ["trusted", "low", "medium", "high"];
    const threatLevel = shouldFlagMalicious 
      ? threatLevelMap[Math.floor(Math.random() * 3) + 1]  // low, medium, or high
      : threatLevelMap[0];  // trusted
    
    // Generate packet
    const packet: PacketData = {
      id: uuidv4(),
      timestamp: now.toString(),
      timestamp_start,
      timestamp_end,
      src_ip,
      dst_ip,
      src_port: Math.floor(Math.random() * 65535) + 1,
      dst_port: Math.floor(Math.random() * 65535) + 1,
      protocol: this.protocols[Math.floor(Math.random() * this.protocols.length)],
      packet_size: Math.floor(Math.random() * 1500) + 64,
      threat_level: threatLevel,
      status: shouldFlagMalicious ? "Unsafe" : "Safe",
      payload: Buffer.from("Test payload").toString('base64'),
      dpi_results: hasSuspiciousPayload ? {
        protocol: ["HTTP", "DNS", "TLS", "SMTP"][Math.floor(Math.random() * 4)],
        isSuspicious: true,
        findings: [
          {
            type: ["SUSPICIOUS_USER_AGENT", "MALICIOUS_PAYLOAD", "WEAK_CIPHER_SUITE"][Math.floor(Math.random() * 3)],
            description: `Suspicious patterns detected in ${this.protocols[Math.floor(Math.random() * this.protocols.length)]} packet payload`,
            severity: Math.random() > 0.5 ? "high" : "medium",
            evidence: `Pattern match in payload data: Port ${Math.floor(Math.random() * 65535) + 1} connection with unusual data patterns`
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
        anomalies: hasSuspiciousBehavior ? [
          {
            type: ["PORT_SCAN", "HIGH_TRAFFIC_VOLUME", "EXCESSIVE_CONNECTIONS"][Math.floor(Math.random() * 3)],
            description: `Unusual network behavior detected from ${src_ip}`,
            severity: Math.random() > 0.5 ? "high" : "medium",
            confidence: 0.7 + Math.random() * 0.3
          }
        ] : []
      }
    };
    
    // Add to the beginning of the array (newest first)
    this.livePackets.unshift(packet);
    
    // Keep only the most recent 100 packets
    if (this.livePackets.length > 100) {
      this.livePackets = this.livePackets.slice(0, 100);
    }
  }
  
  /**
   * Start a timer to periodically refresh the packet data
   */
  private startRefreshTimer(): void {
    // Clear any existing timer
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
    
    // Add new packets at random intervals between 1-3 seconds
    this.refreshInterval = setInterval(() => {
      // Add 1-3 new packets per refresh
      const numPacketsToAdd = Math.floor(Math.random() * 3) + 1;
      
      for (let i = 0; i < numPacketsToAdd; i++) {
        this.addNewPacket();
      }
      
      console.log(`[${new Date().toISOString()}] Added ${numPacketsToAdd} new packets. Total: ${this.livePackets.length}`);
    }, 2000); // Refresh every 2 seconds
  }

  /**
   * Start the API HTTP server
   */
  public async start(): Promise<void> {
    if (this.server) {
      console.info('API server already running');
      return;
    }

    try {
      this.server = http.createServer(async (req, res) => {
        // Set CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        
        // Handle OPTIONS (preflight) requests
        if (req.method === 'OPTIONS') {
          res.statusCode = 204;
          res.end();
          return;
        }
        
        // Only handle GET requests
        if (req.method !== 'GET') {
          res.statusCode = 405;
          res.end('Method Not Allowed');
          return;
        }
        
        // API endpoint: /api/packets - List packets
        if (req.url?.startsWith('/api/packets') && !req.url.includes('/api/packets/')) {
          try {
            // Parse limit parameter
            const url = new URL(req.url, `http://${req.headers.host}`);
            const limit = parseInt(url.searchParams.get('limit') || '50', 10);
            
            // Return live packets
            const packets = this.livePackets.slice(0, Math.min(limit, this.livePackets.length));
            
            res.setHeader('Content-Type', 'application/json');
            res.statusCode = 200;
            res.end(JSON.stringify(packets));
          } catch (error) {
            console.error('Error handling packets request:', error);
            res.statusCode = 500;
            res.end(JSON.stringify({ error: 'Internal Server Error' }));
          }
        } 
        // API endpoint: /api/packets/:id - Get packet by ID (UUID support)
        else if (req.url?.startsWith('/api/packets/')) {
          try {
            // Extract packet ID from URL
            const id = req.url.split('/').pop();
            
            // Find packet by ID
            const packet = this.livePackets.find(p => p.id === id);
            
            if (packet) {
              res.setHeader('Content-Type', 'application/json');
              res.statusCode = 200;
              res.end(JSON.stringify(packet));
            } else {
              console.log(`Packet with ID "${id}" not found. Available IDs: ${this.livePackets.map(p => p.id).join(', ')}`);
              res.statusCode = 404;
              res.end(JSON.stringify({ error: 'Packet not found' }));
            }
          } catch (error) {
            console.error('Error handling packet request:', error);
            res.statusCode = 500;
            res.end(JSON.stringify({ error: 'Internal Server Error' }));
          }
        } 
        // Default response for unknown endpoints
        else {
          res.statusCode = 404;
          res.end(JSON.stringify({ error: 'Not Found' }));
        }
      });

      this.server.listen(this.port, () => {
        console.info(`API server started on http://localhost:${this.port}`);
      });

      this.server.on('error', (error) => {
        console.error('API server error:', error);
      });
    } catch (error) {
      console.error('Failed to start API server:', error);
    }
  }

  /**
   * Stop the API HTTP server and timer
   */
  public async stop(): Promise<void> {
    // Stop the refresh timer
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
    
    // Stop the server
    if (this.server) {
      return new Promise((resolve, reject) => {
        this.server!.close((err) => {
          if (err) {
            console.error('Error stopping API server:', err);
            reject(err);
          } else {
            console.info('API server stopped');
            this.server = null;
            resolve();
          }
        });
      });
    }
  }

  /**
   * Get the API server port
   */
  public getPort(): number {
    return this.port;
  }
}

export const apiServerService = new APIServerService(); 