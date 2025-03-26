import { 
  PacketData, 
  BehavioralAnomaly, 
  BehavioralAnalysisResult,
  ConnectionStats,
  IPBehaviorStats
} from '../types/packet.types.js';
import { metricsService } from './metrics.service.js';

/**
 * Behavioral Analysis Service
 * Tracks connection patterns and detects anomalies in network traffic
 */
class BehavioralAnalysisService {
  // Track connections by source/destination pairs
  private connectionTracker = new Map<string, ConnectionStats>();
  
  // Track IPs by their behavior patterns
  private ipBehaviorTracker = new Map<string, IPBehaviorStats>();
  
  // Period for cleaning up old data (10 minutes)
  private cleanupInterval = 10 * 60 * 1000;
  
  // Maximum age of data to keep (1 hour)
  private maxDataAge = 60 * 60 * 1000;
  
  // Baseline traffic thresholds (packets per minute)
  private normalTrafficThreshold = 20;
  private mediumTrafficThreshold = 100;
  private highTrafficThreshold = 500;
  
  // Normal port ranges
  private commonPorts = new Set([
    // Web services
    80, 443, 8080, 8443,
    // Email
    25, 465, 587, 110, 143, 993, 995,
    // DNS
    53,
    // FTP
    20, 21,
    // SSH
    22,
    // Telnet
    23,
    // DHCP
    67, 68,
    // Windows services
    135, 137, 138, 139, 445,
    // Database
    1433, 1521, 3306, 5432, 27017
  ]);
  
  constructor() {
    // Start periodic cleanup of old data
    setInterval(() => {
      this.cleanupOldData();
    }, this.cleanupInterval);
  }
  
  /**
   * Analyze a packet for behavioral patterns
   * @param packet Packet to analyze
   * @returns Analysis results including anomalies detected
   */
  public analyzePacket(packet: PacketData): BehavioralAnalysisResult {
    const timestamp = new Date(packet.timestamp).getTime();
    const result: BehavioralAnalysisResult = {
      anomalies: [],
      connectionInfo: null,
      sourceInfo: null,
      destinationInfo: null
    };
    
    try {
      // Track connection statistics
      const connectionKey = this.getConnectionKey(packet);
      const connectionStats = this.trackConnection(connectionKey, packet, timestamp);
      result.connectionInfo = connectionStats;
      
      // Track source IP behavior
      const sourceStats = this.trackIPBehavior(packet.src_ip, packet, 'source', timestamp);
      result.sourceInfo = sourceStats;
      
      // Track destination IP behavior
      const destStats = this.trackIPBehavior(packet.dst_ip, packet, 'destination', timestamp);
      result.destinationInfo = destStats;
      
      // Detect anomalies
      const anomalies = this.detectAnomalies(packet, connectionStats, sourceStats, destStats);
      result.anomalies = anomalies;
      
      // Update metrics if anomalies were detected
      if (anomalies.length > 0) {
        metricsService.incrementBehavioralAnomalies(
          anomalies[0].type, 
          anomalies[0].severity
        );
      }
      
      return result;
    } catch (error) {
      console.error('Error in behavioral analysis:', error);
      metricsService.incrementProcessingErrors();
      return result;
    }
  }
  
  /**
   * Track connection statistics
   */
  private trackConnection(connectionKey: string, packet: PacketData, timestamp: number): ConnectionStats {
    let stats = this.connectionTracker.get(connectionKey);
    
    if (!stats) {
      stats = {
        srcIp: packet.src_ip,
        dstIp: packet.dst_ip,
        srcPort: packet.src_port,
        dstPort: packet.dst_port,
        protocol: packet.protocol,
        packetCount: 0,
        firstSeen: timestamp,
        lastSeen: timestamp,
        bytesSent: 0,
        recentActivity: [],
      };
      this.connectionTracker.set(connectionKey, stats);
    }
    
    stats.packetCount++;
    stats.lastSeen = timestamp;
    stats.bytesSent += packet.packet_size;
    
    // Track recent activity (last 5 minutes)
    const fiveMinutesAgo = timestamp - 5 * 60 * 1000;
    stats.recentActivity = stats.recentActivity
      .filter(activity => activity.timestamp > fiveMinutesAgo)
      .concat([{ timestamp, size: packet.packet_size }]);
    
    return stats;
  }
  
  /**
   * Track IP behavior statistics
   */
  private trackIPBehavior(ip: string, packet: PacketData, role: 'source' | 'destination', timestamp: number): IPBehaviorStats {
    let stats = this.ipBehaviorTracker.get(ip);
    
    if (!stats) {
      stats = {
        ip,
        packetCount: 0,
        firstSeen: timestamp,
        lastSeen: timestamp,
        bytesSent: 0,
        bytesReceived: 0,
        uniqueConnections: new Set(),
        uniquePorts: new Set(),
        protocols: new Set(),
        recentActivity: [],
        portScanScore: 0,
        isSuspicious: false
      };
      this.ipBehaviorTracker.set(ip, stats);
    }
    
    stats.packetCount++;
    stats.lastSeen = timestamp;
    
    if (role === 'source') {
      stats.bytesSent += packet.packet_size;
      stats.uniqueConnections.add(packet.dst_ip);
      stats.uniquePorts.add(packet.dst_port);
    } else {
      stats.bytesReceived += packet.packet_size;
      stats.uniqueConnections.add(packet.src_ip);
      stats.uniquePorts.add(packet.src_port);
    }
    
    stats.protocols.add(packet.protocol);
    
    // Track recent activity (last 5 minutes)
    const fiveMinutesAgo = timestamp - 5 * 60 * 1000;
    stats.recentActivity = stats.recentActivity
      .filter(activity => activity.timestamp > fiveMinutesAgo)
      .concat([{ timestamp, size: packet.packet_size }]);
    
    // Update port scan score
    if (role === 'source' && !this.commonPorts.has(packet.dst_port)) {
      // Increase score more if scanning uncommon ports
      stats.portScanScore += 1;
    }
    
    // Mark as suspicious if port scan score is high or if connecting to too many unique destinations
    stats.isSuspicious = stats.portScanScore > 10 || stats.uniqueConnections.size > 20;
    
    return stats;
  }
  
  /**
   * Detect anomalies in network traffic
   */
  private detectAnomalies(
    packet: PacketData, 
    connectionStats: ConnectionStats, 
    sourceStats: IPBehaviorStats, 
    destStats: IPBehaviorStats
  ): BehavioralAnomaly[] {
    const anomalies: BehavioralAnomaly[] = [];
    const currentTime = new Date(packet.timestamp).getTime();
    
    // Check for port scanning behavior
    if (sourceStats.portScanScore > 10) {
      anomalies.push({
        type: 'PORT_SCAN',
        description: `Possible port scanning from ${packet.src_ip} (${sourceStats.uniquePorts.size} unique ports)`,
        severity: sourceStats.portScanScore > 20 ? 'high' : 'medium',
        confidence: Math.min(0.5 + (sourceStats.portScanScore / 50), 0.95)
      });
    }
    
    // Check for rapid connection attempts (potential DoS or brute force)
    const oneMinuteAgo = currentTime - 60 * 1000;
    const recentPacketCount = sourceStats.recentActivity
      .filter(activity => activity.timestamp > oneMinuteAgo)
      .length;
    
    if (recentPacketCount > this.highTrafficThreshold) {
      anomalies.push({
        type: 'HIGH_TRAFFIC_VOLUME',
        description: `Unusually high traffic volume from ${packet.src_ip} (${recentPacketCount} packets/min)`,
        severity: 'high',
        confidence: 0.8
      });
    } else if (recentPacketCount > this.mediumTrafficThreshold) {
      anomalies.push({
        type: 'ELEVATED_TRAFFIC_VOLUME',
        description: `Elevated traffic volume from ${packet.src_ip} (${recentPacketCount} packets/min)`,
        severity: 'medium',
        confidence: 0.6
      });
    }
    
    // Check for unusual port usage
    if (!this.commonPorts.has(packet.dst_port) && packet.dst_port !== 0) {
      anomalies.push({
        type: 'UNCOMMON_PORT',
        description: `Connection to uncommon port ${packet.dst_port}`,
        severity: 'low',
        confidence: 0.4
      });
    }
    
    // Check for excessive unique connections (potential C&C or data exfiltration)
    if (sourceStats.uniqueConnections.size > 30) {
      anomalies.push({
        type: 'EXCESSIVE_CONNECTIONS',
        description: `${packet.src_ip} connecting to excessive unique destinations (${sourceStats.uniqueConnections.size})`,
        severity: 'medium',
        confidence: Math.min(0.4 + (sourceStats.uniqueConnections.size / 100), 0.9)
      });
    }
    
    return anomalies;
  }
  
  /**
   * Clean up old data
   */
  private cleanupOldData(): void {
    const now = Date.now();
    const cutoffTime = now - this.maxDataAge;
    
    // Clean up connection tracker
    for (const [key, stats] of this.connectionTracker.entries()) {
      if (stats.lastSeen < cutoffTime) {
        this.connectionTracker.delete(key);
      }
    }
    
    // Clean up IP behavior tracker
    for (const [ip, stats] of this.ipBehaviorTracker.entries()) {
      if (stats.lastSeen < cutoffTime) {
        this.ipBehaviorTracker.delete(ip);
      }
    }
    
    console.log(`[Behavioral Analysis] Cleaned up data (Connections: ${this.connectionTracker.size}, IPs: ${this.ipBehaviorTracker.size})`);
  }
  
  /**
   * Generate a unique key for a connection
   */
  private getConnectionKey(packet: PacketData): string {
    return `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}-${packet.protocol}`;
  }
  
  /**
   * Get connection statistics for a specific connection
   */
  public getConnectionStats(srcIp: string, srcPort: number, dstIp: string, dstPort: number, protocol: string): ConnectionStats | null {
    const key = `${srcIp}:${srcPort}-${dstIp}:${dstPort}-${protocol}`;
    return this.connectionTracker.get(key) || null;
  }
  
  /**
   * Get behavior statistics for a specific IP
   */
  public getIpBehaviorStats(ip: string): IPBehaviorStats | null {
    return this.ipBehaviorTracker.get(ip) || null;
  }
  
  /**
   * Get all suspicious IPs
   */
  public getSuspiciousIps(): string[] {
    const suspiciousIps: string[] = [];
    
    for (const [ip, stats] of this.ipBehaviorTracker.entries()) {
      if (stats.isSuspicious) {
        suspiciousIps.push(ip);
      }
    }
    
    return suspiciousIps;
  }
}

export const behavioralAnalysisService = new BehavioralAnalysisService(); 