import { PacketData, MaliciousCheckResult, ProtocolAnalysisResult } from '../types/packet.types.js';
import { ipsumFeedService } from './ipsum-feed.service.js';
import { metricsService } from './metrics.service.js';
import { threatIntelligenceService } from './threat-intelligence.service.js';
import { dpiService } from './dpi.service.js';

class MaliciousCheckService {
  private recentIps = new Map<string, {count: number, lastSeen: number}>();
  private recentIpsTtl = 3600000; // 1 hour
  private lastCleanup = Date.now();
  private safeThreshold = 5;

  constructor() {
    setInterval(() => {
      this.cleanupRecentIps();
    }, 60000);
  }

  /**
   * Clean up old entries from the recentIps map
   */
  private cleanupRecentIps(): void {
    const now = Date.now();
    
    if (now - this.lastCleanup < 3600000) {
      return;
    }
    
    console.log(`[Malicious Check] Cleaning up recent IPs map (${this.recentIps.size} entries)`);
    
    for (const [ip, data] of this.recentIps.entries()) {
      if (now - data.lastSeen > this.recentIpsTtl) {
        this.recentIps.delete(ip);
      }
    }
    
    this.lastCleanup = now;
  }

  /**
   * Track IP seeing frequency and potentially add to safe list
   */
  private trackIp(ip: string, isMalicious: boolean): void {
    if (isMalicious) {
      return;
    }
    
    const entry = this.recentIps.get(ip);
    if (entry) {
      entry.count++;
      entry.lastSeen = Date.now();
      
      if (entry.count >= this.safeThreshold) {
        console.log(`[Malicious Check] IP ${ip} seen ${entry.count} times, adding to safe list`);
        this.addSafeIp(ip);
        this.recentIps.delete(ip);
      }
    } else {
      this.recentIps.set(ip, {count: 1, lastSeen: Date.now()});
    }
  }

  /**
   * Checks if a packet is malicious using multiple threat intelligence sources
   * Only checks external APIs if Ipsum feed flags the IP as malicious
   * @param packet The packet data to check
   * @returns Result containing whether the packet is malicious and additional details
   */
  async checkPacket(packet: PacketData): Promise<MaliciousCheckResult> {
    const ipToCheck = packet.dst_ip;
    
    // First, perform deep packet inspection if payload is available
    let dpiResult: ProtocolAnalysisResult | null = null;
    
    if (packet.payload) {
      dpiResult = await dpiService.analyzePacket(packet);
      
      // If DPI analysis found suspicious content, update metrics
      if (dpiResult?.isSuspicious) {
        metricsService.incrementDpiDetections(
          dpiResult.protocol,
          dpiResult.findings[0]?.type || 'general'
        );
      }
    }
    
    if (ipsumFeedService.isSafeIp(ipToCheck)) {
      console.log(`[Safe IP] IP: ${ipToCheck} | Marked as safe`);
      metricsService.incrementSafeListHits();
      
      // Even for safe IPs, include DPI results if they exist and are suspicious
      if (dpiResult?.isSuspicious) {
        return {
          isMalicious: true, // Override safe IP status if DPI finds something suspicious
          reasons: [{
            source: 'dpi',
            category: 'protocol-analysis',
            description: `Suspicious content detected in ${dpiResult.protocol} traffic`
          }],
          threatLevel: 'medium',
          timestamp: new Date().toISOString(),
          score: dpiResult.confidence || 0.7,
          details: {
            source: 'dpi'
          },
          protocolAnalysis: dpiResult
        };
      }
      
      return {
        isMalicious: false,
        reasons: [{
          source: 'safe-list',
          category: 'trusted',
          description: 'IP is in the trusted safe list'
        }],
        threatLevel: 'safe',
        timestamp: new Date().toISOString(),
        score: 0,
        details: {
          source: 'safe-list'
        }
      };
    }

    const ipsumResult = ipsumFeedService.checkIp(ipToCheck);
    
    // If Ipsum flagged it as malicious, then check external APIs for confirmation
    // Otherwise, only use Ipsum result to save API calls
    const checkExternalAPIs = ipsumResult.isMalicious;
    
    // Use the combined threat intelligence service with the optimization flag
    const tiResult = await threatIntelligenceService.checkIp(ipToCheck, checkExternalAPIs);
    
    // Track this IP (only if not malicious) for potential addition to safe list
    // Don't track as safe if DPI found something suspicious
    if (!dpiResult?.isSuspicious) {
      this.trackIp(ipToCheck, tiResult.isMalicious);
    }
    
    if (tiResult.isMalicious) {
      if (tiResult.results.virusTotal?.isMalicious) {
        metricsService.incrementVirusTotalHits();
      }
      
      if (tiResult.results.abuseIPDB?.isMalicious) {
        metricsService.incrementAbuseIPDBHits();
      }
      
      if (tiResult.results.ipsum?.isMalicious) {
        metricsService.incrementIpsumBlacklistHits();
      }
      
      if (tiResult.sourceCount >= 2) {
        metricsService.incrementMultiSourceDetections();
      }
    }
    
    // If either TI or DPI found something suspicious, mark as malicious
    const isMalicious = tiResult.isMalicious || dpiResult?.isSuspicious || false;
    
    // Calculate combined score, giving more weight to TI but including DPI if available
    const combinedScore = dpiResult?.isSuspicious
      ? Math.max(tiResult.combinedScore, dpiResult.confidence * 0.8) 
      : tiResult.combinedScore;
    
    // Determine threat level
    let threatLevel = tiResult.threatLevel;
    if (dpiResult?.isSuspicious) {
      // If DPI found a high severity issue, escalate to high
      if (dpiResult.findings.some(f => f.severity === 'high')) {
        threatLevel = 'high';
      } 
      // Otherwise if TI wasn't already high, escalate to at least medium
      else if (threatLevel !== 'high') {
        threatLevel = 'medium';
      }
    }
    
    // Combine reasons
    const reasons = [
      ...tiResult.reasons.map(reason => ({
        source: 'threat-intelligence',
        category: tiResult.threatLevel,
        description: reason
      }))
    ];
    
    // Add DPI reasons if available
    if (dpiResult?.isSuspicious) {
      reasons.push({
        source: 'dpi',
        category: 'protocol-analysis',
        description: `Suspicious content detected in ${dpiResult.protocol} traffic`
      });
    }
    
    return {
      isMalicious,
      reasons,
      threatLevel,
      timestamp: new Date().toISOString(),
      score: combinedScore,
      details: {
        source: dpiResult?.isSuspicious ? 'multiple-sources' :
                tiResult.sourceCount > 1 ? 'multiple-sources' : 
                tiResult.results.ipsum?.isMalicious ? 'ipsum' :
                tiResult.results.virusTotal?.isMalicious ? 'virustotal' :
                tiResult.results.abuseIPDB?.isMalicious ? 'abuseipdb' : 'unknown',
        sourceCount: tiResult.sourceCount + (dpiResult?.isSuspicious ? 1 : 0),
        enrichment: tiResult.enrichment,
        results: tiResult.results
      },
      protocolAnalysis: dpiResult || undefined
    };
  }

  /**
   * Add an IP to the safe list
   * @param ip The IP address to add to the safe list
   */
  async addSafeIp(ip: string): Promise<void> {
    await ipsumFeedService.addSafeIp(ip);
  }

  /**
   * Remove an IP from the safe list
   * @param ip The IP address to remove from the safe list
   */
  async removeSafeIp(ip: string): Promise<void> {
    await ipsumFeedService.removeSafeIp(ip);
  }

  /**
   * Get all safe IPs
   * @returns Array of safe IPs
   */
  getSafeIps(): string[] {
    return ipsumFeedService.getSafeIps();
  }
}

export const maliciousCheckService = new MaliciousCheckService();