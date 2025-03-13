import { PacketData, MaliciousCheckResult } from '../types/packet.types.js';
import { ipsumFeedService } from './ipsum-feed.service.js';
import { metricsService } from './metrics.service.js';

class MaliciousCheckService {
  /**
   * Checks if a packet is malicious using the Ipsum feed and safe IPs list
   * @param packet The packet data to check
   * @returns Result containing whether the packet is malicious and additional details
   */
  async checkPacket(packet: PacketData): Promise<MaliciousCheckResult> {
    const ipToCheck = packet.dst_ip;
    
    // Check if the IP is in our safe list first
    if (ipsumFeedService.isSafeIp(ipToCheck)) {
      console.log(`[Safe IP] IP: ${ipToCheck} | Marked as safe`);
      metricsService.incrementSafeListHits();
      
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
    
    if (ipsumResult.isMalicious) {
      console.log(`[Ipsum Feed] IP: ${ipToCheck} | Malicious: true | Score: ${ipsumResult.score}`);
      metricsService.incrementIpsumBlacklistHits();
      
      return {
        isMalicious: true,
        reasons: [{
          source: 'ipsum',
          category: 'blacklist',
          description: `IP appears on ${ipsumResult.score} blacklists according to Ipsum feed`
        }],
        threatLevel: ipsumResult.score > 5 ? 'high' : 'medium',
        timestamp: new Date().toISOString(),
        score: ipsumResult.score,
        details: {
          source: 'ipsum',
          blacklistCount: ipsumResult.score
        }
      };
    }

    // If not found in Ipsum and not in safe list, mark as unknown
    return {
      isMalicious: false,
      reasons: [{
        source: 'ipsum',
        category: 'unknown',
        description: 'IP not found in any blacklist'
      }],
      threatLevel: 'unknown',
      timestamp: new Date().toISOString(),
      score: 0,
      details: {
        source: 'ipsum'
      }
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