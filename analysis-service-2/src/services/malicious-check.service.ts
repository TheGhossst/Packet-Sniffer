import axios from 'axios';
import { PacketData, MaliciousCheckResult } from '../types/packet.types.js';

class MaliciousCheckService {
  private apiUrl: string;

  constructor() {
    this.apiUrl = 'https://ismalicious.com/api/check?';
  }

  /**
   * Checks if a packet is malicious by calling the isMalicious API
   * @param packet The packet data to check
   * @returns Result containing whether the packet is malicious and additional details
   */
  async checkPacket(packet: PacketData): Promise<MaliciousCheckResult> {
    try {
      const ipToCheck = packet.dst_ip;

      const response = await axios.get(`${this.apiUrl}ip=${ipToCheck}`, {
        headers: {
          'Accept': 'application/json'
        }
      });

      console.log(`[isMalicious Check] IP: ${ipToCheck} | Status: ${response.status} | Malicious: ${response.data.malicious || false}`);

      return {
        isMalicious: response.data.malicious || false,
        reasons: response.data.sources?.map((source: any) => ({
          source: source.name,
          category: source.category || 'unknown',
          description: `Detected by ${source.name} (${source.type})`
        })) || [],
        threatLevel: response.data.reputation?.malicious > 3 ? 'high' : 'medium',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      const status = (error as any).response?.status || 'unknown';
      console.error(`[isMalicious Check Error] Status: ${status} | Request failed for IP: ${packet.dst_ip}`);

      return {
        isMalicious: false,
        reasons: [],
        threatLevel: 'unknown',
        timestamp: new Date().toISOString()
      };
    }
  }
}

export const maliciousCheckService = new MaliciousCheckService();