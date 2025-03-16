import axios from 'axios';
import { metricsService } from './metrics.service.js';

interface VirusTotalResponse {
  data: {
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
      };
      last_analysis_results: Record<string, any>;
      country?: string;
      as_owner?: string;
    };
  };
}

export interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  score: number;
  country?: string;
  owner?: string;
  isMalicious: boolean;
  detectionEngines?: string[];
}

class VirusTotalService {
  private apiKey: string | undefined;
  private baseUrl = 'https://www.virustotal.com/api/v3/ip_addresses/';
  private cacheMap = new Map<string, { result: VirusTotalResult, timestamp: number }>();
  private cacheTtl = 3600000; // 1 hour in milliseconds
  private requestDelay = 5000;
  private lastRequestTime = 0;
  private requestsInProgress = new Map<string, Promise<VirusTotalResult>>();

  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!this.apiKey) {
      console.warn('[VirusTotal] API key not found in environment variables. VirusTotal service will be disabled.');
    } else {
      console.log('[VirusTotal] API key found. Service initialized successfully.');
    }
  }

  /**
   * Check if an IP is malicious using VirusTotal
   * @param ip The IP address to check
   */
  async checkIp(ip: string): Promise<VirusTotalResult> {
    try {
      // Check cache first
      const cached = this.cacheMap.get(ip);
      if (cached && (Date.now() - cached.timestamp) < this.cacheTtl) {
        console.log(`[VirusTotal] Using cached result for IP: ${ip}`);
        return cached.result;
      }

      if (!this.apiKey) {
        console.log('[VirusTotal] Skipping check due to missing API key');
        return this.getDefaultResult();
      }
      
      if (this.requestsInProgress.has(ip)) {
        console.log(`[VirusTotal] Request already in progress for IP: ${ip}, reusing existing request`);
        return this.requestsInProgress.get(ip)!;
      }

      const requestPromise = this.makeRequest(ip);
      
      this.requestsInProgress.set(ip, requestPromise);
      
      const result = await requestPromise;
      
      this.requestsInProgress.delete(ip);
      
      return result;
    } catch (error) {
      this.requestsInProgress.delete(ip);
      
      console.error(`[VirusTotal] Error checking IP ${ip}:`, error);
      if (axios.isAxiosError(error)) {
        console.error(`[VirusTotal] Request failed with status: ${error.response?.status}`);
        console.error(`[VirusTotal] Response data:`, error.response?.data);
      }
      return this.getDefaultResult();
    }
  }
  
  /**
   * Make the actual API request with rate limiting
   * @param ip The IP address to check
   */
  private async makeRequest(ip: string): Promise<VirusTotalResult> {
    try {
      await this.enforceRateLimit();

      console.log(`[VirusTotal] Making API request for IP: ${ip}`);
      const url = `${this.baseUrl}${ip}`;
      
      const response = await axios.get<VirusTotalResponse>(url, {
        headers: {
          'x-apikey': this.apiKey!,
          'Accept': 'application/json'
        },
        timeout: 5000
      });

      this.lastRequestTime = Date.now();

      if (!response.data?.data?.attributes?.last_analysis_stats) {
        console.error('[VirusTotal] Unexpected response structure:', JSON.stringify(response.data, null, 2).substring(0, 500));
        return this.getDefaultResult();
      }

      const { malicious, suspicious, harmless, undetected } = response.data.data.attributes.last_analysis_stats;
      
      const totalEngines = malicious + suspicious + harmless + undetected;
      const normalizedScore = totalEngines > 0 ? (10 * (malicious + suspicious * 0.5) / totalEngines) : 0;
      
      const detectionEngines = Object.entries(response.data.data.attributes.last_analysis_results || {})
        .filter(([_, result]) => result.category === 'malicious')
        .map(([engine, _]) => engine);

      const result: VirusTotalResult = {
        malicious,
        suspicious,
        harmless,
        undetected,
        score: normalizedScore,
        country: response.data.data.attributes.country,
        owner: response.data.data.attributes.as_owner,
        isMalicious: malicious > 2, // Consider malicious if at least 3 engines flag it
        detectionEngines
      };

      // Cache the result
      this.cacheMap.set(ip, { result, timestamp: Date.now() });
      
      console.log(`[VirusTotal] IP: ${ip} | Malicious: ${result.isMalicious} | Score: ${result.score.toFixed(2)} | Detections: ${malicious}/${totalEngines}`);
      
      return result;
    } catch (error) {
      console.error(`[VirusTotal] Error checking IP ${ip}:`);
      
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNABORTED') {
          console.error(`[VirusTotal] Request timed out after ${error.config?.timeout}ms`);
          metricsService.incrementApiTimeouts('virustotal');
        } else if (error.response) {
          console.error(`[VirusTotal] Request failed with status: ${error.response.status}`);
          console.error(`[VirusTotal] Response data:`, JSON.stringify(error.response.data).substring(0, 500));
          metricsService.incrementApiErrors('virustotal');
        } else if (error.request) {
          console.error('[VirusTotal] No response received from server');
          metricsService.incrementApiErrors('virustotal');
        } else {
          console.error('[VirusTotal] Error setting up request:', error.message);
          metricsService.incrementApiErrors('virustotal');
        }
      } else {
        console.error('[VirusTotal] Unexpected error:', error);
        metricsService.incrementApiErrors('virustotal');
      }
      
      console.log(`[VirusTotal] Returning default result for IP: ${ip} due to API error`);
      return this.getDefaultResult();
    }
  }

  /**
   * Get a default result when the API is unavailable
   */
  private getDefaultResult(): VirusTotalResult {
    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      score: 0,
      isMalicious: false
    };
  }

  /**
   * Enforce rate limiting for VirusTotal API
   */
  private async enforceRateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.requestDelay) {
      const delay = this.requestDelay - timeSinceLastRequest;
      console.log(`[VirusTotal] Rate limiting: Waiting ${delay}ms before next request`);
      
      return new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

export const virusTotalService = new VirusTotalService(); 