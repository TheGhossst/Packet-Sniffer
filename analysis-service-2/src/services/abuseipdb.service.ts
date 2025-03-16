import axios from 'axios';
import { metricsService } from './metrics.service.js';

interface AbuseIPDBResponse {
  data: {
    ipAddress: string;
    abuseConfidenceScore: number;
    countryCode?: string;
    domain?: string;
    isp?: string;
    usageType?: string;
    totalReports?: number;
    numDistinctUsers?: number;
    lastReportedAt?: string;
  };
}

export interface AbuseIPDBResult {
  ipAddress: string;
  abuseConfidenceScore: number;
  countryCode?: string;
  domain?: string;
  isp?: string;
  usageType?: string;
  totalReports?: number;
  numDistinctUsers?: number;
  lastReportedAt?: string;
  isMalicious: boolean;
  score: number;
}

class AbuseIPDBService {
  private apiKey: string | undefined;
  private baseUrl = 'https://api.abuseipdb.com/api/v2/check';
  private cacheMap = new Map<string, { result: AbuseIPDBResult, timestamp: number }>();
  private cacheTtl = 3600000; // 1 hour in milliseconds
  private requestDelay = 2000; // Reduced from 5000 to 2000 ms
  private lastRequestTime = 0;
  private MALICIOUS_THRESHOLD = 75; // Score threshold to consider an IP malicious
  private requestsInProgress = new Map<string, Promise<AbuseIPDBResult>>();

  constructor() {
    this.apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!this.apiKey) {
      console.warn('[AbuseIPDB] API key not found in environment variables. AbuseIPDB service will be disabled.');
    } else {
      console.log('[AbuseIPDB] API key found. Service initialized successfully.');
    }
  }

  /**
   * Check if an IP is malicious using AbuseIPDB
   * @param ip The IP address to check
   */
  async checkIp(ip: string): Promise<AbuseIPDBResult> {
    try {
      const cached = this.cacheMap.get(ip);
      if (cached && (Date.now() - cached.timestamp) < this.cacheTtl) {
        console.log(`[AbuseIPDB] Using cached result for IP: ${ip}`);
        return cached.result;
      }
      if (!this.apiKey) {
        console.log('[AbuseIPDB] Skipping check due to missing API key');
        return this.getDefaultResult(ip);
      }
      
      if (this.requestsInProgress.has(ip)) {
        console.log(`[AbuseIPDB] Request already in progress for IP: ${ip}, reusing existing request`);
        return this.requestsInProgress.get(ip)!;
      }

      const requestPromise = this.makeRequest(ip);
      
      this.requestsInProgress.set(ip, requestPromise);
      
      const result = await requestPromise;
      
      this.requestsInProgress.delete(ip);
      
      return result;
    } catch (error) {
      this.requestsInProgress.delete(ip);
      
      console.error(`[AbuseIPDB] Error checking IP ${ip}:`, error);
      if (axios.isAxiosError(error)) {
        console.error(`[AbuseIPDB] Request failed with status: ${error.response?.status}`);
        console.error(`[AbuseIPDB] Response data:`, error.response?.data);
      }
      return this.getDefaultResult(ip);
    }
  }
  
  /**
   * Make the actual API request with rate limiting
   * @param ip The IP address to check
   */
  private async makeRequest(ip: string): Promise<AbuseIPDBResult> {
    try {
      await this.enforceRateLimit();

      console.log(`[AbuseIPDB] Making API request for IP: ${ip}`);
      
      const response = await axios.get<AbuseIPDBResponse>(this.baseUrl, {
        headers: {
          'Key': this.apiKey!,
          'Accept': 'application/json'
        },
        params: {
          ipAddress: ip,
          maxAgeInDays: 90,
          verbose: true
        },
        timeout: 5000
      });

      this.lastRequestTime = Date.now();

      if (!response.data?.data) {
        console.error('[AbuseIPDB] Unexpected response structure:', JSON.stringify(response.data, null, 2).substring(0, 500));
        return this.getDefaultResult(ip);
      }

      const { 
        abuseConfidenceScore, 
        countryCode, 
        domain, 
        isp, 
        usageType, 
        totalReports, 
        numDistinctUsers, 
        lastReportedAt 
      } = response.data.data;
      
      const normalizedScore = abuseConfidenceScore / 10;
      
      const result: AbuseIPDBResult = {
        ipAddress: ip,
        abuseConfidenceScore,
        countryCode,
        domain,
        isp,
        usageType,
        totalReports,
        numDistinctUsers,
        lastReportedAt,
        isMalicious: abuseConfidenceScore >= this.MALICIOUS_THRESHOLD,
        score: normalizedScore
      };

      this.cacheMap.set(ip, { result, timestamp: Date.now() });
      
      console.log(`[AbuseIPDB] IP: ${ip} | Confidence Score: ${abuseConfidenceScore} | Malicious: ${result.isMalicious}`);
      
      return result;
    } catch (error) {
      console.error(`[AbuseIPDB] Error checking IP ${ip}:`);
      
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNABORTED') {
          console.error(`[AbuseIPDB] Request timed out after ${error.config?.timeout}ms`);
          metricsService.incrementApiTimeouts('abuseipdb');
        } else if (error.response) {
          console.error(`[AbuseIPDB] Request failed with status: ${error.response.status}`);
          console.error(`[AbuseIPDB] Response data:`, JSON.stringify(error.response.data).substring(0, 500));
          metricsService.incrementApiErrors('abuseipdb');
        } else if (error.request) {
          console.error('[AbuseIPDB] No response received from server');
          metricsService.incrementApiErrors('abuseipdb');
        } else {
          console.error('[AbuseIPDB] Error setting up request:', error.message);
          metricsService.incrementApiErrors('abuseipdb');
        }
      } else {
        console.error('[AbuseIPDB] Unexpected error:', error);
        metricsService.incrementApiErrors('abuseipdb');
      }
      console.log(`[AbuseIPDB] Returning default result for IP: ${ip} due to API error`);
      return this.getDefaultResult(ip);
    }
  }

  /**
   * Get a default result when the API is unavailable
   */
  private getDefaultResult(ip: string): AbuseIPDBResult {
    return {
      ipAddress: ip,
      abuseConfidenceScore: 0,
      isMalicious: false,
      score: 0
    };
  }

  /**
   * Enforce rate limiting for AbuseIPDB API
   */
  private async enforceRateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.requestDelay) {
      const delay = this.requestDelay - timeSinceLastRequest;
      console.log(`[AbuseIPDB] Rate limiting: Waiting ${delay}ms before next request`);
      
      return new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

export const abuseIPDBService = new AbuseIPDBService(); 