import { virusTotalService, VirusTotalResult } from './virustotal.service.js';
import { abuseIPDBService, AbuseIPDBResult } from './abuseipdb.service.js';
import { ipsumFeedService } from './ipsum-feed.service.js';
import { metricsService } from './metrics.service.js';

export interface ThreatIntelligenceResult {
  ipAddress: string;
  isMalicious: boolean;
  combinedScore: number;
  threatLevel: string;
  results: {
    ipsum?: { isMalicious: boolean; score: number; source: string };
    virusTotal?: { isMalicious: boolean; score: number; source: string; detections?: number; total?: number };
    abuseIPDB?: { isMalicious: boolean; score: number; source: string; confidenceScore?: number };
  };
  reasons: string[];
  sourceCount: number;
  enrichment: {
    country?: string;
    isp?: string;
    domain?: string;
  };
}

interface WeightConfig {
  ipsum: number;
  virusTotal: number;
  abuseIPDB: number;
}

class ThreatIntelligenceService {
  private weights: WeightConfig = {
    ipsum: 0.4,
    virusTotal: 0.3,
    abuseIPDB: 0.3
  };

  private threatLevelThresholds = {
    low: 3,
    medium: 6,
    high: 10
  };

  private safeIpCache = new Set<string>();
  private safeIpCacheTtl = 3600000; // 1 hour in milliseconds
  private safeIpCacheLastClear = Date.now();

  constructor() {
    setInterval(() => {
      const now = Date.now();
      if (now - this.safeIpCacheLastClear > this.safeIpCacheTtl) {
        console.log(`[Threat Intelligence] Clearing safe IP cache (${this.safeIpCache.size} entries)`);
        this.safeIpCache.clear();
        this.safeIpCacheLastClear = now;
      }
    }, 60000);
  }

  /**
   * Check an IP address against multiple threat intelligence sources
   * @param ip The IP address to check
   * @param checkAllSources If true, will check all available sources regardless of Ipsum result
   */
  async checkIp(ip: string, checkAllSources = false): Promise<ThreatIntelligenceResult> {
    if (this.safeIpCache.has(ip)) {
      console.log(`[Threat Intelligence] IP ${ip} found in safe IP memory cache, skipping all checks`);
      return this.getSafeResult(ip);
    }
    
    if (ipsumFeedService.isSafeIp(ip)) {
      this.safeIpCache.add(ip);
      console.log(`[Threat Intelligence] IP ${ip} is in safe list, skipping all external checks`);
      return this.getSafeResult(ip);
    }
    
    console.log(`[Threat Intelligence] Checking IP: ${ip}`);
    
    const ipsumResult = ipsumFeedService.checkIp(ip);
    
    const result: ThreatIntelligenceResult = {
      ipAddress: ip,
      isMalicious: false,
      combinedScore: 0,
      threatLevel: 'unknown',
      results: {},
      reasons: [],
      sourceCount: 0,
      enrichment: {}
    };
    
    if (ipsumResult.isMalicious) {
      result.results.ipsum = {
        isMalicious: true,
        score: ipsumResult.score,
        source: 'ipsum'
      };
      result.reasons.push(`IP appears on ${ipsumResult.score} blacklists according to Ipsum feed`);
      result.sourceCount++;
      
      if (checkAllSources) {
        console.log(`[Threat Intelligence] IP ${ip} flagged by Ipsum, checking additional sources...`);
        await this.checkAdditionalSources(ip, result);
      } else {
        console.log(`[Threat Intelligence] IP ${ip} flagged by Ipsum, skipping additional API calls to save resources`);
      }
    } else if (checkAllSources) {
      console.log(`[Threat Intelligence] IP ${ip} not flagged by Ipsum, but checking additional sources as requested`);
      await this.checkAdditionalSources(ip, result);
    } else {
      console.log(`[Threat Intelligence] IP ${ip} not flagged by Ipsum, skipping additional API calls`);
      
      // If Ipsum says it's not malicious and we didn't check external sources,
      // add this IP to our safe cache to speed up future checks
      if (!ipsumResult.isMalicious) {
        this.safeIpCache.add(ip);
      }
    }
    
    result.combinedScore = this.calculateWeightedScore(result.results);
    result.isMalicious = result.combinedScore >= this.threatLevelThresholds.low || result.sourceCount >= 2;
    result.threatLevel = this.getThreatLevel(result.combinedScore);
    
    console.log(`[Threat Intelligence] IP: ${ip} | Malicious: ${result.isMalicious} | Score: ${result.combinedScore.toFixed(2)} | Threat Level: ${result.threatLevel} | Sources: ${result.sourceCount}`);
    
    return result;
  }
  
  /**
   * Get a safe result for an IP without doing any checks
   */
  private getSafeResult(ip: string): ThreatIntelligenceResult {
    return {
      ipAddress: ip,
      isMalicious: false,
      combinedScore: 0,
      threatLevel: 'safe',
      results: {},
      reasons: ['IP is in safe list'],
      sourceCount: 0,
      enrichment: {}
    };
  }
  
  /**
   * Check additional intelligence sources if needed
   * @param ip IP address to check
   * @param result Result object to update with findings
   */
  private async checkAdditionalSources(ip: string, result: ThreatIntelligenceResult): Promise<void> {
    try {
      // Now check AbuseIPDB with a timeout
      const abusePromise = this.checkAbuseIPDB(ip, result);
      await Promise.race([
        abusePromise,
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('AbuseIPDB timeout')), 3000)) // 3s timeout
      ]).catch(error => {
        if (error.message === 'AbuseIPDB timeout') {
          console.log(`[Threat Intelligence] AbuseIPDB check timed out for IP: ${ip}`);
          metricsService.incrementApiTimeouts('abuseipdb');
        } else {
          console.error(`[Threat Intelligence] Error checking AbuseIPDB for IP: ${ip}:`, error);
          metricsService.incrementApiErrors('abuseipdb');
        }
      });
      
      // If AbuseIPDB found it malicious, we can potentially skip VirusTotal
      // to save API calls and time - but only if not explicitly told to check all
      if (result.results.abuseIPDB?.isMalicious && result.results.ipsum?.isMalicious) {
        console.log(`[Threat Intelligence] IP ${ip} already confirmed by multiple sources (Ipsum + AbuseIPDB), skipping VirusTotal`);
        return;
      }
      
      const vtPromise = this.checkVirusTotal(ip, result);
      await Promise.race([
        vtPromise,
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('VirusTotal timeout')), 3000)) // 3s timeout
      ]).catch(error => {
        if (error.message === 'VirusTotal timeout') {
          console.log(`[Threat Intelligence] VirusTotal check timed out for IP: ${ip}`);
          metricsService.incrementApiTimeouts('virustotal');
        } else {
          console.error(`[Threat Intelligence] Error checking VirusTotal for IP: ${ip}:`, error);
          metricsService.incrementApiErrors('virustotal');
        }
      });
    } catch (error) {
      console.error(`[Threat Intelligence] Error checking additional sources for ${ip}:`, error);
      metricsService.incrementProcessingErrors();
    }
  }
  
  /**
   * Check an IP against VirusTotal
   */
  private async checkVirusTotal(ip: string, result: ThreatIntelligenceResult): Promise<void> {
    try {
      const vtResult = await virusTotalService.checkIp(ip);
      
      if (vtResult.malicious > 0) {
        result.results.virusTotal = {
          isMalicious: vtResult.isMalicious,
          score: vtResult.score,
          source: 'virustotal',
          detections: vtResult.malicious,
          total: vtResult.malicious + vtResult.suspicious + vtResult.harmless + vtResult.undetected
        };
        
        if (vtResult.isMalicious) {
          result.reasons.push(
            `IP flagged by ${vtResult.malicious} security vendors on VirusTotal`
          );
          result.sourceCount++;
        }
        
        if (vtResult.country) {
          result.enrichment.country = vtResult.country;
        }
        if (vtResult.owner) {
          result.enrichment.isp = vtResult.owner;
        }
      }
    } catch (error) {
      console.error(`[Threat Intelligence] Error checking VirusTotal for ${ip}:`, error);
      metricsService.incrementApiErrors('virustotal');
    }
  }
  
  /**
   * Check an IP against AbuseIPDB
   */
  private async checkAbuseIPDB(ip: string, result: ThreatIntelligenceResult): Promise<void> {
    try {
      const abuseResult = await abuseIPDBService.checkIp(ip);
      
      if (abuseResult.abuseConfidenceScore > 0) {
        result.results.abuseIPDB = {
          isMalicious: abuseResult.isMalicious,
          score: abuseResult.score,
          source: 'abuseipdb',
          confidenceScore: abuseResult.abuseConfidenceScore
        };
        
        if (abuseResult.isMalicious) {
          result.reasons.push(
            `IP has ${abuseResult.abuseConfidenceScore}% confidence score on AbuseIPDB` + 
            (abuseResult.totalReports ? ` (${abuseResult.totalReports} reports)` : '')
          );
          result.sourceCount++;
        }
        
        if (!result.enrichment.country && abuseResult.countryCode) {
          result.enrichment.country = abuseResult.countryCode;
        }
        if (!result.enrichment.isp && abuseResult.isp) {
          result.enrichment.isp = abuseResult.isp;
        }
        if (abuseResult.domain) {
          result.enrichment.domain = abuseResult.domain;
        }
      }
    } catch (error) {
      console.error(`[Threat Intelligence] Error checking AbuseIPDB for ${ip}:`, error);
      metricsService.incrementApiErrors('abuseipdb');
    }
  }
  
  /**
   * Calculate a weighted score based on results from multiple sources
   */
  private calculateWeightedScore(results: ThreatIntelligenceResult['results']): number {
    let weightedSum = 0;
    let weightSum = 0;
    
    if (results.ipsum) {
      weightedSum += this.normalizeScore(results.ipsum.score, 'ipsum') * this.weights.ipsum;
      weightSum += this.weights.ipsum;
    }
    
    if (results.virusTotal) {
      weightedSum += results.virusTotal.score * this.weights.virusTotal;
      weightSum += this.weights.virusTotal;
    }
    
    if (results.abuseIPDB) {
      weightedSum += results.abuseIPDB.score * this.weights.abuseIPDB;
      weightSum += this.weights.abuseIPDB;
    }
    
    if (weightSum === 0) {
      return 0;
    }
    
    return weightedSum / weightSum;
  }
  
  /**
   * Normalize scores from different sources to a 0-10 scale
   */
  private normalizeScore(score: number, source: string): number {
    switch (source) {
      case 'ipsum':
        return Math.min(10, score * 0.4);
        
      default:
        return score;
    }
  }
  
  /**
   * Determine threat level based on score
   */
  private getThreatLevel(score: number): string {
    if (score >= this.threatLevelThresholds.high) {
      return 'high';
    } else if (score >= this.threatLevelThresholds.medium) {
      return 'medium';
    } else if (score >= this.threatLevelThresholds.low) {
      return 'low';
    } else {
      return 'unknown';
    }
  }
}

export const threatIntelligenceService = new ThreatIntelligenceService(); 