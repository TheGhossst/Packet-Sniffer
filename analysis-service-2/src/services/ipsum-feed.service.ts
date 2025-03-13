import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';

interface IpData {
  ip: string;
  score: number;
}

class IpsumFeedService {
  private ipsumUrl = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt';
  private ipCache: Map<string, number> = new Map();
  private safeIps: Set<string> = new Set();
  private lastUpdated: Date | null = null;
  private updateIntervalMs = 24 * 60 * 60 * 1000;
  private cacheFilePath: string;
  private safeIpsFilePath: string;
  private minScoreThreshold = 2;

  constructor() {
    this.cacheFilePath = path.join(process.cwd(), 'data', 'ipsum-cache.json');
    this.safeIpsFilePath = path.join(process.cwd(), 'data', 'safe-ips.json');
    this.ensureCacheDirectory();
  }

  private ensureCacheDirectory() {
    const dir = path.dirname(this.cacheFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`[Ipsum Feed] Created cache directory: ${dir}`);
    }
  }

  /**
   * Initialize the service by loading cached data if available
   * and fetching fresh data if needed
   */
  async initialize(): Promise<void> {
    console.log(`[Ipsum Feed] Initializing service...`);
    console.log(`[Ipsum Feed] Cache file path: ${this.cacheFilePath}`);
    console.log(`[Ipsum Feed] Safe IPs file path: ${this.safeIpsFilePath}`);
    
    await Promise.all([
      this.loadCachedData(),
      this.loadSafeIps()
    ]);
    
    if (this.shouldUpdate()) {
      console.log(`[Ipsum Feed] Cache is outdated or not found, updating from GitHub...`);
      await this.updateFeed();
    } else {
      console.log(`[Ipsum Feed] Using cached data from ${this.lastUpdated?.toLocaleString()}`);
    }

    const updateInterval = this.updateIntervalMs / (1000 * 60 * 60);
    console.log(`[Ipsum Feed] Scheduled automatic updates every ${updateInterval} hours`);
    setInterval(() => this.updateFeed(), this.updateIntervalMs);
    
    console.log(`[Ipsum Feed] Initialization complete with ${this.ipCache.size} malicious IPs and ${this.safeIps.size} safe IPs`);
    
    if (this.ipCache.size > 0) {
      console.log(`[Ipsum Feed] Sample malicious IPs (first 5):`);
      let count = 0;
      for (const [ip, score] of this.ipCache.entries()) {
        if (count < 5) {
          console.log(`[Ipsum Feed] - ${ip} (Score: ${score})`);
          count++;
        } else {
          break;
        }
      }
    }
  }

  /**
   * Load previously cached IP data if available
   */
  private async loadCachedData(): Promise<void> {
    try {
      if (fs.existsSync(this.cacheFilePath)) {
        console.log(`[Ipsum Feed] Found existing cache file, loading...`);
        const readFile = promisify(fs.readFile);
        const data = await readFile(this.cacheFilePath, 'utf8');
        const cache = JSON.parse(data);
        
        this.ipCache = new Map(Object.entries(cache.ipData));
        this.lastUpdated = new Date(cache.lastUpdated);
        
        console.log(`[Ipsum Feed] Successfully loaded ${this.ipCache.size} IPs from cache (last updated: ${this.lastUpdated.toLocaleString()})`);
      } else {
        console.log(`[Ipsum Feed] No cache file found at ${this.cacheFilePath}`);
      }
    } catch (error) {
      console.error(`[Ipsum Feed] Error loading cached data:`, error);
    }
  }

  /**
   * Load safe IP list if available
   */
  private async loadSafeIps(): Promise<void> {
    try {
      if (fs.existsSync(this.safeIpsFilePath)) {
        console.log(`[Ipsum Feed] Found existing safe IPs file, loading...`);
        const readFile = promisify(fs.readFile);
        const data = await readFile(this.safeIpsFilePath, 'utf8');
        const safeIpsList = JSON.parse(data);
        
        this.safeIps = new Set(safeIpsList);
        
        console.log(`[Ipsum Feed] Successfully loaded ${this.safeIps.size} safe IPs from file`);
        if (this.safeIps.size > 0) {
          console.log(`[Ipsum Feed] Sample safe IPs (first 5):`);
          let count = 0;
          for (const ip of this.safeIps) {
            if (count < 5) {
              console.log(`[Ipsum Feed] - ${ip}`);
              count++;
            } else {
              break;
            }
          }
        }
      } else {
        console.log(`[Ipsum Feed] No safe IPs file found at ${this.safeIpsFilePath}`);
      }
    } catch (error) {
      console.error(`[Ipsum Feed] Error loading safe IPs:`, error);
      this.safeIps = new Set();
    }
  }

  /**
   * Save current IP data to cache file
   */
  private async saveCacheData(): Promise<void> {
    try {
      console.log(`[Ipsum Feed] Saving malicious IP cache to ${this.cacheFilePath}...`);
      const writeFile = promisify(fs.writeFile);
      
      const ipData: Record<string, number> = {};
      this.ipCache.forEach((score, ip) => {
        ipData[ip] = score;
      });
      
      const cacheData = {
        lastUpdated: this.lastUpdated?.toISOString(),
        ipData
      };
      
      await writeFile(this.cacheFilePath, JSON.stringify(cacheData, null, 2), 'utf8');
      console.log(`[Ipsum Feed] Successfully saved ${this.ipCache.size} IPs to cache`);
    } catch (error) {
      console.error(`[Ipsum Feed] Error saving cache data:`, error);
    }
  }

  /**
   * Save safe IPs to file
   */
  private async saveSafeIps(): Promise<void> {
    try {
      console.log(`[Ipsum Feed] Saving safe IP list to ${this.safeIpsFilePath}...`);
      const writeFile = promisify(fs.writeFile);
      await writeFile(this.safeIpsFilePath, JSON.stringify(Array.from(this.safeIps), null, 2), 'utf8');
      console.log(`[Ipsum Feed] Successfully saved ${this.safeIps.size} safe IPs to file`);
    } catch (error) {
      console.error(`[Ipsum Feed] Error saving safe IPs:`, error);
    }
  }

  /**
   * Check if the feed should be updated based on last update time
   */
  private shouldUpdate(): boolean {
    if (!this.lastUpdated) {
      console.log(`[Ipsum Feed] No previous update timestamp found, update required`);
      return true;
    }
    
    const now = new Date();
    const diff = now.getTime() - this.lastUpdated.getTime();
    const hoursSinceUpdate = Math.floor(diff / (1000 * 60 * 60));
    
    console.log(`[Ipsum Feed] Hours since last update: ${hoursSinceUpdate}`);
    
    return diff > this.updateIntervalMs;
  }

  /**
   * Fetch and process the latest ipsum feed
   */
  async updateFeed(): Promise<void> {
    try {
      console.log(`[Ipsum Feed] Fetching latest malicious IP database from GitHub...`);
      console.log(`[Ipsum Feed] URL: ${this.ipsumUrl}`);
      
      const startTime = Date.now();
      const response = await axios.get(this.ipsumUrl);
      const fetchTime = Date.now() - startTime;
      
      console.log(`[Ipsum Feed] Successfully fetched data from GitHub (${fetchTime}ms)`);
      console.log(`[Ipsum Feed] Processing data...`);
      
      const oldCacheSize = this.ipCache.size;
      this.ipCache.clear();
      
      const lines = response.data.split('\n');
      console.log(`[Ipsum Feed] Total lines in feed: ${lines.length}`);
      
      let commentLines = 0;
      let validIpLines = 0;
      let skippedIpLines = 0;
      
      for (const line of lines) {
        if (line.startsWith('#')) {
          commentLines++;
          continue;
        }
        
        if (!line.trim()) {
          continue;
        }
        
        const [ip, scoreStr] = line.split('\t');
        if (ip && scoreStr) {
          const score = parseInt(scoreStr, 10);
          if (!isNaN(score)) {
            if (score > this.minScoreThreshold) {
              this.ipCache.set(ip, score);
              validIpLines++;
            } else {
              skippedIpLines++;
            }
          }
        }
      }
      
      this.lastUpdated = new Date();
      await this.saveCacheData();
      
      console.log(`[Ipsum Feed] Update summary:`);
      console.log(`[Ipsum Feed] - Comment lines: ${commentLines}`);
      console.log(`[Ipsum Feed] - Valid IPs (score > ${this.minScoreThreshold}): ${validIpLines}`);
      console.log(`[Ipsum Feed] - Skipped IPs (score <= ${this.minScoreThreshold}): ${skippedIpLines}`);
      console.log(`[Ipsum Feed] - Previous cache size: ${oldCacheSize}`);
      console.log(`[Ipsum Feed] - New cache size: ${this.ipCache.size}`);
      console.log(`[Ipsum Feed] - Update completed at: ${this.lastUpdated.toLocaleString()}`);
    } catch (error) {
      console.error(`[Ipsum Feed] Error updating feed:`, error);
      console.error(`[Ipsum Feed] Will try again later`);
    }
  }

  /**
   * Check if an IP is in the malicious IP database
   * @param ip The IP address to check
   * @returns Object containing whether the IP is malicious and its score
   */
  checkIp(ip: string): { isMalicious: boolean; score: number } {
    // If the IP is in our safe list, it's not malicious
    if (this.safeIps.has(ip)) {
      console.log(`[Ipsum Feed] IP ${ip} found in safe list`);
      return {
        isMalicious: false,
        score: 0
      };
    }
    
    const score = this.ipCache.get(ip) || 0;
    const isMalicious = score > this.minScoreThreshold;
    
    if (score > 0) {
      console.log(`[Ipsum Feed] IP ${ip} found in blacklist with score ${score}`);
    } else {
      console.log(`[Ipsum Feed] IP ${ip} not found in blacklist`);
    }
    
    return {
      isMalicious,
      score
    };
  }

  /**
   * Add an IP to the safe list
   * @param ip The IP address to add to the safe list
   */
  async addSafeIp(ip: string): Promise<void> {
    if (!this.safeIps.has(ip)) {
      this.safeIps.add(ip);
      await this.saveSafeIps();
      console.log(`[Ipsum Feed] Added ${ip} to safe IP list`);
    } else {
      console.log(`[Ipsum Feed] IP ${ip} is already in safe list`);
    }
  }

  /**
   * Remove an IP from the safe list
   * @param ip The IP address to remove from the safe list
   */
  async removeSafeIp(ip: string): Promise<void> {
    if (this.safeIps.has(ip)) {
      this.safeIps.delete(ip);
      await this.saveSafeIps();
      console.log(`[Ipsum Feed] Removed ${ip} from safe IP list`);
    } else {
      console.log(`[Ipsum Feed] IP ${ip} was not in safe list`);
    }
  }

  /**
   * Get all safe IPs
   * @returns Array of safe IPs
   */
  getSafeIps(): string[] {
    return Array.from(this.safeIps);
  }

  /**
   * Check if an IP is in the safe list
   * @param ip The IP address to check
   * @returns True if the IP is in the safe list
   */
  isSafeIp(ip: string): boolean {
    return this.safeIps.has(ip);
  }

  /**
   * Set the minimum score threshold for considering an IP malicious
   * @param threshold The new threshold value
   */
  setMinScoreThreshold(threshold: number): void {
    this.minScoreThreshold = threshold;
    console.log(`[Ipsum Feed] Set minimum score threshold to ${threshold}`);
  }
}

export const ipsumFeedService = new IpsumFeedService();