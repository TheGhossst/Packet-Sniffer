import axios from 'axios';
import { logger } from '../utils/logger';
import * as dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

export interface IPReputationResult {
    isKnownMalicious: boolean;
    abuseConfidenceScore?: number;
    totalReports?: number;
    vtMaliciousCount?: number;
    vtLastAnalysisStats?: {
        harmless: number;
        malicious: number;
        suspicious: number;
        undetected: number;
        timeout: number;
    };
    lastReportedAt?: string;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    categories?: string[];
    recentReports?: Array<{
        reportedAt: string;
        comment: string;
        categories: string[];
    }>;
    vtTags?: string[];
    vtAnalysis?: {
        status: string;
        stats: Record<string, number>;
        results: Record<string, {
            category: string;
            result: string;
            method: string;
            engine_name: string;
        }>;
    };
}

interface AbuseIPDBResponse {
    data: {
        ipAddress: string;
        isPublic: boolean;
        ipVersion: number;
        isWhitelisted: boolean;
        abuseConfidenceScore: number;
        countryCode: string;
        usageType: string;
        isp: string;
        domain: string;
        totalReports: number;
        lastReportedAt: string;
        reports?: Array<{
            reportedAt: string;
            comment: string;
            categories: number[];
        }>;
    };
}

interface VirusTotalResponse {
    data: {
        attributes: {
            last_analysis_stats: {
                harmless: number;
                malicious: number;
                suspicious: number;
                undetected: number;
                timeout: number;
            };
            last_analysis_results: Record<string, {
                category: string;
                result: string;
                method: string;
                engine_name: string;
            }>;
            tags: string[];
            reputation: number;
            last_modification_date: number;
            regional_internet_registry: string;
            network: string;
            country: string;
        };
    };
}

export class IPReputationService {
    private readonly vtApiKey: string;
    private readonly abuseIpDbApiKey: string;
    private readonly reputationCache: Map<string, { data: IPReputationResult; timestamp: number }>;
    private readonly CACHE_TTL = 3600000; // 1 hour in milliseconds
    private readonly VT_API_URL = 'https://www.virustotal.com/api/v3';
    private readonly ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2';

    constructor() {
        this.vtApiKey = process.env.VIRUSTOTAL_API_KEY || '';
        this.abuseIpDbApiKey = process.env.ABUSEIPDB_API_KEY || '';
        this.reputationCache = new Map();

        if (!this.vtApiKey || !this.abuseIpDbApiKey) {
            logger.warn('Missing API keys for IP reputation services');
            logger.debug(`VT Key present: ${!!this.vtApiKey}, AbuseIPDB Key present: ${!!this.abuseIpDbApiKey}`);
        } else {
            this.validateApiKeys().catch(error => {
                logger.error('Error validating API keys:', error);
            });
        }
    }

    private async validateApiKeys(): Promise<void> {
        try {
            // Test VirusTotal API
            const vtResponse = await axios.get(`${this.VT_API_URL}/ip_addresses/8.8.8.8`, {
                headers: {
                    'x-apikey': this.vtApiKey,
                    'Accept': 'application/json'
                },
                timeout: 5000
            });
            logger.info('VirusTotal API key validated successfully');

            // Test AbuseIPDB API
            const abuseResponse = await axios.get(`${this.ABUSEIPDB_API_URL}/check`, {
                params: {
                    ipAddress: '8.8.8.8',
                    maxAgeInDays: 90
                },
                headers: {
                    'Key': this.abuseIpDbApiKey,
                    'Accept': 'application/json'
                },
                timeout: 5000
            });
            logger.info('AbuseIPDB API key validated successfully');

        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 401 || error.response?.status === 403) {
                    logger.error('API key validation failed. Please check your API keys.');
                    if (error.config?.url?.includes('virustotal')) {
                        logger.error('VirusTotal API key is invalid');
                    } else if (error.config?.url?.includes('abuseipdb')) {
                        logger.error('AbuseIPDB API key is invalid');
                    }
                }
            }
            throw error;
        }
    }

    async checkIPReputation(ip: string): Promise<IPReputationResult> {
        try {
            // Check cache first
            const cachedResult = this.getCachedResult(ip);
            if (cachedResult) {
                logger.debug(`Using cached reputation data for IP: ${ip}`);
                return cachedResult;
            }

            logger.info(`Checking reputation for IP: ${ip}`);

            // Parallel API calls with timeout
            const [vtResult, abuseResult] = await Promise.all([
                this.checkVirusTotal(ip).catch(error => {
                    logger.error(`VirusTotal API error for IP ${ip}:`, error);
                    return null;
                }),
                this.checkAbuseIPDB(ip).catch(error => {
                    logger.error(`AbuseIPDB API error for IP ${ip}:`, error);
                    return null;
                })
            ]);

            const result = this.mergeResults(vtResult, abuseResult);
            
            // Cache the result
            this.cacheResult(ip, result);
            
            // Log the results
            logger.info(`Reputation check completed for IP: ${ip}`);
            logger.debug('Reputation results:', {
                ip,
                vtDetections: result.vtMaliciousCount,
                abuseScore: result.abuseConfidenceScore,
                isKnownMalicious: result.isKnownMalicious
            });

            return result;
        } catch (error) {
            const errorDetails: Record<string, any> = {
                message: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                ip,
                service: 'ip-reputation'
            };

            if (axios.isAxiosError(error)) {
                errorDetails.status = error.response?.status;
                errorDetails.statusText = error.response?.statusText;
                errorDetails.url = error.config?.url;
                errorDetails.method = error.config?.method;
            }

            logger.error(`Error checking IP reputation for ${ip}:`, errorDetails);
            return { isKnownMalicious: false };
        }
    }

    private async checkVirusTotal(ip: string): Promise<VirusTotalResponse | null> {
        if (!this.vtApiKey) {
            logger.warn('VirusTotal API key not configured');
            return null;
        }

        try {
            logger.info(`[VirusTotal] Starting API request for IP: ${ip}`);
            const startTime = Date.now();
            
            const response = await axios.get(`${this.VT_API_URL}/ip_addresses/${ip}`, {
                headers: {
                    'x-apikey': this.vtApiKey,
                    'Accept': 'application/json'
                },
                timeout: 10000 // Increased timeout to 10s as per VT docs recommendation
            });

            const duration = Date.now() - startTime;
            logger.info(`[VirusTotal] API request completed for IP: ${ip} (${duration}ms)`);
            logger.info(`[VirusTotal] Analysis stats for ${ip}:`, response.data?.data?.attributes?.last_analysis_stats);
            
            return response.data as VirusTotalResponse;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 404) {
                    logger.info(`[VirusTotal] IP ${ip} not found in database`);
                } else if (error.response?.status === 429) {
                    logger.warn(`[VirusTotal] Rate limit reached for IP ${ip}`);
                } else {
                    logger.error(`[VirusTotal] API error for IP ${ip}: ${error.response?.status} - ${error.message}`);
                }
            }
            throw error;
        }
    }

    private async checkAbuseIPDB(ip: string): Promise<AbuseIPDBResponse | null> {
        if (!this.abuseIpDbApiKey) {
            logger.warn('AbuseIPDB API key not configured');
            return null;
        }

        try {
            logger.info(`[AbuseIPDB] Starting API request for IP: ${ip}`);
            const startTime = Date.now();

            const response = await axios.get(`${this.ABUSEIPDB_API_URL}/check`, {
                params: {
                    ipAddress: ip,
                    maxAgeInDays: 90,
                    verbose: true
                },
                headers: {
                    'Key': this.abuseIpDbApiKey,
                    'Accept': 'application/json',
                    'User-Agent': 'IDS-Analysis-Service'
                },
                timeout: 10000
            });

            const duration = Date.now() - startTime;
            logger.info(`[AbuseIPDB] API request completed for IP: ${ip} (${duration}ms)`);
            logger.info(`[AbuseIPDB] Confidence score for ${ip}: ${response.data?.data?.abuseConfidenceScore}`);

            return response.data as AbuseIPDBResponse;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                if (error.response?.status === 429) {
                    logger.warn(`[AbuseIPDB] Rate limit reached for IP ${ip}`);
                } else {
                    logger.error(`[AbuseIPDB] API error for IP ${ip}: ${error.response?.status} - ${error.message}`);
                }
            }
            throw error;
        }
    }

    private mergeResults(
        vtResult: VirusTotalResponse | null, 
        abuseResult: AbuseIPDBResponse | null
    ): IPReputationResult {
        const vtStats = vtResult?.data?.attributes?.last_analysis_stats;
        const vtMalicious = vtStats?.malicious || 0;
        const vtSuspicious = vtStats?.suspicious || 0;
        const abuseScore = abuseResult?.data?.abuseConfidenceScore || 0;

        // Determine if IP is malicious based on both services
        const isKnownMalicious = (vtMalicious + vtSuspicious >= 2) || (abuseScore >= 25);

        return {
            isKnownMalicious,
            // AbuseIPDB data
            abuseConfidenceScore: abuseResult?.data?.abuseConfidenceScore,
            totalReports: abuseResult?.data?.totalReports,
            countryCode: abuseResult?.data?.countryCode || vtResult?.data?.attributes?.country,
            usageType: abuseResult?.data?.usageType,
            isp: abuseResult?.data?.isp,
            domain: abuseResult?.data?.domain,
            lastReportedAt: abuseResult?.data?.lastReportedAt,
            recentReports: abuseResult?.data?.reports?.map(report => ({
                reportedAt: report.reportedAt,
                comment: report.comment,
                categories: report.categories.map(cat => this.getAbuseIPDBCategory(cat))
            })),
            // VirusTotal data
            vtMaliciousCount: vtMalicious,
            vtLastAnalysisStats: vtStats,
            vtTags: vtResult?.data?.attributes?.tags,
            vtAnalysis: vtResult ? {
                status: 'completed',
                stats: vtResult.data.attributes.last_analysis_stats,
                results: vtResult.data.attributes.last_analysis_results
            } : undefined,
            // Combined categories
            categories: this.combineCategories(
                vtResult?.data?.attributes?.tags || [],
                abuseResult?.data?.reports?.flatMap(r => r.categories.map(this.getAbuseIPDBCategory)) || []
            )
        };
    }

    private combineCategories(vtTags: string[], abuseCategories: string[]): string[] {
        const uniqueCategories = new Set([...vtTags, ...abuseCategories]);
        return Array.from(uniqueCategories);
    }

    private getAbuseIPDBCategory(categoryId: number): string {
        const categories: { [key: number]: string } = {
            1: 'DNS_COMPROMISE',
            2: 'DNS_POISONING',
            3: 'FRAUD_ORDERS',
            4: 'DDoS_ATTACK',
            5: 'FTP_BRUTE_FORCE',
            6: 'PING_OF_DEATH',
            7: 'PHISHING',
            8: 'FRAUD_VOIP',
            9: 'OPEN_PROXY',
            10: 'WEB_SPAM',
            11: 'EMAIL_SPAM',
            12: 'BLOG_SPAM',
            13: 'VPN_IP',
            14: 'PORT_SCAN',
            15: 'HACKING',
            16: 'SQL_INJECTION',
            17: 'SPOOFING',
            18: 'BRUTE_FORCE',
            19: 'BAD_WEB_BOT',
            20: 'EXPLOITED_HOST',
            21: 'WEB_APP_ATTACK',
            22: 'SSH_ATTACK',
            23: 'IOT_TARGETED'
        };
        return categories[categoryId] || 'UNKNOWN';
    }

    private getCachedResult(ip: string): IPReputationResult | null {
        const cached = this.reputationCache.get(ip);
        if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
            return cached.data;
        }
        return null;
    }

    private cacheResult(ip: string, result: IPReputationResult): void {
        this.reputationCache.set(ip, {
            data: result,
            timestamp: Date.now()
        });
    }
}

export const ipReputationService = new IPReputationService(); 