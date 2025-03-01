import { logger } from '../utils/logger';
import { ipReputationService } from './ip-reputation.service';
import { AlertService, Alert, AlertSeverity } from './alert.service';
import { PacketData, PacketAnalysisResult } from '../types/packet';
import { SAFE_NETWORKS } from '../config/safe-networks';
import { RateLimiter } from '../utils/rate-limiter';
import { NetworkUtils } from '../utils/network';
import { ValidationError } from '../utils/errors';
import {
    PacketAnalysisError,
    NetworkValidationError,
    ReputationAnalysisError,
    PatternAnalysisError,
    AlertGenerationError,
    APIIntegrationError,
    RateLimitError,
    TimeoutError,
    AnalysisErrorCode,
    AnalysisErrorContext
} from '../utils/analysis-errors';
import { AlertCause } from '../types/alert';
import { IPReputationService } from './ip-reputation.service';

interface IsMaliciousResponse {
    sources: Array<{
        status: string;
        name: string;
        type: string;
        category?: string;
        url: string;
    }>;
    type: string;
    value: string;
    malicious: boolean;
    reputation: {
        malicious: number;
        harmless: number;
        suspicious: number;
        undetected: number;
        timeout: number;
    };
    whois?: {
        domain?: {
            domain: string;
            punycode: string;
            name: string;
            extension: string;
            status: string[];
            name_servers: string[];
            created_date: string;
            created_date_in_time: string;
            updated_date: string;
            updated_date_in_time: string;
            expiration_date: string;
            expiration_date_in_time: string;
        };
        registrar?: {
            name: string;
            street: string;
            country: string;
            phone: string;
            fax?: string;
            email: string;
            referral_url?: string;
        };
        registrant?: {
            id: string;
        };
        administrative?: {
            id: string;
            name: string;
            street: string;
            country: string;
            phone: string;
            email: string;
        };
        technical?: {
            id: string;
        };
    };
    geo?: {
        status: string;
        message?: string;
        query: string;
    };
    similar_domains?: {
        total_hits: number;
        keywords: string;
        hits: any[];
    };
}

interface TrafficPattern {
    timestamp: number;
    count: number;
    ports: Set<number>;
    bytes: number;
}

export class PacketAnalysisService {
    private alertService: AlertService;
    private readonly IS_MALICIOUS_API_URL = 'https://ismalicious.com/api';
    private readonly IS_MALICIOUS_API_KEY = process.env.ISMALICIOUS_API_KEY || '';
    private readonly IS_MALICIOUS_API_SECRET = process.env.ISMALICIOUS_API_SECRET || '';
    
    // Cache for IsMalicious results
    private isMaliciousCache: Map<string, { result: IsMaliciousResponse; timestamp: number }> = new Map();
    private readonly CACHE_TTL = 3600000; // 1 hour in milliseconds

    // Traffic pattern tracking
    private trafficPatterns: Map<string, TrafficPattern> = new Map();
    private readonly PATTERN_WINDOW = 300000; // 5 minutes in milliseconds

    // Well-known service ports with protocols
    private readonly COMMON_SERVICES: Record<string, { ports: number[]; protocol: string; protocols?: string[] }> = {
        HTTP: { ports: [80, 8080], protocol: 'TCP' },
        HTTPS: { ports: [443, 8443], protocol: 'TCP' },
        SSH: { ports: [22], protocol: 'TCP' },
        FTP: { ports: [20, 21], protocol: 'TCP' },
        SMTP: { ports: [25, 587, 465], protocol: 'TCP' },
        DNS: { ports: [53], protocol: 'TCP', protocols: ['TCP', 'UDP'] },
        MYSQL: { ports: [3306], protocol: 'TCP' },
        POSTGRESQL: { ports: [5432], protocol: 'TCP' },
        NTP: { ports: [123], protocol: 'UDP' },
        SNMP: { ports: [161, 162], protocol: 'UDP' },
        LDAP: { ports: [389, 636], protocol: 'TCP' },
        RDP: { ports: [3389], protocol: 'TCP' }
    };

    // Behavioral thresholds
    private readonly THRESHOLDS = {
        PORT_SCAN: {
            UNIQUE_PORTS: 5,
            TIME_WINDOW: 60000, // 1 minute
            MAX_FAILED_RATIO: 0.8
        },
        DOS_ATTACK: {
            PACKETS_PER_MINUTE: 1000,
            BYTES_PER_MINUTE: 1048576 // 1MB
        },
        BRUTE_FORCE: {
            ATTEMPTS: 10,
            TIME_WINDOW: 60000, // 1 minute
            COMMON_PORTS: [22, 23, 3389, 5900] // SSH, Telnet, RDP, VNC
        },
        CONNECTION_FLOOD: {
            MAX_CONCURRENT: 100,
            TIME_WINDOW: 60000
        }
    };

    // Enhanced metrics tracking
    private metrics = {
        totalPacketsAnalyzed: 0,
        potentialThreatsDetected: 0,
        confirmedThreats: 0,
        apiCalls: {
            virustotal: { count: 0, avgResponseTime: 0, errors: 0 },
            abuseipdb: { count: 0, avgResponseTime: 0, errors: 0 },
            ismalicious: { count: 0, avgResponseTime: 0, errors: 0 }
        },
        sourcePerformance: {
            virustotal: { truePositives: 0, falsePositives: 0, accuracy: 0 },
            abuseipdb: { truePositives: 0, falsePositives: 0, accuracy: 0 },
            ismalicious: { truePositives: 0, falsePositives: 0, accuracy: 0 }
        },
        processingTimes: {
            analysis: { avg: 0, min: Infinity, max: 0, count: 0 },
            reputation: { avg: 0, min: Infinity, max: 0, count: 0 },
            alert: { avg: 0, min: Infinity, max: 0, count: 0 }
        },
        cacheStats: {
            hits: 0,
            misses: 0,
            size: 0
        },
        alertStats: {
            bySource: new Map<string, number>(),
            bySeverity: new Map<AlertSeverity, number>(),
            byType: new Map<string, number>()
        },
        confirmedMaliciousIPs: new Set<string>(),
        lastUpdated: new Date()
    };

    private readonly CONFIRMATION_ABUSE_SCORE = 75; // Threshold for AbuseIPDB confidence score
    private readonly CONFIRMATION_VT_SCORE = 3;    // Threshold for VirusTotal detections

    // Enhanced reputation configuration
    private readonly REPUTATION_CONFIG = {
        weights: {
            isMalicious: 0.4,
            abuseIPDB: 0.3,
            virusTotal: 0.3
        },
        thresholds: {
            source: {
                isMalicious: {
                    score: 0.5,
                    minSources: 2,
                    timeWindow: 3600000 // 1 hour
                },
                abuseIPDB: {
                    score: 0.75,
                    minReports: 3,
                    maxAge: 7200000 // 2 hours
                },
                virusTotal: {
                    score: 0.3,
                    minEngines: 3,
                    consensus: 0.6 // 60% engine agreement
                }
            },
            composite: {
                LOW: { score: 0.3, minSources: 1 },
                MEDIUM: { score: 0.5, minSources: 2 },
                HIGH: { score: 0.7, minSources: 2 },
                CRITICAL: { score: 0.85, minSources: 3 }
            }
        },
        dynamicWeights: {
            enabled: true,
            adjustmentFactor: 0.1,
            maxWeight: 0.5,
            minWeight: 0.2,
            performanceWindow: 86400000, // 24 hours
            minDataPoints: 100 // Minimum data points before adjusting weights
        },
        rateLimit: {
            maxRequestsPerMinute: 60,
            burstSize: 10,
            cooldownPeriod: 60000
        }
    };

    // Add these configurations to the class
    private readonly API_CONFIG = {
        retry: {
            maxAttempts: 3,
            initialDelay: 1000, // 1 second
            maxDelay: 5000,     // 5 seconds
            backoffFactor: 2,   // Exponential backoff
            timeout: 5000       // 5 seconds timeout
        },
        rateLimit: {
            maxRequests: 60,    // 60 requests per minute
            windowMs: 60000,    // 1 minute window
            maxBurst: 10        // Allow burst of 10 requests
        }
    };

    // Add rate limiter instance
    private rateLimiter: RateLimiter;

    private static readonly WEIGHTS = {
        IP_REPUTATION: 0.4,
        TRAFFIC_PATTERN: 0.3,
        PROTOCOL_RISK: 0.2,
        HISTORICAL: 0.1
    };

    constructor(private readonly ipReputationService: IPReputationService) {
        this.alertService = new AlertService(ipReputationService);
        this.startPatternCleanup();
        this.rateLimiter = new RateLimiter(
            this.API_CONFIG.rateLimit.maxRequests,
            this.API_CONFIG.rateLimit.windowMs,
            this.API_CONFIG.rateLimit.maxBurst
        );
    }

    private startPatternCleanup(): void {
        setInterval(() => {
            const cutoff = Date.now() - this.PATTERN_WINDOW;
            for (const [ip, pattern] of this.trafficPatterns) {
                if (pattern.timestamp < cutoff) {
                    this.trafficPatterns.delete(ip);
                }
            }
        }, 60000); // Clean up every minute
    }

    private updateTrafficPattern(packet: PacketData): void {
        const key = packet.src_ip;
        const now = Date.now();
        const current = this.trafficPatterns.get(key) || {
            timestamp: now,
            count: 0,
            ports: new Set<number>(),
            bytes: 0
        };

        // Update pattern
        current.count++;
        current.ports.add(packet.dst_port);
        current.bytes += packet.packet_size;

        // Store updated pattern
        this.trafficPatterns.set(key, current);
    }

    private async validateTrafficPattern(packet: PacketData): Promise<{
        isValid: boolean;
        reason?: string;
        severity?: AlertSeverity;
    }> {
        const pattern = this.trafficPatterns.get(packet.src_ip);
        if (!pattern) return { isValid: true };

        const timeWindow = Date.now() - pattern.timestamp;
        const minuteMultiplier = 60000 / timeWindow;

        // Check for port scanning
        if (pattern.ports.size >= this.THRESHOLDS.PORT_SCAN.UNIQUE_PORTS &&
            timeWindow <= this.THRESHOLDS.PORT_SCAN.TIME_WINDOW) {
            return {
                isValid: false,
                reason: 'Port scanning detected',
                severity: AlertSeverity.HIGH
            };
        }

        // Check for DoS
        const packetsPerMinute = pattern.count * minuteMultiplier;
        const bytesPerMinute = pattern.bytes * minuteMultiplier;
        if (packetsPerMinute >= this.THRESHOLDS.DOS_ATTACK.PACKETS_PER_MINUTE ||
            bytesPerMinute >= this.THRESHOLDS.DOS_ATTACK.BYTES_PER_MINUTE) {
            return {
                isValid: false,
                reason: 'Potential DoS attack',
                severity: AlertSeverity.CRITICAL
            };
        }

        // Check for brute force attempts
        if (this.THRESHOLDS.BRUTE_FORCE.COMMON_PORTS.includes(packet.dst_port)) {
            const attempts = pattern.count;
            if (attempts >= this.THRESHOLDS.BRUTE_FORCE.ATTEMPTS &&
                timeWindow <= this.THRESHOLDS.BRUTE_FORCE.TIME_WINDOW) {
                return {
                    isValid: false,
                    reason: 'Potential brute force attack',
                    severity: AlertSeverity.HIGH
                };
            }
        }

        return { isValid: true };
    }

    private isKnownService(ip: string): { isKnown: boolean; serviceName?: string } {
        for (const network of SAFE_NETWORKS) {
            if (this.isIpInRange(ip, network.cidr)) {
                return { isKnown: true, serviceName: network.provider };
            }
        }
        return { isKnown: false };
    }

    private isValidServicePort(service: string, port: number, protocol: string): boolean {
        const serviceConfig = this.COMMON_SERVICES[service];
        if (!serviceConfig) return false;

        return serviceConfig.ports.includes(port) &&
            (serviceConfig.protocols ? 
                serviceConfig.protocols.includes(protocol) :
                serviceConfig.protocol === protocol);
    }

    private async validatePacketContext(packet: PacketData): Promise<{
        isValid: boolean;
        reason?: string;
        severity?: AlertSeverity;
    }> {
        // Check for invalid protocol combinations
        if (packet.protocol === 'UDP' && this.isKnownTCPOnlyPort(packet.dst_port)) {
            return {
                isValid: false,
                reason: 'Invalid protocol for port',
                severity: AlertSeverity.MEDIUM
            };
        }

        // Check for suspicious port combinations
        if (this.isSuspiciousPortCombination(packet.src_port, packet.dst_port)) {
            return {
                isValid: false,
                reason: 'Suspicious port combination',
                severity: AlertSeverity.MEDIUM
            };
        }

        // Validate service-specific patterns
        const destService = this.isKnownService(packet.dst_ip);
        if (destService.isKnown) {
            if (!this.isValidServicePort(destService.serviceName!, packet.dst_port, packet.protocol)) {
                return {
                    isValid: false,
                    reason: `Invalid port for ${destService.serviceName} service`,
                    severity: AlertSeverity.MEDIUM
                };
            }
        }

        return { isValid: true };
    }

    private isKnownTCPOnlyPort(port: number): boolean {
        const tcpOnlyServices = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'POSTGRESQL', 'MYSQL'];
        return tcpOnlyServices.some(service => 
            this.COMMON_SERVICES[service].ports.includes(port)
        );
    }

    private isSuspiciousPortCombination(srcPort: number, dstPort: number): boolean {
        // Check for symmetrical ports (potential reflection attack)
        if (srcPort === dstPort && !this.isCommonPort(srcPort)) {
            return true;
        }

        // Check for known malicious combinations
        const suspiciousCombos = [
            { src: 53, dst: 23 },  // DNS to Telnet
            { src: 80, dst: 22 },  // HTTP to SSH
            { src: 443, dst: 3389 } // HTTPS to RDP
        ];

        return suspiciousCombos.some(combo => 
            combo.src === srcPort && combo.dst === dstPort
        );
    }

    private isCommonPort(port: number): boolean {
        return Object.values(this.COMMON_SERVICES).some(service =>
            service.ports.includes(port)
        );
    }

    public async analyzePacket(packet: PacketData): Promise<PacketAnalysisResult> {
        const causes: AlertCause[] = [];
        let totalScore = 0;

        try {
            // Check IP reputation
            const reputationScore = await this.checkIpReputation(packet);
            if (reputationScore > 0) {
                causes.push({
                    reason: `Suspicious IP reputation score: ${reputationScore}`,
                    score: reputationScore
                });
                totalScore += reputationScore * PacketAnalysisService.WEIGHTS.IP_REPUTATION;
            }

            // Analyze traffic pattern
            const patternScore = this.analyzeTrafficPattern(packet);
            if (patternScore > 0) {
                causes.push({
                    reason: `Unusual traffic pattern detected: ${patternScore}`,
                    score: patternScore
                });
                totalScore += patternScore * PacketAnalysisService.WEIGHTS.TRAFFIC_PATTERN;
            }

            // Check protocol risk
            const protocolScore = this.assessProtocolRisk(packet);
            if (protocolScore > 0) {
                causes.push({
                    reason: `High-risk protocol behavior: ${protocolScore}`,
                    score: protocolScore
                });
                totalScore += protocolScore * PacketAnalysisService.WEIGHTS.PROTOCOL_RISK;
            }

            // Normalize final score to 0-100 range
            const normalizedScore = Math.min(Math.round(totalScore), 100);

            return {
                packet,
                score: normalizedScore,
                causes,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            logger.error('Error during packet analysis:', {
                error: error instanceof Error ? error.message : 'Unknown error',
                packet: {
                    source: packet.src_ip,
                    destination: packet.dst_ip,
                    protocol: packet.protocol
                }
            });

            return {
                packet,
                score: 0,
                causes: [{ reason: 'Analysis error occurred', score: 0 }],
                timestamp: new Date().toISOString()
            };
        }
    }

    private async checkIpReputation(packet: PacketData): Promise<number> {
        try {
            const sourceRep = await this.ipReputationService.checkIPReputation(packet.src_ip);
            const destRep = await this.ipReputationService.checkIPReputation(packet.dst_ip);
            
            // Extract reputation scores
            const sourceScore = this.getReputationScore(sourceRep);
            const destScore = this.getReputationScore(destRep);
            
            return Math.max(sourceScore, destScore);
        } catch (error) {
            logger.warn('IP reputation check failed:', {
                error: error instanceof Error ? error.message : 'Unknown error',
                source: packet.src_ip,
                destination: packet.dst_ip
            });
            return 0;
        }
    }

    private getReputationScore(result: any): number {
        if (!result) return 0;

        // If result has a direct score property
        if (typeof result.score === 'number') {
            return result.score;
        }

        // If result has abuseConfidenceScore
        if (typeof result.abuseConfidenceScore === 'number') {
            return result.abuseConfidenceScore;
        }

        // If result has malicious reputation
        if (result.reputation?.malicious) {
            return result.reputation.malicious;
        }

        // If the IP is known to be malicious
        if (result.isKnownMalicious) {
            return 100;
        }

        // Default to 0 if no valid score is found
        return 0;
    }

    private analyzeTrafficPattern(packet: PacketData): number {
        // Implement traffic pattern analysis
        // This is a placeholder - implement your actual traffic pattern analysis logic
        return 0;
    }

    private assessProtocolRisk(packet: PacketData): number {
        const highRiskPorts = [22, 23, 3389, 445, 135, 137, 138, 139];
        const portNumber = packet.dst_port;

        if (highRiskPorts.includes(portNumber)) {
            return 75; // High risk for known vulnerable services
        }

        // Add more protocol risk assessment logic here
        return 0;
    }

    private async performReputationAnalysis(packet: PacketData) {
        const startTime = Date.now();
        try {
            // Gather reputation data from all sources
            const [sourceIsMalicious, destIsMalicious, sourceIPReputation, destIPReputation] = 
                await Promise.all([
                    this.checkIsMalicious(packet.src_ip),
                    this.checkIsMalicious(packet.dst_ip),
                    ipReputationService.checkIPReputation(packet.src_ip),
                    ipReputationService.checkIPReputation(packet.dst_ip)
                ]);

            // Calculate composite scores
            const sourceScore = this.calculateCompositeScore(sourceIsMalicious, sourceIPReputation);
            const destScore = this.calculateCompositeScore(destIsMalicious, destIPReputation);

            // Log detailed analysis results
            logger.debug('Reputation analysis completed:', {
                sourceIp: packet.src_ip,
                destIp: packet.dst_ip,
                sourceScore: sourceScore.score,
                destScore: destScore.score,
                maliciousSources: sourceScore.maliciousSources + destScore.maliciousSources,
                processingTime: Date.now() - startTime
            });

            // Generate alert if needed
            const shouldAlert = await this.shouldGenerateAlert(sourceScore, destScore);
            if (shouldAlert) {
                const alert = await this.createAlert(packet, {
                    source: { score: sourceScore, isMalicious: sourceIsMalicious, reputation: sourceIPReputation },
                    destination: { score: destScore, isMalicious: destIsMalicious, reputation: destIPReputation }
                });

                // Update alert statistics
                this.updateAlertStats(alert);
                return alert;
            }

            return null;
        } finally {
            this.updateProcessingMetrics('reputation', Date.now() - startTime);
        }
    }

    private calculateCompositeScore(isMalicious: IsMaliciousResponse | null, reputation: any): {
        score: number;
        maliciousSources: number;
        details: Array<{
            source: string;
            score: number;
            exceeded: boolean;
            rawData: any;
        }>;
    } {
        const scores: Array<{
            source: string;
            score: number;
            exceeded: boolean;
            rawData: any;
        }> = [];
        let maliciousSources = 0;
        const weights = this.REPUTATION_CONFIG.weights;
        const thresholds = this.REPUTATION_CONFIG.thresholds.source;

        // IsMalicious score calculation
        if (isMalicious) {
            const totalReports = isMalicious.reputation.malicious + isMalicious.reputation.harmless;
            const isMaliciousScore = totalReports > 0 ?
                isMalicious.reputation.malicious / totalReports : 0;
            
            const exceeded = isMaliciousScore >= thresholds.isMalicious.score;
            if (exceeded) maliciousSources++;

            scores.push({
                source: 'isMalicious',
                score: isMaliciousScore,
                exceeded,
                rawData: {
                    malicious: isMalicious.reputation.malicious,
                    total: totalReports,
                    sources: isMalicious.sources
                }
            });
        }

        // AbuseIPDB score calculation
        if (reputation?.abuseConfidenceScore !== undefined) {
            const abuseScore = reputation.abuseConfidenceScore / 100;
            const exceeded = abuseScore >= thresholds.abuseIPDB.score;
            if (exceeded) maliciousSources++;

            scores.push({
                source: 'abuseIPDB',
                score: abuseScore,
                exceeded,
                rawData: {
                    confidence: reputation.abuseConfidenceScore,
                    reports: reputation.totalReports
                }
            });
        }

        // VirusTotal score calculation
        if (reputation?.vtMaliciousCount !== undefined) {
            const totalEngines = reputation.vtTotalCount || 1;
            const vtScore = reputation.vtMaliciousCount / totalEngines;
            const exceeded = vtScore >= thresholds.virusTotal.score;
            if (exceeded) maliciousSources++;

            scores.push({
                source: 'virusTotal',
                score: vtScore,
                exceeded,
                rawData: {
                    detections: reputation.vtMaliciousCount,
                    total: totalEngines
                }
            });
        }

        // Calculate weighted average with current weights
        const totalScore = scores.reduce((acc, { source, score }) => 
            acc + (score * (weights[source as keyof typeof weights] || 0)), 0);

        const totalWeight = scores.reduce((acc, { source }) => 
            acc + (weights[source as keyof typeof weights] || 0), 0);

        const finalScore = totalWeight > 0 ? totalScore / totalWeight : 0;

        // Update source performance if we have confirmation
        if (reputation?.confirmedMalicious !== undefined) {
            this.updateSourcePerformance(scores, reputation.confirmedMalicious);
        }

        return {
            score: finalScore,
            maliciousSources,
            details: scores
        };
    }

    private updateSourcePerformance(
        scores: Array<{ source: string; exceeded: boolean; score: number }>,
        confirmedMalicious: boolean
    ): void {
        if (!this.REPUTATION_CONFIG.dynamicWeights.enabled) return;

        scores.forEach(({ source, exceeded }) => {
            const performance = this.metrics.sourcePerformance[source as keyof typeof this.metrics.sourcePerformance];
            if (!performance) return;

            if (exceeded && confirmedMalicious) {
                performance.truePositives++;
            } else if (exceeded && !confirmedMalicious) {
                performance.falsePositives++;
            }
        });

        this.adjustWeights();
    }

    private adjustWeights(): void {
        const { adjustmentFactor, maxWeight, minWeight } = this.REPUTATION_CONFIG.dynamicWeights;
        const weights = this.REPUTATION_CONFIG.weights;
        const sources = Object.keys(weights) as Array<keyof typeof weights>;

        // Calculate accuracy for each source
        const accuracies = sources.map(source => {
            const perf = this.metrics.sourcePerformance[source as keyof typeof this.metrics.sourcePerformance];
            const total = perf.truePositives + perf.falsePositives;
            return {
                source,
                accuracy: total > 0 ? perf.truePositives / total : 0.33 // Default to equal weight if no data
            };
        });

        // Normalize accuracies to weights
        const totalAccuracy = accuracies.reduce((sum, { accuracy }) => sum + accuracy, 0);
        
        if (totalAccuracy > 0) {
            accuracies.forEach(({ source, accuracy }) => {
                const newWeight = (accuracy / totalAccuracy);
                const currentWeight = weights[source];
                
                // Gradually adjust weight within bounds
                weights[source] = Math.min(
                    maxWeight,
                    Math.max(
                        minWeight,
                        currentWeight + (newWeight - currentWeight) * adjustmentFactor
                    )
                );
            });

            // Normalize weights to sum to 1
            const totalWeight = Object.values(weights).reduce((sum, w) => sum + w, 0);
            sources.forEach(source => {
                weights[source] = weights[source] / totalWeight;
            });
        }
    }

    private determineAlertSeverity(score: number): AlertSeverity {
        const thresholds = this.REPUTATION_CONFIG.thresholds.composite;
        if (score >= thresholds.CRITICAL.score) return AlertSeverity.CRITICAL;
        if (score >= thresholds.HIGH.score) return AlertSeverity.HIGH;
        if (score >= thresholds.MEDIUM.score) return AlertSeverity.MEDIUM;
        return AlertSeverity.LOW;
    }

    private formatReputationAlert(
        packet: PacketData,
        data: {
            source: { score: any; isMalicious: IsMaliciousResponse | null; reputation: any };
            destination: { score: any; isMalicious: IsMaliciousResponse | null; reputation: any };
        }
    ): string {
        const formatScoreDetails = (prefix: string, data: { score: any; isMalicious: IsMaliciousResponse | null; reputation: any }) => {
            const details = [];
            details.push(`${prefix} Composite Score: ${(data.score.score * 100).toFixed(2)}%`);
            details.push('Reputation Sources:');
            
            data.score.details.forEach(({ source, score }: { source: string; score: number }) => {
                details.push(`- ${source}: ${(score * 100).toFixed(2)}%`);
            });

            if (data.isMalicious?.malicious) {
                details.push(`\nIsMalicious Details:
- Malicious Sources: ${data.isMalicious.reputation.malicious}
- Total Sources: ${data.isMalicious.sources.length}`);
            }

            if (data.reputation) {
                if (data.reputation.abuseConfidenceScore !== undefined) {
                    details.push(`\nAbuseIPDB Confidence: ${data.reputation.abuseConfidenceScore}%`);
                }
                if (data.reputation.vtMaliciousCount !== undefined) {
                    details.push(`VirusTotal Detections: ${data.reputation.vtMaliciousCount}/${data.reputation.vtTotalCount || 0}`);
                }
            }

            return details.join('\n');
        };

        return `Suspicious IP Activity Detected

${formatScoreDetails('Source IP', data.source)}

${formatScoreDetails('Destination IP', data.destination)}

Packet Details:
- Protocol: ${packet.protocol}
- Source: ${packet.src_ip}:${packet.src_port}
- Destination: ${packet.dst_ip}:${packet.dst_port}
- Size: ${packet.packet_size} bytes
- Type: ${packet.packet_type}
- Timestamp: ${packet.timestamp}`;
    }

    private async shouldGenerateAlert(sourceScore: any, destScore: any): Promise<boolean> {
        const maxScore = Math.max(sourceScore.score, destScore.score);
        const totalMaliciousSources = sourceScore.maliciousSources + destScore.maliciousSources;
        const thresholds = this.REPUTATION_CONFIG.thresholds.composite;

        // Determine severity level based on score
        let severity: keyof typeof thresholds;
        if (maxScore >= thresholds.CRITICAL.score) severity = 'CRITICAL';
        else if (maxScore >= thresholds.HIGH.score) severity = 'HIGH';
        else if (maxScore >= thresholds.MEDIUM.score) severity = 'MEDIUM';
        else if (maxScore >= thresholds.LOW.score) severity = 'LOW';
        else return false;

        // Check if we meet the minimum sources requirement for this severity
        return totalMaliciousSources >= thresholds[severity].minSources;
    }

    private async generateAlert(packet: PacketData, reason: string, severity: AlertSeverity) {
        const alert: Alert = {
            id: `${Date.now()}-${packet.src_ip}-${packet.dst_ip}`,
            timestamp: new Date().toISOString(),
            type: 'SUSPICIOUS_BEHAVIOR',
            severity,
            sourceIp: packet.src_ip,
            message: `${reason}\n\n${this.formatPacketDetails(packet)}`,
            count: 1,
            packets: [packet],
            metadata: {
                reason,
                destinationIp: packet.dst_ip,
                trafficPattern: this.trafficPatterns.get(packet.src_ip)
            }
        };

        await this.alertService.persistAlert(alert);
    }

    private formatPacketDetails(packet: PacketData): string {
        const srcService = this.isKnownService(packet.src_ip);
        const destService = this.isKnownService(packet.dst_ip);

        return `Packet Details:
Source: ${packet.src_ip}:${packet.src_port} ${srcService.serviceName ? `(${srcService.serviceName})` : ''}
Destination: ${packet.dst_ip}:${packet.dst_port} ${destService.serviceName ? `(${destService.serviceName})` : ''}
Protocol: ${packet.protocol}
Type: ${packet.packet_type}
Size: ${packet.packet_size} bytes
Timestamp: ${packet.timestamp}`;
    }

    private isIpInRange(ip: string, cidr: string): boolean {
        try {
            return NetworkUtils.isInRange(ip, cidr);
        } catch (error) {
            const context = { operation: 'ip-range-check', ip, cidr };
            
            if (error instanceof ValidationError) {
                throw new NetworkValidationError(
                    'cidr',
                    error.message,
                    context,
                    error
                );
            }
            
            throw new PacketAnalysisError(
                AnalysisErrorCode.MALFORMED_IP,
                'Error checking IP range',
                context,
                error instanceof Error ? error : undefined
            );
        }
    }

    private validateIP(ip: string): void {
        if (!NetworkUtils.isIPv4(ip) && !NetworkUtils.isIPv6(ip)) {
            throw new NetworkValidationError(
                'ip',
                `Invalid IP address format: ${ip}`,
                { operation: 'ip-validation' }
            );
        }
    }

    // Get enhanced metrics
    getMetrics() {
        const sourceAccuracies = Object.entries(this.metrics.sourcePerformance).map(([source, perf]) => {
            const total = perf.truePositives + perf.falsePositives;
            return {
                source,
                accuracy: total > 0 ? perf.truePositives / total : 0,
                total,
                truePositives: perf.truePositives,
                falsePositives: perf.falsePositives
            };
        });

        return {
            ...this.metrics,
            sourceAccuracies,
            cacheEfficiency: {
                hitRate: this.metrics.cacheStats.hits / (this.metrics.cacheStats.hits + this.metrics.cacheStats.misses),
                size: this.metrics.cacheStats.size
            },
            alertDistribution: {
                bySource: Object.fromEntries(this.metrics.alertStats.bySource),
                bySeverity: Object.fromEntries(this.metrics.alertStats.bySeverity),
                byType: Object.fromEntries(this.metrics.alertStats.byType)
            },
            confirmedMaliciousIPCount: this.metrics.confirmedMaliciousIPs.size,
            weights: this.REPUTATION_CONFIG.weights
        };
    }

    private updateMetrics(data: {
        apiCalls?: Array<{ service: 'virustotal' | 'abuseipdb' | 'ismalicious' }>;
        isPotentialThreat?: boolean;
        isConfirmedThreat?: boolean;
        maliciousIP?: string;
    }) {
        if (data.apiCalls) {
            data.apiCalls.forEach(call => {
                this.metrics.apiCalls[call.service].count++;
            });
        }
        if (data.isPotentialThreat) {
            this.metrics.potentialThreatsDetected++;
        }
        if (data.isConfirmedThreat) {
            this.metrics.confirmedThreats++;
        }
        if (data.maliciousIP) {
            this.metrics.confirmedMaliciousIPs.add(data.maliciousIP);
        }
        this.metrics.lastUpdated = new Date();
    }

    private formatPacket(packet: any): PacketData {
        return {
            protocol: packet.protocol || 'UNKNOWN',
            packet_size: packet.packet_size || packet.size || 0,
            packet_type: packet.packet_type || packet.type || 'UNKNOWN',
            timestamp: packet.timestamp || new Date().toISOString(),
            src_port: packet.src_port || 0,
            dst_port: packet.dst_port || 0,
            src_ip: packet.src_ip || packet.source || '',
            dst_ip: packet.dst_ip || packet.destination || '',
            source: packet.source || packet.src_ip || '',
            destination: packet.destination || packet.dst_ip || '',
            type: packet.type || packet.packet_type || 'UNKNOWN',
            size: packet.size || packet.packet_size || 0,
            payload_size: packet.payload_size || packet.packet_size || 0
        };
    }

    private getAuthHeader(): string {
        const credentials = `${this.IS_MALICIOUS_API_KEY}:${this.IS_MALICIOUS_API_SECRET}`;
        return Buffer.from(credentials).toString('base64');
    }

    private async retryWithBackoff<T>(
        operation: () => Promise<T>,
        attempt: number = 1
    ): Promise<T> {
        try {
            return await operation();
        } catch (error) {
            if (attempt >= this.API_CONFIG.retry.maxAttempts) {
                throw error;
            }

            const delay = Math.min(
                this.API_CONFIG.retry.initialDelay * Math.pow(this.API_CONFIG.retry.backoffFactor, attempt - 1),
                this.API_CONFIG.retry.maxDelay
            );

            logger.warn(`API request failed, retrying in ${delay}ms`, {
                attempt,
                maxAttempts: this.API_CONFIG.retry.maxAttempts,
                error: error instanceof Error ? error.message : String(error)
            });

            await new Promise(resolve => setTimeout(resolve, delay));
            return this.retryWithBackoff(operation, attempt + 1);
        }
    }

    private async checkIsMalicious(ip: string): Promise<IsMaliciousResponse | null> {
        const startTime = Date.now();
        const context = {
            operation: 'malicious-check',
            ip,
            timestamp: new Date().toISOString()
        };

        try {
            // Validate IP
            this.validateIP(ip);

            // Check cache first
            const cached = this.isMaliciousCache.get(ip);
            if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
                this.metrics.cacheStats.hits++;
                return cached.result;
            }
            this.metrics.cacheStats.misses++;

            // Check API credentials
            if (!this.IS_MALICIOUS_API_KEY || !this.IS_MALICIOUS_API_SECRET) {
                throw new APIIntegrationError(
                    'IsMalicious',
                    401,
                    'API credentials not configured',
                    context
                );
            }

            // Wait for rate limit token
            await this.rateLimiter.acquire();

            // Make API request with retry logic and timeout
            const result = await this.retryWithBackoff(async () => {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), this.API_CONFIG.retry.timeout);

                try {
                    const response = await fetch(`${this.IS_MALICIOUS_API_URL}/check?query=${encodeURIComponent(ip)}`, {
                        headers: {
                            'X-API-KEY': this.getAuthHeader(),
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        signal: controller.signal
                    });

                    if (!response.ok) {
                        const errorBody = await response.text();
                        if (response.status === 429) {
                            throw new RateLimitError(
                                'IsMalicious',
                                parseInt(response.headers.get('Retry-After') || '60000'),
                                context
                            );
                        }
                        throw new APIIntegrationError(
                            'IsMalicious',
                            response.status,
                            errorBody,
                            context
                        );
                    }

                    const data: IsMaliciousResponse = await response.json();
                    return data;
                } catch (error) {
                    if (error instanceof Error && error.name === 'AbortError') {
                        throw new TimeoutError(
                            'IsMalicious',
                            this.API_CONFIG.retry.timeout,
                            context
                        );
                    }
                    throw error;
                } finally {
                    clearTimeout(timeout);
                }
            });

            // Cache successful result
            this.isMaliciousCache.set(ip, {
                result,
                timestamp: Date.now()
            });
            this.metrics.cacheStats.size = this.isMaliciousCache.size;

            // Update API metrics
            this.updateApiMetrics('ismalicious', startTime);

            // Log malicious results with enhanced details
            if (result.malicious) {
                logger.info('IsMalicious API detected malicious IP:', {
                    ip,
                    malicious: result.malicious,
                    type: result.type,
                    value: result.value,
                    reputation: result.reputation,
                    sources: result.sources.map(source => ({
                        name: source.name,
                        type: source.type,
                        category: source.category
                    })),
                    responseTime: Date.now() - startTime
                });
            }

            return result;
        } catch (error) {
            this.metrics.apiCalls.ismalicious.errors++;
            
            if (error instanceof PacketAnalysisError) {
                throw error;
            }

            throw new ReputationAnalysisError(
                'IsMalicious',
                error instanceof Error ? error.message : String(error),
                {
                    ...context,
                    duration: Date.now() - startTime
                },
                error instanceof Error ? error : undefined
            );
        }
    }

    private updateApiMetrics(api: 'virustotal' | 'abuseipdb' | 'ismalicious', startTime: number): void {
        const responseTime = Date.now() - startTime;
        const metrics = this.metrics.apiCalls[api];
        
        metrics.count++;
        metrics.avgResponseTime = (metrics.avgResponseTime * (metrics.count - 1) + responseTime) / metrics.count;
    }

    private updateProcessingMetrics(type: 'analysis' | 'reputation' | 'alert', duration: number): void {
        const metrics = this.metrics.processingTimes[type];
        metrics.count++;
        metrics.avg = (metrics.avg * (metrics.count - 1) + duration) / metrics.count;
        metrics.min = Math.min(metrics.min, duration);
        metrics.max = Math.max(metrics.max, duration);
    }

    private updateAlertStats(alert: Alert): void {
        // Update source statistics
        const sources = alert.metadata.sources as string[] || [];
        sources.forEach((source: string) => {
            const current = this.metrics.alertStats.bySource.get(source) || 0;
            this.metrics.alertStats.bySource.set(source, current + 1);
        });

        // Update severity statistics
        const severityCount = this.metrics.alertStats.bySeverity.get(alert.severity) || 0;
        this.metrics.alertStats.bySeverity.set(alert.severity, severityCount + 1);

        // Update type statistics
        const typeCount = this.metrics.alertStats.byType.get(alert.type) || 0;
        this.metrics.alertStats.byType.set(alert.type, typeCount + 1);
    }

    private async createAlert(
        packet: PacketData,
        data: {
            source: { score: any; isMalicious: IsMaliciousResponse | null; reputation: any };
            destination: { score: any; isMalicious: IsMaliciousResponse | null; reputation: any };
        }
    ): Promise<Alert> {
        const severity = this.determineAlertSeverity(Math.max(data.source.score.score, data.destination.score.score));
        const alert: Alert = {
            id: `${Date.now()}-${packet.src_ip}-${packet.dst_ip}`,
            timestamp: new Date().toISOString(),
            type: 'MALICIOUS_IP_DETECTED',
            severity,
            sourceIp: packet.src_ip,
            message: this.formatReputationAlert(packet, data),
            count: 1,
            packets: [packet],
            metadata: {
                destinationIp: packet.dst_ip,
                sources: data.source.score.details.map((d: { source: string }) => d.source),
                sourceScore: data.source.score,
                destScore: data.destination.score,
                sourceIsMalicious: data.source.isMalicious,
                destIsMalicious: data.destination.isMalicious,
                sourceIPReputation: data.source.reputation,
                destIPReputation: data.destination.reputation
            }
        };

        await this.alertService.persistAlert(alert);
        return alert;
    }

    // Helper method to sanitize packet data for logging
    private sanitizePacket(packet: any): Record<string, any> {
        return {
            src_ip: packet.src_ip || packet.sourceIP,
            dst_ip: packet.dst_ip || packet.destinationIP,
            protocol: packet.protocol,
            packet_type: packet.packet_type || packet.type,
            timestamp: packet.timestamp
            // Omit sensitive fields and include only necessary debugging information
        };
    }
}

export const packetAnalysisService = new PacketAnalysisService(ipReputationService);