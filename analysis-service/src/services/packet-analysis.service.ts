import { logger } from '../utils/logger';
import { ipReputationService } from './ip-reputation.service';
import { AlertService, Alert, AlertSeverity } from './alert.service';
import { PacketData } from '../types/packet.types';
import { SAFE_NETWORKS } from '../config/safe-networks';

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
            status: string[];
            created_date: string;
            updated_date: string;
            expiration_date: string;
            name_servers: string[];
        };
        registrar?: {
            name: string;
            country: string;
            phone: string;
            email: string;
        };
    };
    geo?: {
        status: string;
        message?: string;
        query: string;
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
    private readonly IS_MALICIOUS_CONFIDENCE_THRESHOLD = 3; // Minimum number of malicious sources
    
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

    // Metrics tracking
    private metrics = {
        totalPacketsAnalyzed: 0,
        potentialThreatsDetected: 0,
        confirmedThreats: 0,
        apiCalls: {
            virustotal: 0,
            abuseipdb: 0,
            ismalicious: 0
        },
        trafficPatterns: {
            portScans: 0,
            dosAttempts: 0,
            bruteForceAttempts: 0,
            connectionFloods: 0
        },
        confirmedMaliciousIPs: new Set<string>(),
        lastUpdated: new Date()
    };

    private readonly CONFIRMATION_ABUSE_SCORE = 75; // Threshold for AbuseIPDB confidence score
    private readonly CONFIRMATION_VT_SCORE = 3;    // Threshold for VirusTotal detections

    // Reputation scoring configuration
    private readonly REPUTATION_CONFIG = {
        weights: {
            isMalicious: 0.4,
            abuseIPDB: 0.3,
            virusTotal: 0.3
        },
        thresholds: {
            source: {
                isMalicious: 0.5,    // 50% of sources report malicious
                abuseIPDB: 0.75,     // 75% confidence score
                virusTotal: 0.3      // 30% of engines detect as malicious
            },
            composite: {
                LOW: 0.3,
                MEDIUM: 0.5,
                HIGH: 0.7,
                CRITICAL: 0.85
            }
        },
        minimumSources: 2,  // Minimum number of sources that must report malicious activity
        dynamicWeights: {
            enabled: true,
            adjustmentFactor: 0.1,   // How much to adjust weights based on performance
            maxWeight: 0.5,          // Maximum weight for any single source
            minWeight: 0.2           // Minimum weight for any single source
        }
    };

    // Historical performance tracking for dynamic weight adjustment
    private sourcePerformance = {
        isMalicious: { truePositives: 0, falsePositives: 0 },
        abuseIPDB: { truePositives: 0, falsePositives: 0 },
        virusTotal: { truePositives: 0, falsePositives: 0 }
    };

    constructor() {
        this.alertService = new AlertService(ipReputationService);
        this.startPatternCleanup();
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

    async analyzePacket(rawPacket: any) {
        try {
            this.metrics.totalPacketsAnalyzed++;
            const packet = this.formatPacket(rawPacket);
            
            // Update traffic pattern
            this.updateTrafficPattern(packet);

            // Validate packet context
            const contextValidation = await this.validatePacketContext(packet);
            if (!contextValidation.isValid) {
                await this.generateAlert(packet, contextValidation.reason!, contextValidation.severity!);
                return null;
            }

            // Validate traffic pattern
            const patternValidation = await this.validateTrafficPattern(packet);
            if (!patternValidation.isValid) {
                await this.generateAlert(packet, patternValidation.reason!, patternValidation.severity!);
                return null;
            }

            // Check if destination is a known service
            const destService = this.isKnownService(packet.dst_ip);
            if (destService.isKnown && this.isCommonPort(packet.dst_port)) {
                logger.debug('Legitimate service traffic detected', {
                    service: destService.serviceName,
                    destination: `${packet.dst_ip}:${packet.dst_port}`
                });
                return null;
            }

            // Proceed with reputation checks if needed
            return await this.performReputationAnalysis(packet);
        } catch (error) {
            logger.error('Error during packet analysis:', error);
            throw error;
        }
    }

    private async performReputationAnalysis(packet: PacketData) {
        // Gather reputation data from all sources
        const [
            sourceIsMalicious,
            destIsMalicious,
            sourceIPReputation,
            destIPReputation
        ] = await Promise.all([
            this.checkIsMalicious(packet.src_ip),
            this.checkIsMalicious(packet.dst_ip),
            ipReputationService.checkIPReputation(packet.src_ip),
            ipReputationService.checkIPReputation(packet.dst_ip)
        ]);

        // Update metrics for API calls
        this.updateMetrics({
            apiCalls: [
                { service: 'ismalicious' },
                { service: 'abuseipdb' },
                { service: 'virustotal' }
            ]
        });

        // Calculate composite scores
        const sourceScore = this.calculateCompositeScore(sourceIsMalicious, sourceIPReputation);
        const destScore = this.calculateCompositeScore(destIsMalicious, destIPReputation);
        const maxScore = Math.max(sourceScore.score, destScore.score);
        const totalMaliciousSources = sourceScore.maliciousSources + destScore.maliciousSources;

        // Only generate alert if minimum sources threshold is met and score is significant
        if (totalMaliciousSources >= this.REPUTATION_CONFIG.minimumSources && maxScore > this.REPUTATION_CONFIG.thresholds.composite.LOW) {
            const severity = this.determineAlertSeverity(maxScore);
            const alert = {
                id: `${Date.now()}-${packet.src_ip}-${packet.dst_ip}`,
                timestamp: new Date().toISOString(),
                type: 'MALICIOUS_IP_DETECTED',
                severity,
                sourceIp: packet.src_ip,
                message: this.formatReputationAlert(packet, {
                    source: { score: sourceScore, isMalicious: sourceIsMalicious, reputation: sourceIPReputation },
                    destination: { score: destScore, isMalicious: destIsMalicious, reputation: destIPReputation }
                }),
                count: 1,
                packets: [packet],
                metadata: {
                    destinationIp: packet.dst_ip,
                    sourceScore,
                    destScore,
                    sourceIsMalicious,
                    destIsMalicious,
                    sourceIPReputation,
                    destIPReputation
                }
            };
            await this.alertService.persistAlert(alert);
            return alert;
        }

        return null;
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
            
            const exceeded = isMaliciousScore >= thresholds.isMalicious;
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
            const exceeded = abuseScore >= thresholds.abuseIPDB;
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
            const exceeded = vtScore >= thresholds.virusTotal;
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
            const performance = this.sourcePerformance[source as keyof typeof this.sourcePerformance];
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
            const perf = this.sourcePerformance[source];
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
        if (score >= thresholds.CRITICAL) return AlertSeverity.CRITICAL;
        if (score >= thresholds.HIGH) return AlertSeverity.HIGH;
        if (score >= thresholds.MEDIUM) return AlertSeverity.MEDIUM;
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

    private async shouldGenerateAlert(
        packet: PacketData,
        sourceRep: any,
        destRep: any,
        sourceIsMalicious: IsMaliciousResponse | null,
        destIsMalicious: IsMaliciousResponse | null
    ): Promise<boolean> {
        // Only alert if IsMalicious API returns malicious:true
        return (sourceIsMalicious?.malicious ?? false) || (destIsMalicious?.malicious ?? false);
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
            const [rangeIp, bits] = cidr.split('/');
            const ipLong = this.ipToLong(ip);
            const rangeLong = this.ipToLong(rangeIp);
            const mask = -1 << (32 - parseInt(bits));
            return (ipLong & mask) === (rangeLong & mask);
        } catch (error) {
            logger.error('Error checking IP range:', error);
            return false;
        }
    }

    private ipToLong(ip: string): number {
        return ip.split('.')
            .reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
    }

    // Get metrics endpoint
    getMetrics() {
        return {
            ...this.metrics,
            confirmedMaliciousIPs: Array.from(this.metrics.confirmedMaliciousIPs),
            confirmedMaliciousIPCount: this.metrics.confirmedMaliciousIPs.size
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
                this.metrics.apiCalls[call.service]++;
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
            src_ip: packet.sourceIP || packet.src_ip || '',
            dst_ip: packet.destinationIP || packet.dst_ip || '',
            protocol: packet.protocol || 'UNKNOWN',
            packet_size: packet.packet_size || packet.size || 0,
            payload_size: packet.payload_size || packet.packet_size || 0,
            packet_type: packet.packet_type || packet.type || 'UNKNOWN',
            timestamp: packet.timestamp || new Date().toISOString(),
            src_port: packet.src_port || 0,
            dst_port: packet.dst_port || 0
        };
    }

    private async checkIsMalicious(ip: string): Promise<IsMaliciousResponse | null> {
        try {
            // Check cache first
            const cached = this.isMaliciousCache.get(ip);
            if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
                return cached.result;
            }

            const response = await fetch(`${this.IS_MALICIOUS_API_URL}/check?query=${ip}`);
            console.log(response)

            if (!response.ok) {
                throw new Error(`IsMalicious API error: ${response.statusText}`);
            }

            const result: IsMaliciousResponse = await response.json();
            
            // Cache the result
            this.isMaliciousCache.set(ip, {
                result,
                timestamp: Date.now()
            });

            // Only log if malicious
            if (result.malicious) {
                logger.debug('IsMalicious API detected malicious IP:', {
                    ip,
                    malicious: result.malicious,
                    reputation: result.reputation
                });
            }

            return result;
        } catch (error) {
            logger.error('Error checking IsMalicious:', error);
            return null;
        }
    }
}

export const packetAnalysisService = new PacketAnalysisService();