import { createClient, RedisClientType } from 'redis';
import { logger } from '../utils/logger';
import { PacketData } from '../types/packet.types';
import nodemailer, { Transporter } from 'nodemailer';
import { ipReputationService } from './ip-reputation.service';
import { SAFE_NETWORKS, SafeNetwork } from '../config/safe-networks';
import { IPReputationService } from './ip-reputation.service';
import { metricsService } from './metrics.service';


export enum AlertSeverity {
    LOW = 'low',
    MEDIUM = 'medium',
    HIGH = 'high',
    CRITICAL = 'critical'
}

export interface Alert {
    id: string;
    timestamp: string;
    severity: AlertSeverity;
    type: string;
    message: string;
    sourceIp: string;
    count: number;
    packets: PacketData[];
    metadata: Record<string, any>;
    reputationData?: {
        isKnownMalicious: boolean;
        abuseConfidenceScore?: number;
        vtMaliciousCount?: number;
        countryCode?: string;
        isp?: string;
        categories?: string[];
    };
}

export class AlertError extends Error {
    constructor(message: string, public readonly code: string) {
        super(message);
        this.name = 'AlertError';
    }
}

interface AlertThresholds {
    vtMaliciousThreshold: number;
    abuseConfidenceThreshold: number;
    minReportsRequired: number;
    [key: string]: number;
}

export class AlertService {
    private redis!: RedisClientType;
    private readonly ALERT_KEY = 'alerts';
    private readonly ALERT_TTL = 3600;
    private aggregationWindow = 300;
    private emailTransporter!: Transporter;
    private isRedisAvailable = false;
    private alertCache: Map<string, number> = new Map();
    private readonly DEDUP_WINDOW = 300;
    private alertRateLimiter: Map<string, number> = new Map();
    private readonly RATE_LIMIT_WINDOW = 60;
    private readonly MAX_ALERTS_PER_WINDOW = 10;
    private ipReputationService: IPReputationService;
    private readonly alertKeys = {
        pending: 'pending_alerts',
        confirmed: 'confirmed_alerts',
        rejected: 'rejected_alerts'
    };
    private readonly thresholds: AlertThresholds = {
        vtMaliciousThreshold: 2,      // Min number of VT detections
        abuseConfidenceThreshold: 25,  // Min AbuseIPDB confidence score
        minReportsRequired: 1          // Min number of positive reports from either service
    };

    constructor(ipReputationService: IPReputationService) {
        this.ipReputationService = ipReputationService;
        this.initializeServices().catch(error => {
            logger.error('Failed to initialize some services:', error);
            // Don't throw - allow service to run in degraded mode
        });
    }

    private async initializeServices() {
        await this.initializeEmailTransporter();
        await this.initializeRedis();
    }

    private async initializeRedis() {
        try {
            this.redis = createClient({
                url: process.env.REDIS_URL,
                database: parseInt(process.env.ALERT_DB || '2')
            });

            // Add connection timeout
            const connectPromise = this.redis.connect();
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Redis connection timeout')), 5000);
            });

            await Promise.race([connectPromise, timeoutPromise]);

            this.redis.on('error', (err: Error) => {
                logger.error('Redis error:', err);
                this.isRedisAvailable = false;
            });

            this.redis.on('connect', () => {
                logger.info('Redis connected successfully');
                this.isRedisAvailable = true;
            });

            this.isRedisAvailable = true;
        } catch (error) {
            logger.warn('Redis not available - running in degraded mode:', error);
            this.isRedisAvailable = false;
        }
    }

    private async initializeEmailTransporter() {
        try {
            this.emailTransporter = nodemailer.createTransport({
                host: process.env.EMAIL_HOST,
                port: parseInt(process.env.EMAIL_PORT || '587'),
                secure: process.env.EMAIL_SECURE === 'true',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });

            // Verify the connection
            await this.emailTransporter.verify();
            logger.info('Email transporter initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize email transporter:', error);
            throw new AlertError('Email configuration failed', 'EMAIL_INIT_ERROR');
        }
    }

    private validateAlert(alert: Alert): boolean {
        // Basic validation
        if (!alert.sourceIp || !alert.type || !alert.severity || !alert.packets || alert.packets.length === 0) {
            logger.debug(`Alert validation failed - missing required fields: ${JSON.stringify(alert)}`);
            return false;
        }

        // Validate packet data
        if (!this.isValidPacket(alert.packets[0])) {
            logger.debug(`Alert validation failed - invalid packet data: ${JSON.stringify(alert.packets[0])}`);
            return false;
        }

        // Validate alert context
        const validContext = this.validateAlertContext(alert);
        if (!validContext) {
            logger.debug(`Alert validation failed - invalid context: ${JSON.stringify(alert)}`);
            return false;
        }

        // Check thresholds
        const meetsThreshold = this.checkAlertThresholds(alert);
        if (!meetsThreshold) {
            logger.debug(`Alert validation failed - below threshold: ${JSON.stringify(alert)}`);
            return false;
        }

        return true;
    }

    private validateAlertContext(alert: Alert): boolean {
        switch (alert.type) {
            case 'PORT_SCAN':
                return this.validatePortScan(alert);
            case 'SYN_FLOOD':
                return this.validateSynFlood(alert);
            default:
                return true;
        }
    }

    private checkAlertThresholds(alert: Alert): boolean {
        const key = `${alert.type}:${alert.sourceIp}`;
        const threshold = this.getAlertTypeThreshold(alert.type);
        
        return alert.count >= threshold;
    }

    private async enrichAlertWithReputation(alert: Alert): Promise<Alert> {
        try {
            const reputation = await ipReputationService.checkIPReputation(alert.sourceIp);
            alert.reputationData = {
                isKnownMalicious: reputation.isKnownMalicious,
                abuseConfidenceScore: reputation.abuseConfidenceScore,
                vtMaliciousCount: reputation.vtMaliciousCount,
                countryCode: reputation.countryCode,
                isp: reputation.isp,
                categories: reputation.categories
            };

            // Adjust severity based on reputation
            if (reputation.isKnownMalicious) {
                alert.severity = this.escalateSeverityBasedOnReputation(alert.severity, reputation);
            }

            return alert;
        } catch (error) {
            logger.error('Failed to enrich alert with reputation data:', error);
            return alert;
        }
    }

    private escalateSeverityBasedOnReputation(
        currentSeverity: AlertSeverity,
        reputation: { abuseConfidenceScore?: number; vtMaliciousCount?: number }
    ): AlertSeverity {
        if (reputation.abuseConfidenceScore && reputation.abuseConfidenceScore > 90) {
            return AlertSeverity.CRITICAL;
        }
        if (reputation.vtMaliciousCount && reputation.vtMaliciousCount > 10) {
            return AlertSeverity.CRITICAL;
        }
        if (reputation.abuseConfidenceScore && reputation.abuseConfidenceScore > 70) {
            return currentSeverity === AlertSeverity.LOW ? AlertSeverity.MEDIUM : AlertSeverity.HIGH;
        }
        return currentSeverity;
    }

    private async shouldGenerateAlert(alert: Alert): Promise<boolean> {
        // Check if either source or destination is a known safe network
        const isSrcSafe = this.isKnownSafeNetwork(alert.sourceIp);
        const isDestSafe = alert.packets.some(packet => this.isKnownSafeNetwork(packet.dst_ip));

        // If it's communication between known safe networks, suppress the alert
        if (isSrcSafe && isDestSafe) {
            logger.debug(`Alert suppressed - communication between safe networks: ${alert.sourceIp} -> ${alert.packets[0].dst_ip}`);
            return false;
        }

        // Get reputation data
        const reputation = await ipReputationService.checkIPReputation(alert.sourceIp);
        const abuseScore = reputation.abuseConfidenceScore ?? 0;
        const vtDetections = reputation.vtMaliciousCount ?? 0;
        
        // If both reputation services consider it safe, and it's a common service port
        if (!reputation.isKnownMalicious && abuseScore < 25 && vtDetections === 0) {
            // Check if it's a common service port (e.g., 80, 443, 22)
            const commonPorts = [80, 443, 22, 21, 25, 53, 3306, 5432];
            const isCommonPort = alert.packets.some(packet => 
                commonPorts.includes(packet.dst_port)
            );

            if (isCommonPort) {
                logger.debug(`Alert suppressed - legitimate traffic to common port: ${alert.sourceIp}`);
                return false;
            }
        }

        // Additional context-based checks
        if (alert.type === 'PORT_SCAN') {
            // For port scans, require higher confidence or multiple detections
            return abuseScore > 40 || vtDetections > 2;
        }

        return true;
    }

    private isKnownSafeNetwork(ip: string): boolean {
        try {
            const ipAddr = this.parseIPv4(ip);
            if (!ipAddr) return false;

            return SAFE_NETWORKS.some((network: SafeNetwork) => {
                const [networkAddr, bits] = network.cidr.split('/');
                const networkMask = this.createMask(parseInt(bits));
                const networkIp = this.parseIPv4(networkAddr);
                
                if (!networkIp) return false;
                
                return (ipAddr & networkMask) === (networkIp & networkMask);
            });
        } catch (error) {
            logger.error('Error checking safe network:', error);
            return false;
        }
    }

    private parseIPv4(ip: string): number | null {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        
        return ((parseInt(parts[0]) << 24) |
                (parseInt(parts[1]) << 16) |
                (parseInt(parts[2]) << 8) |
                parseInt(parts[3])) >>> 0;
    }

    private createMask(bits: number): number {
        return (0xffffffff << (32 - bits)) >>> 0;
    }

    async persistAlert(alert: Alert): Promise<void> {
        if (!this.validateAlert(alert)) {
            logger.debug('Alert validation failed, skipping persistence');
            return;
        }

        try {
            // First check if we should generate an alert
            if (!await this.shouldGenerateAlert(alert)) {
                logger.debug('Alert suppressed based on reputation and context');
                return;
            }

            // Enrich alert with reputation data
            alert = await this.enrichAlertWithReputation(alert);

            if (this.isRedisAvailable) {
                const key = `${this.ALERT_KEY}:${alert.type}:${alert.sourceIp}`;
                await this.redis.setEx(key, this.ALERT_TTL, JSON.stringify(alert));
            }
            await this.notifyAlert(alert);
        } catch (error) {
            logger.error('Error persisting alert:', error);
        }
    }

    async aggregateAlerts(newAlert: Alert): Promise<Alert> {
        if (!this.isRedisAvailable) {
            return newAlert;
        }

        try {
            const key = `${this.ALERT_KEY}:${newAlert.type}:${newAlert.sourceIp}`;
            const existingAlert = await this.redis.get(key);

            if (existingAlert) {
                const alert = JSON.parse(existingAlert) as Alert;
                const timeDiff = Date.now() - new Date(alert.timestamp).getTime();

                if (timeDiff < this.aggregationWindow * 1000) {
                    alert.count += 1;
                    alert.packets.push(...newAlert.packets);
                    alert.severity = this.escalateSeverity(alert);
                    return alert;
                }
            }
            return newAlert;
        } catch (error) {
            logger.error('Error aggregating alerts:', error);
            return newAlert;
        }
    }

    private escalateSeverity(alert: Alert): AlertSeverity {
        if (alert.count > 100) return AlertSeverity.CRITICAL;
        if (alert.count > 50) return AlertSeverity.HIGH;
        if (alert.count > 20) return AlertSeverity.MEDIUM;
        return AlertSeverity.LOW;
    }

    private isDuplicate(alert: Alert): boolean {
        const key = `${alert.type}:${alert.sourceIp}`;
        const lastTime = this.alertCache.get(key);
        const now = Date.now();

        if (lastTime && (now - lastTime) < (this.DEDUP_WINDOW * 1000)) {
            return true;
        }

        this.alertCache.set(key, now);
        return false;
    }

    async notifyAlert(alert: Alert): Promise<void> {
        try {
            // Rate limiting check
            if (this.isRateLimited(alert.sourceIp)) {
                logger.debug(`Rate limit exceeded for IP: ${alert.sourceIp}`);
                return;
            }

            // Deduplication check
            if (this.isDuplicate(alert)) {
                logger.debug('Duplicate alert suppressed');
                return;
            }

            const formattedMessage = this.formatAlertMessage(alert);
            
            switch (alert.severity) {
                case AlertSeverity.CRITICAL:
                    logger.error(formattedMessage);
                    await this.sendEmailNotification(alert);
                    break;
                case AlertSeverity.HIGH:
                    logger.warn(formattedMessage);
                    await this.sendEmailNotification(alert);
                    break;
                case AlertSeverity.MEDIUM:
                    logger.warn(formattedMessage);
                    break;
                case AlertSeverity.LOW:
                    logger.info(formattedMessage);
                    break;
            }
        } catch (error) {
            logger.error('Notification error:', error);
            throw new AlertError('Failed to send notification', 'NOTIFY_ERROR');
        }
    }

    private async sendEmailNotification(alert: Alert): Promise<void> {
        const emailContent = this.formatEmailContent(alert);
        
        try {
            await this.emailTransporter.sendMail({
                from: process.env.EMAIL_FROM,
                to: process.env.ALERT_EMAIL_RECIPIENTS?.split(','),
                subject: `[${alert.severity.toUpperCase()}] Security Alert: ${alert.type}`,
                html: emailContent
            });
        } catch (error) {
            logger.error('Failed to send email notification:', error);
            throw new AlertError('Email sending failed', 'EMAIL_ERROR');
        }
    }

    private formatEmailContent(alert: Alert): string {
        const formattedMessage = typeof alert.message === 'object'
            ? JSON.stringify(alert.message, null, 2)
            : (alert.message || 'No message provided');

        const reputationInfo = alert.reputationData ? `
            <h3>IP Reputation Information:</h3>
            <ul>
                <li><strong>Known Malicious:</strong> ${alert.reputationData.isKnownMalicious ? 'Yes' : 'No'}</li>
                ${alert.reputationData.abuseConfidenceScore ? `<li><strong>Abuse Confidence:</strong> ${alert.reputationData.abuseConfidenceScore}%</li>` : ''}
                ${alert.reputationData.vtMaliciousCount ? `<li><strong>VirusTotal Detections:</strong> ${alert.reputationData.vtMaliciousCount}</li>` : ''}
                ${alert.reputationData.countryCode ? `<li><strong>Country:</strong> ${alert.reputationData.countryCode}</li>` : ''}
                ${alert.reputationData.isp ? `<li><strong>ISP:</strong> ${alert.reputationData.isp}</li>` : ''}
                ${alert.reputationData.categories ? `<li><strong>Categories:</strong> ${alert.reputationData.categories.join(', ')}</li>` : ''}
            </ul>` : '';

        return `
            <h2>Security Alert Detected</h2>
            <p><strong>Type:</strong> ${alert.type}</p>
            <p><strong>Severity:</strong> ${alert.severity}</p>
            <p><strong>Source IP:</strong> ${alert.sourceIp}</p>
            <p><strong>Count:</strong> ${alert.count}</p>
            <p><strong>Timestamp:</strong> ${alert.timestamp}</p>
            <p><strong>Message:</strong></p>
            <pre>${formattedMessage}</pre>
            ${reputationInfo}
            <h3>Details:</h3>
            <pre>${JSON.stringify(alert.metadata, null, 2)}</pre>
        `;
    }

    private formatAlertMessage(alert: Alert): string {
        const severity = this.getSeverityEmoji(alert.severity);
        const border = '═'.repeat(80);
        
        // Format message properly based on type
        let messageText = 'No message provided';
        if (alert.message) {
            if (typeof alert.message === 'object') {
                try {
                    messageText = JSON.stringify(alert.message, null, 2);
                } catch (error) {
                    messageText = Object.entries(alert.message)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join('\n  ');
                }
            } else {
                messageText = String(alert.message);
            }
        }

        // Get network provider info
        const networkInfo = this.getNetworkProvider(alert.sourceIp);
        const networkText = networkInfo ? ` (${networkInfo})` : '';

        let message = `
${border}
${severity} Security Alert: ${alert.type}
${border}
• Severity: ${alert.severity.toUpperCase()}
• Source IP: ${alert.sourceIp}${networkText}
• Event Count: ${alert.count}
• First Seen: ${alert.timestamp}
• Message:
${messageText.split('\n').map(line => '  ' + line).join('\n')}`;

        if (alert.reputationData) {
            const reputationText = this.formatReputationData(alert.reputationData);
            message += `\n${reputationText}`;
        }

        if (alert.packets && alert.packets.length > 0) {
            message += `\nPacket Information:\n${this.formatPacketDetails(alert.packets[0])}`;
        }

        if (alert.metadata && Object.keys(alert.metadata).length > 0) {
            message += `\nAdditional Data:\n${this.formatMetadata(alert.metadata)}`;
        }

        message += `\n${border}`;
        return message;
    }

    private formatReputationData(reputationData: Alert['reputationData']): string {
        if (!reputationData) return '';

        const lines = ['Reputation Information:'];

        if (reputationData.isKnownMalicious !== undefined) {
            lines.push(`• Known Malicious: ${reputationData.isKnownMalicious ? 'Yes' : 'No'}`);
        }
        if (reputationData.abuseConfidenceScore !== undefined) {
            lines.push(`• Abuse Confidence: ${reputationData.abuseConfidenceScore}%`);
        }
        if (reputationData.vtMaliciousCount !== undefined) {
            lines.push(`• VirusTotal Detections: ${reputationData.vtMaliciousCount}`);
        }
        if (reputationData.countryCode) {
            lines.push(`• Country: ${reputationData.countryCode}`);
        }
        if (reputationData.isp) {
            lines.push(`• ISP: ${reputationData.isp}`);
        }
        if (reputationData.categories && reputationData.categories.length > 0) {
            lines.push(`• Categories: ${reputationData.categories.join(', ')}`);
        }

        return lines.join('\n');
    }

    private formatPacketDetails(packet: PacketData): string {
        const details = [
            `  • Protocol: ${packet.protocol}`,
            `  • Source: ${packet.src_ip}:${packet.src_port}${this.getNetworkProvider(packet.src_ip) ? ` (${this.getNetworkProvider(packet.src_ip)})` : ''}`,
            `  • Destination: ${packet.dst_ip}:${packet.dst_port}${this.getNetworkProvider(packet.dst_ip) ? ` (${this.getNetworkProvider(packet.dst_ip)})` : ''}`,
            `  • Size: ${packet.packet_size} bytes`,
            `  • Type: ${packet.packet_type}`,
            `  • Timestamp: ${packet.timestamp}`
        ];
        return details.join('\n');
    }

    private getSeverityEmoji(severity: AlertSeverity): string {
        switch (severity) {
            case AlertSeverity.CRITICAL: return '🚨';
            case AlertSeverity.HIGH: return '⚠️';
            case AlertSeverity.MEDIUM: return '⚡';
            case AlertSeverity.LOW: return 'ℹ️';
            default: return '🔔';
        }
    }

    private formatMetadata(metadata: Record<string, any>): string {
        return Object.entries(metadata)
            .map(([key, value]) => `• ${key}: ${value}`)
            .join('\n');
    }

    private isRateLimited(sourceIp: string): boolean {
        const key = `rate:${sourceIp}`;
        const count = this.alertRateLimiter.get(key) || 0;
        
        if (count >= this.MAX_ALERTS_PER_WINDOW) {
            return true;
        }

        this.alertRateLimiter.set(key, count + 1);
        return false;
    }

    // Clean up rate limiting data periodically
    private cleanupRateLimiter(): void {
        setInterval(() => {
            this.alertRateLimiter.clear();
        }, this.RATE_LIMIT_WINDOW * 1000);
    }

    private validatePortScan(alert: Alert): boolean {
        // Validate port scan specific conditions
        const uniquePorts = new Set(
            alert.packets.map(packet => packet.dst_port)
        ).size;
        
        const timeWindow = Math.abs(
            new Date(alert.packets[alert.packets.length - 1].timestamp).getTime() -
            new Date(alert.packets[0].timestamp).getTime()
        );

        // Check if many ports were scanned in a short time
        return uniquePorts >= 5 && timeWindow <= 60000; // 1 minute window
    }

    private validateSynFlood(alert: Alert): boolean {
        // Validate SYN flood specific conditions
        const synPackets = alert.packets.filter(
            packet => packet.protocol === 'TCP' && packet.packet_type === 'SYN'
        ).length;

        const timeWindow = Math.abs(
            new Date(alert.packets[alert.packets.length - 1].timestamp).getTime() -
            new Date(alert.packets[0].timestamp).getTime()
        );

        // Check for high rate of SYN packets
        return synPackets >= 20 && timeWindow <= 5000; // 5 second window
    }

    private getAlertTypeThreshold(type: string): number {
        return this.thresholds[type] || 10; // Default threshold of 10
    }

    private isValidPacket(packet: PacketData): boolean {
        if (!packet) {
            logger.debug('Packet validation failed: packet is null or undefined');
            return false;
        }

        // Enhanced IP validation
        if (!this.isValidIpAddress(packet.src_ip)) {
            logger.debug(`Invalid source IP: ${packet.src_ip}`);
            return false;
        }
        if (!this.isValidIpAddress(packet.dst_ip)) {
            logger.debug(`Invalid destination IP: ${packet.dst_ip}`);
            return false;
        }

        // Enhanced port validation
        if (!this.isValidPort(packet.src_port)) {
            logger.debug(`Invalid source port: ${packet.src_port}`);
            return false;
        }
        if (!this.isValidPort(packet.dst_port)) {
            logger.debug(`Invalid destination port: ${packet.dst_port}`);
            return false;
        }

        // Protocol validation
        const validProtocols = ['TCP', 'UDP', 'ICMP', 'IPv4', 'IPv6'];
        if (!validProtocols.includes(packet.protocol)) {
            logger.debug(`Invalid protocol: ${packet.protocol}`);
            return false;
        }

        // Packet size validation (0 to 65535 bytes - max IPv4 packet size)
        if (!this.isValidPacketSize(packet.packet_size)) {
            logger.debug(`Invalid packet size: ${packet.packet_size}`);
            return false;
        }

        // Timestamp validation
        if (!this.isValidTimestamp(packet.timestamp)) {
            logger.debug(`Invalid timestamp: ${packet.timestamp}`);
            return false;
        }

        return true;
    }

    private isValidPort(port: number): boolean {
        return Number.isInteger(port) && port >= 0 && port <= 65535;
    }

    private isValidPacketSize(size: number): boolean {
        return Number.isInteger(size) && size > 0 && size <= 65535;
    }

    private isValidTimestamp(timestamp: string): boolean {
        const date = new Date(timestamp);
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 3600000);
        
        return !isNaN(date.getTime()) && 
               date >= oneHourAgo && 
               date <= now;
    }

    private isValidIpAddress(ip: string): boolean {
        // IPv4 validation
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Regex.test(ip)) {
            return ip.split('.').every(num => {
                const n = parseInt(num);
                return n >= 0 && n <= 255;
            });
        }

        // IPv6 validation (more comprehensive)
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$/;
        return ipv6Regex.test(ip);
    }

    private getNetworkProvider(ip: string): string {
        const network = SAFE_NETWORKS.find((net: SafeNetwork) => this.isInNetwork(ip, net.cidr));
        return network ? network.provider : '';
    }

    private isInNetwork(ip: string, cidr: string): boolean {
        const ipNum = this.parseIPv4(ip);
        if (!ipNum) return false;

        const [networkAddr, bits] = cidr.split('/');
        const networkIp = this.parseIPv4(networkAddr);
        if (!networkIp) return false;

        const mask = this.createMask(parseInt(bits));
        return (ipNum & mask) === (networkIp & mask);
    }

    async validateAndGenerateAlert(sourceIp: string, destIp: string, packet: any): Promise<void> {
        try {
            // Get reputation data for both IPs
            const [sourceReputation, destReputation] = await Promise.all([
                this.ipReputationService.checkIPReputation(sourceIp),
                this.ipReputationService.checkIPReputation(destIp)
            ]);

            const alertContext = {
                timestamp: new Date().toISOString(),
                sourceIp,
                destIp,
                packet,
                sourceReputation,
                destReputation
            };

            // Check if this is a confirmed threat
            const isConfirmedThreat = await this.isConfirmedThreat(sourceReputation, destReputation);
            
            if (isConfirmedThreat) {
                await this.generateConfirmedAlert(alertContext);
            } else {
                // Store as pending for further analysis
                await this.storePendingAlert(alertContext);
            }

            // Update metrics with correct method name
            metricsService.incrementPacketsProcessed();

        } catch (error) {
            logger.error('Error in validateAndGenerateAlert:', error);
            throw error;
        }
    }

    private async isConfirmedThreat(sourceRep: any, destRep: any): Promise<boolean> {
        // Check if either IP is confirmed malicious by reputation services
        const sourceConfirmed = this.isIpConfirmedMalicious(sourceRep);
        const destConfirmed = this.isIpConfirmedMalicious(destRep);

        // Log detailed reputation analysis
        logger.debug('IP Reputation Analysis:', {
            source: {
                ip: sourceRep.ip,
                vtDetections: sourceRep.vtMaliciousCount,
                abuseScore: sourceRep.abuseConfidenceScore,
                isConfirmed: sourceConfirmed
            },
            destination: {
                ip: destRep.ip,
                vtDetections: destRep.vtMaliciousCount,
                abuseScore: destRep.abuseConfidenceScore,
                isConfirmed: destConfirmed
            }
        });

        return sourceConfirmed || destConfirmed;
    }

    private isIpConfirmedMalicious(reputation: any): boolean {
        if (!reputation) return false;

        const vtConfirmed = (reputation.vtMaliciousCount ?? 0) >= this.thresholds.vtMaliciousThreshold;
        const abuseConfirmed = (reputation.abuseConfidenceScore ?? 0) >= this.thresholds.abuseConfidenceThreshold;
        
        // Count how many services confirmed this as malicious
        const confirmations = [vtConfirmed, abuseConfirmed].filter(Boolean).length;
        
        return confirmations >= this.thresholds.minReportsRequired;
    }

    private async generateConfirmedAlert(context: any): Promise<void> {
        const alertId = `alert:${Date.now()}:${context.sourceIp}`;
        const alertData = {
            id: alertId,
            ...context,
            status: 'confirmed',
            analysisDetails: this.formatAnalysisDetails(context)
        };

        await this.redis.hSet(this.alertKeys.confirmed, alertId, JSON.stringify(alertData));
        
        logger.info('Confirmed Alert Generated:', {
            alertId,
            sourceIp: context.sourceIp,
            destIp: context.destIp,
            vtDetections: context.sourceReputation?.vtMaliciousCount,
            abuseScore: context.sourceReputation?.abuseConfidenceScore
        });
    }

    private async storePendingAlert(context: any): Promise<void> {
        const alertId = `pending:${Date.now()}:${context.sourceIp}`;
        const alertData = {
            id: alertId,
            ...context,
            status: 'pending',
            analysisDetails: this.formatAnalysisDetails(context)
        };

        await this.redis.hSet(this.alertKeys.pending, alertId, JSON.stringify(alertData));
        
        logger.debug('Pending Alert Stored:', {
            alertId,
            sourceIp: context.sourceIp,
            destIp: context.destIp
        });
    }

    private formatAnalysisDetails(context: any): string {
        const { sourceReputation, destReputation } = context;
        
        return JSON.stringify({
            source: {
                ip: context.sourceIp,
                reputation: {
                    vtDetections: sourceReputation?.vtMaliciousCount ?? 0,
                    abuseScore: sourceReputation?.abuseConfidenceScore ?? 0,
                    lastReportedAt: sourceReputation?.lastReportedAt,
                    categories: sourceReputation?.categories || []
                }
            },
            destination: {
                ip: context.destIp,
                reputation: {
                    vtDetections: destReputation?.vtMaliciousCount ?? 0,
                    abuseScore: destReputation?.abuseConfidenceScore ?? 0,
                    lastReportedAt: destReputation?.lastReportedAt,
                    categories: destReputation?.categories || []
                }
            },
            analysis: {
                timestamp: new Date().toISOString(),
                confirmationSources: this.getConfirmationSources(sourceReputation, destReputation),
                riskLevel: this.calculateRiskLevel(sourceReputation, destReputation)
            }
        }, null, 2);
    }

    private getConfirmationSources(sourceRep: any, destRep: any): string[] {
        const sources = [];
        
        if ((sourceRep?.vtMaliciousCount ?? 0) >= this.thresholds.vtMaliciousThreshold) {
            sources.push('VirusTotal');
        }
        if ((sourceRep?.abuseConfidenceScore ?? 0) >= this.thresholds.abuseConfidenceThreshold) {
            sources.push('AbuseIPDB');
        }
        if ((destRep?.vtMaliciousCount ?? 0) >= this.thresholds.vtMaliciousThreshold) {
            sources.push('VirusTotal (Destination)');
        }
        if ((destRep?.abuseConfidenceScore ?? 0) >= this.thresholds.abuseConfidenceThreshold) {
            sources.push('AbuseIPDB (Destination)');
        }
        
        return sources;
    }

    private calculateRiskLevel(sourceRep: any, destRep: any): string {
        const vtScore = Math.max(
            sourceRep?.vtMaliciousCount ?? 0,
            destRep?.vtMaliciousCount ?? 0
        );
        const abuseScore = Math.max(
            sourceRep?.abuseConfidenceScore ?? 0,
            destRep?.abuseConfidenceScore ?? 0
        );

        if (vtScore >= 5 || abuseScore >= 75) return 'HIGH';
        if (vtScore >= 2 || abuseScore >= 25) return 'MEDIUM';
        if (vtScore >= 1 || abuseScore >= 10) return 'LOW';
        return 'INFO';
    }
}

export const alertService = new AlertService(ipReputationService); 