import { logger } from '../utils/logger';
import { Counter, Histogram } from 'prom-client';
import { PacketData } from '../types/packet.types';
import { Alert, AlertSeverity, alertService } from '../services/alert.service';
import { rateLimiter } from '../middleware/rate-limit';

export class PacketAnalyzer {
    private portScanThreshold: number;
    private portScanWindow: number;
    private synFloodThreshold: number;
    private synFloodWindow: number;
    private connectionTracker: Map<string, number>;
    private lastCleanup: number;

    // Prometheus metrics
    private packetsProcessed: Counter;
    private packetSize: Histogram;
    private analysisTime: Histogram;

    constructor() {
        this.portScanThreshold = parseInt(process.env.PORT_SCAN_THRESHOLD || '10');
        this.portScanWindow = parseInt(process.env.PORT_SCAN_WINDOW || '1000');
        this.synFloodThreshold = parseInt(process.env.SYN_FLOOD_THRESHOLD || '100');
        this.synFloodWindow = parseInt(process.env.SYN_FLOOD_WINDOW || '1000');
        this.connectionTracker = new Map();
        this.lastCleanup = Date.now();

        // Initialize metrics
        this.packetsProcessed = new Counter({
            name: 'packets_processed_total',
            help: 'Total number of packets processed'
        });

        this.packetSize = new Histogram({
            name: 'packet_size_bytes',
            help: 'Size of processed packets',
            buckets: [64, 128, 256, 512, 1024, 2048]
        });

        this.analysisTime = new Histogram({
            name: 'packet_analysis_duration_seconds',
            help: 'Time spent analyzing packets',
            buckets: [0.1, 0.5, 1, 2, 5]
        });
    }

    async analyzePacket(packet: PacketData): Promise<Alert[]> {
        const alerts: Alert[] = [];

        // Apply rate limiting
        const canProcess = await rateLimiter.checkLimit(`packet:${packet.src_ip}`);
        if (!canProcess) {
            return [this.createAlert('RATE_LIMIT_EXCEEDED', packet, AlertSeverity.HIGH)];
        }

        // Existing checks
        if (await this.detectPortScan(packet)) {
            alerts.push(this.createAlert('PORT_SCAN', packet, AlertSeverity.HIGH));
        }

        if (await this.detectSynFlood(packet)) {
            alerts.push(this.createAlert('SYN_FLOOD', packet, AlertSeverity.CRITICAL));
        }

        // New checks
        if (await this.detectDNSAmplification(packet)) {
            alerts.push(this.createAlert('DNS_AMPLIFICATION', packet, AlertSeverity.HIGH));
        }

        if (await this.detectICMPFlood(packet)) {
            alerts.push(this.createAlert('ICMP_FLOOD', packet, AlertSeverity.MEDIUM));
        }

        if (this.detectAnomalousPacketSize(packet)) {
            alerts.push(this.createAlert('ANOMALOUS_SIZE', packet, AlertSeverity.LOW));
        }

        // Process alerts
        for (const alert of alerts) {
            const aggregatedAlert = await alertService.aggregateAlerts(alert);
            await alertService.persistAlert(aggregatedAlert);
        }

        return alerts;
    }

    private createAlert(type: string, packet: PacketData, severity: AlertSeverity): Alert {
        return {
            id: `${type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
            severity,
            type,
            message: `${type} detected from ${packet.src_ip}`,
            sourceIp: packet.src_ip,
            count: 1,
            packets: [packet],
            metadata: {
                destination: packet.dst_ip,
                protocol: packet.protocol,
                size: packet.packet_size
            }
        };
    }

    private async detectPortScan(packet: PacketData): Promise<boolean> {
        const key = `${packet.src_ip}-ports`;
        const count = this.connectionTracker.get(key) || 0;
        this.connectionTracker.set(key, count + 1);

        return count >= this.portScanThreshold;
    }

    private async detectSynFlood(packet: PacketData): Promise<boolean> {
        if (packet.protocol === 'TCP') {
            const key = `${packet.src_ip}-syn`;
            const count = this.connectionTracker.get(key) || 0;
            this.connectionTracker.set(key, count + 1);

            return count >= this.synFloodThreshold;
        }
        return false;
    }

    private cleanupOldEntries(): void {
        const now = Date.now();
        if (now - this.lastCleanup > this.portScanWindow) {
            this.connectionTracker.clear();
            this.lastCleanup = now;
        }
    }

    private async detectDNSAmplification(packet: PacketData): Promise<boolean> {
        return packet.protocol === 'UDP' &&
            packet.dst_port === 53 &&
            packet.packet_size > 512;
    }

    private async detectICMPFlood(packet: PacketData): Promise<boolean> {
        if (packet.protocol !== 'ICMP') return false;

        const key = `${packet.src_ip}-icmp`;
        const count = this.connectionTracker.get(key) || 0;
        this.connectionTracker.set(key, count + 1);

        return count >= parseInt(process.env.ICMP_FLOOD_THRESHOLD || '50');
    }

    private detectAnomalousPacketSize(packet: PacketData): boolean {
        const avgSize = 500; // Consider making this dynamic based on historical data
        return packet.packet_size > avgSize * 3;
    }
} 