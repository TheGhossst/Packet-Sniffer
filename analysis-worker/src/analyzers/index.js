const PortScanDetector = require('./portScan');
const ProtocolAnalyzer = require('./protocolAnomaly');
const ThreatIntel = require('./threatIntel');
const Logger = require('../utils/logger');

class PacketAnalyzer {
    constructor() {
        this.portScanner = new PortScanDetector();
        this.protocolAnalyzer = new ProtocolAnalyzer();
        this.threatIntel = new ThreatIntel();
        this.knownServices = new Set([80, 443, 53, 22, 25]); // Common legitimate services
        this.logger = new Logger({ level: process.env.LOG_LEVEL || 'debug' });
    }

    async init() {
        await this.threatIntel.init();
    }

    async analyzePacket(packet) {
        const alerts = [];

        try {
            this.logger.debug('Analyzing packet:', { packet });

            // Basic packet validation
            if (!this.isValidPacket(packet)) {
                this.logger.warn('Invalid packet structure', { packet });
                return [];
            }

            // Skip analysis for known legitimate service ports unless suspicious
            if (this.isLegitimateTraffic(packet)) {
                this.logger.debug('Legitimate traffic detected', { 
                    packet,
                    service: `${packet.protocol}:${packet.dst_port}`
                });
                return [];
            }

            // Protocol anomaly detection
            const protocolAlerts = this.protocolAnalyzer.detectAnomalies(packet);
            if (protocolAlerts.length > 0) {
                this.logger.info('Protocol anomalies detected', { 
                    packet,
                    alerts: protocolAlerts 
                });
                alerts.push(...protocolAlerts);
            }

            // Port scan detection
            const portScanAlert = this.portScanner.analyze(packet);
            if (portScanAlert && this.shouldReportPortScan(portScanAlert)) {
                this.logger.info('Port scan detected', { 
                    packet,
                    alert: portScanAlert 
                });
                alerts.push(portScanAlert);
            }

            // Threat intelligence check
            const threatData = await this.threatIntel.checkIP(packet.src_ip);
            if (threatData && threatData.isMailicious) {
                const alert = {
                    type: 'KNOWN_THREAT',
                    severity: 'HIGH',
                    details: `Known malicious IP detected: ${packet.src_ip}`,
                    timestamp: packet.timestamp,
                    metadata: threatData
                };
                this.logger.info('Threat intelligence alert', { 
                    packet,
                    alert 
                });
                alerts.push(alert);
            }

            if (alerts.length > 0) {
                this.logger.info('Analysis summary', { 
                    packet,
                    alerts,
                    alertCount: alerts.length
                });
            }

        } catch (error) {
            this.logger.error('Analysis error', { 
                error: error.message,
                packet
            });
            alerts.push({
                type: 'ANALYSIS_ERROR',
                severity: 'HIGH',
                details: 'Error analyzing packet',
                timestamp: packet.timestamp,
                metadata: { error: error.message }
            });
        }

        return alerts;
    }

    isValidPacket(packet) {
        return (
            packet &&
            packet.protocol &&
            packet.src_ip &&
            packet.dst_ip &&
            packet.timestamp &&
            typeof packet.src_port === 'number' &&
            typeof packet.dst_port === 'number'
        );
    }

    isLegitimateTraffic(packet) {
        // Check if this is normal traffic to common services
        return (
            this.knownServices.has(packet.dst_port) &&
            packet.protocol === 'TCP' &&
            !this.hasAnomalousCharacteristics(packet)
        );
    }

    hasAnomalousCharacteristics(packet) {
        return (
            packet.payload_size > 10000 || // Unusually large payload
            packet.flags?.includes('SYN') && packet.flags?.includes('FIN') || // Invalid flag combination
            packet.packet_count > 100 // High packet count
        );
    }

    shouldReportPortScan(alert) {
        // Additional validation to reduce false positives
        return (
            alert.metadata.portCount >= 3 && // Minimum unique ports
            parseFloat(alert.metadata.scanRate) < 1000 && // Reasonable scan rate
            parseFloat(alert.metadata.timespan) > 0.1 // Minimum time window
        );
    }

    async cleanup() {
        try {
            await this.threatIntel.cache.cleanup();
            // Clear any internal state
            this.portScanner.connectionAttempts.clear();
            this.protocolAnalyzer.tcpStateTracker.clear();
        } catch (error) {
            console.error('PacketAnalyzer cleanup failed:', error);
            throw error;
        }
    }
}

module.exports = PacketAnalyzer; 