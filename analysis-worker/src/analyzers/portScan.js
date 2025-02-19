class PortScanDetector {
    constructor() {
        // Configurable thresholds from environment variables
        this.threshold = parseInt(process.env.PORT_SCAN_THRESHOLD) || 10; // ports per second
        this.timeWindow = parseInt(process.env.PORT_SCAN_WINDOW) || 1000; // milliseconds
        this.minPorts = 3; // Minimum number of unique ports to consider as scan
        this.connectionAttempts = new Map();
        this.lastCleanup = Date.now();
    }

    analyze(packet) {
        const key = `${packet.src_ip}-${packet.dst_ip}`;
        const now = Date.now();

        // Periodic cleanup of old entries
        if (now - this.lastCleanup > 10000) { // Every 10 seconds
            this.cleanup();
            this.lastCleanup = now;
        }

        if (!this.connectionAttempts.has(key)) {
            this.connectionAttempts.set(key, {
                ports: new Set([packet.dst_port]),
                firstSeen: now,
                lastSeen: now,
                packetCount: 1
            });
            return null;
        }

        const attempt = this.connectionAttempts.get(key);
        attempt.ports.add(packet.dst_port);
        attempt.packetCount++;
        attempt.lastSeen = now;

        // Calculate time window and scan metrics
        const timespan = (attempt.lastSeen - attempt.firstSeen) / 1000; // Convert to seconds
        const portCount = attempt.ports.size;
        
        // Avoid division by zero and ensure minimum time window
        const scanRate = timespan < 0.1 ? 0 : portCount / timespan;

        // Clean up old entries
        if (now - attempt.firstSeen > this.timeWindow) {
            this.connectionAttempts.delete(key);
            return null;
        }

        // Enhanced port scan detection logic
        if (this.isPortScan(attempt, scanRate, timespan)) {
            return {
                type: 'PORT_SCAN',
                severity: this.determineSeverity(portCount, scanRate),
                details: `Port scan detected from ${packet.src_ip}: ${portCount} unique ports in ${timespan.toFixed(2)}s`,
                timestamp: packet.timestamp,
                metadata: {
                    sourceIP: packet.src_ip,
                    targetIP: packet.dst_ip,
                    portCount,
                    uniquePorts: Array.from(attempt.ports),
                    scanRate: scanRate.toFixed(2),
                    timespan: timespan.toFixed(2),
                    packetCount: attempt.packetCount
                }
            };
        }

        return null;
    }

    isPortScan(attempt, scanRate, timespan) {
        // Multiple conditions for port scan detection
        return (
            attempt.ports.size >= this.minPorts && // Minimum number of unique ports
            scanRate > this.threshold && // Rate exceeds threshold
            timespan > 0.1 && // Minimum time window to avoid false positives
            attempt.packetCount > attempt.ports.size // Multiple attempts indicator
        );
    }

    determineSeverity(portCount, scanRate) {
        if (portCount > 50 || scanRate > 100) return 'CRITICAL';
        if (portCount > 20 || scanRate > 50) return 'HIGH';
        if (portCount > 10 || scanRate > 20) return 'MEDIUM';
        return 'LOW';
    }

    cleanup() {
        const now = Date.now();
        for (const [key, attempt] of this.connectionAttempts.entries()) {
            if (now - attempt.lastSeen > this.timeWindow) {
                this.connectionAttempts.delete(key);
            }
        }
    }
}

module.exports = PortScanDetector; 