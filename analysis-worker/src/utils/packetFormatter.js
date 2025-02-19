class PacketFormatter {
    static formatPacket(packet) {
        const timestamp = new Date(packet.timestamp).toISOString();
        const connection = `${packet.src_ip}:${packet.src_port} -> ${packet.dst_ip}:${packet.dst_port}`;
        const details = `[${packet.protocol}] Size: ${packet.packet_size}b, Payload: ${packet.payload_size}b`;
        
        return {
            timestamp,
            connection,
            details,
            formatted: `${timestamp} | ${connection} | ${details}`
        };
    }

    static formatAlert(alert) {
        return {
            timestamp: new Date(alert.timestamp).toISOString(),
            type: alert.type.padEnd(20),
            severity: alert.severity.padStart(8),
            details: alert.details,
            formatted: `[${alert.severity}] ${alert.type}: ${alert.details}`
        };
    }

    static colorize(text, type) {
        const colors = {
            HIGH: '\x1b[31m',    // Red
            MEDIUM: '\x1b[33m',  // Yellow
            LOW: '\x1b[32m',     // Green
            INFO: '\x1b[36m',    // Cyan
            reset: '\x1b[0m'
        };

        return `${colors[type] || ''}${text}${colors.reset}`;
    }
}

module.exports = PacketFormatter; 