class ProtocolAnalyzer {
    constructor() {
        // Network and Transport layer protocols
        this.networkProtocols = new Set([
            'IPv4', 'IPv6', 'IPV4', 'IPV6', 'ICMP', 'ARP', 'IGMP'
        ]);

        // Application layer protocols
        this.applicationProtocols = new Set([
            'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 
            'POP3', 'IMAP', 'SNMP', 'DHCP', 'TELNET', 
            'RDP', 'SMB', 'NTP', 'LDAP', 'MQTT'
        ]);

        // Transport layer protocols
        this.transportProtocols = new Set(['TCP', 'UDP', 'SCTP']);

        // TCP state tracking
        this.tcpStateTracker = new Map();
        
        // Common port-protocol mappings with both TCP and UDP
        this.commonPorts = {
            20: { protocol: 'FTP-DATA', transport: 'TCP' },
            21: { protocol: 'FTP', transport: 'TCP' },
            22: { protocol: 'SSH', transport: 'TCP' },
            23: { protocol: 'TELNET', transport: 'TCP' },
            25: { protocol: 'SMTP', transport: 'TCP' },
            53: { protocol: 'DNS', transport: ['TCP', 'UDP'] },
            67: { protocol: 'DHCP', transport: 'UDP' },
            68: { protocol: 'DHCP', transport: 'UDP' },
            69: { protocol: 'TFTP', transport: 'UDP' },
            80: { protocol: 'HTTP', transport: 'TCP' },
            110: { protocol: 'POP3', transport: 'TCP' },
            123: { protocol: 'NTP', transport: 'UDP' },
            143: { protocol: 'IMAP', transport: 'TCP' },
            161: { protocol: 'SNMP', transport: 'UDP' },
            443: { protocol: 'HTTPS', transport: 'TCP' },
            445: { protocol: 'SMB', transport: 'TCP' },
            3389: { protocol: 'RDP', transport: 'TCP' }
        };
    }

    detectAnomalies(packet) {
        const alerts = [];
        
        // Normalize protocol name
        packet.protocol = packet.protocol.toUpperCase();

        // Skip analysis for known network layer protocols
        if (this.networkProtocols.has(packet.protocol)) {
            return [];
        }

        // Protocol validation
        if (!this.isKnownProtocol(packet.protocol)) {
            alerts.push(this.createUnknownProtocolAlert(packet));
        }

        // Port-protocol mismatch detection
        const portAlert = this.detectPortMismatch(packet);
        if (portAlert) alerts.push(portAlert);

        // Protocol-specific analysis
        const protocolAlert = this.analyzeProtocolBehavior(packet);
        if (protocolAlert) alerts.push(protocolAlert);

        return alerts;
    }

    isKnownProtocol(protocol) {
        return (
            this.networkProtocols.has(protocol) ||
            this.transportProtocols.has(protocol) ||
            this.applicationProtocols.has(protocol)
        );
    }

    createUnknownProtocolAlert(packet) {
        return {
            type: 'UNKNOWN_PROTOCOL',
            severity: 'MEDIUM',
            details: `Unknown protocol detected: ${packet.protocol}`,
            timestamp: packet.timestamp,
            metadata: {
                protocol: packet.protocol,
                sourceIP: packet.src_ip,
                destinationIP: packet.dst_ip,
                sourcePort: packet.src_port,
                destinationPort: packet.dst_port,
                packetSize: packet.packet_size,
                payloadSize: packet.payload_size
            }
        };
    }

    detectPortMismatch(packet) {
        const portInfo = this.commonPorts[packet.dst_port];
        
        if (portInfo) {
            const expectedTransport = Array.isArray(portInfo.transport) 
                ? portInfo.transport 
                : [portInfo.transport];

            if (!expectedTransport.includes(packet.protocol) && 
                !this.networkProtocols.has(packet.protocol)) {
                return {
                    type: 'PORT_PROTOCOL_MISMATCH',
                    severity: 'HIGH',
                    details: `Unexpected protocol ${packet.protocol} on port ${packet.dst_port} (expected ${expectedTransport.join(' or ')})`,
                    timestamp: packet.timestamp,
                    metadata: {
                        detectedProtocol: packet.protocol,
                        expectedProtocol: portInfo.protocol,
                        expectedTransport,
                        port: packet.dst_port,
                        sourceIP: packet.src_ip,
                        destinationIP: packet.dst_ip
                    }
                };
            }
        }

        return null;
    }

    analyzeProtocolBehavior(packet) {
        // TCP-specific analysis
        if (packet.protocol === 'TCP') {
            return this.analyzeTCPBehavior(packet);
        }

        // HTTP(S) analysis
        if (packet.dst_port === 80 || packet.dst_port === 443) {
            return this.analyzeHTTPTraffic(packet);
        }

        return null;
    }

    analyzeTCPBehavior(packet) {
        if (!packet.tcp_flags) {
            return {
                type: 'MALFORMED_TCP',
                severity: 'HIGH',
                details: 'TCP packet without flags detected',
                timestamp: packet.timestamp,
                metadata: {
                    sourceIP: packet.src_ip,
                    destinationIP: packet.dst_ip,
                    sourcePort: packet.src_port,
                    destinationPort: packet.dst_port
                }
            };
        }
        return null;
    }

    analyzeHTTPTraffic(packet) {
        const isHTTPS = packet.dst_port === 443;
        if (packet.protocol !== 'TCP') {
            return {
                type: 'INVALID_HTTP_PROTOCOL',
                severity: 'HIGH',
                details: `${isHTTPS ? 'HTTPS' : 'HTTP'} traffic detected on non-TCP protocol`,
                timestamp: packet.timestamp,
                metadata: {
                    protocol: packet.protocol,
                    port: packet.dst_port,
                    sourceIP: packet.src_ip,
                    destinationIP: packet.dst_ip
                }
            };
        }
        return null;
    }
}

module.exports = ProtocolAnalyzer; 