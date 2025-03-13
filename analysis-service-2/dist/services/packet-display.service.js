"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.packetDisplayService = void 0;
const chalk_1 = __importDefault(require("chalk"));
class PacketDisplayService {
    /**
     * Formats packet information in a structured and readable way
     */
    formatPacketInfo(packet, maliciousCheck) {
        const timestamp = new Date(packet.timestamp).toLocaleString();
        // Basic packet information
        let output = `
${chalk_1.default.blue('┌───────────────────────────────────────────────────────────────────────┐')}
${chalk_1.default.blue('│')} ${chalk_1.default.white.bold('PACKET DETAILS')}                                                       ${chalk_1.default.blue('│')}
${chalk_1.default.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Connection')}      : ${chalk_1.default.yellow(packet.src_ip)}:${chalk_1.default.yellow(packet.src_port)} → ${chalk_1.default.yellow(packet.dst_ip)}:${chalk_1.default.yellow(packet.dst_port)}   ${chalk_1.default.blue('│')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Protocol')}        : ${chalk_1.default.yellow(packet.protocol.padEnd(10))}                                      ${chalk_1.default.blue('│')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Size')}            : ${chalk_1.default.yellow(packet.packet_size + ' bytes')}                                      ${chalk_1.default.blue('│')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Type')}            : ${chalk_1.default.yellow(packet.packet_type)}                                      ${chalk_1.default.blue('│')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Timestamp')}       : ${chalk_1.default.yellow(timestamp)}                      ${chalk_1.default.blue('│')}`;
        // Add threat analysis if available
        if (maliciousCheck) {
            const threatColor = maliciousCheck.isMalicious ? chalk_1.default.red : chalk_1.default.green;
            const threatStatus = maliciousCheck.isMalicious ? 'MALICIOUS' : 'BENIGN';
            const threatLevel = maliciousCheck.threatLevel || 'unknown';
            output += `
${chalk_1.default.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk_1.default.blue('│')} ${chalk_1.default.white.bold('THREAT ANALYSIS')}                                                     ${chalk_1.default.blue('│')}
${chalk_1.default.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Status')}          : ${threatColor(threatStatus.padEnd(10))}                                      ${chalk_1.default.blue('│')}
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Threat Level')}    : ${threatColor(threatLevel.padEnd(10))}                                      ${chalk_1.default.blue('│')}`;
            // Only display reasons if packet is malicious
            if (maliciousCheck.isMalicious && maliciousCheck.reasons && maliciousCheck.reasons.length > 0) {
                output += `
${chalk_1.default.blue('│')} ${chalk_1.default.cyan('Reasons')}         : ${threatColor(maliciousCheck.reasons.length + ' detected')}                                    ${chalk_1.default.blue('│')}`;
            }
        }
        output += `
${chalk_1.default.blue('└───────────────────────────────────────────────────────────────────────┘')}`;
        return output;
    }
}
// Export a singleton instance
exports.packetDisplayService = new PacketDisplayService();
//# sourceMappingURL=packet-display.service.js.map