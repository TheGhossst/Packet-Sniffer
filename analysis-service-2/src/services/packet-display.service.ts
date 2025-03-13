import chalk from 'chalk';
import { PacketData, MaliciousCheckResult } from '../types/packet.types.js';

class PacketDisplayService {
  /**
   * Formats packet information in a structured and readable way
   */
  formatPacketInfo(packet: PacketData, maliciousCheck?: MaliciousCheckResult): string {
    const timestamp = new Date(packet.timestamp).toLocaleString();

    let output = `
${chalk.blue('┌───────────────────────────────────────────────────────────────────────┐')}
${chalk.blue('│')} ${chalk.white.bold('PACKET DETAILS')}                                                       ${chalk.blue('│')}
${chalk.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk.blue('│')} ${chalk.cyan('Connection')}      : ${chalk.yellow(packet.src_ip)}:${chalk.yellow(packet.src_port)} → ${chalk.yellow(packet.dst_ip)}:${chalk.yellow(packet.dst_port)}   ${chalk.blue('│')}
${chalk.blue('│')} ${chalk.cyan('Protocol')}        : ${chalk.yellow(packet.protocol.padEnd(10))}                                      ${chalk.blue('│')}
${chalk.blue('│')} ${chalk.cyan('Size')}            : ${chalk.yellow(packet.packet_size + ' bytes')}                                      ${chalk.blue('│')}
${chalk.blue('│')} ${chalk.cyan('Type')}            : ${chalk.yellow(packet.packet_type)}                                      ${chalk.blue('│')}
${chalk.blue('│')} ${chalk.cyan('Timestamp')}       : ${chalk.yellow(timestamp)}                      ${chalk.blue('│')}`;

    if (maliciousCheck) {
      const threatColor = maliciousCheck.isMalicious ? chalk.red : chalk.green;
      const threatStatus = maliciousCheck.isMalicious ? 'Unsafe' : 'Safe';
      
      let threatLevel = maliciousCheck.threatLevel || 'unknown';
      if (threatLevel === 'unknown' && !maliciousCheck.isMalicious) {
        threatLevel = 'not in blacklist';
      } else if (threatLevel === 'safe') {
        threatLevel = 'trusted';
      }

      output += `
${chalk.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk.blue('│')} ${chalk.white.bold('THREAT ANALYSIS')}                                                     ${chalk.blue('│')}
${chalk.blue('├───────────────────────────────────────────────────────────────────────┤')}
${chalk.blue('│')} ${chalk.cyan('Status')}          : ${threatColor(threatStatus.padEnd(10))}                                      ${chalk.blue('│')}
${chalk.blue('│')} ${chalk.cyan('Threat Level')}    : ${threatColor(threatLevel.padEnd(10))}                                      ${chalk.blue('│')}`;

      if (maliciousCheck.details?.source) {
        const source = maliciousCheck.details.source;
        output += `
${chalk.blue('│')} ${chalk.cyan('Source')}          : ${threatColor(source.padEnd(10))}                                      ${chalk.blue('│')}`;
      }
      
      if (maliciousCheck.score !== undefined) {
        output += `
${chalk.blue('│')} ${chalk.cyan('Score')}           : ${threatColor(String(maliciousCheck.score).padEnd(10))}                                      ${chalk.blue('│')}`;
      }

      if (maliciousCheck.isMalicious && maliciousCheck.reasons && maliciousCheck.reasons.length > 0) {
        output += `
${chalk.blue('│')} ${chalk.cyan('Reasons')}         : ${threatColor(maliciousCheck.reasons.length + ' detected')}                                    ${chalk.blue('│')}`;
      }
    }

    output += `
${chalk.blue('└───────────────────────────────────────────────────────────────────────┘')}`;

    return output;
  }
}

export const packetDisplayService = new PacketDisplayService();