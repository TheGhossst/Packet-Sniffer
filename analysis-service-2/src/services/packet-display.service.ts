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
${chalk.blue('│')} ${chalk.cyan('Score')}           : ${threatColor(String(maliciousCheck.score.toFixed(2)).padEnd(10))}                                      ${chalk.blue('│')}`;
      }
      
      if (maliciousCheck.details?.sourceCount) {
        output += `
${chalk.blue('│')} ${chalk.cyan('Source Count')}    : ${threatColor(String(maliciousCheck.details.sourceCount).padEnd(10))}                                      ${chalk.blue('│')}`;
      }
      
      if (maliciousCheck.details?.enrichment) {
        const enrichment = maliciousCheck.details.enrichment;
        
        if (enrichment.country) {
          output += `
${chalk.blue('│')} ${chalk.cyan('Country')}         : ${chalk.yellow(String(enrichment.country).padEnd(10))}                                      ${chalk.blue('│')}`;
        }
        
        if (enrichment.isp) {
          output += `
${chalk.blue('│')} ${chalk.cyan('ISP')}             : ${chalk.yellow(String(enrichment.isp).padEnd(10))}                                      ${chalk.blue('│')}`;
        }
      }
      
      if (maliciousCheck.details?.results?.virusTotal) {
        const vt = maliciousCheck.details.results.virusTotal;
        if (vt.detections && vt.total) {
          output += `
${chalk.blue('│')} ${chalk.cyan('VirusTotal')}      : ${threatColor(`${vt.detections}/${vt.total} engines`.padEnd(10))}                                      ${chalk.blue('│')}`;
        }
      }
      
      if (maliciousCheck.details?.results?.abuseIPDB) {
        const abuse = maliciousCheck.details.results.abuseIPDB;
        if (abuse.confidenceScore !== undefined) {
          output += `
${chalk.blue('│')} ${chalk.cyan('AbuseIPDB')}       : ${threatColor(`${abuse.confidenceScore}% confidence`.padEnd(10))}                                      ${chalk.blue('│')}`;
        }
      }
      
      if (maliciousCheck.details?.results?.ipsum) {
        const ipsum = maliciousCheck.details.results.ipsum;
        if (ipsum.score !== undefined) {
          output += `
${chalk.blue('│')} ${chalk.cyan('Ipsum')}           : ${threatColor(`${ipsum.score} blacklists`.padEnd(10))}                                      ${chalk.blue('│')}`;
        }
      }
      
      output += `
${chalk.blue('└───────────────────────────────────────────────────────────────────────┘')}`;
    }

    return output;
  }
}

export const packetDisplayService = new PacketDisplayService();