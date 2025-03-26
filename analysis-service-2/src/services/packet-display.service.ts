import chalk from 'chalk';
import { PacketData, MaliciousCheckResult, ProtocolAnalysisResult, BehavioralAnomaly } from '../types/packet.types.js';

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

    // Add payload indicator if present
    if (packet.payload) {
      output += `
${chalk.blue('│')} ${chalk.cyan('Payload')}         : ${chalk.yellow('Present (' + packet.payload.length + ' bytes)')}                              ${chalk.blue('│')}`;
    }

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

      // Add behavioral analysis information if present
      if (maliciousCheck.details && maliciousCheck.details.behavioralAnomalies && maliciousCheck.details.behavioralAnomalies.length > 0) {
        const anomalies = maliciousCheck.details.behavioralAnomalies;
        const anomalyCount = anomalies.length;
        const highSeverityCount = anomalies.filter(a => a.severity === 'high').length;
        
        output += `
${chalk.blue('│')} ${chalk.cyan('Behavior')}        : ${threatColor(`${anomalyCount} anomalies detected`.padEnd(10))}                        ${chalk.blue('│')}`;
        
        if (highSeverityCount > 0) {
          output += `
${chalk.blue('│')} ${chalk.cyan('High Severity')}   : ${threatColor(`${highSeverityCount} anomalies`.padEnd(10))}                                  ${chalk.blue('│')}`;
        }
        
        // Add the most critical anomaly
        const criticalAnomaly = this.getMostCriticalAnomaly(anomalies);
        if (criticalAnomaly) {
          output += `
${chalk.blue('│')} ${chalk.cyan('Key Finding')}     : ${threatColor(criticalAnomaly.type.padEnd(10))}                               ${chalk.blue('│')}`;
        }
      }

      // Add DPI information if present
      const dpiResult = maliciousCheck.protocolAnalysis;
      if (dpiResult?.isSuspicious) {
        output += `
${chalk.blue('│')} ${chalk.cyan('DPI')}             : ${threatColor(`Suspicious ${dpiResult.protocol} traffic`.padEnd(10))}                ${chalk.blue('│')}`;
        
        // Add confidence score
        output += `
${chalk.blue('│')} ${chalk.cyan('DPI Confidence')}  : ${threatColor((dpiResult.confidence * 100).toFixed(1) + '%'.padEnd(10))}                                  ${chalk.blue('│')}`;
        
        // Add highest severity finding
        const highestSeverity = this.getHighestSeverityFinding(dpiResult);
        if (highestSeverity) {
          output += `
${chalk.blue('│')} ${chalk.cyan('Finding')}         : ${threatColor(highestSeverity.type.padEnd(10))}                                ${chalk.blue('│')}`;
        }
      }

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
  
  /**
   * Gets the highest severity finding from a protocol analysis result
   */
  private getHighestSeverityFinding(result: ProtocolAnalysisResult) {
    if (!result.findings || !result.findings.length) {
      return null;
    }
    
    // Priority: high > medium > low
    const highSeverity = result.findings.find(f => f.severity === 'high');
    if (highSeverity) return highSeverity;
    
    const mediumSeverity = result.findings.find(f => f.severity === 'medium');
    if (mediumSeverity) return mediumSeverity;
    
    return result.findings[0]; // Return first finding if no high/medium severity
  }
  
  /**
   * Gets the most critical anomaly from a list of behavioral anomalies
   */
  private getMostCriticalAnomaly(anomalies: BehavioralAnomaly[]) {
    if (!anomalies || !anomalies.length) {
      return null;
    }
    
    // First, try to find a high severity anomaly with high confidence
    const highSevHighConf = anomalies.find(a => a.severity === 'high' && a.confidence > 0.7);
    if (highSevHighConf) return highSevHighConf;
    
    // Then, any high severity anomaly
    const highSeverity = anomalies.find(a => a.severity === 'high');
    if (highSeverity) return highSeverity;
    
    // Then, medium severity with high confidence
    const medSevHighConf = anomalies.find(a => a.severity === 'medium' && a.confidence > 0.7);
    if (medSevHighConf) return medSevHighConf;
    
    // Then, any medium severity
    const mediumSeverity = anomalies.find(a => a.severity === 'medium');
    if (mediumSeverity) return mediumSeverity;
    
    // Default to first anomaly
    return anomalies[0];
  }
}

export const packetDisplayService = new PacketDisplayService();