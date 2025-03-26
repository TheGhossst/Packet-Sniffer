import { redisService } from './redis.service.js';
import { maliciousCheckService } from './malicious-check.service.js';
import { packetDisplayService } from './packet-display.service.js';
import { ipsumFeedService } from './ipsum-feed.service.js';
import { metricsService } from './metrics.service.js';
import { behavioralAnalysisService } from './behavioral-analysis.service.js';
import { BatchData, PacketData, ProtocolAnalysisResult, BehavioralAnomaly } from '../types/packet.types.js';

class AnalysisService {
  // Track when we last updated suspicious connections metrics
  private lastMetricsUpdate = 0;
  private metricsUpdateInterval = 60000; // 1 minute

  /**
   * Start the analysis service
   * - Connect to Redis
   * - Initialize the Ipsum feed service
   * - Subscribe to the packet-stream channel
   * - Process incoming packets
   */
  public async start(): Promise<void> {
    console.info('Starting simplified analysis service...');

    try {
      const connected = await redisService.connect();

      if (connected) {
        await ipsumFeedService.initialize();
        console.info('Ipsum feed service initialized');

        await redisService.subscribe('packet-stream', async (message: string) => {
          await this.processPacket(message);
        });
        console.info('Analysis service started successfully');
      } else {
        console.error('Failed to connect to Redis - service cannot start');
        metricsService.incrementProcessingErrors();
      }
    } catch (error) {
      console.error('Error starting analysis service:', error);
      metricsService.incrementProcessingErrors();
    }
  }

  /**
   * Process a packet message received from Redis
   * - Parse the message as JSON
   * - For each packet in the batch, check if it's malicious
   * - Display the packet details
   */
  private async processPacket(message: string): Promise<void> {
    try {
      const data: BatchData = JSON.parse(message);

      console.info(`\nProcessing batch ${data.batchId} with ${data.packets.length} packets`);
      console.info(`Timestamp: ${data.timestamp}`);

      for (const packet of data.packets) {
        const startTime = performance.now();
        
        // Check if packet has payload data that needs Base64 decoding
        if (packet.payload && typeof packet.payload === 'string') {
          console.info(`Packet has payload data (${packet.payload.length} bytes)`);
          
          // Payload is already prepared in the packet object
          // The DPI service will handle decoding it from Base64
        }
        
        await this.analyzePacket(packet);
        const endTime = performance.now();
        
        metricsService.incrementPacketsProcessed();
        metricsService.observeProcessingDuration((endTime - startTime) / 1000); // Convert ms to seconds
        metricsService.observePacketSize(packet.packet_size);
        
        // Update suspicious connections metrics periodically
        const now = Date.now();
        if (now - this.lastMetricsUpdate > this.metricsUpdateInterval) {
          const suspiciousIps = behavioralAnalysisService.getSuspiciousIps();
          metricsService.setSuspiciousConnections(suspiciousIps.length);
          this.lastMetricsUpdate = now;
          
          if (suspiciousIps.length > 0) {
            console.info(`[Behavioral Analysis] Tracking ${suspiciousIps.length} suspicious IPs`);
          }
        }
      }
    } catch (error) {
      console.error('Error processing packet:', error);
      metricsService.incrementProcessingErrors();
    }
  }

  /**
   * Analyze a single packet
   * - Check if it's malicious using the malicious check service
   * - Perform behavioral analysis
   * - Display the packet details
   */
  private async analyzePacket(packet: PacketData): Promise<void> {
    try {
      // Perform malicious check analysis (IP-based + DPI)
      const maliciousCheckResult = await maliciousCheckService.checkPacket(packet);
      
      // Perform behavioral analysis
      const behavioralResult = behavioralAnalysisService.analyzePacket(packet);
      
      // Extract DPI results if they exist
      const dpiResults: ProtocolAnalysisResult | undefined = maliciousCheckResult.protocolAnalysis;
      
      // Format packet information for display
      const formattedPacket = packetDisplayService.formatPacketInfo(packet, maliciousCheckResult);
      console.log(formattedPacket);
      
      // Display behavioral analysis anomalies if found
      if (behavioralResult.anomalies.length > 0) {
        console.log('\n=== BEHAVIORAL ANALYSIS ANOMALIES ===');
        behavioralResult.anomalies.forEach(anomaly => {
          const severityColor = this.getSeverityColor(anomaly.severity);
          console.log(`${severityColor}[${anomaly.severity.toUpperCase()}] ${anomaly.description} (${Math.round(anomaly.confidence * 100)}% confidence)`);
        });
        console.log('====================================\n');
        
        // Update the malicious check result to include behavioral anomalies
        this.updateThreatLevelBasedOnBehavior(maliciousCheckResult, behavioralResult.anomalies);
      }
      
      // If we have DPI results and they're suspicious, log them
      if (dpiResults?.isSuspicious) {
        const findingsDetails = dpiResults.findings.map(f => 
          `[${f.severity.toUpperCase()}] ${f.type}: ${f.description}`
        ).join('\n');
        
        console.log(`\n=== DPI FINDINGS (${dpiResults.protocol}) ===`);
        console.log(findingsDetails);
        console.log(`Confidence: ${dpiResults.confidence * 100}%`);
        console.log('===============================\n');
      }
      
      if (maliciousCheckResult.isMalicious) {
        const threatLevel = maliciousCheckResult.threatLevel || 'unknown';
        metricsService.incrementMaliciousPackets(threatLevel);
        
        switch (threatLevel) {
          case 'high':
            metricsService.setThreatLevel(3);
            break;
          case 'medium':
            metricsService.setThreatLevel(2);
            break;
          case 'unknown':
            metricsService.setThreatLevel(1);
            break;
          case 'safe':
          default:
            metricsService.setThreatLevel(0);
        }
        
        if (maliciousCheckResult.details?.source === 'ipsum') {
          metricsService.incrementIpsumBlacklistHits();
        }
      } else if (maliciousCheckResult.details?.source === 'safe-list') {
        metricsService.incrementSafeListHits();
        metricsService.setThreatLevel(0);
      } else {
        metricsService.setThreatLevel(1);
      }
    } catch (error) {
      console.error('Error analyzing packet:', error);
      metricsService.incrementProcessingErrors();
    }
  }
  
  /**
   * Update the threat level based on behavioral analysis results
   */
  private updateThreatLevelBasedOnBehavior(
    maliciousCheckResult: any, 
    anomalies: BehavioralAnomaly[]
  ): void {
    // If already malicious, don't downgrade
    if (maliciousCheckResult.isMalicious) {
      return;
    }
    
    // Check if we have any high severity anomalies
    const highSeverityAnomaly = anomalies.find(a => a.severity === 'high' && a.confidence > 0.7);
    
    if (highSeverityAnomaly) {
      maliciousCheckResult.isMalicious = true;
      maliciousCheckResult.threatLevel = 'high';
      
      // Add reason
      if (!maliciousCheckResult.reasons) {
        maliciousCheckResult.reasons = [];
      }
      
      maliciousCheckResult.reasons.push({
        source: 'behavioral-analysis',
        category: 'anomaly',
        description: highSeverityAnomaly.description
      });
      
      // Update score
      if (maliciousCheckResult.score !== undefined) {
        maliciousCheckResult.score = Math.max(maliciousCheckResult.score, 0.8);
      } else {
        maliciousCheckResult.score = 0.8;
      }
      
      // Update details
      if (!maliciousCheckResult.details) {
        maliciousCheckResult.details = {};
      }
      
      maliciousCheckResult.details.behavioralAnomalies = anomalies;
    }
    // Multiple medium severity anomalies
    else if (anomalies.filter(a => a.severity === 'medium' && a.confidence > 0.6).length >= 2) {
      maliciousCheckResult.isMalicious = true;
      maliciousCheckResult.threatLevel = 'medium';
      
      // Add reason
      if (!maliciousCheckResult.reasons) {
        maliciousCheckResult.reasons = [];
      }
      
      maliciousCheckResult.reasons.push({
        source: 'behavioral-analysis',
        category: 'anomaly',
        description: 'Multiple suspicious behavioral patterns detected'
      });
      
      // Update score
      if (maliciousCheckResult.score !== undefined) {
        maliciousCheckResult.score = Math.max(maliciousCheckResult.score, 0.6);
      } else {
        maliciousCheckResult.score = 0.6;
      }
      
      // Update details
      if (!maliciousCheckResult.details) {
        maliciousCheckResult.details = {};
      }
      
      maliciousCheckResult.details.behavioralAnomalies = anomalies;
    }
  }
  
  /**
   * Get color code for severity level
   */
  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'high':
        return '\x1b[31m'; // Red
      case 'medium':
        return '\x1b[33m'; // Yellow
      case 'low':
        return '\x1b[36m'; // Cyan
      default:
        return '\x1b[37m'; // White
    }
  }
}

export const analysisService = new AnalysisService();