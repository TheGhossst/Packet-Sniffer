import { redisService } from './redis.service.js';
import { maliciousCheckService } from './malicious-check.service.js';
import { packetDisplayService } from './packet-display.service.js';
import { ipsumFeedService } from './ipsum-feed.service.js';
import { metricsService } from './metrics.service.js';
import { BatchData, PacketData } from '../types/packet.types.js';

class AnalysisService {
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
        await this.analyzePacket(packet);
        const endTime = performance.now();
        
        metricsService.incrementPacketsProcessed();
        metricsService.observeProcessingDuration((endTime - startTime) / 1000); // Convert ms to seconds
        metricsService.observePacketSize(packet.packet_size);
      }
    } catch (error) {
      console.error('Error processing packet:', error);
      metricsService.incrementProcessingErrors();
    }
  }

  /**
   * Analyze a single packet
   * - Check if it's malicious using the malicious check service
   * - Display the packet details
   */
  private async analyzePacket(packet: PacketData): Promise<void> {
    try {
      const maliciousCheckResult = await maliciousCheckService.checkPacket(packet);

      const formattedPacket = packetDisplayService.formatPacketInfo(packet, maliciousCheckResult);

      console.log(formattedPacket);
      
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
}

export const analysisService = new AnalysisService();