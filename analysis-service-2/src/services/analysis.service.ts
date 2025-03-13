import { redisService } from './redis.service.js';
import { maliciousCheckService } from './malicious-check.service.js';
import { packetDisplayService } from './packet-display.service.js';
import { BatchData, PacketData } from '../types/packet.types.js';

class AnalysisService {
  /**
   * Start the analysis service
   * - Connect to Redis
   * - Subscribe to the packet-stream channel
   * - Process incoming packets
   */
  public async start(): Promise<void> {
    console.info('Starting simplified analysis service...');

    try {
      // Connect to Redis
      const connected = await redisService.connect();

      if (connected) {
        // Subscribe to the packet stream
        await redisService.subscribe('packet-stream', async (message: string) => {
          await this.processPacket(message);
        });
        console.info('Analysis service started successfully');
      } else {
        console.error('Failed to connect to Redis - service cannot start');
      }
    } catch (error) {
      console.error('Error starting analysis service:', error);
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
      // Parse the message as JSON
      const data: BatchData = JSON.parse(message);

      console.info(`\nProcessing batch ${data.batchId} with ${data.packets.length} packets`);
      console.info(`Timestamp: ${data.timestamp}`);

      // Process each packet in the batch
      for (const packet of data.packets) {
        await this.analyzePacket(packet);
      }
    } catch (error) {
      console.error('Error processing packet:', error);
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
    } catch (error) {
      console.error('Error analyzing packet:', error);
    }
  }
}

export const analysisService = new AnalysisService();
