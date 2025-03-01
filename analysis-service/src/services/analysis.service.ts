import { logger } from '../utils/logger';
import { redisService } from './redis.service';
import { PacketAnalyzer } from '../analyzers/packet.analyzer';
import { MetricsService } from './metrics.service';
import chalk from 'chalk';
import { PacketData, BatchData } from '../types/packet.types';
import { Alert } from './alert.service';

export class AnalysisService {
    private workers: number;
    private packetAnalyzer: PacketAnalyzer;
    private metricsService: MetricsService;
    
    constructor() {
        this.workers = parseInt(process.env.ANALYSIS_WORKERS || '4');
        this.packetAnalyzer = new PacketAnalyzer();
        this.metricsService = new MetricsService();
    }

    private formatPacketInfo(packet: PacketData): string {
        return `
    ${chalk.cyan('Source')}: ${packet.src_ip}:${packet.src_port}
    ${chalk.cyan('Destination')}: ${packet.dst_ip}:${packet.dst_port}
    ${chalk.cyan('Protocol')}: ${packet.protocol}
    ${chalk.cyan('Size')}: ${packet.packet_size} bytes
    ${chalk.cyan('Type')}: ${packet.packet_type}
    ${chalk.cyan('Timestamp')}: ${packet.timestamp}`;
    }

    public async analyze(packet: PacketData): Promise<Alert[]> {
        try {
            const startTime = Date.now();
            const alerts = await this.packetAnalyzer.analyzePacket(packet);
            
            // Update metrics
            this.metricsService.incrementPacketsProcessed();
            if (alerts.length > 0) {
                this.metricsService.incrementAlertsGenerated();
            }
            this.metricsService.observeProcessingTime(Date.now() - startTime);

            return alerts;
        } catch (error) {
            const errorDetails = {
                message: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                sourceIp: packet.src_ip,
                destinationIp: packet.dst_ip,
                protocol: packet.protocol,
                timestamp: packet.timestamp,
                packetType: packet.packet_type
            };
            logger.error('Error analyzing packet:', errorDetails);
            throw error;
        }
    }

    public async getMetrics() {
        try {
            const [packetsProcessed, alertsGenerated, processingTime] = await Promise.all([
                this.metricsService.getPacketsProcessed(),
                this.metricsService.getAlertsGenerated(),
                this.metricsService.getProcessingTime()
            ]);

            return {
                packetsProcessed,
                alertsGenerated,
                processingTime
            };
        } catch (error) {
            const errorDetails = {
                message: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                service: 'metrics'
            };
            logger.error('Error fetching metrics:', errorDetails);
            throw error;
        }
    }

    public async start() {
        logger.info(`Starting analysis service with ${this.workers} workers`);
        
        // Start metrics server
        await this.metricsService.initialize();

        try {
            // Try to connect to Redis
            await redisService.connect();
            await redisService.subscribe('packet-stream', async (message) => {
                await this.processPacket(message);
            });
        } catch (error) {
            logger.warn('Redis connection failed - running without real-time packet processing');
        }
    }

    private async processPacket(message: string) {
        try {
            const data: BatchData = JSON.parse(message);
            
            logger.info(chalk.yellow('\n=== Batch Processing Start ==='));
            logger.info(chalk.blue(`Batch ID: ${data.batchId}`));
            logger.info(chalk.blue(`Timestamp: ${data.timestamp}`));
            logger.info(chalk.blue(`Packets in batch: ${data.packets.length}`));

            for (const packet of data.packets) {
                const alerts = await this.packetAnalyzer.analyzePacket(packet);
                
                if (alerts.length > 0) {
                    logger.warn(chalk.red('\n🚨 Alert Detected:'));
                    logger.warn(chalk.red(alerts.join('\n')));
                    logger.warn(chalk.yellow('\nPacket Details:'));
                    logger.warn(this.formatPacketInfo(packet));
                } else {
                    logger.debug(chalk.green('✓ Packet analyzed successfully:'));
                    logger.debug(this.formatPacketInfo(packet));
                }
            }

            logger.info(chalk.yellow('\n=== Batch Processing Complete ===\n'));

        } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logger.error(chalk.red(`\n❌ Error processing batch: ${errorMessage}\n`));
        }
    }
}

export const analysisService = new AnalysisService(); 