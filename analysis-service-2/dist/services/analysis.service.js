"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analysisService = void 0;
const redis_service_js_1 = require("./redis.service.js");
const malicious_check_service_js_1 = require("./malicious-check.service.js");
const packet_display_service_js_1 = require("./packet-display.service.js");
class AnalysisService {
    /**
     * Start the analysis service
     * - Connect to Redis
     * - Subscribe to the packet-stream channel
     * - Process incoming packets
     */
    async start() {
        console.info('Starting simplified analysis service...');
        try {
            // Connect to Redis
            const connected = await redis_service_js_1.redisService.connect();
            if (connected) {
                // Subscribe to the packet stream
                await redis_service_js_1.redisService.subscribe('packet-stream', async (message) => {
                    await this.processPacket(message);
                });
                console.info('Analysis service started successfully');
            }
            else {
                console.error('Failed to connect to Redis - service cannot start');
            }
        }
        catch (error) {
            console.error('Error starting analysis service:', error);
        }
    }
    /**
     * Process a packet message received from Redis
     * - Parse the message as JSON
     * - For each packet in the batch, check if it's malicious
     * - Display the packet details
     */
    async processPacket(message) {
        try {
            // Parse the message as JSON
            const data = JSON.parse(message);
            console.info(`\nProcessing batch ${data.batchId} with ${data.packets.length} packets`);
            console.info(`Timestamp: ${data.timestamp}`);
            // Process each packet in the batch
            for (const packet of data.packets) {
                await this.analyzePacket(packet);
            }
        }
        catch (error) {
            console.error('Error processing packet:', error);
        }
    }
    /**
     * Analyze a single packet
     * - Check if it's malicious using the malicious check service
     * - Display the packet details
     */
    async analyzePacket(packet) {
        try {
            // Check if the packet is malicious
            const maliciousCheckResult = await malicious_check_service_js_1.maliciousCheckService.checkPacket(packet);
            // Display the packet details
            const formattedPacket = packet_display_service_js_1.packetDisplayService.formatPacketInfo(packet, maliciousCheckResult);
            // Output to console
            console.log(formattedPacket);
        }
        catch (error) {
            console.error('Error analyzing packet:', error);
        }
    }
}
exports.analysisService = new AnalysisService();
//# sourceMappingURL=analysis.service.js.map