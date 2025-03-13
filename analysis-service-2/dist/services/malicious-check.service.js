"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.maliciousCheckService = void 0;
const axios_1 = __importDefault(require("axios"));
class MaliciousCheckService {
    constructor() {
        this.apiUrl = 'https://ismalicious.com/api/check?';
    }
    /**
     * Checks if a packet is malicious by calling the isMalicious API
     * @param packet The packet data to check
     * @returns Result containing whether the packet is malicious and additional details
     */
    async checkPacket(packet) {
        try {
            // For demo purposes, we'll check the destination IP
            const ipToCheck = packet.dst_ip;
            const response = await axios_1.default.get(`${this.apiUrl}ip=${ipToCheck}`, {
                headers: {
                    'Accept': 'application/json'
                }
            });
            // Simplified response - only log essential information
            console.log(`[isMalicious Check] IP: ${ipToCheck} | Status: ${response.status} | Malicious: ${response.data.malicious || false}`);
            // Format the response according to the API documentation
            return {
                isMalicious: response.data.malicious || false,
                reasons: response.data.sources?.map((source) => ({
                    source: source.name,
                    category: source.category || 'unknown',
                    description: `Detected by ${source.name} (${source.type})`
                })) || [],
                threatLevel: response.data.reputation?.malicious > 3 ? 'high' : 'medium',
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            // Simplified error output
            const status = error.response?.status || 'unknown';
            console.error(`[isMalicious Check Error] Status: ${status} | Request failed for IP: ${packet.dst_ip}`);
            // Return a default non-malicious result in case of error
            return {
                isMalicious: false,
                reasons: [],
                threatLevel: 'unknown',
                timestamp: new Date().toISOString()
            };
        }
    }
}
// Export a singleton instance
exports.maliciousCheckService = new MaliciousCheckService();
//# sourceMappingURL=malicious-check.service.js.map