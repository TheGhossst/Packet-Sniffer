"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const analysis_service_1 = require("./services/analysis.service");
// No need to define __dirname in CommonJS mode as it's already available
// Load environment variables
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, '../.env') });
// Display startup information
console.log('==================================================');
console.log('         Simple Packet Analysis Service           ');
console.log('==================================================');
console.log('Connecting to Redis...');
// Start the analysis service
analysis_service_1.analysisService.start().catch((error) => {
    console.error('Failed to start analysis service:', error);
    process.exit(1);
});
// Handle process termination
process.on('SIGINT', () => {
    console.log('Service shutting down...');
    process.exit(0);
});
process.on('SIGTERM', () => {
    console.log('Service shutting down...');
    process.exit(0);
});
process.on('uncaughtException', (error) => {
    console.error('Uncaught exception:', error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map