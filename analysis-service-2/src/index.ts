import * as dotenv from 'dotenv';
dotenv.config();

console.log('===== ENVIRONMENT VARIABLES =====');
console.log('VIRUSTOTAL_API_KEY:', process.env.VIRUSTOTAL_API_KEY ? `✓ Set (length: ${process.env.VIRUSTOTAL_API_KEY.length})` : '❌ Not set');
console.log('ABUSEIPDB_API_KEY:', process.env.ABUSEIPDB_API_KEY ? `✓ Set (length: ${process.env.ABUSEIPDB_API_KEY.length})` : '❌ Not set');
console.log('REDIS_HOST:', process.env.REDIS_HOST || 'Not set');
console.log('REDIS_PORT:', process.env.REDIS_PORT || 'Not set');
console.log('FORCE_EXTERNAL_API_CHECKS:', process.env.FORCE_EXTERNAL_API_CHECKS || 'Not set');
console.log('================================');

import { analysisService } from './services/analysis.service';
import { metricsServerService } from './services/metrics-server.service';

console.log('==================================================');
console.log('         Simple Packet Analysis Service           ');
console.log('==================================================');
console.log('Connecting to Redis...');

metricsServerService.start().catch((error: Error) => {
  console.error('Failed to start metrics server:', error);
});

analysisService.start().catch((error: Error) => {
  console.error('Failed to start analysis service:', error);
  process.exit(1);
});

process.on('SIGINT', () => {
  console.log('Service shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('Service shutting down...');
  process.exit(0);
});

process.on('uncaughtException', (error: Error) => {
  console.error('Uncaught exception:', error);
  process.exit(1);
});