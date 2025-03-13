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