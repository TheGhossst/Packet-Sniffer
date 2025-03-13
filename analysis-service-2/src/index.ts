import { analysisService } from './services/analysis.service';

console.log('==================================================');
console.log('         Simple Packet Analysis Service           ');
console.log('==================================================');
console.log('Connecting to Redis...');

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