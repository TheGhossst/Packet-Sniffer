import { maliciousCheckService } from './services/malicious-check.service.js';
import { ipsumFeedService } from './services/ipsum-feed.service.js';
import { packetDisplayService } from './services/packet-display.service.js';
import { PacketData } from './types/packet.types.js';

// Sample unsafe IPs from the ipsum cache (with high scores)
const unsafeIps = [
  '93.174.95.106',   // Score: 8
  '156.59.97.86',    // Score: 8
  '193.32.162.131',  // Score: 8
  '218.92.0.219',    // Score: 8
  '92.118.39.74'     // Score: 7
];

// Sample safe IPs for comparison
const safeIps = [
  '8.8.8.8',        // Google DNS (not in blacklist)
  '1.1.1.1',        // Cloudflare DNS (not in blacklist)
  '192.168.1.1'     // Common private IP (not in blacklist)
];

// Also test a safe IP that we'll explicitly add to the safe list
const explicitlySafeIp = '93.174.95.107'; // Similar to a malicious IP but marked as safe

async function runTest() {
  console.log('Initializing Ipsum Feed service...');
  await ipsumFeedService.initialize();

  console.log(`\nAdding ${explicitlySafeIp} to safe list for testing...`);
  await maliciousCheckService.addSafeIp(explicitlySafeIp);

  console.log('\n===== TESTING UNSAFE IPS =====');

  for (const ip of unsafeIps) {
    const testPacket: PacketData = createSamplePacket(ip);
    console.log(`\nTesting IP: ${ip}`);

    const result = await maliciousCheckService.checkPacket(testPacket);
    const display = packetDisplayService.formatPacketInfo(testPacket, result);

    console.log(display);
  }

  console.log('\n===== TESTING SAFE IPS =====');

  for (const ip of safeIps) {
    const testPacket: PacketData = createSamplePacket(ip);
    console.log(`\nTesting IP: ${ip}`);

    const result = await maliciousCheckService.checkPacket(testPacket);
    const display = packetDisplayService.formatPacketInfo(testPacket, result);

    console.log(display);
  }

  console.log('\n===== TESTING EXPLICITLY SAFE IP =====');

  const testPacket: PacketData = createSamplePacket(explicitlySafeIp);
  console.log(`\nTesting explicitly safe IP: ${explicitlySafeIp}`);

  const result = await maliciousCheckService.checkPacket(testPacket);
  const display = packetDisplayService.formatPacketInfo(testPacket, result);

  console.log(display);

  console.log('\nTest completed!');
}

function createSamplePacket(dstIp: string): PacketData {
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: 80,
    protocol: 'TCP',
    packet_size: 1500,
    packet_type: 'DATA',
    timestamp: new Date().toISOString()
  };
}

runTest().catch(error => {
  console.error('Test failed:', error);
});