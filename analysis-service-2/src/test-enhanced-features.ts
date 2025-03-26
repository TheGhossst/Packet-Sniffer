import { maliciousCheckService } from './services/malicious-check.service.js';
import { ipsumFeedService } from './services/ipsum-feed.service.js';
import { packetDisplayService } from './services/packet-display.service.js';
import { dpiService } from './services/dpi.service.js';
import { behavioralAnalysisService } from './services/behavioral-analysis.service.js';
import { PacketData } from './types/packet.types.js';

/**
 * Enhanced Features Test Suite
 * Tests both DPI and Behavioral Analysis features
 */
async function runTests() {
  console.log('Initializing services...');
  await ipsumFeedService.initialize();
  
  console.log('\n========================================');
  console.log(' TESTING DEEP PACKET INSPECTION (DPI)');
  console.log('========================================');
  
  // Test HTTP-based attacks
  await testHttpAttacks();
  
  // Test DNS-based attacks
  await testDnsAttacks();
  
  // Test SQL Injection detection
  await testSqlInjection();
  
  // Test XSS detection
  await testXss();
  
  // Test TLS analysis
  await testTlsAnalysis();
  
  // Test SMTP analysis
  await testSmtpAnalysis();
  
  // Test SMB/Windows protocol analysis
  await testSmbAnalysis();
  
  // Test ICMP protocol analysis
  await testIcmpAnalysis();
  
  console.log('\n========================================');
  console.log(' TESTING BEHAVIORAL ANALYSIS');
  console.log('========================================');
  
  // Test port scanning detection
  await testPortScanning();
  
  // Test high traffic volume detection
  await testHighTrafficVolume();
  
  // Test excessive connections detection
  await testExcessiveConnections();
  
  console.log('\nAll tests completed!');
}

/**
 * Test HTTP-based attacks
 */
async function testHttpAttacks() {
  console.log('\n----- Testing HTTP-based attacks -----');
  
  // Test suspicious user agent
  const sqlmapUserAgentPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /login.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.4.7\r\n\r\n'
  );
  await testPacketDPI(sqlmapUserAgentPacket, 'Suspicious User-Agent (sqlmap)');
  
  // Test directory traversal attack
  const directoryTraversalPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /images/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(directoryTraversalPacket, 'Directory Traversal Attack');
  
  // Test suspicious URI pattern (phpMyAdmin access)
  const suspiciousUriPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /phpmyadmin/index.php HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(suspiciousUriPacket, 'Suspicious URI Pattern (phpMyAdmin)');
}

/**
 * Test DNS-based attacks
 */
async function testDnsAttacks() {
  console.log('\n----- Testing DNS-based attacks -----');
  
  // Test suspicious TLD (.xyz)
  const suspiciousTldPacket = createDnsPacket(
    '8.8.8.8', 
    53, 
    'malware-distribution-domain.xyz'
  );
  await testPacketDPI(suspiciousTldPacket, 'Suspicious TLD (.xyz)');
  
  // Test very long domain name (potential DGA)
  const longDomainPacket = createDnsPacket(
    '8.8.8.8', 
    53, 
    'a123456789b123456789c123456789d123456789.com'
  );
  await testPacketDPI(longDomainPacket, 'Very Long Domain Name (potential DGA)');
  
  // Test large DNS packet (potential DNS tunneling)
  const largeDnsPacket = createDnsPacket(
    '8.8.8.8', 
    53, 
    'normal-domain.com',
    600 // Larger packet size
  );
  await testPacketDPI(largeDnsPacket, 'Large DNS Packet (potential tunneling)');
}

/**
 * Test SQL Injection detection
 */
async function testSqlInjection() {
  console.log('\n----- Testing SQL Injection detection -----');
  
  // Test SQL Injection in HTTP request
  const sqlInjectionPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /profile.php?id=1\' OR \'1\'=\'1 HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(sqlInjectionPacket, 'SQL Injection Attack');
  
  // Test SQL Injection with UNION SELECT
  const unionSelectPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /products.php?category=1 UNION SELECT username,password FROM users HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(unionSelectPacket, 'SQL Injection with UNION SELECT');
}

/**
 * Test XSS detection
 */
async function testXss() {
  console.log('\n----- Testing XSS detection -----');
  
  // Test basic XSS attack
  const basicXssPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(basicXssPacket, 'Basic XSS Attack');
  
  // Test XSS with event handler
  const eventHandlerXssPacket = createHttpPacket(
    '8.8.8.8', 
    80, 
    'GET /profile?name=<img src="x" onerror="alert(1)"> HTTP/1.1\r\nHost: example.com\r\n\r\n'
  );
  await testPacketDPI(eventHandlerXssPacket, 'XSS with Event Handler');
}

/**
 * Test port scanning detection
 */
async function testPortScanning() {
  console.log('\n----- Testing Port Scanning detection -----');
  
  const sourceIp = '192.168.1.10';
  const targetIp = '10.0.0.1';
  
  console.log(`Simulating port scan from ${sourceIp} to ${targetIp}...`);
  
  // Send packets to multiple ports to simulate scanning
  for (let port = 1; port <= 25; port++) {
    const scanPacket = createBasicPacket(sourceIp, 12345, targetIp, port, 'TCP');
    
    // Analyze with behavioral service directly first
    const behavioralResult = behavioralAnalysisService.analyzePacket(scanPacket);
    
    // Then process with maliciousCheck for the last packet to see the combined result
    if (port === 25) {
      await testBehavioral(scanPacket, 'Port Scanning', behavioralResult);
    }
  }
}

/**
 * Test high traffic volume detection
 */
async function testHighTrafficVolume() {
  console.log('\n----- Testing High Traffic Volume detection -----');
  
  const sourceIp = '192.168.1.20';
  const targetIp = '10.0.0.2';
  
  console.log(`Simulating high traffic volume from ${sourceIp} to ${targetIp}...`);
  
  // Send many packets to simulate high traffic
  for (let i = 1; i <= 120; i++) {
    const highTrafficPacket = createBasicPacket(sourceIp, 12345, targetIp, 80, 'TCP');
    
    // Analyze with behavioral service
    const behavioralResult = behavioralAnalysisService.analyzePacket(highTrafficPacket);
    
    // Process the last packet with maliciousCheck
    if (i === 120) {
      await testBehavioral(highTrafficPacket, 'High Traffic Volume', behavioralResult);
    }
  }
}

/**
 * Test excessive connections detection
 */
async function testExcessiveConnections() {
  console.log('\n----- Testing Excessive Connections detection -----');
  
  const sourceIp = '192.168.1.30';
  
  console.log(`Simulating connections to multiple destinations from ${sourceIp}...`);
  
  // Connect to many different destination IPs
  for (let i = 1; i <= 35; i++) {
    const targetIp = `10.0.0.${i}`;
    const excessiveConnectionsPacket = createBasicPacket(sourceIp, 12345, targetIp, 80, 'TCP');
    
    // Analyze with behavioral service
    const behavioralResult = behavioralAnalysisService.analyzePacket(excessiveConnectionsPacket);
    
    // Process the last packet with maliciousCheck
    if (i === 35) {
      await testBehavioral(excessiveConnectionsPacket, 'Excessive Connections', behavioralResult);
    }
  }
}

/**
 * Test a packet with DPI
 */
async function testPacketDPI(packet: PacketData, testName: string) {
  console.log(`\nTesting: ${testName}`);
  
  // First, test directly with DPI service
  const dpiResult = await dpiService.analyzePacket(packet);
  
  if (dpiResult) {
    console.log(`✅ DPI Detection successful! Protocol: ${dpiResult.protocol}, Confidence: ${(dpiResult.confidence * 100).toFixed(1)}%`);
    console.log('Findings:');
    dpiResult.findings.forEach(finding => {
      console.log(`- [${finding.severity.toUpperCase()}] ${finding.type}: ${finding.description}`);
    });
  } else {
    console.log('❌ DPI Detection failed - No findings');
  }
  
  // Then, test with the full malicious check service
  console.log(`\nTesting with full malicious check service:`);
  const result = await maliciousCheckService.checkPacket(packet);
  const display = packetDisplayService.formatPacketInfo(packet, result);
  console.log(display);
}

/**
 * Test a packet with behavioral analysis
 */
async function testBehavioral(packet: PacketData, testName: string, behavioralResult: any) {
  console.log(`\nAnalysis for: ${testName}`);
  
  if (behavioralResult.anomalies.length > 0) {
    console.log('✅ Behavioral Analysis Detection successful!');
    console.log('Anomalies:');
    behavioralResult.anomalies.forEach((anomaly: any) => {
      console.log(`- [${anomaly.severity.toUpperCase()}] ${anomaly.type}: ${anomaly.description} (${(anomaly.confidence * 100).toFixed(1)}% confidence)`);
    });
  } else {
    console.log('❌ Behavioral Analysis Detection failed - No anomalies');
  }
  
  // Test with the full malicious check service
  console.log(`\nTesting with full malicious check service:`);
  const result = await maliciousCheckService.checkPacket(packet);
  const display = packetDisplayService.formatPacketInfo(packet, result);
  console.log(display);
}

/**
 * Create a basic packet
 */
function createBasicPacket(
  srcIp: string, 
  srcPort: number, 
  dstIp: string, 
  dstPort: number, 
  protocol: string
): PacketData {
  return {
    src_ip: srcIp,
    src_port: srcPort,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: protocol,
    packet_size: 64,
    packet_type: 'DATA',
    timestamp: new Date().toISOString()
  };
}

/**
 * Create an HTTP packet with payload
 */
function createHttpPacket(dstIp: string, dstPort: number, payload: string): PacketData {
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: 'TCP',
    packet_size: payload.length + 40, // Add TCP/IP header size
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

/**
 * Create a DNS packet with payload
 */
function createDnsPacket(dstIp: string, dstPort: number, domain: string, packetSize: number = 64): PacketData {
  // Create a simplified DNS query payload
  const payload = `DNS QUERY: ${domain} A IN`;
  
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: 'UDP',
    packet_size: packetSize,
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

/**
 * Test TLS analysis
 */
async function testTlsAnalysis() {
  console.log('\n----- Testing TLS Analysis -----');
  
  // Test TLS handshake
  const tlsHandshakePacket = createTlsPacket(
    '192.168.1.100', 
    443, 
    'TLS handshake packet'
  );
  await testPacketDPI(tlsHandshakePacket, 'TLS Handshake');
  
  // Test SSL stripping attack
  const sslStrippingPacket = createTlsPacket(
    '192.168.1.100', 
    443, 
    'SSL stripping attack packet'
  );
  await testPacketDPI(sslStrippingPacket, 'SSL Stripping Attack');
}

/**
 * Test SMTP analysis
 */
async function testSmtpAnalysis() {
  console.log('\n----- Testing SMTP Analysis -----');
  
  // Test malicious attachment detection
  const maliciousAttachmentPacket = createSmtpPacket(
    '192.168.1.100', 
    25, 
    'MAIL FROM: <someone@example.com>\r\nRCPT TO: <user@example.com>\r\nDATA\r\nFrom: "John Doe" <john@example.com>\r\nSubject: Invoice\r\nContent-Type: multipart/mixed;\r\n\r\nContent-Disposition: attachment; filename="invoice.exe"\r\n\r\nSome base64 content here TVqQAAMAAAAEAA=='
  );
  await testPacketDPI(maliciousAttachmentPacket, 'Malicious Email Attachment');
  
  // Test email spoofing detection
  const spoofedEmailPacket = createSmtpPacket(
    '192.168.1.100', 
    25, 
    'MAIL FROM: <attacker@evil.com>\r\nRCPT TO: <user@example.com>\r\nDATA\r\nFrom: "Microsoft Security" <security@microsoft.com>\r\nReturn-Path: <attacker@evil.com>\r\nSubject: Security Alert\r\n\r\nPlease update your credentials immediately.'
  );
  await testPacketDPI(spoofedEmailPacket, 'Email Spoofing Detection');
}

/**
 * Test SMB/Windows protocol analysis
 */
async function testSmbAnalysis() {
  console.log('\n----- Testing SMB/Windows Protocol Analysis -----');
  
  // Test EternalBlue detection
  const eternalBluePacket = createSmbPacket(
    '192.168.1.100', 
    445, 
    '\xFFSMB\x32\x00\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Trans2 STATUS_INVALID_PARAMETER'
  );
  await testPacketDPI(eternalBluePacket, 'EternalBlue Exploit Detection');
  
  // Test administrative share access
  const adminSharePacket = createSmbPacket(
    '192.168.1.100', 
    445, 
    '\xFFSMB\x75\x00\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Tree Connect AndX Request Path=\\\\192.168.1.5\\ADMIN$'
  );
  await testPacketDPI(adminSharePacket, 'Administrative Share Access');
  
  // Test pass-the-hash attack
  const passTheHashPacket = createSmbPacket(
    '192.168.1.100', 
    445, 
    '\xFFSMB\x73\x00\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Session Setup AndX Request NTLMSSP NTLM Auth User=Administrator AAAAAA=='
  );
  await testPacketDPI(passTheHashPacket, 'Pass-the-Hash Attack');
}

/**
 * Test ICMP protocol analysis
 */
async function testIcmpAnalysis() {
  console.log('\n----- Testing ICMP Protocol Analysis -----');
  
  // Test oversized ICMP packet
  const oversizedIcmpPacket = createIcmpPacket(
    '192.168.1.100', 
    '10.0.0.1',
    'ICMP Echo Type=8 ' + 'A'.repeat(2000),
    2048
  );
  await testPacketDPI(oversizedIcmpPacket, 'Oversized ICMP Packet');
  
  // Test ICMP tunneling
  const icmpTunnelingPacket = createIcmpPacket(
    '192.168.1.100', 
    '10.0.0.1',
    'ICMP Echo Type=8 GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
    256
  );
  await testPacketDPI(icmpTunnelingPacket, 'ICMP Tunneling');
  
  // Test unusual ICMP type
  const unusualIcmpPacket = createIcmpPacket(
    '192.168.1.100', 
    '10.0.0.1',
    'ICMP Type=42 Code=0',
    64
  );
  await testPacketDPI(unusualIcmpPacket, 'Unusual ICMP Type');
}

/**
 * Create a TLS packet with payload
 */
function createTlsPacket(dstIp: string, dstPort: number, payload: string): PacketData {
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: 'TCP',
    packet_size: payload.length + 40, // Add TCP/IP header size
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

/**
 * Create an SMTP packet with payload
 */
function createSmtpPacket(dstIp: string, dstPort: number, payload: string): PacketData {
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: 'TCP',
    packet_size: payload.length + 40, // Add TCP/IP header size
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

/**
 * Create an SMB packet with payload
 */
function createSmbPacket(dstIp: string, dstPort: number, payload: string): PacketData {
  return {
    src_ip: '192.168.1.5',
    src_port: 54321,
    dst_ip: dstIp,
    dst_port: dstPort,
    protocol: 'TCP',
    packet_size: payload.length + 40, // Add TCP/IP header size
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

/**
 * Create an ICMP packet with payload
 */
function createIcmpPacket(srcIp: string, dstIp: string, payload: string, packetSize: number): PacketData {
  return {
    src_ip: srcIp,
    src_port: 0, // ICMP doesn't use ports
    dst_ip: dstIp,
    dst_port: 0,
    protocol: 'ICMP',
    packet_size: packetSize,
    packet_type: 'DATA',
    timestamp: new Date().toISOString(),
    payload: Buffer.from(payload).toString('base64') // Base64 encode the payload
  };
}

// Run all tests
runTests().catch(error => {
  console.error('Tests failed:', error);
}); 