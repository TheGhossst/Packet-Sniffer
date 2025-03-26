import { PacketData, ProtocolAnalysisResult, ProtocolFinding } from '../types/packet.types.js';

/**
 * TLS/HTTPS Protocol Analyzer
 * Uses TLS fingerprinting to identify suspicious encrypted connections
 */
export class TlsAnalyzer {
  // JA3 fingerprints of known malicious clients
  private suspiciousJa3Fingerprints = [
    // Trickbot
    'd8488535fca213ceacf1b28e675f8110',
    // Emotet
    '51c64c77e60f3980eea90869b68c58a8',
    // Metasploit
    'a0e9f5d64349fb13191bc781f81f42e1',
    // Cobalt Strike
    '6734f37431670b3ab4292b8f60f29984',
    // IcedID
    '2db568e72789a9b0a6cb7523b3768aef'
  ];

  // Suspicious certificate patterns
  private suspiciousCertPatterns = [
    // Self-signed certificates with organization variations of legitimate companies
    /google.*inc/i,
    /micro.*soft/i,
    /face.*book/i,
    /app.*le/i,
    // Very short validity periods
    /Valid For: [1-9] days/i,
    // Unusual subject alternative names
    /sAN=\d+\.\d+\.\d+\.\d+/
  ];

  /**
   * Analyze TLS handshake packet for suspicious patterns
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    const tlsData = this.extractTlsData(payload);
    
    // Skip if we can't parse TLS data
    if (!tlsData) {
      return null;
    }
    
    // Check for JA3 fingerprint matches
    if (tlsData.ja3Fingerprint && this.suspiciousJa3Fingerprints.includes(tlsData.ja3Fingerprint)) {
      findings.push({
        type: 'SUSPICIOUS_TLS_FINGERPRINT',
        description: `Matched malicious JA3 fingerprint: ${tlsData.ja3Fingerprint}`,
        severity: 'high',
        evidence: tlsData.ja3Fingerprint
      });
    }
    
    // Check for unusual cipher suites
    if (tlsData.cipherSuites && tlsData.cipherSuites.includes('TLS_RSA_WITH_RC4_128_MD5')) {
      findings.push({
        type: 'WEAK_CIPHER_SUITE',
        description: 'Detected deprecated/weak cipher suite (RC4)',
        severity: 'medium',
        evidence: 'TLS_RSA_WITH_RC4_128_MD5'
      });
    }
    
    // Check for very old TLS versions
    if (tlsData.version && tlsData.version.includes('SSLv3')) {
      findings.push({
        type: 'DEPRECATED_TLS_VERSION',
        description: 'Detected deprecated SSL/TLS version (SSLv3)',
        severity: 'medium',
        evidence: tlsData.version
      });
    }
    
    // Check certificate patterns
    if (tlsData.certificate) {
      for (const pattern of this.suspiciousCertPatterns) {
        if (pattern.test(tlsData.certificate)) {
          findings.push({
            type: 'SUSPICIOUS_CERTIFICATE',
            description: 'Certificate contains suspicious patterns',
            severity: 'high',
            evidence: tlsData.certificate.substring(0, 100) + '...'
          });
          break;
        }
      }
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'TLS',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.some(f => f.severity === 'high') ? 0.85 : 0.6
    };
  }
  
  /**
   * Extract TLS data from payload - simplified implementation
   * In a real-world scenario, this would parse the TLS handshake in detail
   */
  private extractTlsData(payload: string): {
    ja3Fingerprint?: string,
    cipherSuites?: string[],
    version?: string,
    certificate?: string
  } | null {
    try {
      // This is a simplified mock implementation
      // In reality, you'd need proper TLS parsing logic here
      
      // Look for TLS handshake indicators
      if (!payload.includes('TLS') && 
          !payload.includes('SSL') && 
          !payload.includes('HANDSHAKE') &&
          !payload.includes('CLIENT_HELLO')) {
        return null;
      }
      
      // Extract a mock JA3 fingerprint (for simulation)
      // In reality, this would be calculated from ClientHello parameters
      const ja3Match = payload.match(/JA3=([a-f0-9]{32})/i);
      const ja3Fingerprint = ja3Match ? ja3Match[1] : 
                             (payload.includes('Metasploit') ? 'a0e9f5d64349fb13191bc781f81f42e1' : undefined);
      
      // Extract cipher suites (simplified)
      const cipherMatch = payload.match(/CIPHERS=([A-Z0-9_,]+)/i);
      const cipherSuites = cipherMatch ? cipherMatch[1].split(',') : 
                          (payload.includes('RC4') ? ['TLS_RSA_WITH_RC4_128_MD5'] : ['TLS_AES_256_GCM_SHA384']);
      
      // Extract version
      const versionMatch = payload.match(/VERSION=([A-Z0-9_.]+)/i);
      const version = versionMatch ? versionMatch[1] : 
                     (payload.includes('SSLv3') ? 'SSLv3' : 'TLSv1.2');
      
      // Extract certificate info (simplified)
      const certMatch = payload.match(/CERT=([^\n]+)/i);
      const certificate = certMatch ? certMatch[1] : 
                         (payload.includes('google') ? 'CN=www.google.com, O=Google Inc, C=US' : undefined);
      
      return {
        ja3Fingerprint,
        cipherSuites,
        version,
        certificate
      };
    } catch (error) {
      console.error('Error extracting TLS data:', error);
      return null;
    }
  }
}

/**
 * SMTP/Email Protocol Analyzer
 * Identifies phishing attempts and email-based attacks
 */
export class SmtpAnalyzer {
  // Suspicious email sending patterns
  private suspiciousEmailPatterns = [
    /ReplyTo:.*?@(?!gmail\.com|outlook\.com|yahoo\.com)/i, // Suspicious reply-to domains
    /From:.*?@(gmail|yahoo|outlook).*?\.(?!com)/i, // Lookalike domains
  ];

  // Suspicious attachment types
  private suspiciousAttachments = [
    /\.exe$/i,
    /\.zip$/i,
    /\.jar$/i,
    /\.js$/i,
    /\.vbs$/i,
    /\.ps1$/i,
    /\.bat$/i,
    /\.scr$/i
  ];

  // Phishing keywords
  private phishingKeywords = [
    /password.*expire/i,
    /account.*suspend/i,
    /verify.*account/i,
    /unusual.*activity/i,
    /security.*alert/i,
    /login.*attempt/i,
    /click.*here/i,
    /urgent.*action/i,
    /update.*payment/i
  ];

  /**
   * Analyze SMTP traffic for suspicious content
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    
    // Skip if this doesn't look like SMTP
    if (!this.isSmtpTraffic(payload, packet)) {
      return null;
    }
    
    // Check for phishing indicators in email content
    for (const pattern of this.phishingKeywords) {
      if (pattern.test(payload)) {
        findings.push({
          type: 'PHISHING_INDICATORS',
          description: `Email contains phishing keywords (${pattern.toString()})`,
          severity: 'medium',
          evidence: payload.match(pattern)?.[0] || 'pattern match'
        });
      }
    }
    
    // Check for suspicious patterns in email headers
    for (const pattern of this.suspiciousEmailPatterns) {
      if (pattern.test(payload)) {
        findings.push({
          type: 'SUSPICIOUS_EMAIL_HEADER',
          description: 'Email contains suspicious headers',
          severity: 'medium',
          evidence: payload.match(pattern)?.[0] || 'pattern match'
        });
      }
    }
    
    // Check for suspicious attachments
    for (const pattern of this.suspiciousAttachments) {
      if (this.hasAttachment(payload, pattern)) {
        findings.push({
          type: 'SUSPICIOUS_ATTACHMENT',
          description: `Email contains suspicious attachment (${pattern.toString()})`,
          severity: 'high',
          evidence: pattern.toString()
        });
      }
    }
    
    // Check for spoofed sender
    const spoofIndicator = this.checkForSpoofing(payload);
    if (spoofIndicator) {
      findings.push({
        type: 'EMAIL_SPOOFING',
        description: 'Potential email spoofing detected',
        severity: 'high',
        evidence: spoofIndicator
      });
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'SMTP',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.length > 2 ? 0.9 : 0.7
    };
  }
  
  /**
   * Check if packet is SMTP traffic
   */
  private isSmtpTraffic(payload: string, packet: PacketData): boolean {
    // Check port numbers
    const isSmtpPort = packet.dst_port === 25 || packet.dst_port === 465 || packet.dst_port === 587 || 
                       packet.src_port === 25 || packet.src_port === 465 || packet.src_port === 587;
                       
    // Check for SMTP commands
    const hasSmtpCommands = payload.includes('MAIL FROM:') || 
                            payload.includes('RCPT TO:') || 
                            payload.includes('DATA') ||
                            payload.includes('EHLO') ||
                            payload.includes('HELO');
                            
    return isSmtpPort || hasSmtpCommands;
  }
  
  /**
   * Check if payload contains attachment matching pattern
   */
  private hasAttachment(payload: string, pattern: RegExp): boolean {
    // Simple attachment detection
    const contentDispositionMatch = payload.match(/Content-Disposition: attachment; filename="([^"]+)"/i);
    if (contentDispositionMatch && pattern.test(contentDispositionMatch[1])) {
      return true;
    }
    
    // Also check for base64 encoded content with executable signatures
    if (pattern.toString().includes('.exe') && payload.includes('TVqQAAMAAAAEAA')) {
      return true; // MZ header in base64
    }
    
    return false;
  }
  
  /**
   * Check for email spoofing indicators
   */
  private checkForSpoofing(payload: string): string | null {
    // Extract from and return-path
    const fromMatch = payload.match(/From:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    const returnPathMatch = payload.match(/Return-Path:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    
    if (fromMatch && returnPathMatch && fromMatch[1] !== returnPathMatch[1]) {
      return `From: ${fromMatch[1]} doesn't match Return-Path: ${returnPathMatch[1]}`;
    }
    
    // Check for display name vs email mismatch tricks
    const displayNameMatch = payload.match(/From: "?([^"<@]+)"? <([^>]+)>/i);
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].trim().toLowerCase();
      const emailAddress = displayNameMatch[2].toLowerCase();
      
      // Check if display name looks like an email but doesn't match actual email
      if (displayName.includes('@') && displayName !== emailAddress) {
        return `Display name spoofing: "${displayNameMatch[1]}" <${displayNameMatch[2]}>`;
      }
      
      // Check if display name mimics a trusted entity
      if ((displayName.includes('paypal') || displayName.includes('microsoft') || 
           displayName.includes('amazon') || displayName.includes('apple')) && 
          !emailAddress.includes(displayName.replace(/\s+/g, ''))) {
        return `Trusted entity spoofing: "${displayNameMatch[1]}" <${displayNameMatch[2]}>`;
      }
    }
    
    return null;
  }
}

/**
 * SMB/Windows Protocol Analyzer
 * Detects lateral movement and exploitation attempts
 */
export class SmbAnalyzer {
  // Suspicious SMB commands
  private suspiciousCommands = [
    'Write AndX', // Used for uploading files
    'Trans2', // Used in exploits like EternalBlue
    'NT Create AndX', // Used to create or open files/pipes
    'Tree Connect AndX' // Used to connect to shares
  ];

  // Suspicious access patterns
  private suspiciousAccess = [
    /ADMIN\$/i, // Admin share
    /C\$/i,     // C$ share
    /IPC\$/i    // IPC$ share (often used in attacks)
  ];

  /**
   * Analyze SMB traffic for lateral movement and exploitation
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    
    // Skip if not SMB traffic
    if (!this.isSmbTraffic(payload, packet)) {
      return null;
    }
    
    // Check for EternalBlue exploit patterns
    if (this.detectEternalBlue(payload)) {
      findings.push({
        type: 'ETERNALBLUE_EXPLOIT',
        description: 'Potential EternalBlue (MS17-010) exploit attempt',
        severity: 'high',
        evidence: 'Trans2 response invalid status signature'
      });
    }
    
    // Check for suspicious commands
    for (const command of this.suspiciousCommands) {
      if (payload.includes(command)) {
        findings.push({
          type: 'SUSPICIOUS_SMB_COMMAND',
          description: `Detected potentially suspicious SMB command: ${command}`,
          severity: 'medium',
          evidence: command
        });
      }
    }
    
    // Check for access to sensitive shares
    for (const pattern of this.suspiciousAccess) {
      if (pattern.test(payload)) {
        findings.push({
          type: 'SENSITIVE_SHARE_ACCESS',
          description: `Access to sensitive SMB share detected: ${pattern.toString().replace(/\/i$/, '')}`,
          severity: 'medium',
          evidence: payload.match(pattern)?.[0] || pattern.toString()
        });
      }
    }
    
    // Check for brute force attempts
    if (this.detectBruteForce(payload)) {
      findings.push({
        type: 'SMB_BRUTE_FORCE',
        description: 'Potential SMB authentication brute force attempt',
        severity: 'high',
        evidence: 'Multiple STATUS_LOGON_FAILURE responses'
      });
    }
    
    // Check for Pass-the-Hash indicators
    if (this.detectPassTheHash(payload)) {
      findings.push({
        type: 'PASS_THE_HASH',
        description: 'Potential Pass-the-Hash attack detected',
        severity: 'high',
        evidence: 'NTLM authentication without Kerberos pre-authentication'
      });
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'SMB',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.some(f => f.severity === 'high') ? 0.9 : 0.7
    };
  }
  
  /**
   * Check if packet is SMB traffic
   */
  private isSmbTraffic(payload: string, packet: PacketData): boolean {
    // Check port numbers
    const isSmbPort = packet.dst_port === 445 || packet.dst_port === 139 || 
                      packet.src_port === 445 || packet.src_port === 139;
                      
    // Check for SMB signatures
    const hasSmbSignature = payload.includes('SMB') || 
                            payload.includes('\xFFSMB') || 
                            payload.includes('NTLMSSP');
                            
    return isSmbPort || hasSmbSignature;
  }
  
  /**
   * Detect EternalBlue exploit patterns
   */
  private detectEternalBlue(payload: string): boolean {
    return payload.includes('Trans2') && 
           (payload.includes('STATUS_INVALID_PARAMETER') || 
           payload.includes('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'));
  }
  
  /**
   * Detect brute force attempts
   */
  private detectBruteForce(payload: string): boolean {
    return payload.includes('STATUS_LOGON_FAILURE') || 
           payload.includes('STATUS_ACCESS_DENIED') && 
           payload.includes('Session Setup');
  }
  
  /**
   * Detect Pass-the-Hash attack indicators
   */
  private detectPassTheHash(payload: string): boolean {
    return payload.includes('NTLMSSP') && 
           payload.includes('NTLM') && 
           !payload.includes('Kerberos') && 
           (payload.includes('AAAAAA==') || // Empty LM hash
            payload.includes('Administrator'));
  }
}

/**
 * ICMP Protocol Analyzer
 * Detects ping sweeps and covert channels
 */
export class IcmpAnalyzer {
  /**
   * Analyze ICMP packets for suspicious activities
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    
    // Skip if not ICMP
    if (packet.protocol !== 'ICMP') {
      return null;
    }
    
    // Check for abnormally large ICMP packets (potential data exfiltration)
    if (packet.packet_size > 1000) {
      findings.push({
        type: 'OVERSIZED_ICMP',
        description: 'Abnormally large ICMP packet detected',
        severity: 'medium',
        evidence: `Packet size: ${packet.packet_size} bytes`
      });
    }
    
    // Check for ICMP tunneling signatures
    if (this.detectIcmpTunneling(payload)) {
      findings.push({
        type: 'ICMP_TUNNELING',
        description: 'Potential ICMP tunneling detected',
        severity: 'high',
        evidence: 'Structured data in ICMP payload'
      });
    }
    
    // Detect ping sweep (handled at behavioral level in a real implementation)
    if (this.isPingSweep(packet)) {
      findings.push({
        type: 'PING_SWEEP',
        description: 'Potential ping sweep detected',
        severity: 'low',
        evidence: `ICMP echo to ${packet.dst_ip}`
      });
    }
    
    // Check for non-standard ICMP types
    const icmpType = this.extractIcmpType(payload);
    if (icmpType && (icmpType < 0 || icmpType > 18)) {
      findings.push({
        type: 'UNUSUAL_ICMP_TYPE',
        description: `Unusual ICMP message type: ${icmpType}`,
        severity: 'medium',
        evidence: `ICMP Type: ${icmpType}`
      });
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'ICMP',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.length > 1 ? 0.8 : 0.6
    };
  }
  
  /**
   * Extract ICMP type from payload - simplified
   */
  private extractIcmpType(payload: string): number | null {
    try {
      // This is a simplified mock implementation
      if (payload.includes('Type=8')) {
        return 8; // Echo request
      } else if (payload.includes('Type=0')) {
        return 0; // Echo reply
      } else if (payload.includes('Type=')) {
        const match = payload.match(/Type=(\d+)/);
        if (match) {
          return parseInt(match[1], 10);
        }
      }
      
      // Default to echo if contains common ICMP echo strings
      if (payload.includes('Echo') || payload.includes('ping')) {
        return 8;
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Check for ICMP tunneling indicators
   */
  private detectIcmpTunneling(payload: string): boolean {
    // Look for structured data or protocol headers in payload
    return payload.includes('HTTP/') || 
           payload.includes('SSH-') ||
           payload.includes('GET ') || 
           payload.includes('POST ') ||
           payload.includes('TCP') ||
           payload.includes('ICMPTUNNEL') ||
           // Base64 data patterns
           /[A-Za-z0-9+/=]{20,}/.test(payload);
  }
  
  /**
   * Detect ping sweep (simplified)
   * In a real implementation, this would be handled by behavioral analysis
   */
  private isPingSweep(packet: PacketData): boolean {
    // Simple pattern matching for demonstration
    // In reality, this requires tracking multiple packets over time
    return packet.protocol === 'ICMP' && 
           (packet.dst_ip.endsWith('.1') || 
           packet.dst_ip.endsWith('.254'));
  }
} 