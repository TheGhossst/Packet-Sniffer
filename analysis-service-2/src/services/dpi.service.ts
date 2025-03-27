import { PacketData, ProtocolAnalysisResult, ProtocolFinding } from '../types/packet.types.js';
import { metricsService } from './metrics.service.js';
import { 
  TlsAnalyzer, 
  SmtpAnalyzer, 
  SmbAnalyzer, 
  IcmpAnalyzer 
} from './advanced-protocol-analyzers.js';

/**
 * Deep Packet Inspection Service
 * Analyzes packet payloads for suspicious patterns and protocol-specific threats
 */
class DPIService {
  private httpAnalyzer: HttpAnalyzer;
  private dnsAnalyzer: DnsAnalyzer;
  private sqlInjectionDetector: SqlInjectionDetector;
  private xssDetector: XssDetector;
  
  // Add new protocol analyzers
  private tlsAnalyzer: TlsAnalyzer;
  private smtpAnalyzer: SmtpAnalyzer;
  private smbAnalyzer: SmbAnalyzer;
  private icmpAnalyzer: IcmpAnalyzer;

  constructor() {
    this.httpAnalyzer = new HttpAnalyzer();
    this.dnsAnalyzer = new DnsAnalyzer();
    this.sqlInjectionDetector = new SqlInjectionDetector();
    this.xssDetector = new XssDetector();
    
    // Initialize new analyzers
    this.tlsAnalyzer = new TlsAnalyzer();
    this.smtpAnalyzer = new SmtpAnalyzer();
    this.smbAnalyzer = new SmbAnalyzer();
    this.icmpAnalyzer = new IcmpAnalyzer();
  }

  /**
   * Analyze a packet for suspicious patterns
   * @param packet The packet to analyze
   * @returns Analysis result with findings
   */
  async analyzePacket(packet: PacketData): Promise<ProtocolAnalysisResult | null> {
    try {
      // Skip analysis if no payload
      if (!packet.payload) {
        return null;
      }

      // Convert base64 payload to string if needed
      const payloadStr = this.decodePayload(packet.payload);
      
      // Perform generic pattern matching first
      const genericFindings = this.performGenericPatternMatching(payloadStr);
      
      // Perform protocol-specific analysis based on the protocol
      let protocolFindings: ProtocolFinding[] = [];
      
      switch (packet.protocol.toUpperCase()) {
        case 'TCP':
          // Check for HTTP traffic on common ports
          if (packet.dst_port === 80 || packet.dst_port === 8080 || packet.dst_port === 443) {
            const httpResults = this.httpAnalyzer.analyze(payloadStr, packet);
            if (httpResults) {
              protocolFindings = httpResults.findings;
            }
          }
          
          // Check for HTTPS/TLS traffic
          if (packet.dst_port === 443 || packet.dst_port === 8443) {
            const tlsResults = this.tlsAnalyzer.analyze(payloadStr, packet);
            if (tlsResults) {
              protocolFindings = [...protocolFindings, ...tlsResults.findings];
            }
          }
          
          // Check for SMTP traffic
          if (packet.dst_port === 25 || packet.dst_port === 465 || packet.dst_port === 587) {
            const smtpResults = this.smtpAnalyzer.analyze(payloadStr, packet);
            if (smtpResults) {
              protocolFindings = [...protocolFindings, ...smtpResults.findings];
            }
          }
          
          // Check for SMB traffic
          if (packet.dst_port === 445 || packet.dst_port === 139) {
            const smbResults = this.smbAnalyzer.analyze(payloadStr, packet);
            if (smbResults) {
              protocolFindings = [...protocolFindings, ...smbResults.findings];
            }
          }
          break;
          
        case 'UDP':
          // Check for DNS traffic on port 53
          if (packet.dst_port === 53 || packet.src_port === 53) {
            const dnsResults = this.dnsAnalyzer.analyze(payloadStr, packet);
            if (dnsResults) {
              protocolFindings = dnsResults.findings;
            }
          }
          break;
          
        case 'ICMP':
          // Analyze ICMP traffic
          const icmpResults = this.icmpAnalyzer.analyze(payloadStr, packet);
          if (icmpResults) {
            protocolFindings = icmpResults.findings;
          }
          break;
      }
      
      // Combine all findings
      const allFindings = [...genericFindings, ...protocolFindings];
      
      // Skip returning a result if no findings
      if (allFindings.length === 0) {
        return null;
      }
      
      // Determine if the packet is suspicious based on the findings
      const highSeverityCount = allFindings.filter(f => f.severity === 'high').length;
      const mediumSeverityCount = allFindings.filter(f => f.severity === 'medium').length;
      
      const isSuspicious = highSeverityCount > 0 || mediumSeverityCount >= 2;
      
      // Calculate confidence based on findings
      const confidence = this.calculateConfidence(allFindings);
      
      // Determine protocol for result
      let resultProtocol = packet.protocol;
      if (protocolFindings.length > 0) {
        // Use most specific protocol available
        const protocols = new Set(protocolFindings.map(f => f.type.split('_')[0]));
        if (protocols.has('HTTP')) resultProtocol = 'HTTP';
        else if (protocols.has('TLS')) resultProtocol = 'TLS';
        else if (protocols.has('SMTP')) resultProtocol = 'SMTP';
        else if (protocols.has('SMB')) resultProtocol = 'SMB';
        else if (protocols.has('DNS')) resultProtocol = 'DNS';
        else if (protocols.has('ICMP')) resultProtocol = 'ICMP';
      }
      
      // Update metrics
      if (isSuspicious) {
        const findingType = allFindings[0]?.type || 'general';
        
        // Use protocol-specific metrics
        switch (resultProtocol) {
          case 'TLS':
            metricsService.incrementTlsDetections(findingType);
            break;
          case 'SMTP':
            metricsService.incrementSmtpDetections(findingType);
            break;
          case 'SMB':
            metricsService.incrementSmbDetections(findingType);
            break;
          case 'ICMP':
            metricsService.incrementIcmpDetections(findingType);
            break;
          default:
            // Fall back to general DPI metrics
            metricsService.incrementDpiDetections(resultProtocol, findingType);
        }
      }
      
      return {
        protocol: resultProtocol,
        isSuspicious,
        findings: allFindings,
        confidence
      };
    } catch (error) {
      console.error('Error in DPI analysis:', error);
      metricsService.incrementProcessingErrors();
      return null;
    }
  }
  
  /**
   * Decode packet payload from base64 or return as is if already a string
   */
  private decodePayload(payload: string): string {
    // Check if payload is base64 encoded
    const isBase64 = /^[A-Za-z0-9+/=]+$/.test(payload);
    
    if (isBase64) {
      try {
        return Buffer.from(payload, 'base64').toString('utf-8');
      } catch (error) {
        // If decoding fails, return original payload
        return payload;
      }
    }
    
    return payload;
  }
  
  /**
   * Perform generic pattern matching on packet payload
   */
  private performGenericPatternMatching(payload: string): ProtocolFinding[] {
    const findings: ProtocolFinding[] = [];
    
    // Check for SQL injection patterns
    const sqlInjectionResult = this.sqlInjectionDetector.detect(payload);
    if (sqlInjectionResult) {
      findings.push(sqlInjectionResult);
    }
    
    // Check for XSS patterns
    const xssResult = this.xssDetector.detect(payload);
    if (xssResult) {
      findings.push(xssResult);
    }
    
    return findings;
  }
  
  /**
   * Calculate confidence score based on findings
   */
  private calculateConfidence(findings: ProtocolFinding[]): number {
    if (findings.length === 0) return 0;
    
    let score = 0;
    let maxWeight = 0;
    
    // Weight findings by severity
    for (const finding of findings) {
      let weight = 0;
      
      switch (finding.severity) {
        case 'high':
          weight = 3;
          break;
        case 'medium':
          weight = 2;
          break;
        case 'low':
          weight = 1;
          break;
      }
      
      score += weight;
      maxWeight += 3; // Max possible weight
    }
    
    // Normalize to 0-1 range
    return score / maxWeight;
  }
}

/**
 * HTTP Protocol Analyzer
 * Analyzes HTTP traffic for suspicious patterns
 */
class HttpAnalyzer {
  private suspiciousUserAgents = [
    'sqlmap',
    'nikto',
    'nmap',
    'dirbuster',
    'wpscan',
    'hydra'
  ];
  
  private suspiciousHeaders = [
    'x-scan',
    'x-scan-id',
    'x-exploit'
  ];
  
  private suspiciousUriPatterns = [
    /\/etc\/passwd/,
    /\/wp-admin/,
    /\/wp-login/,
    /\/phpmyadmin/,
    /\/admin\//,
    /\.php\?id=/
  ];

  /**
   * Analyze HTTP traffic
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    
    // Parse HTTP headers if this looks like HTTP traffic
    if (!payload.startsWith('GET ') && !payload.startsWith('POST ') && 
        !payload.startsWith('HTTP/')) {
      return null;
    }
    
    // Extract HTTP method and URI
    const firstLine = payload.split('\n')[0];
    const httpMethod = firstLine.split(' ')[0];
    const uri = firstLine.split(' ')[1];
    
    // Extract headers
    const headers: Record<string, string> = {};
    const headerLines = payload.split('\n').slice(1);
    
    for (const line of headerLines) {
      if (line.trim() === '') break; // End of headers
      
      const colonIndex = line.indexOf(':');
      if (colonIndex !== -1) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        headers[key] = value;
      }
    }
    
    // Check for suspicious user agent
    const userAgent = headers['user-agent'] || '';
    for (const suspiciousAgent of this.suspiciousUserAgents) {
      if (userAgent.toLowerCase().includes(suspiciousAgent)) {
        findings.push({
          type: 'SUSPICIOUS_USER_AGENT',
          description: `Detected suspicious user agent: ${suspiciousAgent}`,
          severity: 'medium',
          evidence: userAgent
        });
      }
    }
    
    // Check for suspicious headers
    for (const suspiciousHeader of this.suspiciousHeaders) {
      if (headers[suspiciousHeader.toLowerCase()]) {
        findings.push({
          type: 'SUSPICIOUS_HEADER',
          description: `Detected suspicious header: ${suspiciousHeader}`,
          severity: 'medium',
          evidence: `${suspiciousHeader}: ${headers[suspiciousHeader.toLowerCase()]}`
        });
      }
    }
    
    // Check for suspicious URI patterns
    for (const pattern of this.suspiciousUriPatterns) {
      if (pattern.test(uri)) {
        findings.push({
          type: 'SUSPICIOUS_URI',
          description: `Detected suspicious URI pattern`,
          severity: 'medium',
          evidence: uri
        });
      }
    }
    
    // Check for directory traversal attempts
    if (uri.includes('../') || uri.includes('..%2F')) {
      findings.push({
        type: 'DIRECTORY_TRAVERSAL',
        description: 'Detected potential directory traversal attempt',
        severity: 'high',
        evidence: uri
      });
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'HTTP',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.length > 2 ? 0.9 : 0.7
    };
  }
}

/**
 * DNS Protocol Analyzer
 * Analyzes DNS traffic for suspicious patterns
 */
class DnsAnalyzer {
  private suspiciousDomainPatterns = [
    /\.ru$/,
    /\.cn$/,
    /\.tk$/,
    /\.xyz$/,
    /^[a-z0-9]{30,}\./
  ];
  
  private suspiciousTlds = [
    'xyz', 'top', 'click', 'gdn', 'review'
  ];
  
  /**
   * Analyze DNS traffic
   */
  analyze(payload: string, packet: PacketData): ProtocolAnalysisResult | null {
    const findings: ProtocolFinding[] = [];
    
    // Here we're looking for domain names in the payload text
    const domainRegex = /([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9][-a-zA-Z0-9]*/g;
    const domains = payload.match(domainRegex) || [];
    
    for (const domain of domains) {
      // Check for suspiciously long domain name (potential DGA - Domain Generation Algorithm)
      if (domain.length > 30) {
        findings.push({
          type: 'SUSPICIOUS_DOMAIN_LENGTH',
          description: 'Unusually long domain name detected (possible DGA)',
          severity: 'medium',
          evidence: domain
        });
      }
      
      // Check domain against suspicious patterns
      for (const pattern of this.suspiciousDomainPatterns) {
        if (pattern.test(domain)) {
          findings.push({
            type: 'SUSPICIOUS_DOMAIN_PATTERN',
            description: 'Domain matches suspicious pattern',
            severity: 'low',
            evidence: domain
          });
          break;
        }
      }
      
      // Check TLD against suspicious list
      const tld = domain.split('.').pop()?.toLowerCase();
      if (tld && this.suspiciousTlds.includes(tld)) {
        findings.push({
          type: 'SUSPICIOUS_TLD',
          description: `Domain uses suspicious TLD: .${tld}`,
          severity: 'low',
          evidence: domain
        });
      }
    }
    
    // Check for DNS tunneling indicators (many TXT records or unusually large DNS packets)
    if (packet.packet_size > 512) {
      findings.push({
        type: 'POSSIBLE_DNS_TUNNELING',
        description: 'Unusually large DNS packet detected (possible DNS tunneling)',
        severity: 'medium',
        evidence: `Packet size: ${packet.packet_size} bytes`
      });
    }
    
    if (findings.length === 0) {
      return null;
    }
    
    return {
      protocol: 'DNS',
      isSuspicious: findings.some(f => f.severity === 'high') || findings.length > 1,
      findings,
      confidence: findings.length > 2 ? 0.8 : 0.6
    };
  }
}

/**
 * SQL Injection Detector
 */
class SqlInjectionDetector {
  private sqlInjectionPatterns = [
    /'\s*OR\s*'1'\s*=\s*'1/i,
    /'\s*OR\s*1\s*=\s*1/i,
    /'\s*;\s*DROP\s+TABLE/i,
    /'\s*;\s*SELECT\s+/i,
    /UNION\s+SELECT/i,
    /UNION\s+ALL\s+SELECT/i,
    /CONCAT\s*\(/i,
    /GROUP_CONCAT\s*\(/i,
    /HAVING\s+\d+=\d+/i
  ];

  /**
   * Detect SQL injection patterns in payload
   */
  detect(payload: string): ProtocolFinding | null {
    for (const pattern of this.sqlInjectionPatterns) {
      if (pattern.test(payload)) {
        return {
          type: 'SQL_INJECTION',
          description: 'Detected potential SQL injection attempt',
          severity: 'high',
          evidence: payload.match(pattern)?.[0] || 'Pattern match'
        };
      }
    }
    
    return null;
  }
}

/**
 * XSS (Cross-Site Scripting) Detector
 */
class XssDetector {
  private xssPatterns = [
    /<script\b[^>]*>[\s\S]*?<\/script>/i,
    /javascript\s*:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /onclick\s*=/i,
    /onfocus\s*=/i,
    /onmouseover\s*=/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /document\.write/i,
    /document\.location/i,
    /alert\s*\(/i,
    /prompt\s*\(/i,
    /confirm\s*\(/i
  ];

  /**
   * Detect XSS patterns in payload
   */
  detect(payload: string): ProtocolFinding | null {
    for (const pattern of this.xssPatterns) {
      if (pattern.test(payload)) {
        return {
          type: 'XSS',
          description: 'Detected potential cross-site scripting (XSS) attempt',
          severity: 'high',
          evidence: payload.match(pattern)?.[0] || 'Pattern match'
        };
      }
    }
    
    return null;
  }
}

export const dpiService = new DPIService(); 