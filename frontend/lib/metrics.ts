/**
 * Service for fetching metrics from the Prometheus endpoint
 */

// Metrics endpoint URL - using our API proxy to avoid CORS issues
const METRICS_ENDPOINT = '/api/metrics';

export interface MetricsSummary {
  totalPacketsProcessed: number;
  maliciousPacketsTotal: number;
  processingErrors: number;
  averageProcessingDuration: number;
  threatLevel: number;
  safeListHits: number;
  ipsumsBlacklistHits: number;
  packetSizeDistribution: {
    bucket: string;
    count: number;
  }[];
  lastUpdated: string;
  connectionStatus: 'connected' | 'disconnected';
  maliciousByThreatLevel: {
    high: number;
    medium: number;
    unknown: number;
  };
}

/**
 * Fetch and parse metrics from the Prometheus endpoint
 */
export async function fetchMetrics(): Promise<MetricsSummary> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout
    
    const response = await fetch(METRICS_ENDPOINT, {
      signal: controller.signal,
      headers: {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      throw new Error(`Failed to fetch metrics: ${response.statusText}`);
    }
    
    const text = await response.text();
    
    const result = parsePrometheusMetrics(text);
    
    result.connectionStatus = 'connected';
    result.lastUpdated = new Date().toISOString();
    
    return result;
  } catch (error) {
    console.error('Error fetching metrics:', error);
    
    return {
      totalPacketsProcessed: 0,
      maliciousPacketsTotal: 0,
      processingErrors: 0,
      averageProcessingDuration: 0,
      threatLevel: 0,
      safeListHits: 0,
      ipsumsBlacklistHits: 0,
      packetSizeDistribution: [
        { bucket: '0-64', count: 0 },
        { bucket: '64-128', count: 0 },
        { bucket: '128-256', count: 0 },
        { bucket: '256-512', count: 0 },
        { bucket: '512-1024', count: 0 },
        { bucket: '1024-1500', count: 0 },
        { bucket: '1500+', count: 0 },
      ],
      lastUpdated: new Date().toISOString(),
      connectionStatus: 'disconnected',
      maliciousByThreatLevel: {
        high: 0,
        medium: 0,
        unknown: 0
      }
    };
  }
}

/**
 * Parse Prometheus metrics text format into a structured object
 * @param metricsText Raw Prometheus metrics text
 */
function parsePrometheusMetrics(metricsText: string): MetricsSummary {
  const lines = metricsText.split('\n');
  
  const result: MetricsSummary = {
    totalPacketsProcessed: 0,
    maliciousPacketsTotal: 0,
    processingErrors: 0,
    averageProcessingDuration: 0,
    threatLevel: 0,
    safeListHits: 0,
    ipsumsBlacklistHits: 0,
    packetSizeDistribution: [
      { bucket: '0-64', count: 0 },
      { bucket: '64-128', count: 0 },
      { bucket: '128-256', count: 0 },
      { bucket: '256-512', count: 0 },
      { bucket: '512-1024', count: 0 },
      { bucket: '1024-1500', count: 0 },
      { bucket: '1500+', count: 0 },
    ],
    lastUpdated: new Date().toISOString(),
    connectionStatus: 'connected',
    maliciousByThreatLevel: {
      high: 0,
      medium: 0,
      unknown: 0
    }
  };
  
  const extractValue = (line: string): number => {
    const parts = line.split(' ');
    if (parts.length >= 2) {
      const value = parseFloat(parts[parts.length - 1]);
      return isNaN(value) ? 0 : value;
    }
    return 0;
  };
  
  for (const line of lines) {
    if (line.startsWith('#') || line.trim() === '') {
      continue;
    }
    
    if (line.match(/^packet_sniffer_total_packets_processed\s+\d+/)) {
      result.totalPacketsProcessed = extractValue(line);
    }
    
    if (line.match(/^packet_sniffer_malicious_packets_total{threat_level="high"}/)) {
      result.maliciousByThreatLevel.high = extractValue(line);
      result.maliciousPacketsTotal += result.maliciousByThreatLevel.high;
    }
    
    if (line.match(/^packet_sniffer_malicious_packets_total{threat_level="medium"}/)) {
      result.maliciousByThreatLevel.medium = extractValue(line);
      result.maliciousPacketsTotal += result.maliciousByThreatLevel.medium;
    }
    
    if (line.match(/^packet_sniffer_malicious_packets_total{threat_level="unknown"}/)) {
      result.maliciousByThreatLevel.unknown = extractValue(line);
      result.maliciousPacketsTotal += result.maliciousByThreatLevel.unknown;
    }
    
    if (line.match(/^packet_sniffer_processing_errors_total\s+\d+/)) {
      result.processingErrors = extractValue(line);
    }
    
    // Average processing duration (use sum/count)
    if (line.match(/^packet_sniffer_processing_duration_seconds_sum\s+\d+/)) {
      const sum = extractValue(line);
      const countLine = lines.find(l => l.match(/^packet_sniffer_processing_duration_seconds_count\s+\d+/));
      
      if (countLine) {
        const count = extractValue(countLine);
        if (count > 0) {
          result.averageProcessingDuration = sum / count;
        }
      }
    }
    
    if (line.match(/^packet_sniffer_threat_level\s+\d+/)) {
      result.threatLevel = extractValue(line);
    }
    
    if (line.match(/^packet_sniffer_safe_list_hits_total\s+\d+/)) {
      result.safeListHits = extractValue(line);
    }
    
    if (line.match(/^packet_sniffer_ipsum_blacklist_hits_total\s+\d+/)) {
      result.ipsumsBlacklistHits = extractValue(line);
    }
    
    // Packet size distribution (parse histogram buckets)
    // This is more complex, handling bucket by bucket
    if (line.match(/^packet_sniffer_packet_size_bytes_bucket{le="(\d+)"}\s+(\d+)/)) {
      const match = line.match(/^packet_sniffer_packet_size_bytes_bucket{le="(\d+)"}\s+(\d+)/);
      if (match && match.length >= 3) {
        const bucket = parseFloat(match[1]);
        const count = parseFloat(match[2]);
        
        // Update the corresponding bucket in our distribution
        // This is a simplified approach - for a real implementation,
        // we need to handle the cumulative nature of Prometheus histograms
        if (bucket <= 64 && count > 0) {
          result.packetSizeDistribution[0].count = count;
        } else if (bucket <= 128 && count > 0) {
          const prevCount = result.packetSizeDistribution[0].count;
          result.packetSizeDistribution[1].count = Math.max(0, count - prevCount);
        } else if (bucket <= 256 && count > 0) {
          const prevCount = result.packetSizeDistribution[0].count + result.packetSizeDistribution[1].count;
          result.packetSizeDistribution[2].count = Math.max(0, count - prevCount);
        } else if (bucket <= 512 && count > 0) {
          const prevCount = result.packetSizeDistribution[0].count + result.packetSizeDistribution[1].count +
                            result.packetSizeDistribution[2].count;
          result.packetSizeDistribution[3].count = Math.max(0, count - prevCount);
        } else if (bucket <= 1024 && count > 0) {
          const prevCount = result.packetSizeDistribution[0].count + result.packetSizeDistribution[1].count +
                            result.packetSizeDistribution[2].count + result.packetSizeDistribution[3].count;
          result.packetSizeDistribution[4].count = Math.max(0, count - prevCount);
        } else if (bucket <= 1500 && count > 0) {
          const prevCount = result.packetSizeDistribution[0].count + result.packetSizeDistribution[1].count +
                            result.packetSizeDistribution[2].count + result.packetSizeDistribution[3].count +
                            result.packetSizeDistribution[4].count;
          result.packetSizeDistribution[5].count = Math.max(0, count - prevCount);
        }
      }
    }
    
    // Handle the +Inf bucket separately for the last distribution bucket
    if (line.match(/^packet_sniffer_packet_size_bytes_bucket{le="\+Inf"}\s+(\d+)/)) {
      const match = line.match(/^packet_sniffer_packet_size_bytes_bucket{le="\+Inf"}\s+(\d+)/);
      if (match && match.length >= 2) {
        const totalCount = parseFloat(match[1]);
        
        const prevCount = result.packetSizeDistribution[0].count + result.packetSizeDistribution[1].count +
                          result.packetSizeDistribution[2].count + result.packetSizeDistribution[3].count +
                          result.packetSizeDistribution[4].count + result.packetSizeDistribution[5].count;
                          
        result.packetSizeDistribution[6].count = Math.max(0, totalCount - prevCount);
      }
    }
  }
  
  return result;
}
