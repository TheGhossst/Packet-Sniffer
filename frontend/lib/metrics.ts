/**
 * Service for fetching metrics from the Prometheus endpoint
 */
const METRICS_ENDPOINT = '/api/metrics';

export interface MetricsSummary {
  totalPacketsProcessed: number;
  maliciousPacketsTotal: number;
  processingErrors: number;
  averageProcessingDuration: number;
  threatLevel: number;
  safeListHits: number;
  ipsumsBlacklistHits: number;
  virusTotalHits: number;
  abuseIPDBHits: number;
  multiSourceDetections: number;
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
  apiErrors: {
    source: string;
    count: number;
  }[];
  apiTimeouts: {
    source: string;
    count: number;
  }[];
}

/**
 * Fetch and parse metrics from the Prometheus endpoint
 */
export async function fetchMetrics(): Promise<MetricsSummary> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

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
      virusTotalHits: 0,
      abuseIPDBHits: 0,
      multiSourceDetections: 0,
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
      },
      apiErrors: [],
      apiTimeouts: []
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
    virusTotalHits: 0,
    abuseIPDBHits: 0,
    multiSourceDetections: 0,
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
    },
    apiErrors: [],
    apiTimeouts: []
  };

  const extractValue = (line: string): number => {
    const parts = line.split(' ');
    if (parts.length >= 2) {
      const value = parseFloat(parts[parts.length - 1]);
      return isNaN(value) ? 0 : value;
    }
    return 0;
  };

  const apiErrorsMap: Map<string, number> = new Map();
  const apiTimeoutsMap: Map<string, number> = new Map();

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

    if (line.match(/^packet_sniffer_virustotal_hits_total\s+\d+/)) {
      result.virusTotalHits = extractValue(line);
    }

    if (line.match(/^packet_sniffer_abuseipdb_hits_total\s+\d+/)) {
      result.abuseIPDBHits = extractValue(line);
    }

    if (line.match(/^packet_sniffer_multisource_detections_total\s+\d+/)) {
      result.multiSourceDetections = extractValue(line);
    }

    const apiErrorMatch = line.match(/^packet_sniffer_api_errors_total{source="([^"]+)"}\s+(\d+)/);
    if (apiErrorMatch && apiErrorMatch.length >= 3) {
      const source = apiErrorMatch[1];
      const count = parseInt(apiErrorMatch[2], 10);
      apiErrorsMap.set(source, count);
    }

    const apiTimeoutMatch = line.match(/^packet_sniffer_api_timeouts_total{source="([^"]+)"}\s+(\d+)/);
    if (apiTimeoutMatch && apiTimeoutMatch.length >= 3) {
      const source = apiTimeoutMatch[1];
      const count = parseInt(apiTimeoutMatch[2], 10);
      apiTimeoutsMap.set(source, count);
    }


    // First, collect all bucket values with their boundaries
    const histogramBuckets: Array<{ le: number, count: number }> = [];

    // Extract all histogram buckets including +Inf
    for (const line of lines) {
      // Match regular bucket
      const bucketMatch = line.match(/^packet_sniffer_packet_size_bytes_bucket{le="([^"]+)"}\s+(\d+)/);
      if (bucketMatch) {
        if (bucketMatch[1] === '+Inf') {
          histogramBuckets.push({
            le: Infinity,
            count: parseInt(bucketMatch[2], 10)
          });
        } else {
          histogramBuckets.push({
            le: parseFloat(bucketMatch[1]),
            count: parseInt(bucketMatch[2], 10)
          });
        }
      }
    }

    // Sort buckets by upper bound to ensure correct ordering
    histogramBuckets.sort((a, b) => a.le - b.le);

    // Now convert cumulative counts to discrete bucket counts
    let prevCount = 0;
    const discreteBuckets: Array<{ le: number, count: number }> = [];

    for (const bucket of histogramBuckets) {
      const discreteCount = Math.max(0, bucket.count - prevCount);
      discreteBuckets.push({
        le: bucket.le,
        count: discreteCount
      });
      prevCount = bucket.count;
    }

    result.packetSizeDistribution = [
      { bucket: '0-64', count: 0 },
      { bucket: '64-128', count: 0 },
      { bucket: '128-256', count: 0 },
      { bucket: '256-512', count: 0 },
      { bucket: '512-1024', count: 0 },
      { bucket: '1024-1500', count: 0 },
      { bucket: '1500+', count: 0 }
    ];

    for (const bucket of discreteBuckets) {
      if (bucket.le <= 64) {
        result.packetSizeDistribution[0].count += bucket.count;
      } else if (bucket.le <= 128) {
        result.packetSizeDistribution[1].count += bucket.count;
      } else if (bucket.le <= 256) {
        result.packetSizeDistribution[2].count += bucket.count;
      } else if (bucket.le <= 512) {
        result.packetSizeDistribution[3].count += bucket.count;
      } else if (bucket.le <= 1024) {
        result.packetSizeDistribution[4].count += bucket.count;
      } else if (bucket.le <= 1500) {
        result.packetSizeDistribution[5].count += bucket.count;
      } else {
        result.packetSizeDistribution[6].count += bucket.count;
      }
    }
  }

  result.apiErrors = Array.from(apiErrorsMap.entries()).map(([source, count]) => ({ source, count }));
  result.apiTimeouts = Array.from(apiTimeoutsMap.entries()).map(([source, count]) => ({ source, count }));

  return result;
}
