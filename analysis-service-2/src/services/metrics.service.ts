import * as prometheus from 'prom-client';

/**
 * MetricsService provides Prometheus metrics collection and exposure
 * for the analysis service.
 */
class MetricsService {
  private registry: prometheus.Registry;

  private totalPacketsProcessed!: prometheus.Counter;
  private packetProcessingDuration!: prometheus.Histogram;
  private maliciousPacketsCounter!: prometheus.Counter;
  private packetSizeHistogram!: prometheus.Histogram;
  private ipsumsBlacklistHits!: prometheus.Counter;
  private safeListHits!: prometheus.Counter;
  private processingErrors!: prometheus.Counter;
  private threatLevelGauge!: prometheus.Gauge;

  constructor() {
    this.registry = new prometheus.Registry();

    prometheus.collectDefaultMetrics({ register: this.registry });

    this.initializeMetrics();
  }

  /**
   * Initialize all metrics with appropriate labels
   */
  private initializeMetrics(): void {
    this.totalPacketsProcessed = new prometheus.Counter({
      name: 'packet_sniffer_total_packets_processed',
      help: 'Total number of packets processed by the analysis service',
      registers: [this.registry]
    });

    this.packetProcessingDuration = new prometheus.Histogram({
      name: 'packet_sniffer_processing_duration_seconds',
      help: 'Histogram of packet processing durations in seconds',
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
      registers: [this.registry]
    });

    this.maliciousPacketsCounter = new prometheus.Counter({
      name: 'packet_sniffer_malicious_packets_total',
      help: 'Total number of malicious packets detected',
      labelNames: ['threat_level'],
      registers: [this.registry]
    });

    this.packetSizeHistogram = new prometheus.Histogram({
      name: 'packet_sniffer_packet_size_bytes',
      help: 'Histogram of packet sizes in bytes',
      buckets: [64, 128, 256, 512, 1024, 1500, 9000],
      registers: [this.registry]
    });

    this.ipsumsBlacklistHits = new prometheus.Counter({
      name: 'packet_sniffer_ipsum_blacklist_hits_total',
      help: 'Total number of IPs found in the Ipsum blacklist',
      registers: [this.registry]
    });

    this.safeListHits = new prometheus.Counter({
      name: 'packet_sniffer_safe_list_hits_total',
      help: 'Total number of IPs found in the safe list',
      registers: [this.registry]
    });

    this.processingErrors = new prometheus.Counter({
      name: 'packet_sniffer_processing_errors_total',
      help: 'Total number of errors during packet processing',
      registers: [this.registry]
    });

    this.threatLevelGauge = new prometheus.Gauge({
      name: 'packet_sniffer_threat_level',
      help: 'Current threat level (0=safe, 1=unknown, 2=medium, 3=high)',
      registers: [this.registry]
    });
  }

  /**
   * Increment total packets processed counter
   */
  public incrementPacketsProcessed(): void {
    this.totalPacketsProcessed.inc();
  }

  /**
   * Record processing duration in seconds
   * @param durationSeconds Processing duration in seconds
   */
  public observeProcessingDuration(durationSeconds: number): void {
    this.packetProcessingDuration.observe(durationSeconds);
  }

  /**
   * Increment malicious packets counter with threat level label
   * @param threatLevel Threat level of the packet
   */
  public incrementMaliciousPackets(threatLevel: string): void {
    this.maliciousPacketsCounter.inc({ threat_level: threatLevel });
  }

  /**
   * Record packet size in histogram
   * @param sizeBytes Size of the packet in bytes
   */
  public observePacketSize(sizeBytes: number): void {
    this.packetSizeHistogram.observe(sizeBytes);
  }

  /**
   * Increment ipsum blacklist hits counter
   */
  public incrementIpsumBlacklistHits(): void {
    this.ipsumsBlacklistHits.inc();
  }

  /**
   * Increment safe list hits counter
   */
  public incrementSafeListHits(): void {
    this.safeListHits.inc();
  }

  /**
   * Increment processing errors counter
   */
  public incrementProcessingErrors(): void {
    this.processingErrors.inc();
  }

  /**
   * Set threat level gauge
   * @param level Numeric representation of threat level (0=safe, 1=unknown, 2=medium, 3=high)
   */
  public setThreatLevel(level: number): void {
    this.threatLevelGauge.set(level);
  }

  /**
   * Get Prometheus metrics in the text format
   * @returns Promise with metrics in text format
   */
  public async getMetrics(): Promise<string> {
    return await this.registry.metrics();
  }

  /**
   * Get registry object
   * @returns Prometheus registry
   */
  public getRegistry(): prometheus.Registry {
    return this.registry;
  }
}

export const metricsService = new MetricsService();