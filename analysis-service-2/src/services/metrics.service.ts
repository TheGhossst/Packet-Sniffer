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
  private virusTotalHitsCounter!: prometheus.Counter;
  private abuseipdbHitsCounter!: prometheus.Counter;
  private multiSourceDetectionsCounter!: prometheus.Counter;
  private apiErrorsCounter!: prometheus.Counter;
  private apiTimeoutsCounter!: prometheus.Counter;
  private dpiDetectionsCounter!: prometheus.Counter;
  private behavioralAnomaliesCounter!: prometheus.Counter;
  private suspiciousConnectionsGauge!: prometheus.Gauge;
  private tlsDetectionsCounter!: prometheus.Counter;
  private smtpDetectionsCounter!: prometheus.Counter;
  private smbDetectionsCounter!: prometheus.Counter;
  private icmpDetectionsCounter!: prometheus.Counter;

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

    this.virusTotalHitsCounter = new prometheus.Counter({
      name: 'packet_sniffer_virustotal_hits_total',
      help: 'Total number of IPs found in VirusTotal',
      registers: [this.registry]
    });
    
    this.abuseipdbHitsCounter = new prometheus.Counter({
      name: 'packet_sniffer_abuseipdb_hits_total',
      help: 'Total number of IPs found in AbuseIPDB',
      registers: [this.registry]
    });
    
    this.multiSourceDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_multisource_detections_total',
      help: 'Total number of IPs detected by multiple threat intelligence sources',
      registers: [this.registry]
    });

    this.apiErrorsCounter = new prometheus.Counter({
      name: 'packet_sniffer_api_errors_total',
      help: 'Total number of API errors by source',
      labelNames: ['source'],
      registers: [this.registry]
    });

    this.apiTimeoutsCounter = new prometheus.Counter({
      name: 'packet_sniffer_api_timeouts_total',
      help: 'Total number of API timeouts by source',
      labelNames: ['source'],
      registers: [this.registry]
    });
    
    this.dpiDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_dpi_detections_total',
      help: 'Total number of suspicious packets detected by DPI',
      labelNames: ['protocol', 'type'],
      registers: [this.registry]
    });
    
    this.behavioralAnomaliesCounter = new prometheus.Counter({
      name: 'packet_sniffer_behavioral_anomalies_total',
      help: 'Total number of behavioral anomalies detected',
      labelNames: ['type', 'severity'],
      registers: [this.registry]
    });
    
    this.suspiciousConnectionsGauge = new prometheus.Gauge({
      name: 'packet_sniffer_suspicious_connections',
      help: 'Current number of tracked suspicious connections',
      registers: [this.registry]
    });

    this.tlsDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_tls_detections_total',
      help: 'Total number of suspicious TLS connections detected',
      labelNames: ['type'],
      registers: [this.registry]
    });

    this.smtpDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_smtp_detections_total',
      help: 'Total number of suspicious email activities detected',
      labelNames: ['type'],
      registers: [this.registry]
    });

    this.smbDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_smb_detections_total',
      help: 'Total number of suspicious SMB activities detected',
      labelNames: ['type'],
      registers: [this.registry]
    });

    this.icmpDetectionsCounter = new prometheus.Counter({
      name: 'packet_sniffer_icmp_detections_total',
      help: 'Total number of suspicious ICMP activities detected',
      labelNames: ['type'],
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
   * Increment VirusTotal hits counter
   */
  public incrementVirusTotalHits(): void {
    this.virusTotalHitsCounter.inc();
  }
  
  /**
   * Increment AbuseIPDB hits counter
   */
  public incrementAbuseIPDBHits(): void {
    this.abuseipdbHitsCounter.inc();
  }
  
  /**
   * Increment multi-source detections counter
   */
  public incrementMultiSourceDetections(): void {
    this.multiSourceDetectionsCounter.inc();
  }

  /**
   * Increment API errors counter
   * @param source The API source that encountered an error (e.g., 'virustotal', 'abuseipdb')
   */
  public incrementApiErrors(source: string): void {
    this.apiErrorsCounter.inc({ source });
  }

  /**
   * Increment API timeouts counter
   * @param source The API source that timed out (e.g., 'virustotal', 'abuseipdb')
   */
  public incrementApiTimeouts(source: string): void {
    this.apiTimeoutsCounter.inc({ source });
  }

  /**
   * Increment DPI detections counter
   * @param protocol The protocol where suspicious activity was detected
   * @param type The type of suspicious activity detected
   */
  public incrementDpiDetections(protocol: string = 'unknown', type: string = 'general'): void {
    this.dpiDetectionsCounter.inc({ protocol, type });
  }

  /**
   * Increment behavioral anomalies counter
   * @param type The type of anomaly detected
   * @param severity The severity of the anomaly
   */
  public incrementBehavioralAnomalies(type: string, severity: string = 'medium'): void {
    this.behavioralAnomaliesCounter.inc({ type, severity });
  }

  /**
   * Set current number of suspicious connections
   * @param count Number of suspicious connections
   */
  public setSuspiciousConnections(count: number): void {
    this.suspiciousConnectionsGauge.set(count);
  }

  /**
   * Increment TLS detection counter
   * @param type Type of suspicious TLS activity detected
   */
  public incrementTlsDetections(type: string): void {
    this.tlsDetectionsCounter.inc({ type });
  }

  /**
   * Increment SMTP detection counter
   * @param type Type of suspicious email activity detected
   */
  public incrementSmtpDetections(type: string): void {
    this.smtpDetectionsCounter.inc({ type });
  }

  /**
   * Increment SMB detection counter
   * @param type Type of suspicious SMB activity detected
   */
  public incrementSmbDetections(type: string): void {
    this.smbDetectionsCounter.inc({ type });
  }

  /**
   * Increment ICMP detection counter
   * @param type Type of suspicious ICMP activity detected
   */
  public incrementIcmpDetections(type: string): void {
    this.icmpDetectionsCounter.inc({ type });
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