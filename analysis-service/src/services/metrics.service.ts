import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import express from 'express';
import { logger } from '../utils/logger';

export class MetricsService {
    private app: express.Application;
    private port: number;
    private packetsProcessed: Counter;
    private alertsGenerated: Counter;
    private processingTime: Histogram;
    private registry: Registry;

    constructor() {
        this.app = express();
        this.port = parseInt(process.env.METRICS_PORT || '9090');
        this.registry = new Registry();

        // Initialize Prometheus metrics
        this.packetsProcessed = new Counter({
            name: 'packets_processed_total',
            help: 'Total number of packets processed',
            registers: [this.registry]
        });

        this.alertsGenerated = new Counter({
            name: 'alerts_generated_total',
            help: 'Total number of alerts generated',
            registers: [this.registry]
        });

        this.processingTime = new Histogram({
            name: 'packet_processing_duration_seconds',
            help: 'Time spent processing packets',
            buckets: [0.1, 0.5, 1, 2, 5],
            registers: [this.registry]
        });

        // Enable default metrics
        collectDefaultMetrics({ register: this.registry });

        // Metrics endpoint
        this.app.get('/metrics', async (_req, res) => {
            try {
                res.set('Content-Type', this.registry.contentType);
                res.end(await this.registry.metrics());
            } catch (err) {
                res.status(500).end(err);
            }
        });
    }

    public async initialize(): Promise<void> {
        try {
            await this.registry.setDefaultLabels({
                app: 'network-analysis-service'
            });
            
            // Start the metrics server
            this.app.listen(this.port, () => {
                logger.info(`Metrics server running on port ${this.port}`);
            });

            logger.info('Metrics service initialized');
        } catch (error) {
            const errorMeta = {
                error: error instanceof Error ? {
                    message: error.message,
                    name: error.name,
                    stack: error.stack
                } : String(error)
            };
            logger.error('Failed to initialize metrics service:', errorMeta);
            throw error;
        }
    }

    public async getPacketsProcessed(): Promise<number> {
        const metric = await this.packetsProcessed.get();
        return metric.values[0]?.value || 0;
    }

    public async getAlertsGenerated(): Promise<number> {
        const metric = await this.alertsGenerated.get();
        return metric.values[0]?.value || 0;
    }

    public async getProcessingTime(): Promise<{ avg: number; p95: number }> {
        const metric = await this.processingTime.get();
        const values = metric.values;
        
        if (values.length === 0) {
            return { avg: 0, p95: 0 };
        }

        // Calculate total and count
        let total = 0;
        let count = 0;
        for (const val of values) {
            total += val.value;
            count += 1;
        }

        // Sort values for percentile calculation
        const sortedValues = [...values].sort((a, b) => a.value - b.value);
        const p95Index = Math.floor(sortedValues.length * 0.95);
        const p95 = sortedValues[p95Index]?.value || 0;

        return {
            avg: count > 0 ? total / count : 0,
            p95
        };
    }

    public incrementPacketsProcessed(): void {
        this.packetsProcessed.inc();
    }

    public incrementAlertsGenerated(): void {
        this.alertsGenerated.inc();
    }

    public observeProcessingTime(durationMs: number): void {
        this.processingTime.observe(durationMs / 1000); // Convert to seconds
    }
}

export const metricsService = new MetricsService(); 