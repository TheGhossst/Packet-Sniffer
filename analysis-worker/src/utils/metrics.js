class MetricsCollector {
    constructor() {
        this.metrics = {
            packetsProcessed: 0,
            alertsGenerated: 0,
            processingErrors: 0,
            avgProcessingTime: 0,
            totalProcessingTime: 0
        };
    }

    recordPacketProcessed(processingTime) {
        this.metrics.packetsProcessed++;
        this.metrics.totalProcessingTime += processingTime;
        this.metrics.avgProcessingTime = 
            this.metrics.totalProcessingTime / this.metrics.packetsProcessed;
    }

    recordAlert() {
        this.metrics.alertsGenerated++;
    }

    recordError() {
        this.metrics.processingErrors++;
    }

    getMetrics() {
        return { ...this.metrics };
    }
}

module.exports = MetricsCollector; 