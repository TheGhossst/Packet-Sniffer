import * as http from 'http';
import { metricsService } from './metrics.service.js';

/**
 * MetricsServerService provides an HTTP server to expose Prometheus metrics
 */
class MetricsServerService {
  private server: http.Server | null = null;
  private port: number = 9090;

  /**
   * Start the metrics HTTP server
   */
  public async start(): Promise<void> {
    if (this.server) {
      console.info('Metrics server already running');
      return;
    }

    try {
      this.server = http.createServer(async (req, res) => {
        // Only respond to /metrics endpoint
        if (req.url === '/metrics') {
          res.setHeader('Content-Type', 'text/plain');
          
          try {
            const metrics = await metricsService.getMetrics();
            res.statusCode = 200;
            res.end(metrics);
          } catch (error) {
            console.error('Error generating metrics:', error);
            res.statusCode = 500;
            res.end('Error generating metrics');
          }
        } else {
          // For any other endpoint, return basic information
          res.setHeader('Content-Type', 'text/html');
          res.statusCode = 200;
          res.end(`
            <html>
              <head><title>Packet Sniffer - Analysis Service Metrics</title></head>
              <body>
                <h1>Packet Sniffer - Analysis Service Metrics</h1>
                <p>Prometheus metrics are available at <a href="/metrics">/metrics</a></p>
              </body>
            </html>
          `);
        }
      });

      this.server.listen(this.port, () => {
        console.info(`Metrics server started on http://localhost:${this.port}`);
      });

      this.server.on('error', (error) => {
        console.error('Metrics server error:', error);
      });
    } catch (error) {
      console.error('Failed to start metrics server:', error);
    }
  }

  /**
   * Stop the metrics HTTP server
   */
  public async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve, reject) => {
        this.server!.close((err) => {
          if (err) {
            console.error('Error stopping metrics server:', err);
            reject(err);
          } else {
            console.info('Metrics server stopped');
            this.server = null;
            resolve();
          }
        });
      });
    }
  }

  /**
   * Get the metrics server port
   */
  public getPort(): number {
    return this.port;
  }
}

export const metricsServerService = new MetricsServerService();