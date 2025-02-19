const Redis = require('redis');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const { Logger, RateLimiter, MetricsCollector } = require('./src/utils');
const PacketAnalyzer = require('./src/analyzers');

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const PACKET_CHANNEL = 'packet-stream';
const NUM_WORKERS = os.cpus().length;

if (isMainThread) {
    async function main() {
        try {
            const logger = new Logger({ level: process.env.LOG_LEVEL || 'debug' });
            const pool = await createRedisPool(5);
            const subscriber = pool.subscriber;
            const publisher = pool.publisher;

            logger.info('Connected to Redis');

            const workers = new Array(NUM_WORKERS).fill(null).map((_, index) => {
                return new Worker(__filename, {
                    workerData: { workerId: index }
                });
            });

            logger.info(`Started ${NUM_WORKERS} workers`);

            workers.forEach(worker => {
                worker.on('message', async (analysis) => {
                    if (analysis.alerts && analysis.alerts.length > 0) {
                        await publisher.publish('alerts', JSON.stringify(analysis));
                        logger.info('Alert published:', analysis.alerts[0]);
                    }
                });
            });

            let currentWorker = 0;

            await subscriber.subscribe(PACKET_CHANNEL, (message) => {
                try {
                    const data = JSON.parse(message);
                    logger.debug('Received packet from Redis', { 
                        channel: PACKET_CHANNEL,
                        packetCount: data.packets ? data.packets.length : 1 
                    });
                    
                    if (data.packets && Array.isArray(data.packets)) {
                        data.packets.forEach(packet => {
                            workers[currentWorker].postMessage(packet);
                            currentWorker = (currentWorker + 1) % NUM_WORKERS;
                        });
                    } else {
                        workers[currentWorker].postMessage(data);
                        currentWorker = (currentWorker + 1) % NUM_WORKERS;
                    }
                } catch (err) {
                    logger.error('Error processing message:', err);
                }
            });

            logger.info(`Subscribed to ${PACKET_CHANNEL}`);

            process.on('SIGINT', async () => {
                console.log('Shutting down...');
                await Promise.all(workers.map(w => w.terminate()));
                await pool.cleanup();
                process.exit(0);
            });

        } catch (err) {
            console.error('Startup error:', err);
            process.exit(1);
        }
    }

    main().catch(console.error);

} else {
    console.log(`Worker ${workerData.workerId} started`);
    
    const logger = new Logger({ level: process.env.LOG_LEVEL || 'debug' }); // Set to debug level
    const rateLimiter = new RateLimiter({
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 10000
    });
    const metrics = new MetricsCollector();
    const analyzer = new PacketAnalyzer();
    
    analyzer.init().then(() => {
        parentPort.on('message', async (packet) => {
            const startTime = Date.now();
            try {
                logger.debug('Received packet for analysis:', { 
                    src_ip: packet.src_ip,
                    dst_ip: packet.dst_ip,
                    protocol: packet.protocol,
                    ports: `${packet.src_port}->${packet.dst_port}`
                });

                if (rateLimiter.isRateLimited(packet.src_ip)) {
                    logger.warn('Rate limit exceeded', { ip: packet.src_ip });
                    return;
                }

                const alerts = await analyzer.analyzePacket(packet);
                
                const processingTime = Date.now() - startTime;
                metrics.recordPacketProcessed(processingTime);
                
                if (alerts.length > 0) {
                    metrics.recordAlert();
                    logger.info('Alerts generated:', { alerts });
                    parentPort.postMessage({
                        packetId: `${packet.timestamp}-${packet.src_ip}-${packet.dst_ip}`,
                        timestamp: packet.timestamp,
                        alerts,
                        metrics: metrics.getMetrics()
                    });
                } else {
                    logger.debug('No alerts generated for packet');
                }
            } catch (error) {
                metrics.recordError();
                logger.error('Analysis error', { error: error.message, packet });
            }
        });
    }).catch(error => {
        logger.error('Failed to initialize analyzer', { error: error.message });
        process.exit(1);
    });

    process.on('SIGTERM', async () => {
        try {
            await analyzer.cleanup();  // Need to implement this
            process.exit(0);
        } catch (error) {
            console.error('Cleanup failed:', error);
            process.exit(1);
        }
    });
}

async function createRedisPool(size) {
    const pool = {
        subscriber: Redis.createClient({ url: REDIS_URL }),
        publisher: Redis.createClient({ url: REDIS_URL }),
        connections: []
    };

    for (let i = 0; i < size; i++) {
        pool.connections.push(Redis.createClient({ url: REDIS_URL }));
    }

    await pool.subscriber.connect();
    await pool.publisher.connect();
    await Promise.all(pool.connections.map(client => client.connect()));

    pool.cleanup = async () => {
        await pool.subscriber.quit();
        await pool.publisher.quit();
        await Promise.all(pool.connections.map(client => client.quit()));
    };

    return pool;
}

function analyzePacket(packet, state) {
    const alerts = [];

    if (packet.dst_port === 443 || packet.src_port === 443) {
        alerts.push({
            type: 'HTTPS_TRAFFIC',
            severity: 'INFO',
            details: `HTTPS traffic: ${packet.src_ip}:${packet.src_port} -> ${packet.dst_ip}:${packet.dst_port}`,
            timestamp: packet.timestamp
        });
    }

    if (packet.payload_size > 500) {
        alerts.push({
            type: 'LARGE_PAYLOAD',
            severity: 'INFO',
            details: `Large payload detected: ${packet.payload_size} bytes`,
            timestamp: packet.timestamp
        });
    }

    if (packet.src_ip === state.lastSourceIP && 
        Date.now() - state.lastPacketTime < 100) {
        alerts.push({
            type: 'HIGH_FREQUENCY',
            severity: 'WARNING',
            details: `High frequency traffic from ${packet.src_ip}`,
            timestamp: packet.timestamp
        });
    }

    state.lastSourceIP = packet.src_ip;
    state.lastPacketTime = Date.now();

    return {
        packetId: `${packet.timestamp}-${packet.src_ip}-${packet.dst_ip}`,
        timestamp: packet.timestamp,
        alerts
    };
} 