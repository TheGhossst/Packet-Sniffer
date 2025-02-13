const Redis = require('redis');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');

// Configuration
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const PACKET_CHANNEL = 'packet-stream';
const NUM_WORKERS = os.cpus().length; // Use number of CPU cores

if (isMainThread) {
    // Main thread code
    async function main() {
        try {
            // Create connection pool
            const pool = await createRedisPool(5); // 5 connections in pool
            const subscriber = pool.subscriber;
            const publisher = pool.publisher;

            console.log('Connected to Redis');

            // Create worker pool
            const workers = new Array(NUM_WORKERS).fill(null).map((_, index) => {
                return new Worker(__filename, {
                    workerData: { workerId: index }
                });
            });

            // Handle worker messages
            workers.forEach(worker => {
                worker.on('message', async (analysis) => {
                    if (analysis.alerts && analysis.alerts.length > 0) {
                        await publisher.publish('alerts', JSON.stringify(analysis));
                        console.log('Alert published:', analysis.alerts[0]);
                    }
                });
            });

            // Round-robin worker distribution
            let currentWorker = 0;

            // Subscribe to packet stream
            await subscriber.subscribe(PACKET_CHANNEL, (message) => {
                try {
                    const data = JSON.parse(message);
                    
                    // Handle batch of packets
                    if (data.packets && Array.isArray(data.packets)) {
                        // Distribute packets among workers
                        data.packets.forEach(packet => {
                            workers[currentWorker].postMessage(packet);
                            currentWorker = (currentWorker + 1) % NUM_WORKERS;
                        });
                    } else {
                        // Handle single packet for backward compatibility
                        workers[currentWorker].postMessage(data);
                        currentWorker = (currentWorker + 1) % NUM_WORKERS;
                    }
                } catch (err) {
                    console.error('Error processing message:', err);
                }
            });

            console.log(`Started ${NUM_WORKERS} workers`);
            console.log(`Subscribed to ${PACKET_CHANNEL}`);

            // Handle shutdown
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
    // Worker thread code
    console.log(`Worker ${workerData.workerId} started`);
    
    // Create worker-local state
    const workerState = {
        lastSourceIP: null,
        lastPacketTime: Date.now()
    };
    
    parentPort.on('message', (packet) => {
        const analysis = analyzePacket(packet, workerState);
        if (analysis.alerts.length > 0) {
            parentPort.postMessage(analysis);
        }
    });
}

// Redis connection pool
async function createRedisPool(size) {
    const pool = {
        subscriber: Redis.createClient({ url: REDIS_URL }),
        publisher: Redis.createClient({ url: REDIS_URL }),
        connections: []
    };

    // Create additional connections for the pool
    for (let i = 0; i < size; i++) {
        pool.connections.push(Redis.createClient({ url: REDIS_URL }));
    }

    // Connect all clients
    await pool.subscriber.connect();
    await pool.publisher.connect();
    await Promise.all(pool.connections.map(client => client.connect()));

    // Add cleanup method
    pool.cleanup = async () => {
        await pool.subscriber.quit();
        await pool.publisher.quit();
        await Promise.all(pool.connections.map(client => client.quit()));
    };

    return pool;
}

function analyzePacket(packet, state) {
    const alerts = [];

    // HTTPS Traffic monitoring
    if (packet.dst_port === 443 || packet.src_port === 443) {
        alerts.push({
            type: 'HTTPS_TRAFFIC',
            severity: 'INFO',
            details: `HTTPS traffic: ${packet.src_ip}:${packet.src_port} -> ${packet.dst_ip}:${packet.dst_port}`,
            timestamp: packet.timestamp
        });
    }

    // Large data transfer detection
    if (packet.payload_size > 500) {
        alerts.push({
            type: 'LARGE_PAYLOAD',
            severity: 'INFO',
            details: `Large payload detected: ${packet.payload_size} bytes`,
            timestamp: packet.timestamp
        });
    }

    // High frequency connection detection
    if (packet.src_ip === state.lastSourceIP && 
        Date.now() - state.lastPacketTime < 100) { // Within 100ms
        alerts.push({
            type: 'HIGH_FREQUENCY',
            severity: 'WARNING',
            details: `High frequency traffic from ${packet.src_ip}`,
            timestamp: packet.timestamp
        });
    }

    // Update tracking variables
    state.lastSourceIP = packet.src_ip;
    state.lastPacketTime = Date.now();

    return {
        packetId: `${packet.timestamp}-${packet.src_ip}-${packet.dst_ip}`,
        timestamp: packet.timestamp,
        alerts
    };
} 