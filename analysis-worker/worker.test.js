const { Worker } = require('worker_threads');

describe('Worker Thread Tests', () => {
    test('Worker processes packets correctly', (done) => {
        const worker = new Worker('./index.js', {
            workerData: { workerId: 'test' }
        });

        const testPacket = {
            src_ip: '192.168.1.1',
            dst_ip: '192.168.1.2',
            src_port: 443,
            dst_port: 80,
            protocol: 'TCP',
            payload_size: 600,
            timestamp: new Date().toISOString()
        };

        worker.on('message', (analysis) => {
            expect(analysis.alerts).toBeDefined();
            expect(analysis.alerts.length).toBeGreaterThan(0);
            worker.terminate();
            done();
        });

        worker.postMessage(testPacket);
    });
}); 