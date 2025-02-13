const Redis = require('redis');

describe('Analysis Worker', () => {
    test('Redis connection', async () => {
        const client = Redis.createClient('redis://localhost:6379');
        await expect(client.connect()).resolves.not.toThrow();
        await client.quit();
    });
}); 