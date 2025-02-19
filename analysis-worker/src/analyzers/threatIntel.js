const { promisify } = require('util');
const { CacheManager } = require('../utils');

class ThreatIntel {
    constructor() {
        this.cache = new CacheManager({
            database: 1,
            defaultTTL: 3600
        });
        this.threatAPIs = [
            { name: 'AbuseIPDB', url: process.env.ABUSEIPDB_URL },
            { name: 'VirusTotal', url: process.env.VIRUSTOTAL_URL }
        ];
    }

    async init() {
        await this.cache.init();
    }

    async checkIP(ip) {
        try {
            // Check cache first
            const cached = await this.cache.get(`threat:${ip}`);
            if (cached) {
                return JSON.parse(cached);
            }

            // Query threat intelligence APIs
            const results = await Promise.allSettled(
                this.threatAPIs.map(api => this.queryAPI(api, ip))
            );

            // Aggregate results
            const threatData = this.aggregateResults(results);

            // Cache results
            await this.cache.set(
                `threat:${ip}`, 
                JSON.stringify(threatData), 
                'EX', 
                this.cacheTTL
            );

            return threatData;
        } catch (error) {
            console.error('Threat intelligence check failed:', error);
            return null;
        }
    }

    async queryAPI(api, ip) {
        // Implementation would vary based on the specific API
        // This is a placeholder for actual API calls
        return {
            api: api.name,
            score: Math.random() * 100,
            categories: ['suspicious'],
            lastSeen: new Date().toISOString()
        };
    }

    aggregateResults(results) {
        const validResults = results
            .filter(r => r.status === 'fulfilled')
            .map(r => r.value);

        if (validResults.length === 0) return null;

        const avgScore = validResults.reduce((acc, curr) => acc + curr.score, 0) / validResults.length;

        return {
            score: avgScore,
            sources: validResults.map(r => r.api),
            lastChecked: new Date().toISOString(),
            isMailicious: avgScore > 70
        };
    }
}

module.exports = ThreatIntel; 