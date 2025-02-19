class RateLimiter {
    constructor(options = {}) {
        this.windowMs = options.windowMs || 60000; // 1 minute default
        this.maxRequests = options.maxRequests || 100;
        this.requests = new Map();
    }

    isRateLimited(key) {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        if (!this.requests.has(key)) {
            this.requests.set(key, [now]);
            return false;
        }

        const requests = this.requests.get(key).filter(time => time > windowStart);
        this.requests.set(key, requests);

        if (requests.length >= this.maxRequests) {
            return true;
        }

        requests.push(now);
        return false;
    }

    cleanup() {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        for (const [key, times] of this.requests.entries()) {
            const validTimes = times.filter(time => time > windowStart);
            if (validTimes.length === 0) {
                this.requests.delete(key);
            } else {
                this.requests.set(key, validTimes);
            }
        }
    }
}

module.exports = RateLimiter; 