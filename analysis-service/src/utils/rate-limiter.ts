/**
 * A rate limiter implementation using the token bucket algorithm.
 * This implementation supports bursts while maintaining a long-term rate limit.
 */
export class RateLimiter {
    private tokens: number;
    private lastRefill: number;
    private readonly maxTokens: number;
    private readonly tokensPerMs: number;
    private readonly waitingQueue: Array<{
        resolve: (value: void) => void;
        reject: (reason: Error) => void;
        timeout: NodeJS.Timeout;
    }>;

    /**
     * Creates a new RateLimiter instance
     * @param maxRequestsPerWindow Maximum number of requests allowed in the time window
     * @param windowMs Time window in milliseconds
     * @param burstSize Maximum burst size (defaults to maxRequestsPerWindow)
     */
    constructor(
        maxRequestsPerWindow: number,
        windowMs: number,
        burstSize?: number
    ) {
        this.maxTokens = burstSize || maxRequestsPerWindow;
        this.tokens = this.maxTokens;
        this.tokensPerMs = maxRequestsPerWindow / windowMs;
        this.lastRefill = Date.now();
        this.waitingQueue = [];
    }

    /**
     * Refills tokens based on elapsed time
     * @private
     */
    private refillTokens(): void {
        const now = Date.now();
        const elapsedMs = now - this.lastRefill;
        const newTokens = elapsedMs * this.tokensPerMs;
        
        this.tokens = Math.min(this.maxTokens, this.tokens + newTokens);
        this.lastRefill = now;
    }

    /**
     * Processes the waiting queue when new tokens become available
     * @private
     */
    private processQueue(): void {
        while (this.waitingQueue.length > 0 && this.tokens >= 1) {
            const next = this.waitingQueue.shift();
            if (next) {
                clearTimeout(next.timeout);
                this.tokens--;
                next.resolve();
            }
        }
    }

    /**
     * Acquires a token for rate limiting. Returns a promise that resolves when a token is available.
     * @param timeoutMs Optional timeout in milliseconds
     * @returns Promise that resolves when the request can proceed
     */
    async acquire(timeoutMs: number = 5000): Promise<void> {
        this.refillTokens();

        if (this.tokens >= 1) {
            this.tokens--;
            return Promise.resolve();
        }

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                const index = this.waitingQueue.findIndex(
                    item => item.resolve === resolve
                );
                if (index !== -1) {
                    this.waitingQueue.splice(index, 1);
                    reject(new Error('Rate limit timeout exceeded'));
                }
            }, timeoutMs);

            this.waitingQueue.push({ resolve, reject, timeout });
        });
    }

    /**
     * Returns the current number of available tokens
     * @returns Number of available tokens
     */
    getAvailableTokens(): number {
        this.refillTokens();
        return this.tokens;
    }

    /**
     * Returns the current length of the waiting queue
     * @returns Number of requests waiting for tokens
     */
    getQueueLength(): number {
        return this.waitingQueue.length;
    }

    /**
     * Clears the waiting queue and rejects all pending requests
     */
    clear(): void {
        while (this.waitingQueue.length > 0) {
            const request = this.waitingQueue.shift();
            if (request) {
                clearTimeout(request.timeout);
                request.reject(new Error('Rate limiter cleared'));
            }
        }
    }
} 