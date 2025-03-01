import { CircuitBreakerError, TimeoutError, ErrorCode } from './errors';
import { logger } from './logger';

enum CircuitState {
    CLOSED,
    OPEN,
    HALF_OPEN
}

interface CircuitBreakerOptions {
    failureThreshold: number;
    resetTimeout: number;
    halfOpenRetries: number;
    monitorInterval: number;
    timeout?: number;
    bulkhead?: {
        maxConcurrent: number;
        maxQueued: number;
    };
    adaptiveTimeout: {
        enabled: boolean;
        minTimeout: number;
        maxTimeout: number;
        percentile: number;
    };
}

interface CircuitStats {
    failures: number;
    successes: number;
    lastFailure: number | null;
    lastSuccess: number | null;
    state: CircuitState;
    uptime: number;
    downtime: number;
    concurrentExecutions: number;
    queuedExecutions: number;
    averageResponseTime: number;
    responseTimePercentiles: Record<string, number>;
}

interface FallbackRegistry<T> {
    [key: string]: () => Promise<T>;
}

type ResponseTimeWindow = {
    timestamp: number;
    duration: number;
};

export class CircuitBreaker {
    private state: CircuitState = CircuitState.CLOSED;
    private failures: number = 0;
    private successes: number = 0;
    private lastFailure: number | null = null;
    private lastSuccess: number | null = null;
    private lastStateChange: number = Date.now();
    private halfOpenRetries: number = 0;
    private readonly options: CircuitBreakerOptions;
    private stateTimer: NodeJS.Timeout | null = null;
    private currentExecutions: Set<Promise<any>> = new Set();
    private executionQueue: Array<{
        resolve: (value: any) => void;
        reject: (reason: any) => void;
        operation: () => Promise<any>;
    }> = [];
    private responseTimes: ResponseTimeWindow[] = [];
    private currentTimeout: number;
    private fallbackRegistry: FallbackRegistry<any> = {};
    private manuallyOpened: boolean = false;

    constructor(
        private readonly serviceName: string,
        options: Partial<Omit<CircuitBreakerOptions, 'adaptiveTimeout'>> & {
            adaptiveTimeout?: Partial<CircuitBreakerOptions['adaptiveTimeout']>
        } = {}
    ) {
        // Default adaptive timeout configuration
        const defaultAdaptiveTimeout = {
            enabled: true,
            minTimeout: 1000,
            maxTimeout: 10000,
            percentile: 95
        };

        // Initialize options with defaults
        this.options = {
            // Basic circuit breaker settings
            failureThreshold: options.failureThreshold || 5,
            resetTimeout: options.resetTimeout || 60000,
            halfOpenRetries: options.halfOpenRetries || 3,
            monitorInterval: options.monitorInterval || 5000,
            timeout: options.timeout,

            // Bulkhead configuration
            bulkhead: {
                maxConcurrent: options.bulkhead?.maxConcurrent || 10,
                maxQueued: options.bulkhead?.maxQueued || 20
            },

            // Adaptive timeout with defaults
            adaptiveTimeout: {
                ...defaultAdaptiveTimeout,
                ...(options.adaptiveTimeout || {})
            }
        };

        // Set initial timeout value
        this.currentTimeout = this.options.timeout ?? this.options.adaptiveTimeout.minTimeout;

        // Initialize monitoring intervals
        setInterval(() => this.monitor(), this.options.monitorInterval);
        setInterval(() => this.processQueue(), 100);
        setInterval(() => this.updateAdaptiveTimeout(), 5000);
    }

    /**
     * Register a fallback function for the circuit
     */
    registerFallback<T>(key: string, fallback: () => Promise<T>): void {
        this.fallbackRegistry[key] = fallback;
    }

    /**
     * Execute a function with circuit breaker protection
     */
    async execute<T>(
        operation: () => Promise<T>,
        fallbackKey?: string
    ): Promise<T> {
        if (this.manuallyOpened || (this.state === CircuitState.OPEN && !this.shouldReset())) {
            return this.executeFallback(fallbackKey) as Promise<T>;
        }

        if (this.currentExecutions.size >= this.options.bulkhead!.maxConcurrent) {
            if (this.executionQueue.length >= this.options.bulkhead!.maxQueued) {
                throw new Error('Bulkhead queue full');
            }
            await this.queueExecution(operation);
        }

        const execution = this.executeWithProtection(operation);
        this.currentExecutions.add(execution);

        try {
            return await execution;
        } finally {
            this.currentExecutions.delete(execution);
        }
    }

    /**
     * Manually open the circuit breaker
     */
    manualOpen(): void {
        this.manuallyOpened = true;
        this.toOpen();
    }

    /**
     * Manually close the circuit breaker
     */
    manualClose(): void {
        this.manuallyOpened = false;
        this.reset();
    }

    /**
     * Get current circuit breaker statistics
     */
    getStats(): CircuitStats {
        const now = Date.now();
        const percentiles = this.calculateResponseTimePercentiles();

        return {
            failures: this.failures,
            successes: this.successes,
            lastFailure: this.lastFailure,
            lastSuccess: this.lastSuccess,
            state: this.state,
            uptime: this.state === CircuitState.CLOSED ? now - this.lastStateChange : 0,
            downtime: this.state === CircuitState.OPEN ? now - this.lastStateChange : 0,
            concurrentExecutions: this.currentExecutions.size,
            queuedExecutions: this.executionQueue.length,
            averageResponseTime: this.calculateAverageResponseTime(),
            responseTimePercentiles: percentiles
        };
    }

    /**
     * Reset the circuit breaker to its initial state
     */
    reset(): void {
        this.state = CircuitState.CLOSED;
        this.failures = 0;
        this.successes = 0;
        this.lastFailure = null;
        this.lastSuccess = null;
        this.lastStateChange = Date.now();
        this.halfOpenRetries = 0;
        this.manuallyOpened = false;
        if (this.stateTimer) {
            clearTimeout(this.stateTimer);
            this.stateTimer = null;
        }
    }

    private async executeWithProtection<T>(operation: () => Promise<T>): Promise<T> {
        const startTime = Date.now();

        try {
            if (this.state === CircuitState.OPEN) {
                if (this.shouldReset()) {
                    this.toHalfOpen();
                } else {
                    throw new CircuitBreakerError(this.serviceName);
                }
            }

            const result = await this.executeWithTimeout(operation);
            this.recordResponseTime(Date.now() - startTime);
            this.onSuccess();
            return result;
        } catch (error) {
            this.onFailure(error);
            throw error;
        }
    }

    private async executeWithTimeout<T>(operation: () => Promise<T>): Promise<T> {
        if (!this.currentTimeout) {
            return operation();
        }

        return Promise.race([
            operation(),
            new Promise<T>((_, reject) => {
                setTimeout(() => {
                    reject(new TimeoutError(
                        this.serviceName,
                        this.currentTimeout,
                        { details: { adaptiveTimeout: this.options.adaptiveTimeout?.enabled } }
                    ));
                }, this.currentTimeout);
            })
        ]);
    }

    private async queueExecution<T>(operation: () => Promise<T>): Promise<T> {
        return new Promise((resolve, reject) => {
            this.executionQueue.push({ resolve, reject, operation });
        });
    }

    private async processQueue(): Promise<void> {
        while (
            this.executionQueue.length > 0 &&
            this.currentExecutions.size < this.options.bulkhead!.maxConcurrent
        ) {
            const next = this.executionQueue.shift();
            if (next) {
                try {
                    const result = await this.execute(next.operation);
                    next.resolve(result);
                } catch (error) {
                    next.reject(error);
                }
            }
        }
    }

    private async executeFallback<T>(fallbackKey?: string): Promise<T> {
        if (fallbackKey && this.fallbackRegistry[fallbackKey]) {
            try {
                return await this.fallbackRegistry[fallbackKey]();
            } catch (error) {
                logger.error('Fallback execution failed:', {
                    service: this.serviceName,
                    fallbackKey,
                    error: error instanceof Error ? error.message : String(error)
                });
                throw error;
            }
        }
        throw new CircuitBreakerError(this.serviceName);
    }

    private recordResponseTime(duration: number): void {
        this.responseTimes.push({
            timestamp: Date.now(),
            duration
        });

        // Keep only last 100 response times
        if (this.responseTimes.length > 100) {
            this.responseTimes.shift();
        }
    }

    private calculateAverageResponseTime(): number {
        if (this.responseTimes.length === 0) return 0;
        const sum = this.responseTimes.reduce((acc, time) => acc + time.duration, 0);
        return sum / this.responseTimes.length;
    }

    private calculateResponseTimePercentiles(): Record<string, number> {
        if (this.responseTimes.length === 0) {
            return { p50: 0, p90: 0, p95: 0, p99: 0 };
        }

        const sortedTimes = [...this.responseTimes]
            .sort((a, b) => a.duration - b.duration);

        return {
            p50: this.getPercentile(sortedTimes, 50),
            p90: this.getPercentile(sortedTimes, 90),
            p95: this.getPercentile(sortedTimes, 95),
            p99: this.getPercentile(sortedTimes, 99)
        };
    }

    private getPercentile(sortedTimes: ResponseTimeWindow[], percentile: number): number {
        const index = Math.ceil((percentile / 100) * sortedTimes.length) - 1;
        return sortedTimes[index].duration;
    }

    private updateAdaptiveTimeout(): void {
        if (!this.options.adaptiveTimeout?.enabled) return;

        const { minTimeout, maxTimeout, percentile } = this.options.adaptiveTimeout;
        const times = [...this.responseTimes]
            .sort((a, b) => a.duration - b.duration);

        if (times.length === 0) return;

        const index = Math.ceil((percentile / 100) * times.length) - 1;
        const p95Time = times[index].duration;

        // Add 20% buffer to p95 time
        this.currentTimeout = Math.min(
            maxTimeout,
            Math.max(minTimeout, Math.ceil(p95Time * 1.2))
        );
    }

    private onSuccess(): void {
        this.failures = 0;
        this.successes++;
        this.lastSuccess = Date.now();

        if (this.state === CircuitState.HALF_OPEN) {
            this.halfOpenRetries++;
            if (this.halfOpenRetries >= this.options.halfOpenRetries) {
                this.toClosed();
            }
        }
    }

    private onFailure(error: unknown): void {
        this.failures++;
        this.lastFailure = Date.now();
        this.successes = 0;

        logger.warn(`Circuit breaker failure for ${this.serviceName}:`, {
            error: error instanceof Error ? error.message : String(error),
            failures: this.failures,
            threshold: this.options.failureThreshold,
            state: CircuitState[this.state]
        });

        if (this.state === CircuitState.CLOSED && 
            this.failures >= this.options.failureThreshold) {
            this.toOpen();
        } else if (this.state === CircuitState.HALF_OPEN) {
            this.toOpen();
        }
    }

    private toOpen(): void {
        this.state = CircuitState.OPEN;
        this.lastStateChange = Date.now();
        this.stateTimer = setTimeout(() => {
            if (!this.manuallyOpened) {
                this.toHalfOpen();
            }
        }, this.options.resetTimeout);

        // Clear execution queue
        while (this.executionQueue.length > 0) {
            const queued = this.executionQueue.shift();
            if (queued) {
                queued.reject(new CircuitBreakerError(this.serviceName));
            }
        }

        logger.warn(`Circuit breaker opened for ${this.serviceName}`, {
            failures: this.failures,
            lastFailure: this.lastFailure,
            resetTimeout: this.options.resetTimeout,
            manuallyOpened: this.manuallyOpened
        });
    }

    private toHalfOpen(): void {
        this.state = CircuitState.HALF_OPEN;
        this.lastStateChange = Date.now();
        this.halfOpenRetries = 0;

        logger.info(`Circuit breaker half-open for ${this.serviceName}`, {
            requiredSuccesses: this.options.halfOpenRetries
        });
    }

    private toClosed(): void {
        this.state = CircuitState.CLOSED;
        this.lastStateChange = Date.now();
        this.failures = 0;
        this.halfOpenRetries = 0;

        logger.info(`Circuit breaker closed for ${this.serviceName}`, {
            uptime: Date.now() - this.lastStateChange
        });
    }

    private shouldReset(): boolean {
        return !this.manuallyOpened && 
            this.lastStateChange + this.options.resetTimeout < Date.now();
    }

    private monitor(): void {
        const stats = this.getStats();
        logger.debug(`Circuit breaker status for ${this.serviceName}:`, {
            state: CircuitState[stats.state],
            failures: stats.failures,
            successes: stats.successes,
            uptime: stats.uptime,
            downtime: stats.downtime,
            concurrentExecutions: stats.concurrentExecutions,
            queuedExecutions: stats.queuedExecutions,
            averageResponseTime: stats.averageResponseTime,
            currentTimeout: this.currentTimeout,
            manuallyOpened: this.manuallyOpened
        });
    }
} 