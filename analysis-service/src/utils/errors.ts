/**
 * Enhanced error handling system with error codes, context preservation, and i18n support
 */

export enum ErrorCode {
    // API Errors (1000-1999)
    API_ERROR = 1000,
    RATE_LIMIT_EXCEEDED = 1001,
    TIMEOUT = 1002,
    INVALID_RESPONSE = 1003,

    // Validation Errors (2000-2999)
    VALIDATION_ERROR = 2000,
    INVALID_INPUT = 2001,
    MISSING_REQUIRED_FIELD = 2002,

    // Configuration Errors (3000-3999)
    CONFIG_ERROR = 3000,
    INVALID_CONFIG = 3001,
    MISSING_ENV_VAR = 3002,

    // Cache Errors (4000-4999)
    CACHE_ERROR = 4000,
    CACHE_FULL = 4001,
    CACHE_INVALID = 4002,

    // Circuit Breaker Errors (5000-5999)
    CIRCUIT_BREAKER_ERROR = 5000,
    SERVICE_UNAVAILABLE = 5001,

    // Processing Errors (6000-6999)
    PROCESSING_ERROR = 6000,
    BATCH_PROCESSING_ERROR = 6001,

    // System Errors (7000-7999)
    SYSTEM_ERROR = 7000,
    RESOURCE_EXHAUSTED = 7001,
    INTERNAL_ERROR = 7002
}

export interface ErrorContext {
    code: ErrorCode;
    timestamp: number;
    correlationId?: string;
    requestId?: string;
    source?: string;
    details?: Record<string, unknown>;
    locale?: string;
}

export interface ErrorChain {
    message: string;
    code: ErrorCode;
    timestamp: number;
    stack?: string;
}

/**
 * Base error class with enhanced context and chain support
 */
export class BaseError extends Error {
    public readonly context: ErrorContext;
    public readonly chain: ErrorChain[];

    constructor(
        message: string,
        code: ErrorCode,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(message);
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);

        this.context = {
            code,
            timestamp: Date.now(),
            correlationId: context?.correlationId,
            requestId: context?.requestId,
            source: context?.source,
            details: context?.details,
            locale: context?.locale || 'en'
        };

        this.chain = [{
            message: this.message,
            code: this.context.code,
            timestamp: this.context.timestamp,
            stack: this.stack
        }];

        if (cause instanceof BaseError) {
            this.chain.push(...cause.chain);
        } else if (cause) {
            this.chain.push({
                message: cause.message,
                code: ErrorCode.INTERNAL_ERROR,
                timestamp: Date.now(),
                stack: cause.stack
            });
        }
    }

    /**
     * Get localized error message
     */
    getLocalizedMessage(locale?: string): string {
        // This would integrate with your i18n system
        return this.message; // Placeholder for i18n implementation
    }

    /**
     * Get full error trail
     */
    getErrorTrail(): string {
        return this.chain
            .map(error => `[${error.code}] ${error.message}`)
            .join(' -> ');
    }

    /**
     * Convert error to JSON for logging
     */
    toJSON(): Record<string, unknown> {
        return {
            name: this.name,
            message: this.message,
            code: this.context.code,
            correlationId: this.context.correlationId,
            requestId: this.context.requestId,
            timestamp: this.context.timestamp,
            details: this.context.details,
            chain: this.chain,
            stack: this.stack
        };
    }
}

export class APIError extends BaseError {
    constructor(
        service: string,
        statusCode?: number,
        response?: unknown,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `API Error from ${service}${statusCode ? ` (${statusCode})` : ''}`,
            ErrorCode.API_ERROR,
            {
                ...context,
                source: service,
                details: {
                    statusCode,
                    response,
                    service
                }
            },
            cause
        );
    }
}

export class RateLimitError extends BaseError {
    constructor(
        service: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Rate limit exceeded for ${service}`,
            ErrorCode.RATE_LIMIT_EXCEEDED,
            {
                ...context,
                source: service
            },
            cause
        );
    }
}

export class TimeoutError extends BaseError {
    constructor(
        service: string,
        timeoutMs: number,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Request to ${service} timed out after ${timeoutMs}ms`,
            ErrorCode.TIMEOUT,
            {
                ...context,
                source: service,
                details: { timeoutMs }
            },
            cause
        );
    }
}

export class ValidationError extends BaseError {
    constructor(
        field: string,
        message: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Validation error for ${field}: ${message}`,
            ErrorCode.VALIDATION_ERROR,
            {
                ...context,
                details: { field }
            },
            cause
        );
    }
}

export class ConfigurationError extends BaseError {
    constructor(
        setting: string,
        message: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Configuration error for ${setting}: ${message}`,
            ErrorCode.CONFIG_ERROR,
            {
                ...context,
                details: { setting }
            },
            cause
        );
    }
}

export class CacheError extends BaseError {
    constructor(
        message: string,
        operation: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Cache error during ${operation}: ${message}`,
            ErrorCode.CACHE_ERROR,
            {
                ...context,
                details: { operation }
            },
            cause
        );
    }
}

export class CircuitBreakerError extends BaseError {
    constructor(
        service: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Circuit breaker open for ${service}`,
            ErrorCode.CIRCUIT_BREAKER_ERROR,
            {
                ...context,
                source: service
            },
            cause
        );
    }
}

export class ProcessingError extends BaseError {
    constructor(
        message: string,
        packetId?: string,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Processing error${packetId ? ` for packet ${packetId}` : ''}: ${message}`,
            ErrorCode.PROCESSING_ERROR,
            {
                ...context,
                details: { packetId }
            },
            cause
        );
    }
}

export class BatchProcessingError extends BaseError {
    constructor(
        successCount: number,
        failureCount: number,
        errors: Error[],
        context?: Partial<ErrorContext>
    ) {
        super(
            `Batch processing completed with ${failureCount} failures and ${successCount} successes`,
            ErrorCode.BATCH_PROCESSING_ERROR,
            {
                ...context,
                details: {
                    successCount,
                    failureCount,
                    errors: errors.map(e => e instanceof BaseError ? e.toJSON() : e.message)
                }
            }
        );
    }
}

export class ThrottlingError extends BaseError {
    constructor(
        service: string,
        retryAfter?: number,
        context?: Partial<ErrorContext>,
        cause?: Error
    ) {
        super(
            `Service ${service} is throttling requests${retryAfter ? `, retry after ${retryAfter}ms` : ''}`,
            ErrorCode.RATE_LIMIT_EXCEEDED,
            {
                ...context,
                source: service,
                details: { retryAfter }
            },
            cause
        );
    }
} 