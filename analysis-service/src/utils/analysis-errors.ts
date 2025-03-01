import { BaseError, ErrorCode } from './errors';

// Define AnalysisErrorCode as a type that extends ErrorCode
export const enum AnalysisErrorCode {
    // Network Analysis Errors (8000-8099)
    INVALID_PACKET = 8000,
    MALFORMED_IP = 8001,
    INVALID_PROTOCOL = 8002,
    INVALID_PORT = 8003,
    INVALID_CIDR = 8004,

    // API Integration Errors (8100-8199)
    API_RATE_LIMIT = 8100,
    API_TIMEOUT = 8101,
    API_AUTH_ERROR = 8102,
    API_RESPONSE_ERROR = 8103,

    // Cache Errors (8200-8299)
    CACHE_MISS = 8200,
    CACHE_EXPIRED = 8201,
    CACHE_WRITE_ERROR = 8202,

    // Reputation Analysis Errors (8300-8399)
    REPUTATION_FETCH_ERROR = 8300,
    REPUTATION_PARSE_ERROR = 8301,
    REPUTATION_THRESHOLD_ERROR = 8302,

    // Pattern Analysis Errors (8400-8499)
    PATTERN_ANALYSIS_ERROR = 8400,
    PATTERN_THRESHOLD_ERROR = 8401,
    PATTERN_STORAGE_ERROR = 8402,

    // Alert Generation Errors (8500-8599)
    ALERT_GENERATION_ERROR = 8500,
    ALERT_PERSISTENCE_ERROR = 8501,
    ALERT_THRESHOLD_ERROR = 8502
}

// Define the error context as a Record type
export interface AnalysisErrorContext extends Record<string, unknown> {
    operation: string;
    input?: unknown;
    threshold?: number;
    attempts?: number;
    duration?: number;
    retryAfter?: number;
    timeout?: number;
}

export class PacketAnalysisError extends BaseError {
    constructor(
        code: AnalysisErrorCode,
        message: string,
        context?: AnalysisErrorContext,
        cause?: Error
    ) {
        super(message, code as unknown as ErrorCode, {
            source: 'packet-analysis',
            details: context || {}
        }, cause);
    }
}

export class NetworkValidationError extends PacketAnalysisError {
    constructor(
        field: string,
        message: string,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.INVALID_PACKET,
            `Validation error for ${field}: ${message}`,
            context ? { operation: 'validation', ...context } : { operation: 'validation' },
            cause
        );
    }
}

export class ReputationAnalysisError extends PacketAnalysisError {
    constructor(
        service: string,
        message: string,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.REPUTATION_FETCH_ERROR,
            `Reputation analysis error from ${service}: ${message}`,
            context ? { operation: 'reputation-analysis', ...context } : { operation: 'reputation-analysis' },
            cause
        );
    }
}

export class PatternAnalysisError extends PacketAnalysisError {
    constructor(
        pattern: string,
        message: string,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.PATTERN_ANALYSIS_ERROR,
            `Pattern analysis error for ${pattern}: ${message}`,
            context ? { operation: 'pattern-analysis', ...context } : { operation: 'pattern-analysis' },
            cause
        );
    }
}

export class AlertGenerationError extends PacketAnalysisError {
    constructor(
        alertType: string,
        message: string,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.ALERT_GENERATION_ERROR,
            `Alert generation error for ${alertType}: ${message}`,
            context ? { operation: 'alert-generation', ...context } : { operation: 'alert-generation' },
            cause
        );
    }
}

export class APIIntegrationError extends PacketAnalysisError {
    constructor(
        service: string,
        statusCode: number,
        message: string,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.API_RESPONSE_ERROR,
            `API error from ${service} (${statusCode}): ${message}`,
            context ? { operation: 'api-integration', ...context } : { operation: 'api-integration' },
            cause
        );
    }
}

export class RateLimitError extends PacketAnalysisError {
    constructor(
        service: string,
        retryAfter: number,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.API_RATE_LIMIT,
            `Rate limit exceeded for ${service}, retry after ${retryAfter}ms`,
            {
                operation: 'rate-limit',
                ...(context || {}),
                retryAfter
            },
            cause
        );
    }
}

export class TimeoutError extends PacketAnalysisError {
    constructor(
        service: string,
        timeoutMs: number,
        context?: Partial<AnalysisErrorContext>,
        cause?: Error
    ) {
        super(
            AnalysisErrorCode.API_TIMEOUT,
            `Request to ${service} timed out after ${timeoutMs}ms`,
            {
                operation: 'timeout',
                ...(context || {}),
                timeout: timeoutMs
            },
            cause
        );
    }
} 