export type AlertLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface AlertCause {
    reason: string;
    score: number;
    details?: Record<string, any>;
}

export interface Alert {
    timestamp: string;
    level: AlertLevel;
    score: number;
    packet: {
        source: string;
        destination: string;
        protocol: string;
        size: number;
    };
    causes: AlertCause[];
}

// Validation functions
export const isValidAlertCause = (cause: any): cause is AlertCause => {
    return (
        typeof cause === 'object' &&
        cause !== null &&
        typeof cause.reason === 'string' &&
        typeof cause.score === 'number'
    );
};

export const isValidAlert = (alert: any): alert is Alert => {
    return (
        typeof alert === 'object' &&
        alert !== null &&
        typeof alert.timestamp === 'string' &&
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(alert.level) &&
        typeof alert.score === 'number' &&
        Array.isArray(alert.causes) &&
        alert.causes.every(isValidAlertCause)
    );
}; 