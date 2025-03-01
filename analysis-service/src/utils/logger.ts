/**
 * Enhanced logger utility with structured logging support
 */

import winston from 'winston';
import chalk from 'chalk';

interface PacketDetails {
    source: string;
    destination: string;
    protocol: string;
    size: number;
    type: string;
    timestamp: string;
}

interface AlertMessage {
    packetDetails?: PacketDetails;
    severity?: string;
    rule?: string;
    score?: number;
    [key: string]: any; // Allow additional properties
}

const isPacketDetails = (obj: any): obj is PacketDetails => {
    return obj && typeof obj === 'object' &&
        typeof obj.source === 'string' &&
        typeof obj.destination === 'string' &&
        typeof obj.protocol === 'string' &&
        typeof obj.type === 'string' &&
        typeof obj.timestamp === 'string';
};

const isAlertMessage = (obj: any): obj is AlertMessage => {
    return obj && typeof obj === 'object';
};

const formatPacketDetails = (details: PacketDetails): string => {
    const fields = [
        ['Source', details.source],
        ['Destination', details.destination],
        ['Protocol', details.protocol],
        ['Size', `${details.size} bytes`],
        ['Type', details.type],
        ['Timestamp', details.timestamp]
    ];

    return fields
        .map(([key, value]) => `    ${chalk.cyan(key.padEnd(12))}: ${value}`)
        .join('\n');
};

const formatAlert = (alert: AlertMessage): string => {
    return Object.entries(alert)
        .map(([key, value]) => `    ${chalk.yellow(key.padEnd(12))}: ${value}`)
        .join('\n');
};

const customFormat = winston.format.printf(({ level, message, timestamp }) => {
    // Handle string messages
    if (typeof message === 'string') {
        // Format batch processing headers
        if (message.includes('=== Batch Processing')) {
            return `\n${chalk.yellow(message)}\n`;
        }

        // Format batch details
        if (message.startsWith('Batch ID:') || 
            message.startsWith('Timestamp:') || 
            message.startsWith('Packets in batch:')) {
            return chalk.blue(message);
        }

        // Format alert headers
        if (message === '🚨 Alert Detected:') {
            return `\n${chalk.red('🚨 Alert Detected:')}\n`;
        }

        // Default string message format
        return `${timestamp} [${level.toUpperCase()}]: ${message}`;
    }

    // Handle object messages
    if (isAlertMessage(message)) {
        if (message.packetDetails && isPacketDetails(message.packetDetails)) {
            return `${chalk.yellow('\nPacket Details:')}\n${formatPacketDetails(message.packetDetails)}`;
        }
        return `${chalk.yellow('Alert Details:')}\n${formatAlert(message)}`;
    }

    // Fallback for unknown message types
    return `${timestamp} [${level.toUpperCase()}]: ${JSON.stringify(message)}`;
});

export const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.colorize(),
        customFormat
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.colorize(),
                customFormat
            )
        }),
        new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),
        new winston.transports.File({
            filename: 'logs/combined.log',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ]
}); 