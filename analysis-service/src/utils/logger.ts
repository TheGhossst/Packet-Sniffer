import winston from 'winston';
import chalk from 'chalk';

// Import Winston types
import { TransformableInfo } from 'logform';

// Custom format for pretty printing
const prettyPrint = winston.format((info: TransformableInfo) => {
    // Remove color codes from log files
    const cleanMessage = info.message?.toString().replace(/\u001b\[\d+m/g, '') || '';
    
    switch (info.level) {
        case 'info':
            if (cleanMessage.includes('=== Batch Processing Start ===')) {
                info.message = '\n' + '='.repeat(50) + '\n' + 
                    `📦 BATCH PROCESSING START\n` +
                    '='.repeat(50);
            } else if (cleanMessage.includes('=== Batch Processing Complete ===')) {
                info.message = '\n' + '-'.repeat(50) + '\n' +
                    `✅ BATCH PROCESSING COMPLETE\n` +
                    '-'.repeat(50) + '\n';
            } else if (cleanMessage.includes('Batch ID:')) {
                const batchId = cleanMessage.split('Batch ID: ')[1];
                info.message = `🔍 Batch ID: ${chalk.blue(batchId)}`;
            } else if (cleanMessage.includes('Packets in batch:')) {
                const count = cleanMessage.split('Packets in batch: ')[1];
                info.message = `📊 Packet Count: ${chalk.blue(count)}`;
            }
            break;
        case 'warn':
            if (cleanMessage.includes('Alert Detected')) {
                info.message = '\n' + '!'.repeat(50) + '\n' +
                    `🚨 ALERT DETECTED\n` +
                    '!'.repeat(50);
            }
            break;
        case 'error':
            info.message = '\n' + '❌'.repeat(25) + '\n' +
                `ERROR: ${cleanMessage}\n` +
                '❌'.repeat(25) + '\n';
            break;
    }
    return info;
});

// Create custom format
const logFormat = winston.format.combine(
    winston.format.timestamp(),
    prettyPrint(),
    winston.format.printf((info: TransformableInfo) => {
        // Ensure timestamp is a valid string or number
        const timestamp = typeof info.timestamp === 'string' || typeof info.timestamp === 'number' 
            ? info.timestamp 
            : Date.now();
            
        const ts = new Date(timestamp).toLocaleTimeString();
        let icon = '📝';
        switch (info.level) {
            case 'error': icon = '❌'; break;
            case 'warn': icon = '⚠️'; break;
            case 'info': icon = 'ℹ️'; break;
            case 'debug': icon = '🔍'; break;
        }
        return `${icon} ${ts} | ${info.message}`;
    })
);

// Configure logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                logFormat
            )
        }),
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            format: winston.format.combine(
                winston.format.uncolorize(),
                logFormat
            )
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            format: winston.format.combine(
                winston.format.uncolorize(),
                logFormat
            )
        })
    ]
});

export { logger }; 