import { createClient, RedisClientType } from 'redis';
import { logger } from '../utils/logger';
import { PacketData } from '../types/packet.types';
import nodemailer, { Transporter } from 'nodemailer';

export enum AlertSeverity {
    LOW = 'low',
    MEDIUM = 'medium',
    HIGH = 'high',
    CRITICAL = 'critical'
}

export interface Alert {
    id: string;
    timestamp: string;
    severity: AlertSeverity;
    type: string;
    message: string;
    sourceIp: string;
    count: number;
    packets: PacketData[];
    metadata: Record<string, any>;
}

export class AlertError extends Error {
    constructor(message: string, public readonly code: string) {
        super(message);
        this.name = 'AlertError';
    }
}

export class AlertService {
    private redis!: RedisClientType;
    private readonly ALERT_KEY = 'alerts';
    private readonly ALERT_TTL = 3600;
    private aggregationWindow = 300;
    private emailTransporter!: Transporter;
    private isRedisAvailable = false;

    constructor() {
        this.initializeServices().catch(error => {
            logger.error('Failed to initialize some services:', error);
            // Don't throw - allow service to run in degraded mode
        });
    }

    private async initializeServices() {
        await this.initializeEmailTransporter();
        await this.initializeRedis();
    }

    private async initializeRedis() {
        try {
            this.redis = createClient({
                url: process.env.REDIS_URL,
                database: parseInt(process.env.ALERT_DB || '2')
            });

            // Add connection timeout
            const connectPromise = this.redis.connect();
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Redis connection timeout')), 5000);
            });

            await Promise.race([connectPromise, timeoutPromise]);

            this.redis.on('error', (err: Error) => {
                logger.error('Redis error:', err);
                this.isRedisAvailable = false;
            });

            this.redis.on('connect', () => {
                logger.info('Redis connected successfully');
                this.isRedisAvailable = true;
            });

            this.isRedisAvailable = true;
        } catch (error) {
            logger.warn('Redis not available - running in degraded mode:', error);
            this.isRedisAvailable = false;
        }
    }

    private async initializeEmailTransporter() {
        try {
            this.emailTransporter = nodemailer.createTransport({
                host: process.env.EMAIL_HOST,
                port: parseInt(process.env.EMAIL_PORT || '587'),
                secure: process.env.EMAIL_SECURE === 'true',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });

            // Verify the connection
            await this.emailTransporter.verify();
            logger.info('Email transporter initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize email transporter:', error);
            throw new AlertError('Email configuration failed', 'EMAIL_INIT_ERROR');
        }
    }

    async persistAlert(alert: Alert): Promise<void> {
        try {
            if (this.isRedisAvailable) {
                const key = `${this.ALERT_KEY}:${alert.type}:${alert.sourceIp}`;
                await this.redis.setEx(key, this.ALERT_TTL, JSON.stringify(alert));
            }
            await this.notifyAlert(alert);
        } catch (error) {
            logger.error('Error persisting alert:', error);
            // Continue even if Redis fails - notifications will still work
        }
    }

    async aggregateAlerts(newAlert: Alert): Promise<Alert> {
        if (!this.isRedisAvailable) {
            return newAlert;
        }

        try {
            const key = `${this.ALERT_KEY}:${newAlert.type}:${newAlert.sourceIp}`;
            const existingAlert = await this.redis.get(key);

            if (existingAlert) {
                const alert = JSON.parse(existingAlert) as Alert;
                const timeDiff = Date.now() - new Date(alert.timestamp).getTime();

                if (timeDiff < this.aggregationWindow * 1000) {
                    alert.count += 1;
                    alert.packets.push(...newAlert.packets);
                    alert.severity = this.escalateSeverity(alert);
                    return alert;
                }
            }
            return newAlert;
        } catch (error) {
            logger.error('Error aggregating alerts:', error);
            return newAlert;
        }
    }

    private escalateSeverity(alert: Alert): AlertSeverity {
        if (alert.count > 100) return AlertSeverity.CRITICAL;
        if (alert.count > 50) return AlertSeverity.HIGH;
        if (alert.count > 20) return AlertSeverity.MEDIUM;
        return AlertSeverity.LOW;
    }

    private async notifyAlert(alert: Alert): Promise<void> {
        try {
            switch (alert.severity) {
                case AlertSeverity.CRITICAL:
                case AlertSeverity.HIGH:
                    await this.sendEmailNotification(alert);
                    break;
                case AlertSeverity.MEDIUM:
                case AlertSeverity.LOW:
                    logger.warn(`Alert: ${alert.message}`, { alert });
                    break;
            }
        } catch (error) {
            logger.error('Notification error:', error);
            throw new AlertError('Failed to send notification', 'NOTIFY_ERROR');
        }
    }

    private async sendEmailNotification(alert: Alert): Promise<void> {
        const emailContent = this.formatEmailContent(alert);
        
        try {
            await this.emailTransporter.sendMail({
                from: process.env.EMAIL_FROM,
                to: process.env.ALERT_EMAIL_RECIPIENTS?.split(','),
                subject: `[${alert.severity.toUpperCase()}] Security Alert: ${alert.type}`,
                html: emailContent
            });
        } catch (error) {
            logger.error('Failed to send email notification:', error);
            throw new AlertError('Email sending failed', 'EMAIL_ERROR');
        }
    }

    private formatEmailContent(alert: Alert): string {
        return `
            <h2>Security Alert Detected</h2>
            <p><strong>Type:</strong> ${alert.type}</p>
            <p><strong>Severity:</strong> ${alert.severity}</p>
            <p><strong>Source IP:</strong> ${alert.sourceIp}</p>
            <p><strong>Count:</strong> ${alert.count}</p>
            <p><strong>Timestamp:</strong> ${alert.timestamp}</p>
            <h3>Details:</h3>
            <pre>${JSON.stringify(alert.metadata, null, 2)}</pre>
        `;
    }
}

export const alertService = new AlertService(); 