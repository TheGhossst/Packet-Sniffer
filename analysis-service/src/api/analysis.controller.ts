import { Router, Request, Response } from 'express';
import { analysisService } from '../services/analysis.service';
import { logger } from '../utils/logger';
import { PacketData } from '../types/packet.types';

/**
 * @swagger
 * components:
 *   schemas:
 *     PacketData:
 *       type: object
 *       required:
 *         - src_ip
 *         - dst_ip
 *         - protocol
 *       properties:
 *         src_ip:
 *           type: string
 *         dst_ip:
 *           type: string
 *         protocol:
 *           type: string
 *         packet_size:
 *           type: number
 */
export class AnalysisController {
    public router = Router();

    constructor() {
        this.initializeRoutes();
    }

    private initializeRoutes() {
        /**
         * @swagger
         * /api/analysis/packet:
         *   post:
         *     summary: Analyze a network packet
         *     tags: [Analysis]
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             $ref: '#/components/schemas/PacketData'
         *     responses:
         *       200:
         *         description: Analysis results
         *       400:
         *         description: Invalid packet data
         *       500:
         *         description: Server error
         */
        this.router.post('/packet', this.analyzePacket);

        /**
         * @swagger
         * /api/analysis/status:
         *   get:
         *     summary: Get service status
         *     tags: [Analysis]
         *     responses:
         *       200:
         *         description: Service status
         */
        this.router.get('/status', this.getServiceStatus);
    }

    private analyzePacket = async (req: Request, res: Response) => {
        try {
            const packet = this.validatePacketData(req.body);
            const result = await analysisService.analyze(packet);
            res.json(result);
        } catch (error) {
            this.handleError(error, res);
        }
    };

    private getServiceStatus = async (_req: Request, res: Response) => {
        try {
            const metrics = await analysisService.getMetrics();
            res.json({
                status: 'running',
                uptime: process.uptime(),
                metrics
            });
        } catch (error) {
            this.handleError(error, res);
        }
    };

    private validatePacketData(data: any): PacketData {
        const requiredFields = ['src_ip', 'dst_ip', 'protocol'];
        for (const field of requiredFields) {
            if (!data[field]) {
                throw new Error(`Missing required field: ${field}`);
            }
        }

        // Validate IP addresses
        if (!this.isValidIp(data.src_ip) || !this.isValidIp(data.dst_ip)) {
            throw new Error('Invalid IP address format');
        }

        return {
            src_ip: data.src_ip,
            dst_ip: data.dst_ip,
            protocol: data.protocol,
            src_port: data.src_port || 0,
            dst_port: data.dst_port || 0,
            packet_size: data.packet_size || 0,
            packet_type: data.packet_type || 'unknown',
            payload_size: data.payload_size || 0,
            timestamp: data.timestamp || new Date().toISOString()
        };
    }

    private isValidIp(ip: string): boolean {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    private handleError(error: any, res: Response) {
        logger.error('API Error:', error);
        
        if (error.name === 'AlertError') {
            res.status(400).json({
                error: error.message,
                code: error.code
            });
            return;
        }

        if (error.message.includes('Missing required field') || 
            error.message.includes('Invalid IP address')) {
            res.status(400).json({
                error: 'Validation Error',
                message: error.message
            });
            return;
        }

        res.status(500).json({
            error: 'Internal server error',
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
} 