import express from 'express';
import * as dotenv from 'dotenv';
import path from 'path';
import { AnalysisController } from './api/analysis.controller';
import { analysisService } from './services/analysis.service';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { logger } from './utils/logger';

// Load environment variables at startup
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Swagger configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Network Analysis API',
            version: '1.0.0',
            description: 'API for network packet analysis and threat detection'
        },
        servers: [
            {
                url: `http://localhost:${process.env.PORT || 3000}`
            }
        ]
    },
    apis: ['./src/api/*.ts']
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Initialize controller
const analysisController = new AnalysisController();

// Routes
app.use('/api', analysisController.router);

// Start services
analysisService.start();

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
}); 