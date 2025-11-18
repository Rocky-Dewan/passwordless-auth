// File: passwordless-auth/src/server.ts
// Purpose: Entry point for the application.

import { App } from './app';
import { Logger } from './utils/logger';

const logger = new Logger('Server');
const PORT = parseInt(process.env.PORT || '3000', 10);

async function bootstrap() {
    try {
        const app = new App();
        // The initialize() method is called within the App constructor
        // to ensure all dependencies and DB are ready before starting the server.
        
        // Wait for initialization to complete before starting to listen
        // @ts-ignore - Accessing private method for a clean startup sequence
        await app.initialize(); 

        app.start(PORT);

        // Handle process termination signals gracefully
        process.on('SIGINT', async () => {
            logger.info('SIGINT received. Shutting down gracefully...');
            // In a real application, you would close the DB/Redis connections here.
            process.exit(0);
        });

        process.on('SIGTERM', async () => {
            logger.info('SIGTERM received. Shutting down gracefully...');
            process.exit(0);
        });

    } catch (error) {
        logger.error('FATAL: Server bootstrap failed.', { error });
        process.exit(1);
    }
}

bootstrap();

