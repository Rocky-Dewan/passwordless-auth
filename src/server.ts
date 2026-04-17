import 'reflect-metadata';
import app from './app';
import { config } from './config';
import { logger } from './utils/logger';
import { initDatabase } from './utils/database';
import { redisService } from './services/redis.service';

async function bootstrap(): Promise<void> {
  try {
    logger.info('Connecting to PostgreSQL...');
    await initDatabase();
    logger.info('PostgreSQL connected');

    logger.info('Connecting to Redis...');
    await redisService.connect();
    logger.info('Redis connected');

    const server = app.listen(config.port, () => {
      logger.info(`Server running on http://localhost:${config.port}`, {
        env: config.env,
        port: config.port,
      });
    });

    const shutdown = async (signal: string) => {
      logger.info(`${signal} received — shutting down`);
      server.close(async () => {
        try { redisService.getClient().disconnect(); } catch {}
        process.exit(0);
      });
      setTimeout(() => process.exit(1), 10_000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT',  () => shutdown('SIGINT'));
  } catch (err) {
    logger.error('Failed to start server', { err });
    process.exit(1);
  }
}

bootstrap();
