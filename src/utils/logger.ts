
import { createLogger, format, transports, Logger as WinstonLogger } from 'winston';
import 'dotenv/config';

const { combine, timestamp, printf, colorize, errors, json } = format;

// --- Configuration Constants ---
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const LOG_FILE_PATH = process.env.LOG_FILE_PATH || 'logs/app.log';
const ERROR_LOG_FILE_PATH = process.env.ERROR_LOG_FILE_PATH || 'logs/error.log';

// --- Custom Log Format for Console (Development) ---
const consoleFormat = printf(({ level, message, timestamp, context, stack }) => {
    const contextString = context ? `[${context}] ` : '';
    const stackTrace = stack ? `\n${stack}` : '';
    return `${timestamp} ${level}: ${contextString}${message}${stackTrace}`;
});

// --- Custom Log Format for Files (Production/Structured) ---
const fileFormat = combine(
    errors({ stack: true }), // Log stack traces for errors
    timestamp(),
    json() // Use JSON format for easy parsing by log aggregation tools
);

// --- Transports Configuration ---
const transportsList: transports.ConsoleTransportInstance[] | transports.FileTransportInstance[] = [
    // Console Transport (for real-time monitoring during development)
    new transports.Console({
        level: LOG_LEVEL,
        format: IS_PRODUCTION ? fileFormat : combine(
            colorize({ all: true }),
            timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            consoleFormat
        ),
        silent: process.env.NODE_ENV === 'test' // Silence logs during tests
    }),
];

if (IS_PRODUCTION) {
    // File Transport (for persistent, structured logging in production)
    transportsList.push(
        new transports.File({ filename: ERROR_LOG_FILE_PATH, level: 'error', format: fileFormat }),
        new transports.File({ filename: LOG_FILE_PATH, format: fileFormat })
    );
}
