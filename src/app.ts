import 'dotenv/config';


const logger = new Logger('App');



interface CustomError extends Error {
    statusCode?: number;
    code?: string;
    details?: any;
}
