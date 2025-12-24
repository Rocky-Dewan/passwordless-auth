
import { Router } from 'express';
import { injectable, inject } from 'tsyringe';
import { AuthController } from '../controllers/auth.controller';
import { Logger } from '../utils/logger';

/**
 * @injectable
 * Defines the main router for authentication-related endpoints.
 */
@injectable()
export class AuthRoutes {
    public router: Router;
    private readonly logger = new Logger(AuthRoutes.name);

    constructor(
        @inject(AuthController) private authController: AuthController
    ) {
        this.router = Router();
        this.initializeRoutes();
        this.logger.info('AuthRoutes initialized.');
    }

    /**
     * Maps the controller methods to the corresponding HTTP methods and paths.
     */
    private initializeRoutes(): void {
        // The actual route definitions are handled within the AuthController's router
        // to keep the routing logic and the controller logic tightly coupled.
        this.router.use('/', this.authController.router);


    }

