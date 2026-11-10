import { Request, Response, NextFunction } from 'express';
import { JwtPanelPayload } from '../types';
declare global {
    namespace Express {
        interface Request {
            admin?: JwtPanelPayload;
        }
    }
}
export declare function adminMiddleware(req: Request, res: Response, next: NextFunction): Promise<void>;
export declare function requirePermission(permission: string): (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=adminMiddleware.d.ts.map