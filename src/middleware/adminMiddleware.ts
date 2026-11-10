import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../lib/prisma';
import { getRoleConfig } from '../utils/rbac';
import { JwtPanelPayload } from '../types';

declare global {
  namespace Express {
    interface Request {
      admin?: JwtPanelPayload;
    }
  }
}

export async function adminMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ success: false, message: 'No token provided.' });
    return;
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.ADMIN_JWT_SECRET || 'admin-secret'
    ) as JwtPanelPayload;

    const dbUser = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, role: true, name: true, department: true },
    });

    if (!dbUser) {
      res.status(401).json({ success: false, message: 'User account not found.' });
      return;
    }

    const roleConfig = await getRoleConfig(dbUser.role);

    req.admin = {
      id: dbUser.id,
      email: dbUser.email,
      role: dbUser.role,
      name: dbUser.name,
      department: dbUser.department ?? null,
      roleLabel: roleConfig.label,
      dataScope: dbUser.role === 'admin' ? 'all' : roleConfig.dataScope,
      menus: dbUser.role === 'admin' && !roleConfig.menus.includes('roles')
        ? [...roleConfig.menus, 'roles']
        : roleConfig.menus,
      permissions: roleConfig.permissions,
    };

    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
}

export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.admin;
    if (!user) {
      res.status(401).json({ success: false, message: 'Authentication required.' });
      return;
    }

    if (user.role === 'admin' || user.permissions?.includes(permission)) {
      next();
      return;
    }

    res.status(403).json({
      success: false,
      message: `Access denied. Missing permission: ${permission}`,
    });
  };
}
