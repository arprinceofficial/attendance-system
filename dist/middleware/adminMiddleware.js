"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminMiddleware = adminMiddleware;
exports.requirePermission = requirePermission;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const prisma_1 = __importDefault(require("../lib/prisma"));
const rbac_1 = require("../utils/rbac");
async function adminMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ success: false, message: 'No token provided.' });
        return;
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.ADMIN_JWT_SECRET || 'admin-secret');
        const dbUser = await prisma_1.default.user.findUnique({
            where: { id: decoded.id },
            select: { id: true, email: true, role: true, name: true, department: true },
        });
        if (!dbUser) {
            res.status(401).json({ success: false, message: 'User account not found.' });
            return;
        }
        const roleConfig = await (0, rbac_1.getRoleConfig)(dbUser.role);
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
    }
    catch {
        res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
}
function requirePermission(permission) {
    return (req, res, next) => {
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
//# sourceMappingURL=adminMiddleware.js.map