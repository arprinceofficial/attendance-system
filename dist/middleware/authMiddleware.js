"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = authMiddleware;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ success: false, message: 'No token provided.' });
        return;
    }
    const token = authHeader.split(' ')[1];
    try {
        jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET || 'secret');
        next();
    }
    catch {
        res.status(401).json({ success: false, message: 'Invalid or expired token.' });
    }
}
//# sourceMappingURL=authMiddleware.js.map