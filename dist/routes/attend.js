"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const path_1 = __importDefault(require("path"));
const prisma_1 = __importDefault(require("../lib/prisma"));
const tokenUtils_1 = require("../utils/tokenUtils");
const router = (0, express_1.Router)();
// GET /attend/validate/:token
router.get('/validate/:token', async (req, res) => {
    try {
        const token = String(req.params.token);
        const today = (0, tokenUtils_1.getTodayDate)();
        const link = await prisma_1.default.attendanceLink.findFirst({
            where: { token, isActive: true },
        });
        if (!link) {
            res.json({ valid: false, reason: 'Token not found or inactive.' });
            return;
        }
        if (link.date !== today) {
            res.json({ valid: false, reason: "Token has expired (not today's link)." });
            return;
        }
        if ((0, tokenUtils_1.isLinkExpired)(link.expiresAt)) {
            res.json({ valid: false, reason: 'This attendance link has expired.' });
            return;
        }
        res.json({
            valid: true,
            date: link.date,
            token: link.token,
            expiresAt: link.expiresAt,
            durationMinutes: link.durationMinutes,
            remainingMs: link.expiresAt ? Math.max(0, link.expiresAt.getTime() - Date.now()) : null,
        });
    }
    catch (err) {
        console.error('Token validation error:', err);
        res.status(500).json({ valid: false, reason: 'Server error' });
    }
});
// GET /attend/:token
router.get('/:token', async (req, res) => {
    try {
        const token = String(req.params.token);
        const today = (0, tokenUtils_1.getTodayDate)();
        const link = await prisma_1.default.attendanceLink.findFirst({
            where: { token, isActive: true },
        });
        if (!link || link.date !== today || (0, tokenUtils_1.isLinkExpired)(link.expiresAt)) {
            res.status(404).sendFile(path_1.default.join(__dirname, '..', '..', 'public', 'error.html'));
            return;
        }
        res.sendFile(path_1.default.join(__dirname, '..', '..', 'public', 'attend.html'));
    }
    catch (err) {
        console.error('Attend route error:', err);
        res.status(500).sendFile(path_1.default.join(__dirname, '..', '..', 'public', 'error.html'));
    }
});
exports.default = router;
//# sourceMappingURL=attend.js.map