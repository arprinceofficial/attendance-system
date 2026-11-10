"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateToken = generateToken;
exports.getTodayDate = getTodayDate;
exports.getExpiresAt = getExpiresAt;
exports.isLinkExpired = isLinkExpired;
const crypto_1 = __importDefault(require("crypto"));
function generateToken() {
    return crypto_1.default.randomBytes(32).toString('hex');
}
function getTodayDate() {
    return new Date().toISOString().split('T')[0];
}
function getExpiresAt(durationMinutes) {
    if (!durationMinutes || durationMinutes <= 0)
        return null;
    const expires = new Date();
    expires.setMinutes(expires.getMinutes() + durationMinutes);
    return expires;
}
function isLinkExpired(expiresAt) {
    if (!expiresAt)
        return false;
    return new Date() > expiresAt;
}
//# sourceMappingURL=tokenUtils.js.map