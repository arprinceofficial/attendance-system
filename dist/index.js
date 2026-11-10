"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const path_1 = __importDefault(require("path"));
const attend_1 = __importDefault(require("./routes/attend"));
const auth_1 = __importDefault(require("./routes/auth"));
const admin_1 = __importDefault(require("./routes/admin"));
const app = (0, express_1.default)();
// Middleware
app.use((0, cors_1.default)());
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
app.use(express_1.default.static(path_1.default.join(__dirname, '..', 'public')));
// Routes
app.use('/attend', attend_1.default);
app.use('/api/auth', auth_1.default);
app.use('/api/admin', admin_1.default);
// Admin HTML pages
app.get('/admin/login', (_req, res) => {
    res.sendFile(path_1.default.join(__dirname, '..', 'public', 'admin', 'login.html'));
});
app.get('/admin/dashboard', (_req, res) => {
    res.sendFile(path_1.default.join(__dirname, '..', 'public', 'admin', 'dashboard.html'));
});
app.get('/admin', (_req, res) => {
    res.redirect('/admin/login');
});
app.get('/login', (_req, res) => {
    res.redirect('/admin/login');
});
app.get('/dashboard', (_req, res) => {
    res.redirect('/admin/dashboard');
});
app.get('/', (_req, res) => {
    res.redirect('/admin/login');
});
// 404 handler
app.use((_req, res) => {
    res.status(404).sendFile(path_1.default.join(__dirname, '..', 'public', 'error.html'));
});
// Error handler
app.use((err, _req, res, _next) => {
    console.error(err.stack);
    res.status(500).json({ success: false, message: 'Internal server error' });
});
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
app.listen(PORT, () => {
    console.log(`\n🚀 Attendance System running on port ${PORT} [${NODE_ENV}]`);
    console.log(`   Admin panel: http://localhost:${PORT}/admin/login\n`);
});
exports.default = app;
//# sourceMappingURL=index.js.map