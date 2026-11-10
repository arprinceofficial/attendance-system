import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';

import attendRoute from './routes/attend';
import authRoute from './routes/auth';
import adminRoute from './routes/admin';

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Routes
app.use('/attend', attendRoute);
app.use('/api/auth', authRoute);
app.use('/api/admin', adminRoute);

// Admin HTML pages
app.get('/admin/login', (_req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', (_req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'admin', 'dashboard.html'));
});

app.get('/admin', (_req: Request, res: Response) => {
  res.redirect('/admin/login');
});

app.get('/login', (_req: Request, res: Response) => {
  res.redirect('/admin/login');
});

app.get('/dashboard', (_req: Request, res: Response) => {
  res.redirect('/admin/dashboard');
});

app.get('/', (_req: Request, res: Response) => {
  res.redirect('/admin/login');
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).sendFile(path.join(__dirname, '..', 'public', 'error.html'));
});

// Error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

app.listen(PORT, () => {
  console.log(`\n🚀 Attendance System running on port ${PORT} [${NODE_ENV}]`);
  console.log(`   Admin panel: http://localhost:${PORT}/admin/login\n`);
});

export default app;
