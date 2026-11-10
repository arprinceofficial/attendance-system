import { Router, Request, Response } from 'express';
import path from 'path';
import prisma from '../lib/prisma';
import { getTodayDate, isLinkExpired } from '../utils/tokenUtils';

const router = Router();

// GET /attend/validate/:token
router.get('/validate/:token', async (req: Request, res: Response): Promise<void> => {
  try {
    const token = String(req.params.token);
    const today = getTodayDate();

    const link = await prisma.attendanceLink.findFirst({
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

    if (isLinkExpired(link.expiresAt)) {
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
  } catch (err) {
    console.error('Token validation error:', err);
    res.status(500).json({ valid: false, reason: 'Server error' });
  }
});

// GET /attend/:token
router.get('/:token', async (req: Request, res: Response): Promise<void> => {
  try {
    const token = String(req.params.token);
    const today = getTodayDate();

    const link = await prisma.attendanceLink.findFirst({
      where: { token, isActive: true },
    });

    if (!link || link.date !== today || isLinkExpired(link.expiresAt)) {
      res.status(404).sendFile(
        path.join(__dirname, '..', '..', 'public', 'error.html')
      );
      return;
    }

    res.sendFile(
      path.join(__dirname, '..', '..', 'public', 'attend.html')
    );
  } catch (err) {
    console.error('Attend route error:', err);
    res.status(500).sendFile(
      path.join(__dirname, '..', '..', 'public', 'error.html')
    );
  }
});

export default router;
