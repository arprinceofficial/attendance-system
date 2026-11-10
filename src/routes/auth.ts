import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../lib/prisma';
import { getTodayDate, isLinkExpired } from '../utils/tokenUtils';
import { getRoleConfig } from '../utils/rbac';
import { AttendanceLoginBody } from '../types';

const router = Router();

function getIpAddress(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

async function getMacAddress(ip: string): Promise<string> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const arp = require('@network-utils/arp-lookup') as { toMAC: (ip: string) => Promise<string | null> };
    const mac = await arp.toMAC(ip);
    return mac || 'N/A';
  } catch {
    return 'N/A';
  }
}

function issuePortalToken(user: { id: string; email: string; role: string; name: string; department: string | null }): string {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
      department: user.department ?? null,
    },
    process.env.ADMIN_JWT_SECRET || 'admin-secret',
    { expiresIn: '8h' }
  );
}

// POST /api/auth/login
router.post('/login', async (req: Request<Record<string, string>, unknown, AttendanceLoginBody>, res: Response): Promise<void> => {
  try {
    const { email, password, token } = req.body;

    if (!email || !password || !token) {
      res.status(400).json({ success: false, message: 'Email, password, and attendance token are required.' });
      return;
    }

    const today = getTodayDate();

    // 1. Validate the attendance link token
    const link = await prisma.attendanceLink.findFirst({
      where: { token, isActive: true },
    });

    if (!link) {
      res.status(400).json({ success: false, message: 'Invalid or inactive attendance link.' });
      return;
    }

    if (link.date !== today) {
      res.status(400).json({ success: false, message: 'This attendance link has expired.' });
      return;
    }

    if (isLinkExpired(link.expiresAt)) {
      res.status(400).json({ success: false, message: 'This attendance link has expired (time limit reached).' });
      return;
    }

    // 2. Verify user credentials
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      res.status(401).json({ success: false, message: 'Invalid email or password.' });
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      res.status(401).json({ success: false, message: 'Invalid email or password.' });
      return;
    }

    // If link belongs to a specific teacher, only that teacher's students can mark attendance via it
    if (link.teacherId && (user.role !== 'student' || user.teacherId !== link.teacherId)) {
      res.status(403).json({
        success: false,
        message: 'This attendance link is restricted to students of the issuing teacher.',
      });
      return;
    }

    const roleConfig = await getRoleConfig(user.role);
    const portalToken = issuePortalToken(user);

    // 3. Check if attendance already marked for today
    const existingAttendance = await prisma.attendance.findFirst({
      where: { userId: user.id, date: today },
    });

    if (existingAttendance) {
      res.status(409).json({
        success: false,
        alreadyMarked: true,
        token: portalToken,
        id: user.id,
        name: user.name,
        role: user.role,
        roleLabel: roleConfig.label,
        department: user.department ?? null,
        message: `Attendance already marked at ${existingAttendance.markedAt.toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
        })}.`,
      });
      return;
    }

    // 4. Get current IP and MAC
    const ipAddress = getIpAddress(req);
    const macAddress = await getMacAddress(ipAddress);
    const userAgent = req.headers['user-agent'] || 'unknown';

    // 5. Get previous attendance record for IP/MAC comparison
    const previousAttendance = await prisma.attendance.findFirst({
      where: { userId: user.id },
      orderBy: { markedAt: 'desc' },
    });

    let ipChanged = false;
    let macChanged = false;

    if (previousAttendance) {
      if (
        previousAttendance.ipAddress &&
        previousAttendance.ipAddress !== 'unknown' &&
        previousAttendance.ipAddress !== ipAddress
      ) {
        ipChanged = true;
      }
      if (
        previousAttendance.macAddress &&
        previousAttendance.macAddress !== 'N/A' &&
        previousAttendance.macAddress !== macAddress
      ) {
        macChanged = true;
      }
    }

    // 6. Determine status (present vs late if lateAfter HH:mm cutoff is set on link)
    let status: 'present' | 'late' = 'present';
    if (link.lateAfter && /^\d{2}:\d{2}$/.test(link.lateAfter)) {
      const now = new Date();
      const currentHHMM = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      if (currentHHMM > link.lateAfter) {
        status = 'late';
      }
    }

    // 7. Create attendance record
    const attendance = await prisma.attendance.create({
      data: {
        userId: user.id,
        date: today,
        status,
        ipAddress,
        macAddress,
        userAgent,
        linkToken: token,
        ipChanged,
        macChanged,
      },
    });

    const markedAt = attendance.markedAt.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    res.status(200).json({
      success: true,
      message: `Attendance marked successfully at ${markedAt}.`,
      status,
      token: portalToken,
      id: user.id,
      name: user.name,
      role: user.role,
      roleLabel: roleConfig.label,
      department: user.department ?? null,
      markedAt,
      ipChanged,
      macChanged,
    });
  } catch (err) {
    console.error('Auth login error:', err);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

export default router;
