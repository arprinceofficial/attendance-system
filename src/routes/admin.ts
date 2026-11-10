import { Router, Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../lib/prisma';
import { adminMiddleware, requirePermission } from '../middleware/adminMiddleware';
import { generateToken, getTodayDate, getExpiresAt } from '../utils/tokenUtils';
import {
  ALL_MENUS,
  ALL_PERMISSIONS,
  ensureDefaultRoles,
  getRoleConfig,
  resetRolesCache,
} from '../utils/rbac';
import {
  CreateUserBody,
  ManualAttendanceBody,
  UpdateAttendanceBody,
  CreateLinkBody,
  UpsertRoleBody,
  UpsertDepartmentBody,
  AttendanceStatus,
  JwtPanelPayload,
  DataScope,
} from '../types';

const router = Router();

function isPrismaNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: string }).code === 'P2025'
  );
}

function requireAnyPermission(permissions: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = req.admin;
    if (!user) {
      res.status(401).json({ success: false, message: 'Authentication required.' });
      return;
    }
    if (user.role === 'admin' || permissions.some((p) => user.permissions?.includes(p))) {
      next();
      return;
    }
    res.status(403).json({
      success: false,
      message: `Access denied. Requires one of: ${permissions.join(', ')}`,
    });
  };
}

async function getScopedStudentIds(
  panelUser: JwtPanelPayload,
  department?: string,
  teacherId?: string
): Promise<string[]> {
  const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');

  if (scope === 'own') {
    return [panelUser.id];
  }

  if (scope === 'assigned_students') {
    const students = await prisma.user.findMany({
      where: { role: 'student', teacherId: panelUser.id },
      select: { id: true },
    });
    return students.map((s) => s.id);
  }

  if (scope === 'department') {
    const dept = panelUser.department?.trim();
    if (!dept) return [];

    const deptTeachers = await prisma.user.findMany({
      where: { role: 'teacher', department: dept },
      select: { id: true },
    });
    const deptTeacherIds = deptTeachers.map((t) => t.id);

    const andConditions: Record<string, unknown>[] = [
      { role: 'student' },
      {
        OR: [
          { department: dept },
          ...(deptTeacherIds.length > 0 ? [{ teacherId: { in: deptTeacherIds } }] : []),
        ],
      },
    ];

    if (teacherId) {
      andConditions.push({ teacherId });
    }

    const students = await prisma.user.findMany({
      where: { AND: andConditions },
      select: { id: true },
    });
    return students.map((s) => s.id);
  }

  // scope === 'all'
  const canFilter = panelUser.role === 'admin' || panelUser.permissions?.includes('filter_department');
  const andConditions: Record<string, unknown>[] = [{ role: 'student' }];

  if (canFilter && teacherId) {
    andConditions.push({ teacherId });
  }

  if (canFilter && department) {
    const deptTeachers = await prisma.user.findMany({
      where: { role: 'teacher', department },
      select: { id: true },
    });
    const deptTeacherIds = deptTeachers.map((t) => t.id);

    andConditions.push({
      OR: [
        { department },
        ...(deptTeacherIds.length > 0 ? [{ teacherId: { in: deptTeacherIds } }] : []),
      ],
    });
  }

  const students = await prisma.user.findMany({
    where: { AND: andConditions },
    select: { id: true },
  });
  return students.map((s) => s.id);
}

async function canAccessStudent(panelUser: JwtPanelPayload, targetUser: { id: string; role: string; department: string | null; teacherId: string | null }): Promise<boolean> {
  const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');
  if (scope === 'all') return true;
  if (scope === 'own') return targetUser.id === panelUser.id;
  if (scope === 'assigned_students') {
    return targetUser.role === 'student' && targetUser.teacherId === panelUser.id;
  }
  if (scope === 'department') {
    if (!panelUser.department) return false;
    if (targetUser.department === panelUser.department) return true;
    if (targetUser.teacherId) {
      const t = await prisma.user.findUnique({ where: { id: targetUser.teacherId }, select: { department: true } });
      return t?.department === panelUser.department;
    }
    return false;
  }
  return false;
}

// ─────────────────────────────────────────
// AUTH (public — all roles supported)
// ─────────────────────────────────────────

// POST /api/admin/login
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body as { email?: string; password?: string };

    if (!email || !password) {
      res.status(400).json({ success: false, message: 'Email and password are required.' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ success: false, message: 'Invalid credentials.' });
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      res.status(401).json({ success: false, message: 'Invalid credentials.' });
      return;
    }

    const roleConfig = await getRoleConfig(user.role);

    const token = jwt.sign(
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

    res.json({
      success: true,
      token,
      id: user.id,
      name: user.name,
      role: user.role,
      roleLabel: roleConfig.label,
      department: user.department ?? null,
      dataScope: user.role === 'admin' ? 'all' : roleConfig.dataScope,
      menus: roleConfig.menus,
      permissions: roleConfig.permissions,
    });
  } catch (err) {
    console.error('Portal login error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// All routes below require valid portal auth
router.use(adminMiddleware);

// GET /api/admin/me — current user profile + live RBAC config
router.get('/me', async (req: Request, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    const user = await prisma.user.findUnique({
      where: { id: panelUser.id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        teacherId: true,
        teacher: { select: { id: true, name: true, email: true, department: true } },
        createdAt: true,
      },
    });

    if (!user) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }

    res.json({
      success: true,
      user: {
        ...user,
        roleLabel: panelUser.roleLabel,
        dataScope: panelUser.dataScope,
        menus: panelUser.menus,
        permissions: panelUser.permissions,
      },
      menuCatalog: ALL_MENUS,
    });
  } catch (err) {
    console.error('Get me error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// PERSONAL PROFILE & ATTENDANCE (Students / Staff)
// ─────────────────────────────────────────

// GET /api/admin/my/profile
router.get('/my/profile', requirePermission('view_own_profile'), async (req: Request, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    const user = await prisma.user.findUnique({
      where: { id: panelUser.id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        teacherId: true,
        teacher: { select: { id: true, name: true, email: true, department: true } },
        _count: { select: { students: true, attendance: true } },
        createdAt: true,
      },
    });

    if (!user) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }

    const today = getTodayDate();
    const todayAttendance = await prisma.attendance.findFirst({
      where: { userId: panelUser.id, date: today },
    });

    res.json({
      success: true,
      profile: {
        ...user,
        roleLabel: panelUser.roleLabel,
        markedToday: !!todayAttendance,
        todayMarkedAt: todayAttendance?.markedAt ?? null,
      },
    });
  } catch (err) {
    console.error('Get own profile error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// GET /api/admin/my/attendance?month=YYYY-MM
router.get('/my/attendance', requirePermission('view_own_attendance'), async (req: Request, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    const today = getTodayDate();
    const defaultMonth = today.slice(0, 7);
    const reqMonth = typeof req.query.month === 'string' && /^\d{4}-\d{2}$/.test(req.query.month)
      ? req.query.month
      : defaultMonth;

    const [yearStr, monthStr] = reqMonth.split('-');
    const year = parseInt(yearStr, 10);
    const monthIndex = parseInt(monthStr, 10) - 1; // 0-based
    const daysInMonth = new Date(year, monthIndex + 1, 0).getDate();

    const monthRecords = await prisma.attendance.findMany({
      where: {
        userId: panelUser.id,
        date: { startsWith: `${reqMonth}-` },
      },
      orderBy: { date: 'asc' },
    });

    const latestRecord = await prisma.attendance.findFirst({
      where: { userId: panelUser.id },
      orderBy: { markedAt: 'desc' },
    });

    const todayRecord = await prisma.attendance.findFirst({
      where: { userId: panelUser.id, date: today },
    });

    const recordByDate = new Map(monthRecords.map((r) => [r.date, r]));

    let presentDays = 0;
    let lateDays = 0;
    let absentDays = 0;
    let totalDays = 0;

    // Weekends: Friday (5) and Saturday (6)
    const isWeekendDay = (dayOfWeek: number): boolean => dayOfWeek === 5 || dayOfWeek === 6;

    for (let d = 1; d <= daysInMonth; d++) {
      const dateStr = `${reqMonth}-${String(d).padStart(2, '0')}`;
      if (dateStr > today) break; // Future dates not counted yet

      const dow = new Date(year, monthIndex, d).getDay();
      if (isWeekendDay(dow)) continue;

      totalDays++;
      const rec = recordByDate.get(dateStr);
      if (rec) {
        if (rec.status === 'late') {
          lateDays++;
        } else {
          presentDays++; // "present" and "late_approved" count as present
        }
      } else if (dateStr < today) {
        absentDays++;
      }
    }

    const totalAllTime = await prisma.attendance.count({ where: { userId: panelUser.id } });

    res.json({
      success: true,
      month: reqMonth,
      today,
      summary: {
        presentDays,
        lateDays,
        absentDays,
        totalDays,
      },
      totalPresent: totalAllTime,
      markedToday: !!todayRecord,
      todayMarkedAt: todayRecord?.markedAt ?? null,
      lastIpAddress: latestRecord?.ipAddress ?? null,
      lastMacAddress: latestRecord?.macAddress ?? null,
      records: monthRecords,
    });
  } catch (err) {
    console.error('Get own attendance error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// FILTERS (Departments, Teachers, Roles)
// ─────────────────────────────────────────

router.get('/filters', async (req: Request, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    await ensureDefaultRoles();

    const roles = await prisma.role.findMany({
      select: { name: true, label: true, dataScope: true },
      orderBy: { createdAt: 'asc' },
    });

    const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');

    if (scope === 'assigned_students' || scope === 'own') {
      res.json({
        success: true,
        departments: panelUser.department ? [panelUser.department] : [],
        teachers: panelUser.role === 'teacher'
          ? [{ id: panelUser.id, name: panelUser.name, email: panelUser.email, department: panelUser.department ?? null }]
          : [],
        roles,
      });
      return;
    }

    if (scope === 'department') {
      const teachers = await prisma.user.findMany({
        where: { role: 'teacher', department: panelUser.department ?? undefined },
        select: { id: true, name: true, email: true, department: true },
        orderBy: { name: 'asc' },
      });
      res.json({
        success: true,
        departments: panelUser.department ? [panelUser.department] : [],
        teachers,
        roles,
      });
      return;
    }

    const teachers = await prisma.user.findMany({
      where: { role: 'teacher' },
      select: { id: true, name: true, email: true, department: true },
      orderBy: { name: 'asc' },
    });

    const managedDepts = await prisma.department.findMany({
      select: { name: true },
      orderBy: { name: 'asc' },
    });

    const allDeptUsers = await prisma.user.findMany({
      where: { department: { not: null } },
      select: { department: true },
    });

    const deptSet = new Set<string>();
    for (const d of managedDepts) {
      if (d.name.trim()) deptSet.add(d.name.trim());
    }
    for (const u of allDeptUsers) {
      if (u.department && u.department.trim()) {
        deptSet.add(u.department.trim());
      }
    }

    res.json({
      success: true,
      departments: Array.from(deptSet).sort(),
      teachers,
      roles,
    });
  } catch (err) {
    console.error('Get filters error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// DEPARTMENTS CRUD (Admin / manage_departments)
// ─────────────────────────────────────────

// GET /api/admin/departments
router.get('/departments', requirePermission('manage_departments'), async (_req: Request, res: Response): Promise<void> => {
  try {
    const departments = await prisma.department.findMany({
      orderBy: { name: 'asc' },
    });

    const users = await prisma.user.findMany({
      where: { department: { not: null } },
      select: { department: true, role: true },
    });

    const counts: Record<string, { teachers: number; students: number; total: number }> = {};
    for (const u of users) {
      const dept = u.department?.trim();
      if (!dept) continue;
      if (!counts[dept]) counts[dept] = { teachers: 0, students: 0, total: 0 };
      counts[dept].total++;
      if (u.role === 'teacher') counts[dept].teachers++;
      if (u.role === 'student') counts[dept].students++;
    }

    res.json({
      success: true,
      departments: departments.map((d) => ({
        ...d,
        teacherCount: counts[d.name]?.teachers || 0,
        studentCount: counts[d.name]?.students || 0,
        totalUsers: counts[d.name]?.total || 0,
      })),
    });
  } catch (err) {
    console.error('Get departments error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/departments
router.post('/departments', requirePermission('manage_departments'), async (req: Request<Record<string, string>, unknown, UpsertDepartmentBody>, res: Response): Promise<void> => {
  try {
    const name = req.body.name?.trim();
    const code = req.body.code?.trim() || null;
    const description = req.body.description?.trim() || null;

    if (!name) {
      res.status(400).json({ success: false, message: 'Department name is required.' });
      return;
    }

    const existing = await prisma.department.findUnique({ where: { name } });
    if (existing) {
      res.status(409).json({ success: false, message: `Department "${name}" already exists.` });
      return;
    }

    const department = await prisma.department.create({
      data: { name, code, description },
    });

    res.status(201).json({ success: true, department });
  } catch (err) {
    console.error('Create department error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PUT /api/admin/departments/:id
router.put('/departments/:id', requirePermission('manage_departments'), async (req: Request<Record<string, string>, unknown, Partial<UpsertDepartmentBody>>, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const existing = await prisma.department.findUnique({ where: { id } });
    if (!existing) {
      res.status(404).json({ success: false, message: 'Department not found.' });
      return;
    }

    const nextName = req.body.name?.trim() || existing.name;
    const nextCode = req.body.code !== undefined ? (req.body.code?.trim() || null) : existing.code;
    const nextDesc = req.body.description !== undefined ? (req.body.description?.trim() || null) : existing.description;

    if (nextName !== existing.name) {
      const conflict = await prisma.department.findUnique({ where: { name: nextName } });
      if (conflict) {
        res.status(409).json({ success: false, message: `Department "${nextName}" already exists.` });
        return;
      }
    }

    const department = await prisma.department.update({
      where: { id },
      data: {
        name: nextName,
        code: nextCode,
        description: nextDesc,
      },
    });

    // Keep users synced if department was renamed
    if (nextName !== existing.name) {
      await prisma.user.updateMany({
        where: { department: existing.name },
        data: { department: nextName },
      });
    }

    res.json({ success: true, department });
  } catch (err) {
    console.error('Update department error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/admin/departments/:id
router.delete('/departments/:id', requirePermission('manage_departments'), async (req: Request, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const existing = await prisma.department.findUnique({ where: { id } });
    if (!existing) {
      res.status(404).json({ success: false, message: 'Department not found.' });
      return;
    }

    await prisma.user.updateMany({
      where: { department: existing.name },
      data: { department: null },
    });

    await prisma.department.delete({ where: { id } });
    res.json({ success: true, message: `Department "${existing.name}" deleted.` });
  } catch (err) {
    console.error('Delete department error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// RBAC ROLES MANAGEMENT (Admin / manage_roles)
// ─────────────────────────────────────────

// GET /api/admin/roles
router.get('/roles', requirePermission('manage_roles'), async (_req: Request, res: Response): Promise<void> => {
  try {
    await ensureDefaultRoles();
    const roles = await prisma.role.findMany({ orderBy: { createdAt: 'asc' } });

    // Count users per role
    const allUsers = await prisma.user.findMany({ select: { role: true } });
    const countMap: Record<string, number> = {};
    for (const u of allUsers) {
      countMap[u.role] = (countMap[u.role] || 0) + 1;
    }

    res.json({
      success: true,
      roles: roles.map((r) => ({ ...r, userCount: countMap[r.name] || 0 })),
      menuCatalog: ALL_MENUS,
      permissionCatalog: ALL_PERMISSIONS,
    });
  } catch (err) {
    console.error('Get roles error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/roles
router.post('/roles', requirePermission('manage_roles'), async (req: Request<Record<string, string>, unknown, UpsertRoleBody>, res: Response): Promise<void> => {
  try {
    const { name, label, description, dataScope, menus, permissions } = req.body;

    if (!name || !label) {
      res.status(400).json({ success: false, message: 'Role key name and display label are required.' });
      return;
    }

    const normalizedName = name.trim().toLowerCase().replace(/\s+/g, '_');
    if (!/^[a-z0-9_-]+$/.test(normalizedName)) {
      res.status(400).json({ success: false, message: 'Role key may only contain lowercase letters, numbers, underscores, or hyphens.' });
      return;
    }

    const existing = await prisma.role.findUnique({ where: { name: normalizedName } });
    if (existing) {
      res.status(409).json({ success: false, message: `Role "${normalizedName}" already exists.` });
      return;
    }

    const validScopes: DataScope[] = ['all', 'department', 'assigned_students', 'own'];
    const safeScope: DataScope = validScopes.includes(dataScope) ? dataScope : 'own';
    const validMenuKeys = new Set(ALL_MENUS.map((m) => m.key));
    const validPermKeys = new Set(ALL_PERMISSIONS.map((p) => p.key));

    const role = await prisma.role.create({
      data: {
        name: normalizedName,
        label: label.trim(),
        description: description?.trim() || null,
        isSystem: false,
        dataScope: safeScope,
        menus: Array.isArray(menus) ? menus.filter((m) => validMenuKeys.has(m)) : [],
        permissions: Array.isArray(permissions) ? permissions.filter((p) => validPermKeys.has(p)) : [],
      },
    });

    resetRolesCache();
    res.status(201).json({ success: true, role });
  } catch (err) {
    console.error('Create role error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PUT /api/admin/roles/:id
router.put('/roles/:id', requirePermission('manage_roles'), async (req: Request<Record<string, string>, unknown, Partial<UpsertRoleBody>>, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const existing = await prisma.role.findUnique({ where: { id } });
    if (!existing) {
      res.status(404).json({ success: false, message: 'Role not found.' });
      return;
    }

    const { label, description, dataScope, menus, permissions } = req.body;
    const validScopes: DataScope[] = ['all', 'department', 'assigned_students', 'own'];
    const validMenuKeys = new Set(ALL_MENUS.map((m) => m.key));
    const validPermKeys = new Set(ALL_PERMISSIONS.map((p) => p.key));

    let nextMenus = Array.isArray(menus)
      ? menus.filter((m) => validMenuKeys.has(m))
      : existing.menus;
    let nextPermissions = Array.isArray(permissions)
      ? permissions.filter((p) => validPermKeys.has(p))
      : existing.permissions;
    let nextScope: DataScope = validScopes.includes(dataScope as DataScope)
      ? (dataScope as DataScope)
      : (existing.dataScope as DataScope);

    // Protect core admin access so admin never locks themselves out
    if (existing.name === 'admin') {
      if (!nextMenus.includes('roles')) nextMenus = [...nextMenus, 'roles'];
      if (!nextPermissions.includes('manage_roles')) nextPermissions = [...nextPermissions, 'manage_roles'];
      nextScope = 'all';
    }

    const role = await prisma.role.update({
      where: { id },
      data: {
        ...(label?.trim() ? { label: label.trim() } : {}),
        ...(description !== undefined ? { description: description?.trim() || null } : {}),
        dataScope: nextScope,
        menus: nextMenus,
        permissions: nextPermissions,
      },
    });

    resetRolesCache();
    res.json({ success: true, role });
  } catch (err) {
    console.error('Update role error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/admin/roles/:id
router.delete('/roles/:id', requirePermission('manage_roles'), async (req: Request, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const existing = await prisma.role.findUnique({ where: { id } });
    if (!existing) {
      res.status(404).json({ success: false, message: 'Role not found.' });
      return;
    }

    if (existing.isSystem) {
      res.status(400).json({ success: false, message: 'System roles cannot be deleted.' });
      return;
    }

    const assignedUsers = await prisma.user.count({ where: { role: existing.name } });
    if (assignedUsers > 0) {
      res.status(400).json({
        success: false,
        message: `Cannot delete role "${existing.label}" because ${assignedUsers} user(s) still have this role.`,
      });
      return;
    }

    await prisma.role.delete({ where: { id } });
    resetRolesCache();
    res.json({ success: true, message: 'Role deleted.' });
  } catch (err) {
    console.error('Delete role error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// STATS
// ─────────────────────────────────────────

router.get('/stats', requirePermission('view_dashboard'), async (req: Request, res: Response): Promise<void> => {
  try {
    const today = getTodayDate();
    const studentIds = await getScopedStudentIds(req.admin!);
    const totalUsers = studentIds.length;
    const todayPresent =
      totalUsers > 0
        ? await prisma.attendance.count({
            where: { date: today, userId: { in: studentIds } },
          })
        : 0;

    res.json({
      success: true,
      totalUsers,
      todayPresent,
      todayAbsent: Math.max(0, totalUsers - todayPresent),
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// ATTENDANCE
// ─────────────────────────────────────────

// GET /api/admin/attendance/today
router.get(
  '/attendance/today',
  requireAnyPermission(['view_dashboard', 'view_attendance']),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const today = getTodayDate();
      const department =
        typeof req.query.department === 'string' && req.query.department.trim()
          ? req.query.department.trim()
          : undefined;
      const teacherId =
        typeof req.query.teacherId === 'string' && req.query.teacherId.trim()
          ? req.query.teacherId.trim()
          : undefined;

      const studentIds = await getScopedStudentIds(req.admin!, department, teacherId);

      const records =
        studentIds.length > 0
          ? await prisma.attendance.findMany({
              where: { date: today, userId: { in: studentIds } },
              include: {
                user: {
                  select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                    department: true,
                    teacherId: true,
                    teacher: { select: { id: true, name: true, department: true } },
                  },
                },
              },
              orderBy: { markedAt: 'asc' },
            })
          : [];

      res.json({
        success: true,
        date: today,
        present: records.length,
        total: studentIds.length,
        absent: Math.max(0, studentIds.length - records.length),
        records,
      });
    } catch (err) {
      console.error('Get today attendance error:', err);
      res.status(500).json({ success: false, message: 'Server error.' });
    }
  }
);

// GET /api/admin/attendance?date=YYYY-MM-DD
router.get('/attendance', requirePermission('view_attendance'), async (req: Request, res: Response): Promise<void> => {
  try {
    const date = typeof req.query.date === 'string' ? req.query.date : undefined;
    const department =
      typeof req.query.department === 'string' && req.query.department.trim()
        ? req.query.department.trim()
        : undefined;
    const teacherId =
      typeof req.query.teacherId === 'string' && req.query.teacherId.trim()
        ? req.query.teacherId.trim()
        : undefined;

    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      res.status(400).json({ success: false, message: 'Valid date query parameter (YYYY-MM-DD) required.' });
      return;
    }

    const studentIds = await getScopedStudentIds(req.admin!, department, teacherId);

    const records =
      studentIds.length > 0
        ? await prisma.attendance.findMany({
            where: { date, userId: { in: studentIds } },
            include: {
              user: {
                select: {
                  id: true,
                  name: true,
                  email: true,
                  role: true,
                  department: true,
                  teacherId: true,
                  teacher: { select: { id: true, name: true, department: true } },
                },
              },
            },
            orderBy: { markedAt: 'asc' },
          })
        : [];

    res.json({
      success: true,
      date,
      present: records.length,
      total: studentIds.length,
      absent: Math.max(0, studentIds.length - records.length),
      records,
    });
  } catch (err) {
    console.error('Get attendance error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/attendance — Manual mark
router.post('/attendance', requirePermission('manage_attendance'), async (req: Request<Record<string, string>, unknown, ManualAttendanceBody>, res: Response): Promise<void> => {
  try {
    const { userId, date, status } = req.body;
    const panelUser = req.admin!;

    if (!userId || !date) {
      res.status(400).json({ success: false, message: 'userId and date are required.' });
      return;
    }

    const validStatuses: AttendanceStatus[] = ['present', 'late', 'late_approved'];
    const safeStatus: AttendanceStatus = status && validStatuses.includes(status) ? status : 'present';

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }

    if (!(await canAccessStudent(panelUser, user))) {
      res.status(403).json({ success: false, message: 'You cannot mark attendance for users outside your scope.' });
      return;
    }

    const existing = await prisma.attendance.findFirst({ where: { userId, date } });
    if (existing) {
      res.status(409).json({ success: false, message: 'Attendance already marked for this date.' });
      return;
    }

    const attendance = await prisma.attendance.create({
      data: {
        userId,
        date,
        status: safeStatus,
        ipAddress: 'manual',
        macAddress: 'manual',
        userAgent: `${panelUser.role}-manual`,
        ipChanged: false,
        macChanged: false,
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            department: true,
            teacher: { select: { id: true, name: true, department: true } },
          },
        },
      },
    });

    res.status(201).json({ success: true, attendance });
  } catch (err) {
    console.error('Manual mark error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PUT /api/admin/attendance/:id
router.put('/attendance/:id', requirePermission('manage_attendance'), async (req: Request<Record<string, string>, unknown, UpdateAttendanceBody>, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const panelUser = req.admin!;
    const { status, ipAddress, macAddress, userAgent, ipChanged, macChanged } = req.body;

    const existing = await prisma.attendance.findUnique({
      where: { id },
      include: { user: { select: { id: true, role: true, department: true, teacherId: true } } },
    });

    if (!existing) {
      res.status(404).json({ success: false, message: 'Record not found.' });
      return;
    }

    if (!(await canAccessStudent(panelUser, existing.user))) {
      res.status(403).json({ success: false, message: 'You cannot modify attendance outside your scope.' });
      return;
    }

    const validStatuses: AttendanceStatus[] = ['present', 'late', 'late_approved'];
    const safeStatus = status && validStatuses.includes(status) ? status : undefined;

    const updated = await prisma.attendance.update({
      where: { id },
      data: {
        ...(safeStatus !== undefined && { status: safeStatus }),
        ...(ipAddress !== undefined && { ipAddress }),
        ...(macAddress !== undefined && { macAddress }),
        ...(userAgent !== undefined && { userAgent }),
        ...(ipChanged !== undefined && { ipChanged }),
        ...(macChanged !== undefined && { macChanged }),
      },
      include: { user: { select: { id: true, name: true, email: true, department: true } } },
    });

    res.json({ success: true, attendance: updated });
  } catch (err) {
    console.error('Update attendance error:', err);
    if (isPrismaNotFound(err)) {
      res.status(404).json({ success: false, message: 'Record not found.' });
      return;
    }
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/admin/attendance/:id
router.delete('/attendance/:id', requirePermission('manage_attendance'), async (req: Request, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const panelUser = req.admin!;

    const existing = await prisma.attendance.findUnique({
      where: { id },
      include: { user: { select: { id: true, role: true, department: true, teacherId: true } } },
    });

    if (!existing) {
      res.status(404).json({ success: false, message: 'Record not found.' });
      return;
    }

    if (!(await canAccessStudent(panelUser, existing.user))) {
      res.status(403).json({ success: false, message: 'You cannot delete attendance outside your scope.' });
      return;
    }

    await prisma.attendance.delete({ where: { id } });
    res.json({ success: true, message: 'Attendance record deleted.' });
  } catch (err) {
    console.error('Delete attendance error:', err);
    if (isPrismaNotFound(err)) {
      res.status(404).json({ success: false, message: 'Record not found.' });
      return;
    }
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// USERS
// ─────────────────────────────────────────

// GET /api/admin/users
router.get('/users', requirePermission('view_users'), async (req: Request, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');

    const roleFilter =
      typeof req.query.role === 'string' && req.query.role.trim()
        ? req.query.role.trim()
        : undefined;
    const deptFilter =
      typeof req.query.department === 'string' && req.query.department.trim()
        ? req.query.department.trim()
        : undefined;
    const teacherFilter =
      typeof req.query.teacherId === 'string' && req.query.teacherId.trim()
        ? req.query.teacherId.trim()
        : undefined;

    const where: Record<string, unknown> = {};

    if (scope === 'own') {
      where.id = panelUser.id;
    } else if (scope === 'assigned_students') {
      where.role = 'student';
      where.teacherId = panelUser.id;
    } else if (scope === 'department') {
      where.department = panelUser.department || '__none__';
      if (roleFilter) where.role = roleFilter;
      if (teacherFilter) where.teacherId = teacherFilter;
    } else {
      if (roleFilter) where.role = roleFilter;
      if (deptFilter) where.department = deptFilter;
      if (teacherFilter) where.teacherId = teacherFilter;
    }

    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        teacherId: true,
        teacher: { select: { id: true, name: true, department: true } },
        _count: { select: { students: true } },
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json({ success: true, users });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/users
router.post('/users', requirePermission('create_users'), async (req: Request<Record<string, string>, unknown, CreateUserBody>, res: Response): Promise<void> => {
  try {
    const panelUser = req.admin!;
    const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');
    const { name, email, password, role, department, teacherId } = req.body;

    if (!name || !email || !password) {
      res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
      return;
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      res.status(409).json({ success: false, message: 'Email already in use.' });
      return;
    }

    await ensureDefaultRoles();

    let resolvedRole: string = role?.trim() || 'student';
    let resolvedDept: string | null = department?.trim() || null;
    let resolvedTeacherId: string | null = teacherId?.trim() || null;

    if (scope === 'assigned_students') {
      resolvedRole = 'student';
      resolvedTeacherId = panelUser.id;
      resolvedDept = resolvedDept || panelUser.department || null;
    } else if (scope === 'department') {
      if (resolvedRole === 'admin') {
        res.status(403).json({ success: false, message: 'You cannot create admin users.' });
        return;
      }
      resolvedDept = panelUser.department || null;
    } else if (scope === 'own') {
      res.status(403).json({ success: false, message: 'You cannot create users.' });
      return;
    }

    const roleExists = await prisma.role.findUnique({ where: { name: resolvedRole } });
    if (!roleExists) {
      res.status(400).json({ success: false, message: `Role "${resolvedRole}" does not exist.` });
      return;
    }

    if (resolvedRole === 'student' && resolvedTeacherId) {
      const assignedTeacher = await prisma.user.findUnique({ where: { id: resolvedTeacherId } });
      if (!assignedTeacher || assignedTeacher.role !== 'teacher') {
        res.status(400).json({ success: false, message: 'Assigned teacher not found.' });
        return;
      }
      if (!resolvedDept && assignedTeacher.department) {
        resolvedDept = assignedTeacher.department;
      }
    } else if (resolvedRole !== 'student') {
      resolvedTeacherId = null;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: resolvedRole,
        department: resolvedDept,
        teacherId: resolvedTeacherId,
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        teacherId: true,
        teacher: { select: { id: true, name: true, department: true } },
        createdAt: true,
      },
    });

    res.status(201).json({ success: true, user });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// PUT /api/admin/users/:id
router.put('/users/:id', requirePermission('edit_users'), async (req: Request, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const panelUser = req.admin!;
    const scope = panelUser.role === 'admin' ? 'all' : (panelUser.dataScope || 'own');
    const { name, email, password, role, department, teacherId } = req.body as Partial<CreateUserBody>;

    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }

    if (!(await canAccessStudent(panelUser, target))) {
      res.status(403).json({ success: false, message: 'You cannot edit users outside your scope.' });
      return;
    }

    const updateData: {
      name?: string;
      email?: string;
      role?: string;
      department?: string | null;
      teacherId?: string | null;
      password?: string;
    } = {};

    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (password) updateData.password = await bcrypt.hash(password, 12);

    if (scope === 'assigned_students') {
      if (department !== undefined) {
        updateData.department = department?.trim() || panelUser.department || null;
      }
    } else if (scope === 'all' || scope === 'department') {
      const nextRole = role?.trim() || target.role;
      if (role) {
        if (scope === 'department' && role === 'admin') {
          res.status(403).json({ success: false, message: 'You cannot promote users to admin.' });
          return;
        }
        const roleExists = await prisma.role.findUnique({ where: { name: nextRole } });
        if (!roleExists) {
          res.status(400).json({ success: false, message: `Role "${nextRole}" does not exist.` });
          return;
        }
        updateData.role = nextRole;
      }
      if (department !== undefined && scope === 'all') {
        updateData.department = department?.trim() || null;
      }
      if (nextRole !== 'student') {
        updateData.teacherId = null;
      } else if (teacherId !== undefined) {
        const nextTeacherId = teacherId?.trim() || null;
        if (nextTeacherId) {
          const assignedTeacher = await prisma.user.findUnique({ where: { id: nextTeacherId } });
          if (!assignedTeacher || assignedTeacher.role !== 'teacher') {
            res.status(400).json({ success: false, message: 'Assigned teacher not found.' });
            return;
          }
          if (department === undefined && !target.department && assignedTeacher.department) {
            updateData.department = assignedTeacher.department;
          }
        }
        updateData.teacherId = nextTeacherId;
      }
    }

    const user = await prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        teacherId: true,
        teacher: { select: { id: true, name: true, department: true } },
        createdAt: true,
        updatedAt: true,
      },
    });

    res.json({ success: true, user });
  } catch (err) {
    console.error('Update user error:', err);
    if (isPrismaNotFound(err)) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// DELETE /api/admin/users/:id
router.delete('/users/:id', requirePermission('delete_users'), async (req: Request, res: Response): Promise<void> => {
  try {
    const id = String(req.params.id);
    const panelUser = req.admin!;

    if (id === panelUser.id) {
      res.status(400).json({ success: false, message: 'You cannot delete your own account.' });
      return;
    }

    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }

    if (!(await canAccessStudent(panelUser, target))) {
      res.status(403).json({ success: false, message: 'You cannot delete users outside your scope.' });
      return;
    }

    if (target.role === 'teacher') {
      await prisma.user.updateMany({ where: { teacherId: id }, data: { teacherId: null } });
      await prisma.attendanceLink.updateMany({ where: { teacherId: id }, data: { isActive: false } });
    }

    await prisma.attendance.deleteMany({ where: { userId: id } });
    await prisma.user.delete({ where: { id } });
    res.json({ success: true, message: 'User and their attendance records deleted.' });
  } catch (err) {
    console.error('Delete user error:', err);
    if (isPrismaNotFound(err)) {
      res.status(404).json({ success: false, message: 'User not found.' });
      return;
    }
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ─────────────────────────────────────────
// LINK MANAGER
// ─────────────────────────────────────────

// GET /api/admin/link
router.get('/link', requirePermission('manage_links'), async (req: Request, res: Response): Promise<void> => {
  try {
    const today = getTodayDate();
    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
    const now = new Date();
    const panelUser = req.admin!;
    const scopeTeacherId = panelUser.dataScope === 'assigned_students' ? panelUser.id : null;

    const link = await prisma.attendanceLink.findFirst({
      where: { date: today, isActive: true, teacherId: scopeTeacherId },
      orderBy: { createdAt: 'desc' },
    });

    const historyWhere = panelUser.dataScope === 'assigned_students'
      ? { date: today, teacherId: panelUser.id }
      : { date: today };

    const historyLinks = await prisma.attendanceLink.findMany({
      where: historyWhere,
      include: { createdBy: { select: { id: true, name: true, role: true, department: true } } },
      orderBy: { createdAt: 'desc' },
      take: 15,
    });

    const history = historyLinks.map((item) => {
      const expired = item.expiresAt ? now > item.expiresAt : false;
      return {
        id: item.id,
        date: item.date,
        isActive: item.isActive,
        isExpired: expired,
        durationMinutes: item.durationMinutes,
        expiresAt: item.expiresAt,
        createdAt: item.createdAt,
        createdBy: item.createdBy,
        tokenPreview: `${item.token.slice(0, 8)}...${item.token.slice(-6)}`,
      };
    });

    if (!link) {
      res.json({ success: true, link: null, history });
      return;
    }

    const isExpired = link.expiresAt ? now > link.expiresAt : false;

    res.json({
      success: true,
      link: {
        ...link,
        url: `${baseUrl}/attend/${link.token}`,
        isExpired,
        remainingMs: link.expiresAt ? Math.max(0, link.expiresAt.getTime() - now.getTime()) : null,
      },
      history,
    });
  } catch (err) {
    console.error('Get link error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/link/create
router.post('/link/create', requirePermission('manage_links'), async (req: Request<Record<string, string>, unknown, CreateLinkBody>, res: Response): Promise<void> => {
  try {
    const rawDuration = req.body.durationMinutes;
    const durationMinutes =
      typeof rawDuration === 'number' && Number.isFinite(rawDuration) && rawDuration > 0
        ? Math.floor(rawDuration)
        : null;
    const lateAfter =
      typeof req.body.lateAfter === 'string' && /^\d{2}:\d{2}$/.test(req.body.lateAfter.trim())
        ? req.body.lateAfter.trim()
        : null;

    const today = getTodayDate();
    const panelUser = req.admin!;
    const scopeTeacherId = panelUser.dataScope === 'assigned_students' ? panelUser.id : null;

    await prisma.attendanceLink.updateMany({
      where: { date: today, isActive: true, teacherId: scopeTeacherId },
      data: { isActive: false },
    });

    const token = generateToken();
    const expiresAt = getExpiresAt(durationMinutes);

    const link = await prisma.attendanceLink.create({
      data: {
        token,
        date: today,
        isActive: true,
        durationMinutes,
        expiresAt,
        lateAfter,
        teacherId: scopeTeacherId,
        createdById: panelUser.id,
      },
    });

    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

    res.status(201).json({
      success: true,
      message: 'Attendance link created successfully.',
      link: {
        ...link,
        url: `${baseUrl}/attend/${link.token}`,
        remainingMs: expiresAt ? Math.max(0, expiresAt.getTime() - Date.now()) : null,
      },
    });
  } catch (err) {
    console.error('Create link error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/admin/link/deactivate
router.post('/link/deactivate', requirePermission('manage_links'), async (req: Request, res: Response): Promise<void> => {
  try {
    const today = getTodayDate();
    const panelUser = req.admin!;
    const scopeTeacherId = panelUser.dataScope === 'assigned_students' ? panelUser.id : null;

    await prisma.attendanceLink.updateMany({
      where: { date: today, isActive: true, teacherId: scopeTeacherId },
      data: { isActive: false },
    });
    res.json({ success: true, message: 'Link deactivated.' });
  } catch (err) {
    console.error('Deactivate link error:', err);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

export default router;
