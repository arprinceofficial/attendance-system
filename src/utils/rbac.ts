import prisma from '../lib/prisma';
import { DataScope, RoleConfig } from '../types';

export interface MenuCatalogItem {
  key: string;
  label: string;
  description: string;
}

export interface PermissionCatalogItem {
  key: string;
  label: string;
  group: string;
}

export const ALL_MENUS: MenuCatalogItem[] = [
  { key: 'dashboard', label: 'Dashboard', description: 'Overview stats cards & recent attendance' },
  { key: 'today', label: "Today's Attendance", description: 'Live daily attendance list & manual marking' },
  { key: 'history', label: 'Attendance History', description: 'Date-based attendance lookup & CSV export' },
  { key: 'departments', label: 'Departments', description: 'Add, edit & delete academic/company departments' },
  { key: 'users', label: 'User Management', description: 'Manage users or assigned members' },
  { key: 'link', label: 'Link Manager', description: 'Create & manage attendance links with timer' },
  { key: 'roles', label: 'Roles & RBAC', description: 'Manage roles, permissions & left sidebar menus' },
  { key: 'my_profile', label: 'My Profile', description: 'Personal student/staff profile information' },
  { key: 'my_attendance', label: 'My Attendance', description: 'Personal attendance calendar & history' },
];

export const ALL_PERMISSIONS: PermissionCatalogItem[] = [
  { key: 'view_dashboard', label: 'View Dashboard', group: 'Attendance' },
  { key: 'view_attendance', label: 'View Attendance Records', group: 'Attendance' },
  { key: 'manage_attendance', label: 'Mark / Edit / Delete Attendance', group: 'Attendance' },
  { key: 'export_attendance', label: 'Export Attendance CSV', group: 'Attendance' },
  { key: 'filter_department', label: 'Filter by Department & Teacher', group: 'Attendance' },
  { key: 'manage_departments', label: 'Add / Edit / Delete Departments', group: 'Departments' },
  { key: 'view_users', label: 'View Users', group: 'Users' },
  { key: 'create_users', label: 'Create Users', group: 'Users' },
  { key: 'edit_users', label: 'Edit Users', group: 'Users' },
  { key: 'delete_users', label: 'Delete Users', group: 'Users' },
  { key: 'manage_links', label: 'Manage Attendance Links', group: 'Links' },
  { key: 'manage_roles', label: 'Manage Roles, Permissions & Menus', group: 'RBAC' },
  { key: 'view_own_profile', label: 'View Own Profile', group: 'Personal' },
  { key: 'view_own_attendance', label: 'View Own Attendance', group: 'Personal' },
];

export const DEFAULT_ROLES: Array<{
  name: string;
  label: string;
  description: string;
  isSystem: boolean;
  dataScope: DataScope;
  menus: string[];
  permissions: string[];
}> = [
  {
    name: 'admin',
    label: 'Administrator',
    description: 'Full access to everything across all departments, users, links, and RBAC settings.',
    isSystem: true,
    dataScope: 'all',
    menus: ['dashboard', 'today', 'history', 'departments', 'users', 'link', 'roles', 'my_profile'],
    permissions: ALL_PERMISSIONS.map((p) => p.key),
  },
  {
    name: 'teacher',
    label: 'Teacher',
    description: 'Department-wise faculty managing only their assigned students and attendance links.',
    isSystem: true,
    dataScope: 'assigned_students',
    menus: ['dashboard', 'today', 'history', 'users', 'link', 'my_profile'],
    permissions: [
      'view_dashboard',
      'view_attendance',
      'manage_attendance',
      'export_attendance',
      'view_users',
      'create_users',
      'edit_users',
      'delete_users',
      'manage_links',
      'view_own_profile',
    ],
  },
  {
    name: 'hr',
    label: 'HR Manager',
    description: 'Configurable HR role — customize permissions and sidebar menus from the Admin Panel.',
    isSystem: false,
    dataScope: 'all',
    menus: ['dashboard', 'today', 'history', 'departments', 'users', 'my_profile', 'my_attendance'],
    permissions: [
      'view_dashboard',
      'view_attendance',
      'export_attendance',
      'filter_department',
      'view_users',
      'create_users',
      'edit_users',
      'view_own_profile',
      'view_own_attendance',
    ],
  },
  {
    name: 'student',
    label: 'Student',
    description: 'Student portal access to view personal info and own attendance calendar.',
    isSystem: true,
    dataScope: 'own',
    menus: ['my_attendance', 'my_profile'],
    permissions: ['view_own_profile', 'view_own_attendance'],
  },
];

let rolesSeeded = false;

export async function ensureDefaultRoles(): Promise<void> {
  if (rolesSeeded) return;
  for (const role of DEFAULT_ROLES) {
    const existing = await prisma.role.findUnique({ where: { name: role.name } });
    if (!existing) {
      await prisma.role.create({ data: role });
    } else if (role.name === 'admin') {
      // Ensure newly introduced system capabilities (like departments) are available to existing admin
      const missingMenus = role.menus.filter((m) => m !== 'my_profile' && !existing.menus.includes(m));
      const missingPerms = role.permissions.filter((p) => !existing.permissions.includes(p));
      if (missingMenus.length > 0 || missingPerms.length > 0) {
        const updatedMenus = [...existing.menus];
        for (const m of missingMenus) {
          const usersIdx = updatedMenus.indexOf('users');
          if (m === 'departments' && usersIdx >= 0) {
            updatedMenus.splice(usersIdx, 0, m);
          } else {
            updatedMenus.push(m);
          }
        }
        await prisma.role.update({
          where: { id: existing.id },
          data: {
            menus: updatedMenus,
            permissions: [...existing.permissions, ...missingPerms],
          },
        });
      }
    }
  }
  rolesSeeded = true;
}

export function resetRolesCache(): void {
  rolesSeeded = false;
}

export async function getRoleConfig(roleName: string): Promise<RoleConfig> {
  await ensureDefaultRoles();

  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (role) {
    return {
      id: role.id,
      name: role.name,
      label: role.label,
      description: role.description,
      isSystem: role.isSystem,
      dataScope: (role.dataScope as DataScope) || 'own',
      menus: role.menus,
      permissions: role.permissions,
    };
  }

  const fallback = DEFAULT_ROLES.find((r) => r.name === roleName) || DEFAULT_ROLES[3];
  return {
    id: '',
    name: fallback.name,
    label: fallback.label,
    description: fallback.description,
    isSystem: fallback.isSystem,
    dataScope: fallback.dataScope,
    menus: fallback.menus,
    permissions: fallback.permissions,
  };
}
