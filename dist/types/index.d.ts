export type DataScope = 'all' | 'department' | 'assigned_students' | 'own';
export type AttendanceStatus = 'present' | 'late' | 'late_approved';
export interface RoleConfig {
    id: string;
    name: string;
    label: string;
    description: string | null;
    isSystem: boolean;
    dataScope: DataScope;
    menus: string[];
    permissions: string[];
}
export interface JwtPanelPayload {
    id: string;
    email: string;
    role: string;
    name: string;
    department?: string | null;
    roleLabel?: string;
    dataScope?: DataScope;
    menus?: string[];
    permissions?: string[];
    iat?: number;
    exp?: number;
}
export type JwtAdminPayload = JwtPanelPayload;
export interface AttendanceLoginBody {
    email: string;
    password: string;
    token: string;
}
export interface CreateUserBody {
    name: string;
    email: string;
    password: string;
    role?: string;
    department?: string | null;
    teacherId?: string | null;
}
export interface ManualAttendanceBody {
    userId: string;
    date: string;
    status?: AttendanceStatus;
}
export interface UpdateAttendanceBody {
    status?: AttendanceStatus;
    ipAddress?: string;
    macAddress?: string;
    userAgent?: string;
    ipChanged?: boolean;
    macChanged?: boolean;
}
export interface CreateLinkBody {
    durationMinutes?: number | null;
    lateAfter?: string | null;
}
export interface UpsertRoleBody {
    name: string;
    label: string;
    description?: string | null;
    dataScope: DataScope;
    menus: string[];
    permissions: string[];
}
export interface UpsertDepartmentBody {
    name: string;
    code?: string | null;
    description?: string | null;
}
//# sourceMappingURL=index.d.ts.map