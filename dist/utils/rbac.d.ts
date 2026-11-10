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
export declare const ALL_MENUS: MenuCatalogItem[];
export declare const ALL_PERMISSIONS: PermissionCatalogItem[];
export declare const DEFAULT_ROLES: Array<{
    name: string;
    label: string;
    description: string;
    isSystem: boolean;
    dataScope: DataScope;
    menus: string[];
    permissions: string[];
}>;
export declare function ensureDefaultRoles(): Promise<void>;
export declare function resetRolesCache(): void;
export declare function getRoleConfig(roleName: string): Promise<RoleConfig>;
//# sourceMappingURL=rbac.d.ts.map