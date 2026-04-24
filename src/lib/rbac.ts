// InjectProof — Role-based access control (client-side UX matrix)
// ================================================================
// Mirror of the server-side role gates in src/server/trpc.ts. Used to hide
// sidebar links and disable action buttons for roles that can't use them,
// so the UI stays consistent with what the server will accept.
//
// IMPORTANT: This is a UX-only helper. Every mutation MUST still be enforced
// by the appropriate *Procedure on the server (protectedProcedure /
// pentesterProcedure / etc.). Never trust this matrix for security decisions.
//
// Role hierarchy (lowest → highest): viewer < developer < pentester < security_lead < admin
//
// Who can see which route:
//  - admin, security_lead, pentester: all routes
//  - developer: dashboard, vulnerabilities (read), reports, settings
//  - viewer: dashboard, vulnerabilities (read), reports, settings
//
// Who can take which action on a target / scan / vuln:
//  - create target / edit target: pentester+
//  - start scan / stop scan: pentester+
//  - run deep exploit: pentester+
//  - sign scope approval: security_lead+
//  - user management: admin

export type Role = 'viewer' | 'developer' | 'pentester' | 'security_lead' | 'admin';

const ROLE_WEIGHT: Record<Role, number> = {
    viewer: 0,
    developer: 1,
    pentester: 2,
    security_lead: 3,
    admin: 4,
};

export function roleAtLeast(role: string | undefined | null, minimum: Role): boolean {
    if (!role) return false;
    const have = ROLE_WEIGHT[role as Role];
    if (have === undefined) return false;
    return have >= ROLE_WEIGHT[minimum];
}

/**
 * Which sidebar routes this role is allowed to see. A route returning `false`
 * gets filtered out of the sidebar. The route still exists at the URL level —
 * guarding is advisory UX, not a hard security boundary.
 */
export function canSeeRoute(role: string | undefined | null, route: string): boolean {
    if (!role) return false;
    // Admin / security_lead / pentester: see everything.
    if (roleAtLeast(role, 'pentester')) return true;
    // Developer / viewer: can browse read-heavy pages.
    const READ_ROUTES = ['/dashboard', '/vulnerabilities', '/reports', '/settings'];
    return READ_ROUTES.some(r => route === r || route.startsWith(r + '/'));
}

/** Action capability helpers — match these to the server-side procedure name. */
export const canCreateTarget       = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canEditTarget         = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canDeleteTarget       = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canStartScan          = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canStopScan           = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canDeleteScan         = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canRunDeepExploit     = (role: string | undefined | null) => roleAtLeast(role, 'pentester');
export const canSignScopeApproval  = (role: string | undefined | null) => roleAtLeast(role, 'security_lead');
export const canManageUsers        = (role: string | undefined | null) => roleAtLeast(role, 'admin');

/** Friendly human label for a role — matches casing in `UserMenu` / sidebar. */
export function formatRole(role: string | undefined | null): string {
    if (!role) return 'Unknown';
    return role.replace(/_/g, ' ');
}
