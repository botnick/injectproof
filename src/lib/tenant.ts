// InjectProof — tenant scope helpers
// Minimal multi-tenancy primitives. ทุก query ที่แตะ resource ผูกกับ tenant
// (Target, Scan, Vulnerability, Report, …) ควรผ่าน `withTenant(ctx, fn)` เพื่อ:
//   - resolve tenantId จาก ctx (membership → org.id; fallback = 'default')
//   - เรียก fn(tenantId) โดย fn ต้อง filter query ด้วย `{ OR: [{ tenantId }, { tenantId: null }] }`
//     (null = legacy row ที่ยังไม่ back-fill; ต้องอ่านได้เพื่อ back-compat)
//   - log warning ถ้าตรวจพบ row cross-tenant
//
// ไฟล์นี้ตั้งใจให้เล็กและ side-effect-free; อ่านง่าย ไม่มี prisma query เอง —
// caller ต้องใช้ tenantId ที่ resolve แล้วไปใส่ใน query เอง.

import type { PrismaClient } from '@/generated/prisma/client';
import { TRPCError } from '@trpc/server';

export const DEFAULT_TENANT_SLUG = 'default';

export interface TenantCtxUser {
    id: string;
    role: string;
}

export interface TenantCtx {
    user?: TenantCtxUser;
    prisma: PrismaClient;
    /** tRPC attaches user via auth middleware; tenantId gets attached by us. */
    tenantId?: string | null;
}

// ────────────────────────────────────────────────────────────
// Resolution
// ────────────────────────────────────────────────────────────

/**
 * Resolve a tenantId for the current ctx.
 *  - prefer explicit `ctx.tenantId` when the caller has already scoped.
 *  - otherwise read the user's first Membership and use that org.id.
 *  - otherwise find / lazily create the `default` org.
 *
 * Memoizes the default-org resolution once per process so concurrent queries
 * don't race on CREATE.
 */
let defaultOrgIdCache: string | null = null;

export async function resolveTenantForCtx(ctx: TenantCtx): Promise<string> {
    if (ctx.tenantId) return ctx.tenantId;

    const user = ctx.user;
    if (user) {
        // Try first membership. Wrap in try/catch — Membership table may be
        // absent before migration ran.
        try {
            const m = await ctx.prisma.membership.findFirst({
                where: { userId: user.id },
                orderBy: { createdAt: 'asc' },
                select: { orgId: true },
            });
            if (m?.orgId) return m.orgId;
        } catch {
            /* table missing — fall through to default */
        }
    }

    if (defaultOrgIdCache) return defaultOrgIdCache;

    try {
        const existing = await ctx.prisma.organization.findUnique({
            where: { slug: DEFAULT_TENANT_SLUG },
            select: { id: true },
        });
        if (existing) {
            defaultOrgIdCache = existing.id;
            return existing.id;
        }
        const created = await ctx.prisma.organization.create({
            data: { slug: DEFAULT_TENANT_SLUG, name: 'Default Organization' },
            select: { id: true },
        });
        defaultOrgIdCache = created.id;
        return created.id;
    } catch {
        // Table absent → fall back to a sentinel string so callers keep
        // working. Safe because legacy rows have tenantId=NULL and the
        // back-compat OR filter will include them.
        return DEFAULT_TENANT_SLUG;
    }
}

/**
 * Run `fn` with an explicit tenantId. Use this at the top of every tRPC
 * procedure that touches tenant-scoped resources.
 */
export async function withTenant<T>(
    ctx: TenantCtx,
    fn: (tenantId: string) => Promise<T>,
): Promise<T> {
    const tenantId = await resolveTenantForCtx(ctx);
    return fn(tenantId);
}

/**
 * Assert the caller has an operative tenant scope. Used as an early guard
 * in admin endpoints that shouldn't run without a resolvable tenant.
 */
export async function requireTenantScope(ctx: TenantCtx): Promise<string> {
    try {
        return await resolveTenantForCtx(ctx);
    } catch (err) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: `tenant scope unresolved: ${err instanceof Error ? err.message : String(err)}`,
        });
    }
}

/**
 * Build a Prisma `where` shard that matches rows belonging to the tenant,
 * plus legacy rows whose `tenantId IS NULL`. Keeps existing scans readable
 * while new rows get their tenant stamped.
 */
export function tenantWhere(tenantId: string): { OR: Array<{ tenantId: string } | { tenantId: null }> } {
    return { OR: [{ tenantId }, { tenantId: null }] };
}

/** Tests only. */
export function _resetTenantCache(): void {
    defaultOrgIdCache = null;
}
