// InjectProof — tRPC authorization helpers
// Ownership + scope gates for the target/scan routers. These complement
// the existing role middleware in `server/trpc.ts` — use them AFTER
// pentesterProcedure so the caller is already authenticated.

import { TRPCError } from '@trpc/server';
import prisma from '@/lib/prisma';
import { hasRole } from '@/lib/auth';

export interface OwnershipContext {
    user: { id: string; role: string };
}

/**
 * Assert the caller may read/write this target. Security leads and admins
 * see every target; everyone else must own the row.
 */
export async function assertTargetOwnership(ctx: OwnershipContext, targetId: string): Promise<void> {
    if (hasRole(ctx.user.role, 'security_lead')) return;
    const target = await prisma.target.findUnique({
        where: { id: targetId },
        select: { createdById: true },
    });
    if (!target) throw new TRPCError({ code: 'NOT_FOUND', message: 'target not found' });
    if (target.createdById !== ctx.user.id) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: 'you may only act on targets you registered — escalate to security_lead for cross-user access',
        });
    }
}

/**
 * Assert the target has a valid, unrevoked ScopeApproval for the requested
 * safety mode. `observe` + `probe` require only basic approval; `exploit`
 * additionally needs `exploitAllowed` on the approval row.
 */
export async function assertScopeApproval(
    targetId: string,
    safetyMode: 'observe' | 'probe' | 'exploit',
): Promise<void> {
    if (safetyMode === 'observe') return; // no scope gate for read-only observation
    const target = await prisma.target.findUnique({
        where: { id: targetId },
        include: { scopeApproval: true },
    });
    if (!target) throw new TRPCError({ code: 'NOT_FOUND', message: 'target not found' });

    const approval = target.scopeApproval;
    if (!approval) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: 'no ScopeApproval attached to this target — a security_lead+ must approve the engagement scope before scanning',
        });
    }
    if (approval.revokedAt) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: `ScopeApproval was revoked on ${approval.revokedAt.toISOString()}: ${approval.revokedReason ?? 'no reason given'}`,
        });
    }
    if (approval.expiresAt && approval.expiresAt < new Date()) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: `ScopeApproval expired on ${approval.expiresAt.toISOString()} — re-request authorization`,
        });
    }
    if (safetyMode === 'exploit' && !approval.exploitAllowed) {
        throw new TRPCError({
            code: 'FORBIDDEN',
            message: 'ScopeApproval does not permit safetyMode="exploit" — only "observe"/"probe" allowed on this target',
        });
    }
}
