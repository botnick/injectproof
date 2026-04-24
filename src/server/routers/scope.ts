// InjectProof — ScopeApproval router
// Create, list, revoke written-authorization records that gate every
// scan with safetyMode='exploit' or any production-environment target.

import { z } from 'zod';
import { router, protectedProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';
import { hasRole } from '@/lib/auth';

export const scopeRouter = router({
    /** List approvals for a target. Anyone who can see the target can read. */
    listForTarget: protectedProcedure
        .input(z.object({ targetId: z.string() }))
        .query(async ({ ctx, input }) => {
            const target = await ctx.prisma.target.findUnique({
                where: { id: input.targetId },
                select: { id: true, createdById: true, scopeApprovalId: true },
            });
            if (!target) throw new TRPCError({ code: 'NOT_FOUND' });
            if (target.createdById !== ctx.user!.userId && !hasRole(ctx.user!.role, 'security_lead')) {
                throw new TRPCError({ code: 'FORBIDDEN' });
            }
            const approvals = await ctx.prisma.scopeApproval.findMany({
                where: { targets: { some: { id: input.targetId } } },
                orderBy: { createdAt: 'desc' },
            });
            return { current: target.scopeApprovalId, history: approvals };
        }),

    /**
     * Create an approval for a target. Only security_lead+ may sign scope —
     * pentesters request via email/ticket and someone with authority creates
     * the row.
     */
    create: protectedProcedure
        .input(
            z.object({
                targetId: z.string(),
                allowedPaths: z.array(z.string()).min(1),
                allowedMethods: z.array(z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'])).default(['GET', 'POST']),
                exploitAllowed: z.boolean().default(false),
                osCommandAllowed: z.boolean().default(false),
                fileReadAllowed: z.boolean().default(false),
                dataExfilAllowed: z.boolean().default(false),
                validFrom: z.date().optional(),
                expiresAt: z.date().optional(),
                rationale: z.string().optional(),
                signedDocument: z.string().optional(),
            }),
        )
        .mutation(async ({ ctx, input }) => {
            if (!hasRole(ctx.user!.role, 'security_lead')) {
                throw new TRPCError({
                    code: 'FORBIDDEN',
                    message: 'only security_lead or admin may sign scope approvals',
                });
            }

            const approval = await ctx.prisma.scopeApproval.create({
                data: {
                    approvedById: ctx.user!.userId,
                    targetId: input.targetId,
                    allowedPaths: JSON.stringify(input.allowedPaths),
                    allowedMethods: JSON.stringify(input.allowedMethods),
                    exploitAllowed: input.exploitAllowed,
                    osCommandAllowed: input.osCommandAllowed,
                    fileReadAllowed: input.fileReadAllowed,
                    dataExfilAllowed: input.dataExfilAllowed,
                    validFrom: input.validFrom,
                    expiresAt: input.expiresAt,
                    rationale: input.rationale,
                    signedDocument: input.signedDocument,
                },
            });

            await ctx.prisma.target.update({
                where: { id: input.targetId },
                data: { scopeApprovalId: approval.id },
            });

            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'update_settings',
                    resource: 'target',
                    resourceId: input.targetId,
                    details: JSON.stringify({
                        event: 'scope_approval_created',
                        approvalId: approval.id,
                        exploitAllowed: input.exploitAllowed,
                    }),
                },
            });

            return approval;
        }),

    revoke: protectedProcedure
        .input(z.object({ approvalId: z.string(), reason: z.string().min(1) }))
        .mutation(async ({ ctx, input }) => {
            if (!hasRole(ctx.user!.role, 'security_lead')) {
                throw new TRPCError({ code: 'FORBIDDEN' });
            }
            const approval = await ctx.prisma.scopeApproval.update({
                where: { id: input.approvalId },
                data: { revokedAt: new Date(), revokedReason: input.reason },
            });
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'update_settings',
                    resource: 'target',
                    resourceId: approval.targetId,
                    details: JSON.stringify({
                        event: 'scope_approval_revoked',
                        approvalId: approval.id,
                        reason: input.reason,
                    }),
                },
            });
            return { ok: true };
        }),
});
