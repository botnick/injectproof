// InjectProof — tRPC Server Initialization
// Sets up tRPC v11 with middleware for auth and error handling

import { initTRPC, TRPCError } from '@trpc/server';
import superjson from 'superjson';
import type { Context } from '@/server/context';

const t = initTRPC.context<Context>().create({
    transformer: superjson,
    errorFormatter({ shape, error }) {
        return {
            ...shape,
            data: {
                ...shape.data,
                zodError: error.cause instanceof Error ? error.cause.message : null,
            },
        };
    },
});

export const router = t.router;
export const publicProcedure = t.procedure;
export const createCallerFactory = t.createCallerFactory;

/**
 * Auth middleware — verifies JWT token and attaches user to context
 */
const enforceAuth = t.middleware(async ({ ctx, next }) => {
    if (!ctx.user) {
        throw new TRPCError({
            code: 'UNAUTHORIZED',
            message: 'You must be logged in to perform this action',
        });
    }

    return next({
        ctx: {
            ...ctx,
            user: ctx.user,
        },
    });
});

/**
 * Role-based middleware factory
 * Creates middleware that ensures user has minimum required role
 */
function enforceRole(minRole: string) {
    return t.middleware(async ({ ctx, next }) => {
        if (!ctx.user) {
            throw new TRPCError({ code: 'UNAUTHORIZED' });
        }

        const roleHierarchy: Record<string, number> = {
            viewer: 0,
            developer: 1,
            pentester: 2,
            security_lead: 3,
            admin: 4,
        };

        const userLevel = roleHierarchy[ctx.user.role] ?? -1;
        const requiredLevel = roleHierarchy[minRole] ?? 999;

        if (userLevel < requiredLevel) {
            throw new TRPCError({
                code: 'FORBIDDEN',
                message: `This action requires ${minRole} role or higher`,
            });
        }

        return next({ ctx });
    });
}

export const protectedProcedure = t.procedure.use(enforceAuth);
export const pentesterProcedure = t.procedure.use(enforceAuth).use(enforceRole('pentester'));
export const adminProcedure = t.procedure.use(enforceAuth).use(enforceRole('admin'));
