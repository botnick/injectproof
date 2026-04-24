// InjectProof — Auth Router
// Login, register, profile management

import { z } from 'zod';
import { router, publicProcedure, protectedProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';
import { createToken, hashPassword, comparePassword } from '@/lib/auth';
import { checkLockout, recordFailure, recordSuccess } from '@/lib/rate-limit-login';

export const authRouter = router({
    /** Login with email and password */
    login: publicProcedure
        .input(z.object({
            email: z.string().email(),
            password: z.string().min(1),
        }))
        .mutation(async ({ ctx, input }) => {
            const user = await ctx.prisma.user.findUnique({
                where: { email: input.email },
            });

            if (!user || !user.isActive) {
                // Generic message — don't leak user-existence to the caller.
                throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Invalid email or password' });
            }

            // Throttle: reject if this account is within a lockout window.
            const lockout = await checkLockout(user.id);
            if (!lockout.allowed) {
                await ctx.prisma.auditLog.create({
                    data: {
                        userId: user.id,
                        action: 'login',
                        resource: 'user',
                        resourceId: user.id,
                        details: JSON.stringify({
                            email: user.email,
                            outcome: 'blocked',
                            reason: lockout.reason,
                            lockoutMs: lockout.lockoutMs,
                        }),
                    },
                });
                throw new TRPCError({
                    code: 'TOO_MANY_REQUESTS',
                    message: `Too many failed attempts. Try again in ${Math.ceil((lockout.lockoutMs ?? 60_000) / 1000)} seconds.`,
                });
            }

            const valid = await comparePassword(input.password, user.passwordHash);
            if (!valid) {
                await recordFailure(user.id);
                await ctx.prisma.auditLog.create({
                    data: {
                        userId: user.id,
                        action: 'login',
                        resource: 'user',
                        resourceId: user.id,
                        details: JSON.stringify({ email: user.email, outcome: 'failed_password' }),
                    },
                });
                throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Invalid email or password' });
            }

            // Success path: reset the failure counter + stamp last-login.
            await recordSuccess(user.id);

            // Create audit log
            await ctx.prisma.auditLog.create({
                data: {
                    userId: user.id,
                    action: 'login',
                    resource: 'user',
                    resourceId: user.id,
                    details: JSON.stringify({ email: user.email, outcome: 'success' }),
                },
            });

            const token = await createToken({
                userId: user.id,
                email: user.email,
                role: user.role,
                name: user.name,
            });

            return {
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    avatar: user.avatar,
                    mustChangePassword: user.mustChangePassword,
                },
            };
        }),

    /** Rotate password — required on first login for seeded/invited accounts. */
    changePassword: protectedProcedure
        .input(z.object({
            currentPassword: z.string().min(1),
            newPassword: z.string().min(12),
        }))
        .mutation(async ({ ctx, input }) => {
            const user = await ctx.prisma.user.findUnique({ where: { id: ctx.user!.userId } });
            if (!user) throw new TRPCError({ code: 'NOT_FOUND', message: 'User not found' });
            const valid = await comparePassword(input.currentPassword, user.passwordHash);
            if (!valid) {
                await recordFailure(user.id);
                throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Current password is incorrect' });
            }
            const newHash = await hashPassword(input.newPassword);
            await ctx.prisma.user.update({
                where: { id: user.id },
                data: {
                    passwordHash: newHash,
                    mustChangePassword: false,
                    passwordChangedAt: new Date(),
                    loginFailureState: null,
                },
            });
            await ctx.prisma.auditLog.create({
                data: {
                    userId: user.id,
                    action: 'login',
                    resource: 'user',
                    resourceId: user.id,
                    details: JSON.stringify({ event: 'password_changed' }),
                },
            });
            return { ok: true };
        }),

    /**
     * Register a new user. Two paths:
     *  - First-run bootstrap (zero users exist) — the caller can self-register
     *    as admin. Enables /signup before any seed/admin exists.
     *  - Normal operation (≥1 user exists) — only an authenticated admin may
     *    create additional accounts. Public self-serve signup is disabled
     *    after bootstrap to prevent privilege escalation via an open form.
     *
     * Non-admin registrants (developer/viewer/pentester paths) always get
     * `viewer` role regardless of the input — role selection is a trust decision
     * that must be made by an admin, not the signup form.
     */
    register: publicProcedure
        .input(z.object({
            email: z.string().email(),
            password: z.string().min(8),
            name: z.string().min(1),
            role: z.enum(['admin', 'security_lead', 'pentester', 'developer', 'viewer']).default('viewer'),
        }))
        .mutation(async ({ ctx, input }) => {
            const userCount = await ctx.prisma.user.count();
            const isFirstRun = userCount === 0;
            const callerRole = ctx.user?.role;
            const callerIsAdmin = callerRole === 'admin';

            // Gate: after bootstrap, only admins can register new users.
            if (!isFirstRun && !callerIsAdmin) {
                throw new TRPCError({
                    code: 'FORBIDDEN',
                    message: 'User registration is closed. Ask an admin to create an account for you.',
                });
            }

            // Role assignment: bootstrap user gets admin; otherwise the role
            // from input is trusted only because we already gated on admin.
            const effectiveRole = isFirstRun ? 'admin' : input.role;

            const existing = await ctx.prisma.user.findUnique({
                where: { email: input.email },
            });

            if (existing) {
                throw new TRPCError({ code: 'CONFLICT', message: 'Email already registered' });
            }

            const passwordHash = await hashPassword(input.password);

            const user = await ctx.prisma.user.create({
                data: {
                    email: input.email,
                    passwordHash,
                    name: input.name,
                    role: effectiveRole,
                },
            });

            // Audit trail — track who created whom, especially important in
            // the post-bootstrap path where admins invite others.
            await ctx.prisma.auditLog.create({
                data: {
                    userId: callerIsAdmin ? ctx.user!.userId : user.id,
                    action: 'user_registered',
                    resource: 'user',
                    resourceId: user.id,
                    details: JSON.stringify({
                        via: isFirstRun ? 'bootstrap' : 'admin-invite',
                        role: effectiveRole,
                        email: input.email,
                    }),
                },
            });

            const token = await createToken({
                userId: user.id,
                email: user.email,
                role: user.role,
                name: user.name,
            });

            return {
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                },
                isFirstRun,
            };
        }),

    /**
     * Returns true when the database has zero users — used by the login page
     * to conditionally show a "Sign up" link (bootstrap flow). Once an admin
     * exists, signup is admin-gated, so the login page doesn't advertise it.
     */
    isFirstRun: publicProcedure.query(async ({ ctx }) => {
        const count = await ctx.prisma.user.count();
        return count === 0;
    }),

    /** Get current user info */
    me: protectedProcedure.query(async ({ ctx }) => {
        const user = await ctx.prisma.user.findUnique({
            where: { id: ctx.user!.userId },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                avatar: true,
                mfaEnabled: true,
                lastLoginAt: true,
                createdAt: true,
            },
        });

        if (!user) {
            throw new TRPCError({ code: 'NOT_FOUND', message: 'User not found' });
        }

        return user;
    }),
});
