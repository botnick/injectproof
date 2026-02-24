// VibeCode — Auth Router
// Login, register, profile management

import { z } from 'zod';
import { router, publicProcedure, protectedProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';
import { createToken, hashPassword, comparePassword } from '@/lib/auth';

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
                throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Invalid email or password' });
            }

            const valid = await comparePassword(input.password, user.passwordHash);
            if (!valid) {
                throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Invalid email or password' });
            }

            // Update last login
            await ctx.prisma.user.update({
                where: { id: user.id },
                data: { lastLoginAt: new Date() },
            });

            // Create audit log
            await ctx.prisma.auditLog.create({
                data: {
                    userId: user.id,
                    action: 'login',
                    resource: 'user',
                    resourceId: user.id,
                    details: JSON.stringify({ email: user.email }),
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
                },
            };
        }),

    /** Register a new user (admin only in production, open for initial setup) */
    register: publicProcedure
        .input(z.object({
            email: z.string().email(),
            password: z.string().min(8),
            name: z.string().min(1),
            role: z.enum(['admin', 'security_lead', 'pentester', 'developer', 'viewer']).default('viewer'),
        }))
        .mutation(async ({ ctx, input }) => {
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
                    role: input.role,
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
            };
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
