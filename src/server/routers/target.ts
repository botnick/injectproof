// InjectProof — Target Router
// CRUD operations for scan targets

import { z } from 'zod';
import { router, protectedProcedure, pentesterProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';

export const targetRouter = router({
    /** List all targets with pagination and filtering */
    list: protectedProcedure
        .input(z.object({
            page: z.number().min(1).default(1),
            pageSize: z.number().min(1).max(100).default(20),
            search: z.string().optional(),
            environment: z.string().optional(),
            criticality: z.string().optional(),
        }).optional())
        .query(async ({ ctx, input }) => {
            const { page = 1, pageSize = 20, search, environment, criticality } = input || {};

            const where: Record<string, unknown> = {};
            if (search) {
                where.OR = [
                    { name: { contains: search } },
                    { baseUrl: { contains: search } },
                ];
            }
            if (environment) where.environment = environment;
            if (criticality) where.criticality = criticality;

            const [items, total] = await Promise.all([
                ctx.prisma.target.findMany({
                    where: where as any,
                    include: {
                        createdBy: { select: { id: true, name: true, email: true } },
                        _count: { select: { scans: true, vulnerabilities: true } },
                    },
                    orderBy: { createdAt: 'desc' },
                    skip: (page - 1) * pageSize,
                    take: pageSize,
                }),
                ctx.prisma.target.count({ where: where as any }),
            ]);

            return {
                items,
                total,
                page,
                pageSize,
                totalPages: Math.ceil(total / pageSize),
            };
        }),

    /** Get target by ID with full details */
    getById: protectedProcedure
        .input(z.string())
        .query(async ({ ctx, input }) => {
            const target = await ctx.prisma.target.findUnique({
                where: { id: input },
                include: {
                    createdBy: { select: { id: true, name: true, email: true } },
                    scans: {
                        orderBy: { createdAt: 'desc' },
                        take: 10,
                        include: {
                            startedBy: { select: { name: true } },
                        },
                    },
                    _count: { select: { scans: true, vulnerabilities: true } },
                },
            });

            if (!target) {
                throw new TRPCError({ code: 'NOT_FOUND', message: 'Target not found' });
            }

            return target;
        }),

    /** Create a new target */
    create: pentesterProcedure
        .input(z.object({
            name: z.string().min(1).max(100),
            baseUrl: z.string().url(),
            description: z.string().optional(),
            environment: z.enum(['production', 'staging', 'development', 'internal']).default('production'),
            criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
            tags: z.array(z.string()).optional(),
            authType: z.enum(['none', 'token', 'cookie', 'session', 'scripted']).optional(),
            authConfig: z.record(z.unknown()).optional(),
            headers: z.record(z.string()).optional(),
            excludePaths: z.array(z.string()).optional(),
            includePaths: z.array(z.string()).optional(),
            maxCrawlDepth: z.number().min(1).max(50).default(10),
            maxUrls: z.number().min(1).max(5000).default(500),
            requestTimeout: z.number().min(1000).max(120000).default(30000),
            rateLimit: z.number().min(1).max(100).default(10),
        }))
        .mutation(async ({ ctx, input }) => {
            const target = await ctx.prisma.target.create({
                data: {
                    name: input.name,
                    baseUrl: input.baseUrl,
                    description: input.description,
                    environment: input.environment,
                    criticality: input.criticality,
                    tags: input.tags ? JSON.stringify(input.tags) : null,
                    authType: input.authType,
                    authConfig: input.authConfig ? JSON.stringify(input.authConfig) : null,
                    headers: input.headers ? JSON.stringify(input.headers) : null,
                    excludePaths: input.excludePaths ? JSON.stringify(input.excludePaths) : null,
                    includePaths: input.includePaths ? JSON.stringify(input.includePaths) : null,
                    maxCrawlDepth: input.maxCrawlDepth,
                    maxUrls: input.maxUrls,
                    requestTimeout: input.requestTimeout,
                    rateLimit: input.rateLimit,
                    createdById: ctx.user!.userId,
                },
            });

            // Audit log
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'create_target',
                    resource: 'target',
                    resourceId: target.id,
                    details: JSON.stringify({ name: input.name, baseUrl: input.baseUrl }),
                },
            });

            return target;
        }),

    /** Update a target */
    update: pentesterProcedure
        .input(z.object({
            id: z.string(),
            name: z.string().min(1).max(100).optional(),
            baseUrl: z.string().url().optional(),
            description: z.string().optional(),
            environment: z.enum(['production', 'staging', 'development', 'internal']).optional(),
            criticality: z.enum(['critical', 'high', 'medium', 'low']).optional(),
            tags: z.array(z.string()).optional(),
            authType: z.enum(['none', 'token', 'cookie', 'session', 'scripted']).optional(),
            authConfig: z.record(z.unknown()).optional(),
            headers: z.record(z.string()).optional(),
            excludePaths: z.array(z.string()).optional(),
            includePaths: z.array(z.string()).optional(),
            maxCrawlDepth: z.number().min(1).max(50).optional(),
            maxUrls: z.number().min(1).max(5000).optional(),
            isActive: z.boolean().optional(),
        }))
        .mutation(async ({ ctx, input }) => {
            const { id, tags, authConfig, headers, excludePaths, includePaths, ...rest } = input;

            const target = await ctx.prisma.target.update({
                where: { id },
                data: {
                    ...rest,
                    tags: tags ? JSON.stringify(tags) : undefined,
                    authConfig: authConfig ? JSON.stringify(authConfig) : undefined,
                    headers: headers ? JSON.stringify(headers) : undefined,
                    excludePaths: excludePaths ? JSON.stringify(excludePaths) : undefined,
                    includePaths: includePaths ? JSON.stringify(includePaths) : undefined,
                },
            });

            return target;
        }),

    /** Delete a target */
    delete: pentesterProcedure
        .input(z.string())
        .mutation(async ({ ctx, input }) => {
            await ctx.prisma.target.delete({ where: { id: input } });

            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'delete_target',
                    resource: 'target',
                    resourceId: input,
                },
            });

            return { success: true };
        }),
});
