// VibeCode — Scan Router
// Scan management, launch, stop, and log retrieval

import { z } from 'zod';
import { router, protectedProcedure, pentesterProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';
import { runScan } from '@/scanner';
import type { ScanConfig } from '@/types';

export const scanRouter = router({
    /** List all scans with pagination */
    list: protectedProcedure
        .input(z.object({
            page: z.number().min(1).default(1),
            pageSize: z.number().min(1).max(100).default(20),
            targetId: z.string().optional(),
            status: z.string().optional(),
        }).optional())
        .query(async ({ ctx, input }) => {
            const { page = 1, pageSize = 20, targetId, status } = input || {};

            const where: Record<string, unknown> = {};
            if (targetId) where.targetId = targetId;
            if (status) where.status = status;

            const [items, total] = await Promise.all([
                ctx.prisma.scan.findMany({
                    where: where as any,
                    include: {
                        target: { select: { id: true, name: true, baseUrl: true } },
                        startedBy: { select: { id: true, name: true } },
                        _count: { select: { vulnerabilities: true } },
                    },
                    orderBy: { createdAt: 'desc' },
                    skip: (page - 1) * pageSize,
                    take: pageSize,
                }),
                ctx.prisma.scan.count({ where: where as any }),
            ]);

            return { items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
        }),

    /** Get scan by ID with details */
    getById: protectedProcedure
        .input(z.string())
        .query(async ({ ctx, input }) => {
            const scan = await ctx.prisma.scan.findUnique({
                where: { id: input },
                include: {
                    target: true,
                    startedBy: { select: { id: true, name: true, email: true } },
                    vulnerabilities: {
                        orderBy: [
                            { severity: 'asc' },
                            { createdAt: 'desc' },
                        ],
                    },
                    _count: { select: { vulnerabilities: true, scanLogs: true } },
                },
            });

            if (!scan) {
                throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
            }

            return scan;
        }),

    /** Create and start a new scan */
    create: pentesterProcedure
        .input(z.object({
            targetId: z.string(),
            scanType: z.enum(['quick', 'standard', 'deep', 'custom']).default('standard'),
            modules: z.array(z.string()).optional(),
            authType: z.string().optional(),
            authConfig: z.record(z.unknown()).optional(),
        }))
        .mutation(async ({ ctx, input }) => {
            // Get target
            const target = await ctx.prisma.target.findUnique({
                where: { id: input.targetId },
            });

            if (!target) {
                throw new TRPCError({ code: 'NOT_FOUND', message: 'Target not found' });
            }

            // Determine modules based on scan type
            let modules = input.modules || [];
            if (modules.length === 0) {
                switch (input.scanType) {
                    case 'quick':
                        modules = ['headers', 'cors', 'info_disclosure'];
                        break;
                    case 'standard':
                        modules = ['xss', 'sqli', 'headers', 'cors', 'ssrf', 'open_redirect'];
                        break;
                    case 'deep':
                        modules = ['xss', 'sqli', 'headers', 'cors', 'ssrf', 'path_traversal', 'open_redirect'];
                        break;
                    default:
                        modules = ['xss', 'sqli', 'headers', 'cors', 'ssrf', 'path_traversal', 'open_redirect'];
                }
            }

            // Create scan record
            const scan = await ctx.prisma.scan.create({
                data: {
                    targetId: input.targetId,
                    startedById: ctx.user!.userId,
                    scanType: input.scanType,
                    scanModules: JSON.stringify(modules),
                    authType: input.authType || target.authType,
                    authConfig: input.authConfig ? JSON.stringify(input.authConfig) : target.authConfig,
                    status: 'queued',
                },
            });

            // Audit log
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'start_scan',
                    resource: 'scan',
                    resourceId: scan.id,
                    details: JSON.stringify({
                        targetId: target.id,
                        targetName: target.name,
                        scanType: input.scanType,
                    }),
                },
            });

            // Start scan in background (non-blocking)
            const scanConfig: ScanConfig = {
                targetId: target.id,
                scanId: scan.id,
                baseUrl: target.baseUrl,
                maxCrawlDepth: target.maxCrawlDepth,
                maxUrls: target.maxUrls,
                requestTimeout: target.requestTimeout,
                rateLimit: target.rateLimit,
                modules,
                authType: input.authType || target.authType || undefined,
                authConfig: input.authConfig || (target.authConfig ? JSON.parse(target.authConfig) : undefined),
                customHeaders: target.headers ? JSON.parse(target.headers) : undefined,
                excludePaths: target.excludePaths ? JSON.parse(target.excludePaths) : undefined,
                includePaths: target.includePaths ? JSON.parse(target.includePaths) : undefined,
            };

            // Run scan asynchronously
            runScan(scanConfig).catch(err => {
                console.error(`[Scan ${scan.id}] Error:`, err);
            });

            return scan;
        }),

    /** Stop a running scan */
    stop: pentesterProcedure
        .input(z.string())
        .mutation(async ({ ctx, input }) => {
            const scan = await ctx.prisma.scan.findUnique({ where: { id: input } });
            if (!scan) throw new TRPCError({ code: 'NOT_FOUND' });

            if (scan.status !== 'running' && scan.status !== 'queued') {
                throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan is not running' });
            }

            await ctx.prisma.scan.update({
                where: { id: input },
                data: {
                    status: 'cancelled',
                    completedAt: new Date(),
                },
            });

            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'stop_scan',
                    resource: 'scan',
                    resourceId: input,
                },
            });

            return { success: true };
        }),

    /** Delete a scan and all related data */
    delete: pentesterProcedure
        .input(z.string())
        .mutation(async ({ ctx, input }) => {
            const scan = await ctx.prisma.scan.findUnique({ where: { id: input } });
            if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

            // Cannot delete a running scan
            if (scan.status === 'running') {
                throw new TRPCError({ code: 'BAD_REQUEST', message: 'Cannot delete a running scan. Stop it first.' });
            }

            // Delete related data first (cascade)
            await ctx.prisma.scanLog.deleteMany({ where: { scanId: input } });
            await ctx.prisma.vulnerability.deleteMany({ where: { scanId: input } });

            // Delete the scan itself
            await ctx.prisma.scan.delete({ where: { id: input } });

            // Audit log
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'delete_scan',
                    resource: 'scan',
                    resourceId: input,
                    details: JSON.stringify({
                        targetId: scan.targetId,
                        scanType: scan.scanType,
                    }),
                },
            });

            return { success: true };
        }),

    /** Get scan logs */
    getLogs: protectedProcedure
        .input(z.object({
            scanId: z.string(),
            level: z.string().optional(),
            module: z.string().optional(),
            limit: z.number().min(1).max(500).default(100),
        }))
        .query(async ({ ctx, input }) => {
            const where: Record<string, unknown> = { scanId: input.scanId };
            if (input.level) where.level = input.level;
            if (input.module) where.module = input.module;

            return ctx.prisma.scanLog.findMany({
                where: where as any,
                orderBy: { timestamp: 'desc' },
                take: input.limit,
            });
        }),
});
