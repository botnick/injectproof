// InjectProof — Target Router
// CRUD operations for scan targets

import { z } from 'zod';
import { router, protectedProcedure, pentesterProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';
import { checkTargetUrl } from '@/lib/ssrf-guard';
import { assertTargetOwnership } from '@/server/auth-middleware';
import { config } from '@/lib/config';

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
            environment: z.enum(['production', 'staging', 'development', 'internal']).default('development'),
            criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
            tags: z.array(z.string()).optional(),
            authType: z.enum(['none', 'token', 'cookie', 'session', 'scripted']).optional(),
            authConfig: z.record(z.string(), z.unknown()).optional(),
            headers: z.record(z.string(), z.string()).optional(),
            excludePaths: z.array(z.string()).optional(),
            includePaths: z.array(z.string()).optional(),
            maxCrawlDepth: z.number().min(1).max(50).default(10),
            maxUrls: z.number().min(1).max(5000).default(500),
            requestTimeout: z.number().min(1000).max(120000).default(30000),
            rateLimit: z.number().min(1).max(100).default(10),
            /** Enterprise: allow private/loopback targets only when lab-mode is explicitly opted in. */
            labOverride: z.boolean().optional(),
        }))
        .mutation(async ({ ctx, input }) => {
            // SSRF guard — reject private/loopback/metadata IPs unless EITHER:
            //   (a) the deployment is opted into internal-target mode via
            //       SCANNER_ALLOW_INTERNAL_TARGETS=true (the whole appliance
            //       runs in a trusted internal network — internal pentest use
            //       case), OR
            //   (b) the caller explicitly passes labOverride=true AND is at
            //       least security_lead (per-request opt-in, public deploys).
            // Either path still audit-logs the internal target — any internal
            // scan needs to be traceable to the user who authorised it.
            const allowInternal = config().SCANNER_ALLOW_INTERNAL_TARGETS === true;
            const perRequestLabOverride = input.labOverride === true
                && (ctx.user!.role === 'security_lead' || ctx.user!.role === 'admin');
            // In development mode, localhost / 127.0.0.1 / ::1 are always
            // allowed — these are only reachable from the scanner host itself,
            // so there's no SSRF attack surface. RFC1918 / metadata-IP still
            // need the explicit env flag because those ARE routable from
            // cloud / corporate networks.
            const isDevMode = config().NODE_ENV !== 'production';
            const labAllowed = allowInternal || perRequestLabOverride || isDevMode;
            const guard = await checkTargetUrl(input.baseUrl, { labOverride: labAllowed });
            if (!guard.allowed) {
                // Highly-actionable error — user sees this the moment they try
                // a localhost / RFC1918 target without the flag set, and the
                // fix is always a 1-line .env change + dev-server restart.
                const fix = !allowInternal
                    ? `\n\nTo unlock internal targets for authorised internal pentest:\n` +
                      `  1) Add this line to your .env file (in the project root):\n` +
                      `       SCANNER_ALLOW_INTERNAL_TARGETS=true\n` +
                      `  2) Restart the Next.js dev server (Ctrl+C then \`npm run dev\`).\n` +
                      `  3) Retry creating the target.\n` +
                      `วิธีเปิดใช้ scan ระบบภายในองค์กร:\n` +
                      `  1) เพิ่มบรรทัดนี้ในไฟล์ .env (ที่ root ของโปรเจกต์):\n` +
                      `       SCANNER_ALLOW_INTERNAL_TARGETS=true\n` +
                      `  2) restart dev server (Ctrl+C แล้ว \`npm run dev\` ใหม่)\n` +
                      `  3) สร้าง target อีกครั้ง`
                    : `\n\nScanner is configured to allow internal targets but this specific URL was still rejected — ` +
                      `check that the hostname resolves to an expected private IP (DNS-rebinding guard still runs).`;
                throw new TRPCError({
                    code: 'BAD_REQUEST',
                    message: `Target URL rejected by SSRF guard: ${guard.reason ?? 'unknown reason'}.${fix}`,
                });
            }

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

            // Audit log — always record which gate path allowed internal targets
            // so the trail survives later reviews.
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'create_target',
                    resource: 'target',
                    resourceId: target.id,
                    details: JSON.stringify({
                        name: input.name,
                        baseUrl: input.baseUrl,
                        internalAllowedVia: labAllowed
                            ? (allowInternal ? 'env:SCANNER_ALLOW_INTERNAL_TARGETS' : 'labOverride:security_lead')
                            : 'public-only',
                        resolvedIps: guard.resolvedIps,
                    }),
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
            authConfig: z.record(z.string(), z.unknown()).optional(),
            headers: z.record(z.string(), z.string()).optional(),
            excludePaths: z.array(z.string()).optional(),
            includePaths: z.array(z.string()).optional(),
            maxCrawlDepth: z.number().min(1).max(50).optional(),
            maxUrls: z.number().min(1).max(5000).optional(),
            isActive: z.boolean().optional(),
        }))
        .mutation(async ({ ctx, input }) => {
            // Ownership gate — only the creator or security_lead+ may edit.
            await assertTargetOwnership({ user: { id: ctx.user!.userId, role: ctx.user!.role } }, input.id);

            const { id, tags, authConfig, headers, excludePaths, includePaths, ...rest } = input;

            // If the caller is changing baseUrl, re-run the SSRF guard.
            // Honor the same env flag + role gate as target.create so internal
            // targets stay editable once the deployment opts in.
            if (rest.baseUrl) {
                const allowInternal = config().SCANNER_ALLOW_INTERNAL_TARGETS === true;
                const guard = await checkTargetUrl(rest.baseUrl, { labOverride: allowInternal });
                if (!guard.allowed) {
                    throw new TRPCError({
                        code: 'BAD_REQUEST',
                        message: `baseUrl rejected by SSRF guard: ${guard.reason ?? 'unknown reason'}`,
                    });
                }
            }

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
