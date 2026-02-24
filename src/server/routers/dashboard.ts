// VibeCode — Dashboard Router
// Statistics, trend data, severity distribution, and recent scans

import { z } from 'zod';
import { router, protectedProcedure } from '@/server/trpc';

export const dashboardRouter = router({
    /** Get global dashboard statistics */
    stats: protectedProcedure.query(async ({ ctx }) => {
        const [
            totalTargets,
            totalScans,
            totalVulnerabilities,
            activeScans,
            vulnsBySeverity,
            vulnsByStatus,
            avgDuration,
            lastScan,
        ] = await Promise.all([
            ctx.prisma.target.count(),
            ctx.prisma.scan.count(),
            ctx.prisma.vulnerability.count(),
            ctx.prisma.scan.count({ where: { status: 'running' } }),
            ctx.prisma.vulnerability.groupBy({
                by: ['severity'],
                _count: { id: true },
            }),
            ctx.prisma.vulnerability.groupBy({
                by: ['status'],
                _count: { id: true },
            }),
            ctx.prisma.scan.aggregate({
                _avg: { duration: true },
                where: { status: 'completed' },
            }),
            ctx.prisma.scan.findFirst({
                orderBy: { createdAt: 'desc' },
                select: { createdAt: true },
            }),
        ]);

        const severityMap: Record<string, number> = {};
        for (const s of vulnsBySeverity) severityMap[s.severity] = s._count.id;

        const statusMap: Record<string, number> = {};
        for (const s of vulnsByStatus) statusMap[s.status] = s._count.id;

        return {
            totalTargets,
            totalScans,
            totalVulnerabilities,
            activeScans,
            criticalVulns: severityMap.critical || 0,
            highVulns: severityMap.high || 0,
            mediumVulns: severityMap.medium || 0,
            lowVulns: severityMap.low || 0,
            infoVulns: severityMap.info || 0,
            openVulns: statusMap.open || 0,
            fixedVulns: statusMap.fixed || 0,
            avgScanDuration: avgDuration._avg.duration || 0,
            lastScanDate: lastScan?.createdAt?.toISOString(),
        };
    }),

    /** Get severity distribution for chart */
    severityDistribution: protectedProcedure.query(async ({ ctx }) => {
        const data = await ctx.prisma.vulnerability.groupBy({
            by: ['severity'],
            _count: { id: true },
        });

        const colors: Record<string, string> = {
            critical: '#dc2626',
            high: '#ea580c',
            medium: '#d97706',
            low: '#2563eb',
            info: '#6b7280',
        };

        return data.map(d => ({
            severity: d.severity,
            count: d._count.id,
            color: colors[d.severity] || '#6b7280',
        }));
    }),

    /** Get trend data (last 30 days) */
    trendData: protectedProcedure.query(async ({ ctx }) => {
        // Get all vulnerabilities from last 30 days
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const vulns = await ctx.prisma.vulnerability.findMany({
            where: { createdAt: { gte: thirtyDaysAgo } },
            select: { severity: true, createdAt: true },
            orderBy: { createdAt: 'asc' },
        });

        // Group by date
        const dateMap: Record<string, Record<string, number>> = {};
        for (let i = 0; i < 30; i++) {
            const date = new Date();
            date.setDate(date.getDate() - (29 - i));
            const key = date.toISOString().split('T')[0];
            dateMap[key] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        }

        for (const vuln of vulns) {
            const key = vuln.createdAt.toISOString().split('T')[0];
            if (dateMap[key]) {
                dateMap[key][vuln.severity] = (dateMap[key][vuln.severity] || 0) + 1;
            }
        }

        return Object.entries(dateMap).map(([date, counts]) => ({
            date,
            ...counts,
            total: Object.values(counts).reduce((a, b) => a + b, 0),
        }));
    }),

    /** Get recent scans */
    recentScans: protectedProcedure
        .input(z.number().min(1).max(20).default(5).optional())
        .query(async ({ ctx, input }) => {
            return ctx.prisma.scan.findMany({
                take: input || 5,
                orderBy: { createdAt: 'desc' },
                include: {
                    target: { select: { id: true, name: true, baseUrl: true } },
                    startedBy: { select: { name: true } },
                    _count: { select: { vulnerabilities: true } },
                },
            });
        }),

    /** Get vulnerability heatmap data */
    heatmapData: protectedProcedure.query(async ({ ctx }) => {
        const vulns = await ctx.prisma.vulnerability.findMany({
            select: {
                category: true,
                severity: true,
                target: { select: { name: true } },
            },
        });

        const heatmap: Record<string, Record<string, { count: number; maxSeverity: string }>> = {};
        const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

        for (const v of vulns) {
            const targetName = v.target.name;
            if (!heatmap[targetName]) heatmap[targetName] = {};
            if (!heatmap[targetName][v.category]) {
                heatmap[targetName][v.category] = { count: 0, maxSeverity: 'info' };
            }

            heatmap[targetName][v.category].count++;
            const current = severityOrder[heatmap[targetName][v.category].maxSeverity] || 0;
            const incoming = severityOrder[v.severity] || 0;
            if (incoming > current) {
                heatmap[targetName][v.category].maxSeverity = v.severity;
            }
        }

        const result: Array<{ targetName: string; category: string; count: number; maxSeverity: string }> = [];
        for (const [targetName, categories] of Object.entries(heatmap)) {
            for (const [category, data] of Object.entries(categories)) {
                result.push({ targetName, category, ...data });
            }
        }

        return result;
    }),
});
