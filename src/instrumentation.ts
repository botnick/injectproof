// InjectProof — Next.js server instrumentation
// Runs once on server startup (edge + node runtimes). Wires long-running
// singletons that must survive the lifetime of the process: scheduled-scan
// driver, orphan-scan recovery, etc.
//
// Next.js loads this file automatically when it is present at src/instrumentation.ts
// (or instrumentation.ts at the project root for older layouts). The exported
// `register` function is called exactly once per process start.

export async function register(): Promise<void> {
    // Only run server-side singletons in the Node.js runtime (not Edge).
    if (process.env.NEXT_RUNTIME !== 'nodejs') return;

    // ── Scan scheduler — fires cron-scheduled scans ────────────
    if (process.env.SCHEDULER_ENABLED === 'true') {
        const { ScanScheduler } = await import('@/worker/scheduler');
        const { getScanPool } = await import('@/worker/pool');

        const scheduler = new ScanScheduler({
            enqueue: async ({ targetId, startedById, scanType, scanModules }) => {
                // Lazy-import to avoid circular deps at module load time.
                const { default: prisma } = await import('@/lib/prisma');
                const { runScan } = await import('@/scanner');

                const scan = await prisma.scan.create({
                    data: {
                        targetId,
                        startedById,
                        scanType: scanType ?? 'standard',
                        scanModules: scanModules ? JSON.stringify(scanModules) : '[]',
                        status: 'queued',
                    },
                });

                const target = await prisma.target.findUnique({ where: { id: targetId } });
                if (!target) throw new Error(`Target ${targetId} not found`);

                const pool = getScanPool();
                await pool.enqueue({
                    scanId: scan.id,
                    run: async () => {
                        await runScan({
                            targetId: target.id,
                            scanId: scan.id,
                            baseUrl: target.baseUrl,
                            maxCrawlDepth: target.maxCrawlDepth,
                            maxUrls: target.maxUrls,
                            requestTimeout: target.requestTimeout,
                            rateLimit: target.rateLimit,
                            modules: scanModules ?? [],
                            scanType: (scanType as any) ?? 'standard',
                            customHeaders: target.headers ? JSON.parse(target.headers) : undefined,
                            excludePaths: target.excludePaths ? JSON.parse(target.excludePaths) : undefined,
                            includePaths: target.includePaths ? JSON.parse(target.includePaths) : undefined,
                        });
                    },
                });

                return { scanId: scan.id };
            },
            tickMs: 30_000,
        });

        scheduler.start();
        console.log('[InjectProof] ScanScheduler started');
    }

    // ── Orphan recovery — reclaim scans that were running when the server died ──
    if (process.env.SCANNER_ORPHAN_RECOVERY !== 'false') {
        const { recoverOrphans } = await import('@/worker/pool');
        // 5-minute stale threshold: scans with no heartbeat for >5 min are orphaned
        await recoverOrphans(5 * 60 * 1000).catch(() => {});
    }
}
