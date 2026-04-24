// InjectProof — In-process scan worker pool
// Replaces the fire-and-forget `.catch()` detach in scan.create with a
// bounded queue + AbortController-per-scan. Why not BullMQ/Redis? Because
// the single-box deployment this platform is designed for doesn't need it
// yet, and a well-bounded in-process pool removes OOM failure modes without
// the operational overhead of a queue service.
//
// Promotes to BullMQ becomes a two-file change when that day comes — this
// module's interface (`enqueue`, `abort`, `activeCount`) is queue-agnostic.
//
// Responsibilities:
//   - Respect SCANNER_MAX_CONCURRENT (default 2)
//   - Maintain one AbortController per running scan → forceful cancellation
//   - Emit `heartbeatAt` every N seconds → orphan recovery works
//   - On scan completion/error, mark Scan.status appropriately and clean up

import prisma from '@/lib/prisma';
import { logScan } from '@/scanner/engine/log';

export interface ScanWorkerInput {
    scanId: string;
    /** The runScan() entrypoint — injected so the pool stays testable. */
    run: (scanId: string, signal: AbortSignal) => Promise<void>;
}

interface ActiveScan {
    scanId: string;
    controller: AbortController;
    heartbeatTimer: NodeJS.Timeout;
    startedAt: number;
}

export class ScanWorkerPool {
    private maxConcurrent: number;
    private active = new Map<string, ActiveScan>();
    private queue: ScanWorkerInput[] = [];

    constructor(options?: { maxConcurrent?: number }) {
        const fromEnv = Number(process.env.SCANNER_MAX_CONCURRENT);
        this.maxConcurrent = options?.maxConcurrent ?? (Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : 2);
    }

    /**
     * Add a scan to the queue. Returns immediately with queue/run status —
     * the scan itself runs async and reports via Scan.status + ScanLog.
     */
    async enqueue(input: ScanWorkerInput): Promise<{ started: boolean; position?: number }> {
        if (this.active.size < this.maxConcurrent) {
            void this.start(input);
            return { started: true };
        }
        this.queue.push(input);
        await prisma.scan.update({
            where: { id: input.scanId },
            data: { status: 'queued' },
        });
        return { started: false, position: this.queue.length };
    }

    /** Forcefully cancel a running scan via its AbortController. */
    async abort(scanId: string, reason = 'cancelled by user'): Promise<boolean> {
        const active = this.active.get(scanId);
        if (active) {
            active.controller.abort(new Error(reason));
            // Best-effort DB mark; the scan's own exit handler will finalize.
            await prisma.scan.update({
                where: { id: scanId },
                data: { status: 'cancelled', errorMessage: reason, completedAt: new Date() },
            }).catch(() => undefined);
            return true;
        }
        // Queued scan — drop it from the queue and mark cancelled.
        const idx = this.queue.findIndex((q) => q.scanId === scanId);
        if (idx >= 0) {
            this.queue.splice(idx, 1);
            await prisma.scan.update({
                where: { id: scanId },
                data: { status: 'cancelled', errorMessage: 'cancelled before start', completedAt: new Date() },
            }).catch(() => undefined);
            return true;
        }
        return false;
    }

    activeCount(): number {
        return this.active.size;
    }

    queueDepth(): number {
        return this.queue.length;
    }

    private async start(input: ScanWorkerInput): Promise<void> {
        const controller = new AbortController();
        const heartbeatTimer = setInterval(() => {
            prisma.scan
                .update({ where: { id: input.scanId }, data: { heartbeatAt: new Date() } })
                .catch(() => undefined);
        }, 5_000);
        this.active.set(input.scanId, { scanId: input.scanId, controller, heartbeatTimer, startedAt: Date.now() });

        try {
            await input.run(input.scanId, controller.signal);
        } catch (err) {
            await logScan({
                scanId: input.scanId,
                level: 'error',
                module: 'worker.pool',
                message: `Scan crashed: ${err instanceof Error ? err.message : String(err)}`,
                details: {
                    stack: err instanceof Error ? err.stack : undefined,
                    aborted: controller.signal.aborted,
                },
            });
            await prisma.scan
                .update({
                    where: { id: input.scanId },
                    data: {
                        status: controller.signal.aborted ? 'cancelled' : 'failed',
                        errorMessage: err instanceof Error ? err.message : String(err),
                        completedAt: new Date(),
                    },
                })
                .catch(() => undefined);
        } finally {
            clearInterval(heartbeatTimer);
            this.active.delete(input.scanId);
            // Drain one more from the queue
            const next = this.queue.shift();
            if (next) void this.start(next);
        }
    }
}

// ============================================================
// Singleton (module-scope) — shared across Next.js API route handlers
// ============================================================

let poolSingleton: ScanWorkerPool | null = null;

export function getScanPool(): ScanWorkerPool {
    if (!poolSingleton) poolSingleton = new ScanWorkerPool();
    return poolSingleton;
}

// ============================================================
// Orphan recovery — call at Next.js init
// ============================================================

/**
 * Mark any `running` scan whose heartbeatAt is stale (or missing + started
 * more than `staleMs` ago) as `failed`. Handles server restarts mid-scan
 * without leaving zombie rows that block the queue.
 */
export async function recoverOrphans(staleMs = 60_000): Promise<number> {
    const cutoff = new Date(Date.now() - staleMs);
    const orphans = await prisma.scan.findMany({
        where: {
            status: 'running',
            OR: [
                { heartbeatAt: { lt: cutoff } },
                { heartbeatAt: null, startedAt: { lt: cutoff } },
            ],
        },
        select: { id: true },
    });
    if (orphans.length === 0) return 0;

    await prisma.scan.updateMany({
        where: { id: { in: orphans.map((o) => o.id) } },
        data: {
            status: 'failed',
            errorMessage: 'Scan process exited without marking completion (recovered on server start)',
            completedAt: new Date(),
            currentPhase: 'failed',
        },
    });
    for (const o of orphans) {
        await logScan({
            scanId: o.id,
            level: 'warn',
            module: 'worker.pool',
            message: 'orphan recovery: marked stale scan as failed',
        });
    }
    return orphans.length;
}
