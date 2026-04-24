import { describe, it, expect, vi, beforeEach } from 'vitest';

// ------------------------------------------------------------
// Prisma mock — tracks every scan.update payload so tests can
// assert state transitions (queued → running → completed/failed/cancelled).
// ------------------------------------------------------------

type ScanRow = { id: string; status: string; heartbeatAt?: Date | null; errorMessage?: string | null; completedAt?: Date | null; startedAt?: Date | null };
const scans = new Map<string, ScanRow>();
const updateCalls: Array<{ id: string; data: Record<string, unknown> }> = [];
const logCalls: Array<{ scanId: string; level: string; module: string; message: string }> = [];

const prismaMock = {
    scan: {
        update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
            updateCalls.push({ id: where.id, data });
            const row = scans.get(where.id) ?? { id: where.id, status: 'queued' };
            Object.assign(row, data);
            scans.set(where.id, row);
            return row;
        }),
        findMany: vi.fn(async ({ where }: { where: { status: string; OR?: Array<Record<string, unknown>> } }) => {
            const out: ScanRow[] = [];
            for (const row of scans.values()) {
                if (row.status !== where.status) continue;
                // Simplified OR matcher — we only need to support the recoverOrphans query.
                if (where.OR) {
                    const [a, b] = where.OR as Array<{ heartbeatAt?: { lt?: Date } | null; startedAt?: { lt?: Date } }>;
                    const staleHeartbeat = a.heartbeatAt && 'lt' in a.heartbeatAt && row.heartbeatAt && row.heartbeatAt < (a.heartbeatAt.lt as Date);
                    const noHeartbeatStale = !row.heartbeatAt && b.startedAt && row.startedAt && row.startedAt < (b.startedAt.lt as Date);
                    if (!staleHeartbeat && !noHeartbeatStale) continue;
                }
                out.push(row);
            }
            return out;
        }),
        updateMany: vi.fn(async ({ where, data }: { where: { id: { in: string[] } }; data: Record<string, unknown> }) => {
            for (const id of where.id.in) {
                const row = scans.get(id);
                if (row) Object.assign(row, data);
            }
            return { count: where.id.in.length };
        }),
    },
    scanLog: {
        create: vi.fn(async ({ data }: { data: { scanId: string; level: string; module: string; message: string } }) => {
            logCalls.push(data);
            return data;
        }),
    },
};

vi.mock('@/lib/prisma', () => ({ default: prismaMock }));

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function resetMocks(): void {
    scans.clear();
    updateCalls.length = 0;
    logCalls.length = 0;
    prismaMock.scan.update.mockClear();
    prismaMock.scan.findMany.mockClear();
    prismaMock.scan.updateMany.mockClear();
    prismaMock.scanLog.create.mockClear();
}

function seedQueuedScan(id: string): void {
    scans.set(id, { id, status: 'queued' });
}

// Import under test AFTER mocks are in place.
const { ScanWorkerPool, recoverOrphans } = await import('./pool');

beforeEach(resetMocks);

// ============================================================
// enqueue + start
// ============================================================

describe('ScanWorkerPool', () => {
    it('starts a scan immediately when capacity is available', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 2 });
        seedQueuedScan('s1');
        let ran = false;
        await pool.enqueue({
            scanId: 's1',
            run: async () => {
                ran = true;
                await wait(5);
            },
        });
        await wait(30);
        expect(ran).toBe(true);
        expect(pool.activeCount()).toBe(0);
    });

    it('respects the maxConcurrent cap and queues overflow', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 2 });
        seedQueuedScan('s1');
        seedQueuedScan('s2');
        seedQueuedScan('s3');

        const gate = { resolve: () => {} };
        const gatePromise = new Promise<void>((r) => { gate.resolve = r; });

        const run = async () => {
            await gatePromise;
        };

        await pool.enqueue({ scanId: 's1', run });
        await pool.enqueue({ scanId: 's2', run });
        const third = await pool.enqueue({ scanId: 's3', run });
        expect(third.started).toBe(false);
        expect(third.position).toBe(1);
        expect(pool.activeCount()).toBe(2);
        expect(pool.queueDepth()).toBe(1);

        gate.resolve();
        await wait(30);
        expect(pool.activeCount()).toBe(0);
        expect(pool.queueDepth()).toBe(0);
    });

    it('marks a scan as failed in DB when the run function throws', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 1 });
        seedQueuedScan('s1');
        await pool.enqueue({
            scanId: 's1',
            run: async () => {
                throw new Error('kaboom');
            },
        });
        await wait(30);
        const failedUpdate = updateCalls.find((c) => c.id === 's1' && c.data.status === 'failed');
        expect(failedUpdate).toBeTruthy();
        expect(failedUpdate!.data.errorMessage).toBe('kaboom');
        expect(logCalls.some((l) => l.scanId === 's1' && l.level === 'error' && /kaboom/.test(l.message))).toBe(true);
    });

    it('abort() on a running scan signals the AbortController and marks status', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 1 });
        seedQueuedScan('s1');
        const observed: { signal: AbortSignal | null } = { signal: null };
        const running = new Promise<void>((resolve) => {
            void pool.enqueue({
                scanId: 's1',
                run: async (_id, signal) => {
                    observed.signal = signal;
                    await new Promise<void>((res) => {
                        signal.addEventListener('abort', () => res());
                    });
                    throw new Error('aborted');
                },
            }).then(() => resolve());
        });
        await wait(20);
        expect(await pool.abort('s1', 'test cancel')).toBe(true);
        await running;
        await wait(20);
        expect(observed.signal).not.toBeNull();
        expect(observed.signal!.aborted).toBe(true);
        const cancelled = updateCalls.find((c) => c.id === 's1' && c.data.status === 'cancelled');
        expect(cancelled).toBeTruthy();
    });

    it('abort() on a queued (not-yet-running) scan removes it from the queue', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 1 });
        seedQueuedScan('s1');
        seedQueuedScan('s2');
        await pool.enqueue({ scanId: 's1', run: async () => { await wait(50); } });
        await pool.enqueue({ scanId: 's2', run: async () => { await wait(50); } });
        expect(pool.queueDepth()).toBe(1);
        expect(await pool.abort('s2', 'never mind')).toBe(true);
        expect(pool.queueDepth()).toBe(0);
        const cancelled = updateCalls.find((c) => c.id === 's2' && c.data.status === 'cancelled');
        expect(cancelled).toBeTruthy();
    });

    it('abort() on an unknown scan returns false without throwing', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 1 });
        expect(await pool.abort('nonexistent')).toBe(false);
    });

    it('drains the queue as scans complete', async () => {
        const pool = new ScanWorkerPool({ maxConcurrent: 1 });
        seedQueuedScan('s1');
        seedQueuedScan('s2');
        seedQueuedScan('s3');
        const completed: string[] = [];
        const make = (id: string) => async () => {
            await wait(10);
            completed.push(id);
        };
        await pool.enqueue({ scanId: 's1', run: make('s1') });
        await pool.enqueue({ scanId: 's2', run: make('s2') });
        await pool.enqueue({ scanId: 's3', run: make('s3') });
        await wait(100);
        expect(completed).toEqual(['s1', 's2', 's3']);
    });
});

// ============================================================
// recoverOrphans
// ============================================================

describe('recoverOrphans', () => {
    it('marks stale running scans as failed and logs the recovery', async () => {
        const old = new Date(Date.now() - 5 * 60_000);
        scans.set('stale', { id: 'stale', status: 'running', heartbeatAt: old });
        scans.set('fresh', { id: 'fresh', status: 'running', heartbeatAt: new Date() });

        const recovered = await recoverOrphans(60_000);
        expect(recovered).toBe(1);
        expect(scans.get('stale')?.status).toBe('failed');
        expect(scans.get('fresh')?.status).toBe('running');
        expect(logCalls.some((l) => l.scanId === 'stale' && /orphan/.test(l.message))).toBe(true);
    });

    it('returns 0 when there are no orphans', async () => {
        scans.set('fresh', { id: 'fresh', status: 'running', heartbeatAt: new Date() });
        expect(await recoverOrphans(60_000)).toBe(0);
    });
});
