// InjectProof — Scheduled-scan driver
// Consumes ScheduledScan rows and enqueues scans per their cron spec.
// Boots on first call to start(); reboot-safe because next-run-at is
// recomputed from the cron expression at every tick (no drift after
// process restarts).
//
// Parses a restricted cron subset (5 fields: min hour day month weekday,
// supporting *, N, */N, N-M, A,B,C). This avoids pulling `node-cron` as a
// dependency — the full POSIX cron spec isn't needed for scheduled scans.

import prisma from '@/lib/prisma';
import { logScan } from '@/scanner/engine/log';

// ============================================================
// Cron parser (5-field)
// ============================================================

interface CronFields {
    minutes: Set<number>;
    hours: Set<number>;
    days: Set<number>;
    months: Set<number>;
    weekdays: Set<number>;
}

function expandField(expr: string, min: number, max: number): Set<number> {
    const out = new Set<number>();
    for (const part of expr.split(',')) {
        if (part === '*') {
            for (let i = min; i <= max; i++) out.add(i);
            continue;
        }
        const stepMatch = part.match(/^(.+)\/(\d+)$/);
        if (stepMatch) {
            const step = Number(stepMatch[2]);
            const range = stepMatch[1] === '*' ? [min, max] : stepMatch[1].split('-').map(Number);
            const [lo, hi] = range.length === 1 ? [range[0], max] : [range[0], range[1]];
            for (let i = lo; i <= hi; i += step) out.add(i);
            continue;
        }
        if (part.includes('-')) {
            const [lo, hi] = part.split('-').map(Number);
            for (let i = lo; i <= hi; i++) out.add(i);
            continue;
        }
        const n = Number(part);
        if (!Number.isNaN(n)) out.add(n);
    }
    return out;
}

export function parseCron(expr: string): CronFields {
    const fields = expr.trim().split(/\s+/);
    if (fields.length !== 5) throw new Error(`cron expression must have 5 fields: "${expr}"`);
    return {
        minutes: expandField(fields[0], 0, 59),
        hours: expandField(fields[1], 0, 23),
        days: expandField(fields[2], 1, 31),
        months: expandField(fields[3], 1, 12),
        weekdays: expandField(fields[4], 0, 6),
    };
}

/** Compute the next fire time strictly after `from`. */
export function nextFire(cronExpr: string, from: Date = new Date()): Date | null {
    const f = parseCron(cronExpr);
    // Brute-force search, minute-by-minute, up to 366 days forward.
    // Adequate for scheduled scans (minute granularity).
    const start = new Date(from);
    start.setSeconds(0, 0);
    start.setMinutes(start.getMinutes() + 1);
    const limit = new Date(start.getTime() + 366 * 24 * 60 * 60 * 1000);
    for (let d = new Date(start); d < limit; d.setMinutes(d.getMinutes() + 1)) {
        if (
            f.minutes.has(d.getMinutes()) &&
            f.hours.has(d.getHours()) &&
            f.days.has(d.getDate()) &&
            f.months.has(d.getMonth() + 1) &&
            f.weekdays.has(d.getDay())
        ) {
            return new Date(d);
        }
    }
    return null;
}

// ============================================================
// Scheduler
// ============================================================

export type EnqueueScanFn = (input: {
    targetId: string;
    startedById: string;
    scanType: string;
    scanModules?: string[];
}) => Promise<{ scanId: string }>;

interface SchedulerOptions {
    /** Invoked with the schedule row to actually create + enqueue a scan. */
    enqueue: EnqueueScanFn;
    /** Tick interval (ms). Default 30s. */
    tickMs?: number;
    /** Minimum gap between runs of the same schedule to avoid double-fire. */
    minGapMs?: number;
    /**
     * System user ID to attribute scheduled runs to. Falls back to the
     * target's createdById when absent.
     */
    systemUserId?: string;
}

export class ScanScheduler {
    private timer: NodeJS.Timeout | null = null;
    private lastRun = new Map<string, number>();

    constructor(private opts: SchedulerOptions) {}

    start(): void {
        if (this.timer) return;
        const tick = this.opts.tickMs ?? 30_000;
        this.timer = setInterval(() => void this.tick(), tick);
        void this.tick();
    }

    stop(): void {
        if (this.timer) clearInterval(this.timer);
        this.timer = null;
    }

    private async tick(): Promise<void> {
        const now = new Date();
        const schedules = await prisma.scheduledScan.findMany({ where: { isActive: true } });
        for (const s of schedules) {
            try {
                // Skip if this schedule ran recently — prevents double-fire
                // when the tick catches two consecutive minutes' match windows.
                const last = this.lastRun.get(s.id) ?? 0;
                if (Date.now() - last < (this.opts.minGapMs ?? 45_000)) continue;

                const due = isDue(s.cronExpression, s.lastRunAt ?? null, now);
                if (!due) continue;

                const target = await prisma.target.findUnique({
                    where: { id: s.targetId },
                    select: { createdById: true },
                });
                if (!target) continue;
                const startedById = this.opts.systemUserId ?? target.createdById;
                const modules: string[] | undefined = s.scanModules ? (JSON.parse(s.scanModules) as string[]) : undefined;

                const { scanId } = await this.opts.enqueue({
                    targetId: s.targetId,
                    startedById,
                    scanType: s.scanType,
                    scanModules: modules,
                });

                this.lastRun.set(s.id, Date.now());
                await prisma.scheduledScan.update({
                    where: { id: s.id },
                    data: {
                        lastRunAt: now,
                        nextRunAt: nextFire(s.cronExpression, now),
                        runCount: { increment: 1 },
                    },
                });
                await logScan({
                    scanId,
                    level: 'info',
                    module: 'worker.scheduler',
                    message: `Scheduled scan "${s.name}" fired — cron="${s.cronExpression}"`,
                });
            } catch {
                // Swallow — next tick will retry. The pool's own logging
                // captures any downstream failure.
            }
        }
    }
}

function isDue(cronExpr: string, lastRunAt: Date | null, now: Date): boolean {
    // Due if: the most recent scheduled time on/before `now` is strictly
    // after lastRunAt.
    const next = nextFire(cronExpr, lastRunAt ?? new Date(now.getTime() - 366 * 24 * 60 * 60 * 1000));
    if (!next) return false;
    return next <= now;
}
