// InjectProof — Global kill switch
// Singleton row (id='global') อ่าน/เขียนโดย admin + oncall. ทุก request ผ่าน
// `shouldProceed()` ก่อนยิง network — ถ้าเปิดอยู่ จะ throw
// `KillSwitchEngagedError` ให้ detector รู้ตัวและ abort.
//
// Caching: สั้นมาก (≤ 1s) ไม่งั้น DB ถูกตบหนัก. ถ้าคลิก toggle บน UI แล้ว
// effect ต้องเห็นใน ≤ 1s บน live scan ด้วย.
//
// ออกแบบมาให้ oncall flip ได้แม้ UI พัง: `UPDATE "KillSwitch" SET engaged=1`.

import prisma from '@/lib/prisma';
import { logScan } from '@/scanner/engine/log';

export class KillSwitchEngagedError extends Error {
    readonly code = 'KILL_SWITCH_ENGAGED';
    constructor(public readonly reason?: string) {
        super(`kill switch engaged${reason ? `: ${reason}` : ''}`);
        this.name = 'KillSwitchEngagedError';
    }
}

// ────────────────────────────────────────────────────────────
// Cache
// ────────────────────────────────────────────────────────────

interface CachedState {
    engaged: boolean;
    reason: string | null;
    engagedBy: string | null;
    fetchedAt: number;
}

const CACHE_TTL_MS = 1_000;
let cached: CachedState | null = null;
/**
 * Manual override for tests / environments without the DB table present.
 * Reader functions honour this before hitting cache/DB so callers can unit-
 * test with zero Prisma setup.
 */
let forcedState: { engaged: boolean; reason: string | null; engagedBy: string | null } | null = null;

// ────────────────────────────────────────────────────────────
// Read
// ────────────────────────────────────────────────────────────

interface KillSwitchRow {
    engaged: boolean;
    reason: string | null;
    engagedBy: string | null;
    engagedAt: Date | null;
}

async function loadRow(): Promise<KillSwitchRow> {
    // Table may not exist yet on older DBs — treat as "not engaged" instead of throwing.
    try {
        const rows = await prisma.$queryRawUnsafe<Array<KillSwitchRow>>(
            'SELECT engaged, reason, engagedBy, engagedAt FROM "KillSwitch" WHERE id = $1 LIMIT 1',
            'global',
        );
        const row = rows[0];
        if (!row) return { engaged: false, reason: null, engagedBy: null, engagedAt: null };
        return {
            engaged: Boolean(row.engaged),
            reason: row.reason ?? null,
            engagedBy: row.engagedBy ?? null,
            engagedAt: row.engagedAt,
        };
    } catch {
        return { engaged: false, reason: null, engagedBy: null, engagedAt: null };
    }
}

/** True if the switch is currently engaged. Cached for ≤ 1s. */
export async function isEngaged(): Promise<{ engaged: boolean; reason?: string; engagedBy?: string }> {
    if (forcedState) {
        return {
            engaged: forcedState.engaged,
            reason: forcedState.reason ?? undefined,
            engagedBy: forcedState.engagedBy ?? undefined,
        };
    }
    const now = Date.now();
    if (cached && now - cached.fetchedAt < CACHE_TTL_MS) {
        return {
            engaged: cached.engaged,
            reason: cached.reason ?? undefined,
            engagedBy: cached.engagedBy ?? undefined,
        };
    }
    const row = await loadRow();
    cached = { engaged: row.engaged, reason: row.reason, engagedBy: row.engagedBy, fetchedAt: now };
    return {
        engaged: cached.engaged,
        reason: cached.reason ?? undefined,
        engagedBy: cached.engagedBy ?? undefined,
    };
}

/**
 * Throw if the switch is engaged. Call this at every outbound fetch boundary
 * in `lib/http/request.ts`, not per-detector (centralization).
 */
export async function shouldProceed(): Promise<void> {
    const state = await isEngaged();
    if (state.engaged) throw new KillSwitchEngagedError(state.reason);
}

// ────────────────────────────────────────────────────────────
// Write
// ────────────────────────────────────────────────────────────

export interface ToggleOpts {
    /** User id of the oncall engaging/disengaging. */
    by: string;
    /** Short reason for audit. */
    reason?: string;
    /** Scan IDs to log the engagement against (for visibility on the scan page). */
    scanIds?: string[];
}

export async function engage(opts: ToggleOpts): Promise<void> {
    await prisma.$executeRawUnsafe(
        `INSERT INTO "KillSwitch" (id, engaged, reason, engagedBy, engagedAt, updatedAt)
         VALUES ($1, 1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET engaged=1, reason=$2, engagedBy=$3, engagedAt=CURRENT_TIMESTAMP, updatedAt=CURRENT_TIMESTAMP`,
        'global',
        opts.reason ?? null,
        opts.by,
    );
    cached = null;
    for (const scanId of opts.scanIds ?? []) {
        await logScan({
            scanId,
            level: 'warn',
            module: 'safety.kill-switch',
            message: `kill switch engaged by ${opts.by}${opts.reason ? `: ${opts.reason}` : ''}`,
        });
    }
}

export async function disengage(opts: ToggleOpts): Promise<void> {
    await prisma.$executeRawUnsafe(
        `UPDATE "KillSwitch" SET engaged=0, reason=$1, engagedBy=$2, updatedAt=CURRENT_TIMESTAMP WHERE id=$3`,
        opts.reason ?? null,
        opts.by,
        'global',
    );
    cached = null;
}

// ────────────────────────────────────────────────────────────
// Test hooks (not exported from the module's public surface in production)
// ────────────────────────────────────────────────────────────

/** Invalidate the cache — tests use this; runtime code should not. */
export function _invalidateCache(): void {
    cached = null;
}

/** Force in-memory state for tests that have no DB table. */
export function _forceState(state: { engaged: boolean; reason?: string; engagedBy?: string } | null): void {
    if (state === null) {
        forcedState = null;
        return;
    }
    forcedState = {
        engaged: state.engaged,
        reason: state.reason ?? null,
        engagedBy: state.engagedBy ?? null,
    };
}
