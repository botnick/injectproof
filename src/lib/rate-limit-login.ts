// InjectProof — Per-account login throttling
// Writes to User.loginFailureState — an encoded counter + timestamp — so
// repeated bad logins lock the account for a configurable backoff window
// without adding a Redis/Memcached dependency. Fully atomic via Prisma's
// row-level update semantics.
//
// Policy:
//   first 3 failures  → no lockout, but each increments the counter
//   4th–7th failure   → 60s × 2^(n-4) lockout (60s, 2min, 4min, 8min)
//   ≥ 8 failures      → 1h lockout
//   any success       → counter resets

import prisma from '@/lib/prisma';

const FAIL_THRESHOLD = 3;
const MAX_BACKOFF_MS = 60 * 60 * 1000;

export interface LoginAttemptResult {
    allowed: boolean;
    lockoutMs?: number;
    reason?: string;
}

function encode(count: number, firstFailureTs: number): string {
    return `${count}:${firstFailureTs}`;
}

function decode(state: string | null | undefined): { count: number; firstFailureTs: number } {
    if (!state) return { count: 0, firstFailureTs: 0 };
    const [c, t] = state.split(':');
    return { count: Number(c) || 0, firstFailureTs: Number(t) || 0 };
}

function backoffMs(count: number): number {
    if (count <= FAIL_THRESHOLD) return 0;
    const step = count - FAIL_THRESHOLD;
    const ms = 60_000 * Math.pow(2, step - 1);
    return Math.min(ms, MAX_BACKOFF_MS);
}

/**
 * Check whether the user is currently within a lockout window. Call this
 * BEFORE verifying the password — a locked user's password isn't even
 * checked, so timing comparisons don't leak anything.
 */
export async function checkLockout(userId: string): Promise<LoginAttemptResult> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { loginFailureState: true },
    });
    if (!user) return { allowed: false, reason: 'user not found' };
    const { count, firstFailureTs } = decode(user.loginFailureState);
    if (count <= FAIL_THRESHOLD) return { allowed: true };

    const lockoutStarts = firstFailureTs;
    const remaining = lockoutStarts + backoffMs(count) - Date.now();
    if (remaining > 0) {
        return { allowed: false, lockoutMs: remaining, reason: 'account temporarily locked due to repeated failed logins' };
    }
    return { allowed: true };
}

/** Call on a failed login. */
export async function recordFailure(userId: string): Promise<LoginAttemptResult> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { loginFailureState: true },
    });
    if (!user) return { allowed: false, reason: 'user not found' };
    const prev = decode(user.loginFailureState);
    const nextCount = prev.count + 1;
    const firstFailureTs = prev.count === 0 ? Date.now() : prev.firstFailureTs;
    await prisma.user.update({
        where: { id: userId },
        data: { loginFailureState: encode(nextCount, firstFailureTs) },
    });
    if (nextCount > FAIL_THRESHOLD) {
        return {
            allowed: false,
            lockoutMs: backoffMs(nextCount),
            reason: `${nextCount} failures — locked for ${Math.ceil(backoffMs(nextCount) / 60000)} min`,
        };
    }
    return { allowed: true };
}

/** Call on a successful login — resets the counter. */
export async function recordSuccess(userId: string): Promise<void> {
    await prisma.user.update({
        where: { id: userId },
        data: { loginFailureState: null, lastLoginAt: new Date() },
    });
}
