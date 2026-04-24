import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
    KillSwitchEngagedError, isEngaged, shouldProceed,
    _forceState, _invalidateCache,
} from './kill-switch';
import {
    BudgetExceededError, RequestBudget, budgetTrackerFor, _clearBudgetRegistry,
} from './request-budget';
import { classifyAction } from './action-classifier';
import { ScanPolicySchema, BUILTIN_PROFILES, LEGACY_PASSTHROUGH } from '../policy/schema';

beforeEach(() => {
    _forceState(null);
    _invalidateCache();
    _clearBudgetRegistry();
});

describe('kill-switch', () => {
    it('shouldProceed resolves when not engaged', async () => {
        _forceState({ engaged: false });
        await expect(shouldProceed()).resolves.toBeUndefined();
    });

    it('shouldProceed throws with reason when engaged', async () => {
        _forceState({ engaged: true, reason: 'war-room' });
        await expect(shouldProceed()).rejects.toBeInstanceOf(KillSwitchEngagedError);
        await expect(shouldProceed()).rejects.toThrow(/war-room/);
    });

    it('isEngaged echoes fields from forced state', async () => {
        _forceState({ engaged: true, reason: 'x', engagedBy: 'ops' });
        const s = await isEngaged();
        expect(s.engaged).toBe(true);
        expect(s.reason).toBe('x');
        expect(s.engagedBy).toBe('ops');
    });
});

describe('request-budget', () => {
    it('reserve throws once maxRequests exceeded', () => {
        const b = new RequestBudget('s1', { maxRequests: 2, maxBytes: 1e9, maxWallMs: 60_000 });
        b.reserve(); b.reserve();
        expect(() => b.reserve()).toThrow(BudgetExceededError);
    });

    it('commit accumulates bytes and exhausts budget', () => {
        const b = new RequestBudget('s1', { maxRequests: 100, maxBytes: 200, maxWallMs: 60_000 });
        const c = b.reserve(); c(300);
        expect(() => b.reserve()).toThrow(/bytes/);
    });

    it('wall-clock budget exhausts under fake timers', () => {
        vi.useFakeTimers();
        const b = new RequestBudget('s1', { maxRequests: 100, maxBytes: 1e9, maxWallMs: 1_000 });
        b.reserve();
        vi.setSystemTime(Date.now() + 5_000);
        expect(() => b.reserve()).toThrow(/wallMs/);
        vi.useRealTimers();
    });

    it('budgetTrackerFor returns the same instance per scanId', () => {
        const limits = { maxRequests: 1, maxBytes: 1, maxWallMs: 1 };
        const a = budgetTrackerFor('scan-a', limits);
        const b = budgetTrackerFor('scan-a', limits);
        expect(a).toBe(b);
    });

    it('snapshot returns remaining per axis', () => {
        const b = new RequestBudget('s', { maxRequests: 10, maxBytes: 1000, maxWallMs: 60_000 });
        const c = b.reserve(); c(100);
        const snap = b.snapshot();
        expect(snap.remaining.requests).toBe(9);
        expect(snap.remaining.bytes).toBe(900);
    });
});

describe('action-classifier', () => {
    const strict = LEGACY_PASSTHROUGH; // allowDangerousActions=false, requireExplicitMutationApproval=true by default

    it('GET /users classifies as read-only and allowed', () => {
        const v = classifyAction(strict, { method: 'GET', url: '/users' });
        expect(v.class).toBe('read-only');
        expect(v.allowed).toBe(true);
    });

    it('DELETE /users/1 classifies as dangerous and blocked', () => {
        const v = classifyAction(strict, { method: 'DELETE', url: '/users/1' });
        expect(v.class).toBe('dangerous');
        expect(v.allowed).toBe(false);
    });

    it('POST /logout classifies as dangerous via keyword', () => {
        const v = classifyAction(strict, { method: 'POST', url: '/logout' });
        expect(v.class).toBe('dangerous');
    });

    it('score is within [0,1] and signals array non-empty', () => {
        const v = classifyAction(strict, { method: 'DELETE', url: '/api/users/1' });
        expect(v.score).toBeGreaterThanOrEqual(0);
        expect(v.score).toBeLessThanOrEqual(1);
        expect(v.signals.length).toBeGreaterThan(0);
    });

    it('allowDangerousActions=true lets dangerous action pass', () => {
        const permissive = ScanPolicySchema.parse({
            id: 'permissive',
            risk: { allowDangerousActions: true },
            misc: { requireExplicitMutationApproval: false },
        });
        const v = classifyAction(permissive, { method: 'DELETE', url: '/users/1' });
        expect(v.allowed).toBe(true);
    });
});
