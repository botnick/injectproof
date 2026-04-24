import { describe, it, expect, vi } from 'vitest';
import { STATE_DEFS, ScanState, canTransition, isTerminal } from './states';
import { runStateMachine } from './machine';

describe('state graph', () => {
    it('CREATED can reach VALIDATING_SCOPE + CANCELLED', () => {
        expect(canTransition('CREATED', 'VALIDATING_SCOPE')).toBe(true);
        expect(canTransition('CREATED', 'CANCELLED')).toBe(true);
        expect(canTransition('CREATED', 'COMPLETED')).toBe(false);
    });

    it('terminal states block further transitions', () => {
        expect(canTransition('COMPLETED', 'CREATED')).toBe(false);
        expect(canTransition('FAILED', 'CREATED')).toBe(false);
        expect(canTransition('CANCELLED', 'CREATED')).toBe(false);
    });

    it('isTerminal marks COMPLETED/FAILED/CANCELLED/COMPLETED_WITH_WARNINGS', () => {
        expect(isTerminal('COMPLETED')).toBe(true);
        expect(isTerminal('COMPLETED_WITH_WARNINGS')).toBe(true);
        expect(isTerminal('FAILED')).toBe(true);
        expect(isTerminal('CANCELLED')).toBe(true);
        expect(isTerminal('CREATED')).toBe(false);
    });

    it('every non-terminal state has at least one successor', () => {
        for (const [name, def] of Object.entries(STATE_DEFS)) {
            if (def.terminal) continue;
            // PAUSED explicitly has all non-paused successors.
            expect(def.successors.length, `${name} must have successors`).toBeGreaterThan(0);
        }
    });
});

describe('runStateMachine', () => {
    it('runs through a chain of handlers to COMPLETED', async () => {
        const handlers = {
            CREATED: async () => ({ scanId: 'x', createdAt: new Date(), __nextState: ScanState.VALIDATING_SCOPE }),
            VALIDATING_SCOPE: async () => ({ policy: {}, scopeApprovalId: null, __nextState: ScanState.INITIALIZING }),
            INITIALIZING: async () => ({ budgetReady: true, killSwitchOk: true, __nextState: ScanState.PROFILING_TARGET }),
            PROFILING_TARGET: async () => ({ techHints: [], wafHint: null, __nextState: ScanState.CRAWLING_HTTP }),
            CRAWLING_HTTP: async () => ({ endpointCount: 0, formCount: 0, __nextState: ScanState.BUILDING_SURFACE_GRAPH }),
            BUILDING_SURFACE_GRAPH: async () => ({ nodeCount: 0, edgeCount: 0, __nextState: ScanState.MODELING_INPUTS }),
            MODELING_INPUTS: async () => ({ inputCount: 0, __nextState: ScanState.PLANNING_DETECTION }),
            PLANNING_DETECTION: async () => ({ plannedProbes: 0, detectorIds: [], __nextState: ScanState.RUNNING_PASSIVE_ANALYSIS }),
            RUNNING_PASSIVE_ANALYSIS: async () => ({ passiveFindings: 0, __nextState: ScanState.CORRELATING_EVIDENCE }),
            CORRELATING_EVIDENCE: async () => ({ correlatedFindings: 0, __nextState: ScanState.SCORING_FINDINGS }),
            SCORING_FINDINGS: async () => ({ scoredFindings: 0, __nextState: ScanState.GENERATING_REPORT }),
            GENERATING_REPORT: async () => ({ reportId: 'r', __nextState: ScanState.COMPLETED }),
        };
        const res = await runStateMachine('s1', { handlers, persistCheckpoints: false });
        expect(res.finalState).toBe('COMPLETED');
        expect(res.history.length).toBeGreaterThanOrEqual(12);
    });

    it('marks FAILED when a handler throws with retry=1', async () => {
        const res = await runStateMachine('s2', {
            persistCheckpoints: false,
            handlers: {
                CREATED: async () => ({ scanId: 'x', createdAt: new Date(), __nextState: ScanState.VALIDATING_SCOPE }),
                VALIDATING_SCOPE: async () => { throw new Error('scope kaboom'); },
            },
        });
        expect(res.finalState).toBe('FAILED');
        const failed = res.history.find((h) => h.state === 'VALIDATING_SCOPE');
        expect(failed?.ok).toBe(false);
        expect(failed?.error).toContain('scope kaboom');
    });

    it('cancels when signal aborts mid-run', async () => {
        const ctrl = new AbortController();
        const p = runStateMachine('s3', {
            persistCheckpoints: false,
            signal: ctrl.signal,
            handlers: {
                CREATED: async () => {
                    ctrl.abort();
                    return { scanId: 'x', createdAt: new Date(), __nextState: ScanState.VALIDATING_SCOPE };
                },
            },
        });
        const res = await p;
        expect(res.finalState).toBe('CANCELLED');
    });

    it('rejects an invalid output shape with FAILED', async () => {
        const res = await runStateMachine('s4', {
            persistCheckpoints: false,
            handlers: {
                CREATED: async () => ({}), // missing required scanId/createdAt
            },
        });
        expect(res.finalState).toBe('FAILED');
    });

    it('timeout raises TimeoutError and marks FAILED', async () => {
        const def = STATE_DEFS.VALIDATING_SCOPE;
        const original = def.timeoutMs;
        (def as unknown as { timeoutMs: number }).timeoutMs = 50;
        try {
            const res = await runStateMachine('s5', {
                persistCheckpoints: false,
                handlers: {
                    CREATED: async () => ({ scanId: 'x', createdAt: new Date(), __nextState: ScanState.VALIDATING_SCOPE }),
                    VALIDATING_SCOPE: async () => {
                        await new Promise((r) => setTimeout(r, 500));
                        return { policy: {}, scopeApprovalId: null };
                    },
                },
            });
            expect(res.finalState).toBe('FAILED');
        } finally {
            (def as unknown as { timeoutMs: number }).timeoutMs = original;
        }
    });

    it('no-op passes through when no handler registered', async () => {
        const res = await runStateMachine('s6', { handlers: {}, persistCheckpoints: false });
        expect(res.finalState).toBe('COMPLETED');
    });
});
