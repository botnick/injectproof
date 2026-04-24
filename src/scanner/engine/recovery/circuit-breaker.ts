// InjectProof — Per-host circuit breaker
// ป้องกันไม่ให้ scanner วนซ้ำโดน 403/429 จนโดนแบน IP. State machine 3 สถานะ:
//   - closed     : ยิง request ปกติ ถ้า fail ติดกัน N ครั้ง → open
//   - open       : ปฏิเสธ request ทันที จน cooldown หมด → half-open
//   - half-open  : อนุญาต 1 probe เพื่อลอง; success → closed, fail → open ใหม่
//
// Takes `now` function for fake-clock unit testing.

export type BreakerState = 'closed' | 'open' | 'half-open';
export type Outcome = 'success' | 'fail';

export interface BreakerConfig {
    /** Consecutive failures that trip the breaker. Default 5. */
    failThreshold?: number;
    /** Cool-down duration (ms) before half-open. Default 60_000. */
    cooldownMs?: number;
    /** Clock injection for tests. */
    now?: () => number;
}

interface HostState {
    state: BreakerState;
    consecutiveFails: number;
    openedAt: number | null;
    lastOutcomeAt: number | null;
}

export class CircuitBreaker {
    private readonly states = new Map<string, HostState>();
    private readonly failThreshold: number;
    private readonly cooldownMs: number;
    private readonly now: () => number;

    constructor(config: BreakerConfig = {}) {
        this.failThreshold = config.failThreshold ?? 5;
        this.cooldownMs = config.cooldownMs ?? 60_000;
        this.now = config.now ?? Date.now;
    }

    private state(host: string): HostState {
        const existing = this.states.get(host);
        if (existing) return existing;
        const fresh: HostState = { state: 'closed', consecutiveFails: 0, openedAt: null, lastOutcomeAt: null };
        this.states.set(host, fresh);
        return fresh;
    }

    /** True if a request to this host is allowed right now. */
    allow(host: string): boolean {
        const s = this.state(host);
        if (s.state === 'closed') return true;
        if (s.state === 'open') {
            if (s.openedAt !== null && this.now() - s.openedAt >= this.cooldownMs) {
                // Auto-transition to half-open on the first allow() after cooldown.
                s.state = 'half-open';
                return true;
            }
            return false;
        }
        // half-open: admit the probe request
        return true;
    }

    /** Record an outcome after a request completed. */
    record(host: string, outcome: Outcome): void {
        const s = this.state(host);
        s.lastOutcomeAt = this.now();

        if (outcome === 'success') {
            if (s.state === 'half-open' || s.state === 'closed') {
                s.state = 'closed';
                s.consecutiveFails = 0;
                s.openedAt = null;
            } else {
                // In 'open', we shouldn't have received a real request; treat as
                // spurious success and keep breaker open.
            }
            return;
        }

        // Fail path
        s.consecutiveFails++;
        if (s.state === 'half-open') {
            // Probe failed → reopen.
            s.state = 'open';
            s.openedAt = this.now();
            return;
        }
        if (s.state === 'closed' && s.consecutiveFails >= this.failThreshold) {
            s.state = 'open';
            s.openedAt = this.now();
        }
    }

    snapshot(host: string): Readonly<HostState> {
        return { ...this.state(host) };
    }

    /** Force-close a host (admin override). */
    reset(host: string): void {
        this.states.delete(host);
    }
}

// ────────────────────────────────────────────────────────────
// Process-global default breaker
// ────────────────────────────────────────────────────────────

let defaultBreaker: CircuitBreaker | null = null;

export function globalCircuitBreaker(): CircuitBreaker {
    if (!defaultBreaker) defaultBreaker = new CircuitBreaker();
    return defaultBreaker;
}

/** Tests only. */
export function _resetGlobalBreaker(): void {
    defaultBreaker = null;
}
