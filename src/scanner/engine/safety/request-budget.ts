// InjectProof — Per-scan request budget
// enforcement มี 3 มิติ: requests, bytes, wall-clock. ทำงานแบบ in-memory
// ต่อ scan (key ด้วย scanId) — ข้อมูลหายเมื่อ process restart แต่ orchestrator
// มี checkpoint/resume แยก ที่จัดการกรณี restart.
//
// API:
//   const tracker = budgetTrackerFor(scanId, policy.budget);
//   await tracker.reserve();         // throws BudgetExceededError on exhaust
//   tracker.commit({ bytes: resp.length });
//   tracker.remaining();
//
// ไม่มี race condition เพราะเป็น single-process ต่อ scan. เมื่อย้ายเป็น
// distributed worker (v2) จะย้ายไปเก็บ state ใน Redis.

export interface BudgetLimits {
    maxRequests: number;
    maxBytes: number;
    maxWallMs: number;
}

export class BudgetExceededError extends Error {
    readonly code = 'BUDGET_EXCEEDED';
    constructor(public readonly limiting: 'requests' | 'bytes' | 'wallMs', detail?: string) {
        super(`scan budget exceeded on ${limiting}${detail ? `: ${detail}` : ''}`);
        this.name = 'BudgetExceededError';
    }
}

export interface BudgetSnapshot {
    requests: number;
    bytes: number;
    wallMs: number;
    limits: BudgetLimits;
    remaining: {
        requests: number;
        bytes: number;
        wallMs: number;
    };
}

export class RequestBudget {
    private requests = 0;
    private bytes = 0;
    private readonly startedAt = Date.now();

    constructor(public readonly scanId: string, public readonly limits: BudgetLimits) {}

    /**
     * Reserve one request slot. Call BEFORE firing the request. If we are at
     * or past any limit, throw. Returns a commit handle the caller must use
     * to report the actual bytes consumed after the response arrives.
     */
    reserve(): (bytes: number) => void {
        const wallMs = Date.now() - this.startedAt;
        if (this.requests >= this.limits.maxRequests)
            throw new BudgetExceededError('requests', `${this.requests}/${this.limits.maxRequests}`);
        if (wallMs >= this.limits.maxWallMs)
            throw new BudgetExceededError('wallMs', `${wallMs}/${this.limits.maxWallMs}`);
        if (this.bytes >= this.limits.maxBytes)
            throw new BudgetExceededError('bytes', `${this.bytes}/${this.limits.maxBytes}`);

        this.requests++;
        let committed = false;
        return (bytes: number) => {
            if (committed) return;
            committed = true;
            this.bytes += Math.max(0, bytes);
        };
    }

    snapshot(): BudgetSnapshot {
        const wallMs = Date.now() - this.startedAt;
        return {
            requests: this.requests,
            bytes: this.bytes,
            wallMs,
            limits: this.limits,
            remaining: {
                requests: Math.max(0, this.limits.maxRequests - this.requests),
                bytes: Math.max(0, this.limits.maxBytes - this.bytes),
                wallMs: Math.max(0, this.limits.maxWallMs - wallMs),
            },
        };
    }

    /** True if any dimension is exhausted. */
    exhausted(): { exhausted: boolean; limiting?: 'requests' | 'bytes' | 'wallMs' } {
        const snap = this.snapshot();
        if (snap.remaining.requests === 0) return { exhausted: true, limiting: 'requests' };
        if (snap.remaining.bytes === 0) return { exhausted: true, limiting: 'bytes' };
        if (snap.remaining.wallMs === 0) return { exhausted: true, limiting: 'wallMs' };
        return { exhausted: false };
    }
}

// ────────────────────────────────────────────────────────────
// Registry keyed by scanId
// ────────────────────────────────────────────────────────────

const registry = new Map<string, RequestBudget>();

export function budgetTrackerFor(scanId: string, limits: BudgetLimits): RequestBudget {
    const existing = registry.get(scanId);
    if (existing) return existing;
    const t = new RequestBudget(scanId, limits);
    registry.set(scanId, t);
    return t;
}

export function releaseBudgetTracker(scanId: string): void {
    registry.delete(scanId);
}

/** Tests only. */
export function _clearBudgetRegistry(): void {
    registry.clear();
}
