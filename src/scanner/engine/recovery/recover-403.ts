// InjectProof — 403 / WAF / Cloudflare recovery driver
// รับ ChallengeVerdict จาก classifier แล้วเดินตามลำดับ step 1→7 ที่อธิบายไว้ใน
// docs/enterprise/05-TEST-PLAN.md. Caller ส่ง `retry(adjustments)` ให้
// re-execute request; driver ไม่รู้จัก fetch/Puppeteer เอง — แยก concerns.

import { CircuitBreaker, globalCircuitBreaker } from './circuit-breaker';
import { DESKTOP_UA_POOL, rotateUa } from './ua-pool';
import { classifyChallenge, type ChallengeInput, type ChallengeVerdict } from './challenge-detect';

// ────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────

export interface RecoveryAdjustments {
    extraHeaders?: Record<string, string>;
    removeHeaders?: string[];
    userAgent?: string;
    waitMs?: number;
    useBrowser?: boolean;
    tlsFingerprintHint?: 'chrome' | 'firefox' | 'safari';
}

export interface RecoveryAttempt {
    step: string;
    adjustments: RecoveryAdjustments;
    verdict: ChallengeVerdict;
    durationMs: number;
    ok: boolean;
}

export interface RecoveryResponse {
    status: number;
    headers: Record<string, string>;
    bodyPreview?: string;
}

export interface RecoveryBudget {
    maxRetries: number;
    maxTotalWaitMs: number;
    maxWallMs: number;
}

export interface RecoverOptions {
    /** Initial verdict that triggered this recovery (from classifyChallenge). */
    verdict: ChallengeVerdict;
    /** Caller-supplied fn that re-executes the request with adjustments. */
    retry: (adj: RecoveryAdjustments) => Promise<RecoveryResponse | null>;
    /** Hostname key for circuit breaker scope. */
    host: string;
    /** Optional budget cap. Default: 5 retries / 3 min total wait / 10 min wall. */
    budget?: Partial<RecoveryBudget>;
    /** Inject a custom breaker (tests) — defaults to the process-global one. */
    breaker?: CircuitBreaker;
    /** Emit per-step events. No-op default; tests capture events. */
    onEvent?: (attempt: RecoveryAttempt) => void;
    /** Clock injection for tests. */
    now?: () => number;
    /** Sleep injection for tests — receives ms, returns a promise. */
    sleep?: (ms: number) => Promise<void>;
}

export interface RecoveryResult {
    recovered: boolean;
    finalResponse: RecoveryResponse | null;
    stepsUsed: string[];
    circuitOpen: boolean;
    budgetExhausted: boolean;
    reason?: string;
}

// ────────────────────────────────────────────────────────────
// Main driver
// ────────────────────────────────────────────────────────────

/**
 * Walk the 7-step recovery ladder in order. Stops at the first step that
 * returns an `ok` verdict. Each step escalates: from cheap header massage
 * to browser handoff. Always records the decision on the per-host circuit
 * breaker so abusive retries are short-circuited process-wide.
 */
export async function recover(opts: RecoverOptions): Promise<RecoveryResult> {
    const breaker = opts.breaker ?? globalCircuitBreaker();
    const now = opts.now ?? Date.now;
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const budget: RecoveryBudget = {
        maxRetries: opts.budget?.maxRetries ?? 5,
        maxTotalWaitMs: opts.budget?.maxTotalWaitMs ?? 3 * 60_000,
        maxWallMs: opts.budget?.maxWallMs ?? 10 * 60_000,
    };

    const stepsUsed: string[] = [];
    const started = now();
    let waitBudgetLeft = budget.maxTotalWaitMs;
    let retriesUsed = 0;
    let uaIndex = -1;

    if (!breaker.allow(opts.host)) {
        return {
            recovered: false,
            finalResponse: null,
            stepsUsed,
            circuitOpen: true,
            budgetExhausted: false,
            reason: `circuit open for host ${opts.host}`,
        };
    }

    // Step definitions as a list of lambdas so the order is explicit and
    // testable, not buried in if/else.
    const steps: Array<{ name: string; build: () => RecoveryAdjustments }> = [
        {
            name: 'realistic-headers',
            build: () => ({
                extraHeaders: {
                    Accept:
                        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9,th;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Upgrade-Insecure-Requests': '1',
                },
            }),
        },
        {
            name: 'strip-automation',
            build: () => ({
                removeHeaders: ['Sec-Purpose', 'Sec-Fetch-Dest', 'X-Scanner'],
                userAgent: DESKTOP_UA_POOL[0].ua,
            }),
        },
        {
            name: 'jittered-backoff',
            build: () => ({
                waitMs: jitter(opts.verdict.suggestedWaitMs || 5_000, retriesUsed),
            }),
        },
        {
            name: 'ua-rotate',
            build: () => {
                const { ua, nextIndex } = rotateUa(uaIndex);
                uaIndex = nextIndex;
                return { userAgent: ua };
            },
        },
        {
            name: 'tls-fingerprint-hint',
            build: () => ({ tlsFingerprintHint: 'chrome' as const }),
        },
        {
            name: 'browser-handoff',
            build: () => ({ useBrowser: true, userAgent: DESKTOP_UA_POOL[0].ua }),
        },
    ];

    for (const step of steps) {
        if (retriesUsed >= budget.maxRetries) {
            return {
                recovered: false,
                finalResponse: null,
                stepsUsed,
                circuitOpen: false,
                budgetExhausted: true,
                reason: `retries exhausted (${retriesUsed})`,
            };
        }
        if (now() - started >= budget.maxWallMs) {
            return {
                recovered: false,
                finalResponse: null,
                stepsUsed,
                circuitOpen: false,
                budgetExhausted: true,
                reason: `wall-time exhausted`,
            };
        }

        const adj = step.build();
        if (adj.waitMs) {
            const w = Math.min(adj.waitMs, waitBudgetLeft);
            if (w > 0) await sleep(w);
            waitBudgetLeft -= w;
        }

        const stepStarted = now();
        const response = await opts.retry(adj);
        retriesUsed++;
        const durationMs = now() - stepStarted;

        if (!response) {
            const verdict: ChallengeVerdict = {
                class: '403-waf-generic',
                signals: ['retry returned null'],
                retryable: false,
                suggestedWaitMs: 0,
            };
            opts.onEvent?.({ step: step.name, adjustments: adj, verdict, durationMs, ok: false });
            stepsUsed.push(step.name);
            breaker.record(opts.host, 'fail');
            continue;
        }

        const classifyInput: ChallengeInput = {
            status: response.status,
            headers: response.headers,
            bodyPreview: response.bodyPreview,
        };
        const verdict = classifyChallenge(classifyInput);
        const ok = verdict.class === 'ok';
        opts.onEvent?.({ step: step.name, adjustments: adj, verdict, durationMs, ok });
        stepsUsed.push(step.name);

        if (ok) {
            breaker.record(opts.host, 'success');
            return { recovered: true, finalResponse: response, stepsUsed, circuitOpen: false, budgetExhausted: false };
        }
        breaker.record(opts.host, 'fail');
    }

    // Step 7 — abandon.
    stepsUsed.push('abandon');
    return {
        recovered: false,
        finalResponse: null,
        stepsUsed,
        circuitOpen: !breaker.allow(opts.host),
        budgetExhausted: false,
        reason: 'recovery_exhausted',
    };
}

// ────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────

function jitter(baseMs: number, attempt: number): number {
    const expo = Math.min(baseMs * Math.pow(2, attempt), 60_000);
    const j = expo * 0.25 * (Math.random() * 2 - 1); // ±25 %
    return Math.max(0, Math.round(expo + j));
}
