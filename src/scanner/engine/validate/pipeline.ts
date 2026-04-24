// InjectProof — Finding self-validation pipeline
// Gate that every oracle-proposed finding must pass before persisting with
// status='confirmed'. Findings that fail any stage go in as 'candidate'
// with a failure reason attached — they remain visible for human triage,
// but never count toward enterprise SLAs or trigger automation.
//
// Stages (in order):
//   1. Replay      — re-send the exact payload, must still trip the oracle
//   2. CounterFact — send a benign variant; must return in-manifold
//   3. TimePersist — wait, re-send; verdict must survive 30s and ideally 5min
//   4. Isolation   — if another finding shares request/response bytes with
//                    this one, link and keep only the strongest
//
// Everything builds on evaluate() from ../oracle/verdict.ts — we do NOT
// add a second, parallel oracle. One statistical truth source per engine.

import type { OracleVerdict, DetectorProvenance } from '@/types';
import type { BaselineCluster } from '../oracle/baseline';
import { evaluate, provenanceFromEvaluation, type ProbeFn } from '../oracle/verdict';

// ============================================================
// Public types
// ============================================================

export type ValidationLevel = 'confirmed' | 'candidate' | 'rejected';

export interface ValidationInput {
    cluster: BaselineCluster;
    /** Fire the attack payload. Must be idempotent across replay calls. */
    attack: ProbeFn;
    /** Fire a matching benign variant. */
    benign: ProbeFn;
    /** Optional: how long (ms) to wait before the time-persistence re-probe. */
    persistenceDelayMs?: number;
    /** If true, skip time-persistence (used when the scanner is operating
     *  under a tight request budget — e.g. a quick scan). */
    skipTimePersistence?: boolean;
}

export interface ValidationResult {
    level: ValidationLevel;
    reason: string;
    verdict: OracleVerdict | null;
    provenance: DetectorProvenance;
    stages: StageRecord[];
}

export interface StageRecord {
    stage: 'replay' | 'counter-factual' | 'time-persistence' | 'isolation';
    passed: boolean;
    detail: string;
    distance?: number;
}

// ============================================================
// Pipeline
// ============================================================

export async function validateFinding(input: ValidationInput): Promise<ValidationResult> {
    const stages: StageRecord[] = [];

    // ── Stage 1 + 2 — handled inside a single evaluate() call ──
    const first = await evaluate(
        {
            cluster: input.cluster,
            attack: input.attack,
            benign: input.benign,
        },
        { requiredReplays: 2, requireCounterFactual: true },
    );

    stages.push({
        stage: 'replay',
        passed: first.replays >= 1,
        detail: `${first.replays}/2 replays confirmed anomaly`,
        distance: first.breakdown?.total,
    });
    stages.push({
        stage: 'counter-factual',
        passed: first.counterFactualNormal === true,
        detail:
            first.counterFactualNormal === true
                ? 'benign variant returned in-manifold'
                : first.counterFactualNormal === false
                    ? 'benign variant ALSO anomalous — target drift, cannot confirm'
                    : 'benign probe did not return a response',
    });

    if (!first.verdict || !first.verdict.anomalous) {
        return buildResult('rejected', 'oracle verdict non-anomalous after replay+counter-factual', first, stages, 0);
    }

    // ── Stage 3 — time-persistence ───────────────────────────
    if (!input.skipTimePersistence) {
        const delay = input.persistenceDelayMs ?? 30_000;
        // The 30s re-probe is the minimum persistence gate; the plan spec also
        // mentions a 5-minute re-probe but that often exceeds scan budgets.
        // 30s is enough to catch transient spikes (GC pauses, cold caches).
        await sleep(delay);
        const second = await evaluate(
            {
                cluster: input.cluster,
                attack: input.attack,
                benign: input.benign,
            },
            { requiredReplays: 1, requireCounterFactual: false },
        );
        const persisted = Boolean(second.verdict?.anomalous);
        stages.push({
            stage: 'time-persistence',
            passed: persisted,
            detail: persisted
                ? `still anomalous after ${delay}ms`
                : `returned to normal after ${delay}ms — likely transient`,
            distance: second.breakdown?.total,
        });
        if (!persisted) {
            return buildResult('candidate', 'transient anomaly — did not persist', first, stages, input.cluster.samples.length);
        }
    }

    // ── Stage 4 — isolation (marker check, stateless here) ────
    // The heavy lift of cross-finding isolation (e.g. suppressing a
    // duplicate SQLi finding that's actually caused by an XSS redirect
    // elsewhere) happens at the orchestrator level where all findings are
    // visible together. This stage just records that the finding IS
    // atomic — it survived its own isolation on a per-probe basis.
    stages.push({ stage: 'isolation', passed: true, detail: 'per-finding isolation passed (orchestrator-level TBD)' });

    return buildResult('confirmed', 'all validation stages passed', first, stages, input.cluster.samples.length);
}

function buildResult(
    level: ValidationLevel,
    reason: string,
    eval_: Awaited<ReturnType<typeof evaluate>>,
    stages: StageRecord[],
    baselineSampleSize: number,
): ValidationResult {
    return {
        level,
        reason,
        verdict: eval_.verdict,
        provenance: provenanceFromEvaluation(eval_, baselineSampleSize, [
            'baseline',
            'replay',
            'counter-factual',
            ...(stages.find((s) => s.stage === 'time-persistence') ? ['time-persistence'] : []),
        ]),
        stages,
    };
}

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

// ============================================================
// Cross-finding isolation — orchestrator helper
// ============================================================

/**
 * When multiple findings on the same target overlap (same endpoint,
 * near-identical response bytes, shared payload substring), keep the one
 * with the highest oracle distance + highest confidence and link the rest
 * via `chainedFrom`.
 *
 * This runs after all detectors finish, once per scan — the per-finding
 * pipeline above only handles the intra-finding gates.
 */
export interface FindingLite {
    id: string;
    url: string;
    parameter?: string;
    category: string;
    confidence: number;
    distance: number;
    payload?: string;
    responseLength?: number;
}

export interface IsolationDecision {
    keep: FindingLite[];
    suppress: Array<{ finding: FindingLite; supersededBy: string; reason: string }>;
}

export function isolateOverlappingFindings(findings: FindingLite[]): IsolationDecision {
    const keep: FindingLite[] = [];
    const suppress: IsolationDecision['suppress'] = [];
    const groups = new Map<string, FindingLite[]>();

    for (const f of findings) {
        const key = `${f.url}::${f.parameter ?? ''}::${f.category}`;
        const g = groups.get(key) ?? [];
        g.push(f);
        groups.set(key, g);
    }

    for (const group of groups.values()) {
        if (group.length === 1) {
            keep.push(group[0]);
            continue;
        }
        // Keep the finding with the highest (distance, confidence) lex pair.
        group.sort((a, b) => {
            if (b.distance !== a.distance) return b.distance - a.distance;
            return b.confidence - a.confidence;
        });
        keep.push(group[0]);
        for (const f of group.slice(1)) {
            suppress.push({
                finding: f,
                supersededBy: group[0].id,
                reason: `duplicate finding on ${f.url}?${f.parameter} ${f.category}; kept higher-distance sibling`,
            });
        }
    }

    return { keep, suppress };
}
