// InjectProof — Compound response-distance function
// Produces a single scalar anomaly score in σ-units by normalizing each
// feature axis against the baseline's own variance, then composing. Replaces
// per-detector `responseDiff > 50` heuristics.
//
// A score of 0 means "identical to baseline mean" across all axes. A score
// >= cluster.anomalyThreshold (default 3.0) is flagged anomalous. The
// composition is additive-quadratic: each axis contributes its squared
// z-score, and the total is sqrt(sum) — classic Mahalanobis-on-diagonal.

import type { ResponseFeatures } from '@/types';
import type { BaselineClusterStats } from './baseline';
import { simhashHamming } from './features';

export interface DistanceBreakdown {
    total: number;
    contributions: {
        status: number;
        length: number;
        wordCount: number;
        responseTime: number;
        simhash: number;
        headers: number;
        domStructure: number;
        newTokens: number;
    };
    /** Words in candidate that never appeared in baseline — strongest single signal for error-based SQLi. */
    unseenTokens: string[];
}

export interface DistanceOptions {
    /** Clip any single axis at this σ. Prevents one pathological axis from dominating. */
    perAxisCap?: number;
    /** Whether to factor `newTokens` into distance. Default true. */
    useNewTokens?: boolean;
    /** Extra dictionary of "known-suspicious" tokens that amplify the newTokens signal when present. */
    suspiciousTokens?: ReadonlySet<string>;
}

const DEFAULT_OPTS: Required<DistanceOptions> = {
    perAxisCap: 6,
    useNewTokens: true,
    suspiciousTokens: new Set(),
};

/**
 * Compute the composite σ-distance of a candidate response from the baseline
 * cluster. Each axis contributes its normalized z-score squared; total is
 * the sqrt of the sum.
 */
export function responseDistance(
    candidate: ResponseFeatures,
    baseline: BaselineClusterStats,
    candidateTokens: ReadonlySet<string> | null,
    options: DistanceOptions = {},
): DistanceBreakdown {
    const opts = { ...DEFAULT_OPTS, ...options };
    const contributions = {
        status: 0,
        length: 0,
        wordCount: 0,
        responseTime: 0,
        simhash: 0,
        headers: 0,
        domStructure: 0,
        newTokens: 0,
    };

    // ── Status class axis ──────────────────────────────────────
    // Ordinal: 2xx/3xx/4xx/5xx. A different class than any baseline sample
    // saw is a strong signal — treat as 3σ equivalent.
    const candClass = Math.floor(candidate.status / 100);
    if (!baseline.statusClasses.has(candClass)) contributions.status = 3.0;
    else if (candidate.status !== [...baseline.statusClasses].pop()) contributions.status = 0.5;

    // ── Length axis ────────────────────────────────────────────
    contributions.length = clip(
        Math.abs(candidate.length - baseline.length.mean) / baseline.length.stddev,
        opts.perAxisCap,
    );

    // ── Word-count axis ────────────────────────────────────────
    contributions.wordCount = clip(
        Math.abs(candidate.wordCount - baseline.wordCount.mean) / baseline.wordCount.stddev,
        opts.perAxisCap,
    );

    // ── Timing axis ────────────────────────────────────────────
    // This is the oracle replacement for the `> 4000ms` time-based SQLi
    // threshold: p-value against the learned timing distribution, in σ.
    contributions.responseTime = clip(
        Math.max(0, candidate.responseTimeMs - baseline.responseTimeMs.mean) / baseline.responseTimeMs.stddev,
        opts.perAxisCap,
    );

    // ── Content-simhash axis ───────────────────────────────────
    // Min hamming from every baseline simhash; anything way beyond the
    // baseline's internal spread counts as off-manifold.
    let minHam = Infinity;
    for (const h of baseline.simhashes) {
        const d = simhashHamming(h, candidate.contentSimhash);
        if (d < minHam) minHam = d;
    }
    if (!Number.isFinite(minHam)) minHam = 64;
    const simhashZ =
        baseline.simhashStddev > 0
            ? Math.max(0, minHam - baseline.simhashMean) / baseline.simhashStddev
            : minHam / 8; // bootstrap stddev when benign samples were identical
    contributions.simhash = clip(simhashZ, opts.perAxisCap);

    // ── Header set axis ────────────────────────────────────────
    contributions.headers = baseline.headerSetHashes.has(candidate.headerSetHash) ? 0 : 1.5;

    // ── DOM structure axis ─────────────────────────────────────
    if (candidate.domStructureHash) {
        contributions.domStructure = baseline.domHashes.has(candidate.domStructureHash) ? 0 : 2.0;
    }

    // ── Unseen tokens (SQL errors, stack traces, etc) ─────────
    const unseenTokens: string[] = [];
    if (opts.useNewTokens && candidateTokens) {
        let suspiciousHits = 0;
        for (const t of candidateTokens) {
            if (!baseline.vocabulary.has(t)) {
                unseenTokens.push(t);
                if (opts.suspiciousTokens.has(t)) suspiciousHits++;
            }
        }
        // ≥ 5 unseen tokens is unusual; suspicious hits amplify.
        const base = Math.min(unseenTokens.length / 5, 1);
        contributions.newTokens = clip(base * 2 + suspiciousHits * 1.5, opts.perAxisCap);
    }

    const sumSquares = Object.values(contributions).reduce((s, v) => s + v * v, 0);
    return { total: Math.sqrt(sumSquares), contributions, unseenTokens };
}

function clip(n: number, cap: number): number {
    if (!Number.isFinite(n)) return cap;
    return Math.max(0, Math.min(n, cap));
}

// ============================================================
// Built-in suspicious-token dictionary (seed, not oracle)
// ============================================================
//
// These show up in SQL error messages across DBMSes. Presence in an
// "unseen tokens" set amplifies the distance score but never sole-triggers
// a verdict — the cluster-distance must also be anomalous. This list is a
// *seed* to Phase 2's synthesis, not the detection oracle itself.
export const SUSPICIOUS_TOKENS: ReadonlySet<string> = new Set([
    'sql', 'syntax', 'mysql', 'mariadb', 'postgresql', 'postgres', 'sqlite', 'mssql', 'oracle',
    'odbc', 'sqlstate', 'unclosed', 'quotation', 'near', 'error', 'exception', 'traceback',
    'warning', 'fatal', 'pdoexception', 'pg_query', 'mysqli', 'mysql_query', 'sqlcipher',
    'sqlexception', 'ora-', 'postgresql_exception', 'syntaxerror',
]);
