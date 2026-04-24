// InjectProof — Oracle verdict + replay gate
// Replaces `if responseDiff > 50 && errorPattern.matched` heuristics across
// every detector. Now: a finding is only reported when
//   (1) candidate distance > cluster.anomalyThreshold
//   (2) K re-probes with the same payload remain anomalous (replay)
//   (3) a fresh benign probe returns to in-manifold (counter-factual)
//
// Confidence is a Bayesian posterior: prior 0.5, each confirming replay
// multiplies odds ≥ 3×, counter-factual anti-replay multiplies ≥ 2×.

import type { OracleVerdict, ResponseFeatures } from '@/types';
import type { BaselineCluster } from './baseline';
import { responseDistance, SUSPICIOUS_TOKENS, type DistanceBreakdown } from './distance';
import { extractFeatures, tokenize } from './features';

export interface VerdictOptions {
    /** Number of additional replays required to confirm. Default 2. */
    requiredReplays?: number;
    /** Require a fresh benign probe to return to in-manifold. Default true. */
    requireCounterFactual?: boolean;
    /** Optional suspicious-tokens override. */
    suspiciousTokens?: ReadonlySet<string>;
}

export interface ProbeFn {
    (): Promise<{ status: number; headers: Record<string, string>; body: string; responseTimeMs: number } | null>;
}

export interface VerdictContext {
    cluster: BaselineCluster;
    /** The attack probe — fires the payload and returns a raw response. */
    attack: ProbeFn;
    /** A benign probe — fires a non-attack value for the same parameter. Used for counter-factual. */
    benign: ProbeFn;
    /** Initial attack response; caller has already run the first probe to get here. */
    initialResponse?: { status: number; headers: Record<string, string>; body: string; responseTimeMs: number };
}

const DEFAULTS: Required<VerdictOptions> = {
    requiredReplays: 2,
    requireCounterFactual: true,
    suspiciousTokens: SUSPICIOUS_TOKENS,
};

/**
 * Full oracle pipeline for one candidate payload. Returns the verdict plus
 * the *audit trail* — every response it sampled along the way, so the
 * finding's `provenance` block can be populated with real numbers (not
 * synthetic ones).
 */
export async function evaluate(
    ctx: VerdictContext,
    options: VerdictOptions = {},
): Promise<{
    verdict: OracleVerdict | null;
    probes: number;
    replays: number;
    counterFactualNormal: boolean | null;
    breakdown: DistanceBreakdown | null;
}> {
    const opts = { ...DEFAULTS, ...options };
    const stats = ctx.cluster.stats();
    const vocab = ctx.cluster.vocabulary();

    let probes = 0;

    // Attack probe 1 — reuse initialResponse if supplied to avoid double-fetching.
    const firstRes = ctx.initialResponse ?? (await ctx.attack());
    probes += ctx.initialResponse ? 0 : 1;
    if (!firstRes) {
        return { verdict: null, probes, replays: 0, counterFactualNormal: null, breakdown: null };
    }

    const firstFeatures = extractFeatures({
        status: firstRes.status,
        headers: firstRes.headers,
        body: firstRes.body,
        responseTimeMs: firstRes.responseTimeMs,
        baselineTokens: vocab,
    });
    const firstTokens = new Set(tokenize(firstRes.body));
    const firstDist = responseDistance(firstFeatures, stats, firstTokens, {
        suspiciousTokens: opts.suspiciousTokens,
    });

    if (firstDist.total < stats.anomalyThreshold) {
        // Not anomalous on first shot — no need to burn replay probes.
        return {
            verdict: {
                anomalous: false,
                distance: firstDist.total,
                threshold: stats.anomalyThreshold,
                confidence: 0,
                features: firstFeatures,
                explanation: `distance ${firstDist.total.toFixed(2)}σ below threshold ${stats.anomalyThreshold}`,
            },
            probes,
            replays: 0,
            counterFactualNormal: null,
            breakdown: firstDist,
        };
    }

    // Replay confirmation — independent probes with the same payload.
    let replays = 0;
    for (let i = 0; i < opts.requiredReplays; i++) {
        const r = await ctx.attack();
        probes++;
        if (!r) continue;
        const f = extractFeatures({
            status: r.status,
            headers: r.headers,
            body: r.body,
            responseTimeMs: r.responseTimeMs,
            baselineTokens: vocab,
        });
        const t = new Set(tokenize(r.body));
        const d = responseDistance(f, stats, t, { suspiciousTokens: opts.suspiciousTokens });
        if (d.total >= stats.anomalyThreshold) replays++;
    }

    // Counter-factual — a benign probe should NOT be anomalous. If it is,
    // the target has drifted since baseline was built and the original
    // finding is unsafe to confirm.
    let counterFactualNormal: boolean | null = null;
    if (opts.requireCounterFactual) {
        const cf = await ctx.benign();
        probes++;
        if (cf) {
            const f = extractFeatures({
                status: cf.status,
                headers: cf.headers,
                body: cf.body,
                responseTimeMs: cf.responseTimeMs,
                baselineTokens: vocab,
            });
            const t = new Set(tokenize(cf.body));
            const d = responseDistance(f, stats, t, { suspiciousTokens: opts.suspiciousTokens });
            counterFactualNormal = d.total < stats.anomalyThreshold;
        } else {
            counterFactualNormal = null;
        }
    }

    // Posterior confidence via Bayesian odds. Prior = 0.5.
    // Each replay: +lnOdds(3). Counter-factual confirmed benign: +lnOdds(2).
    // Counter-factual that flags: -lnOdds(2) (evidence of drift).
    let logOdds = 0;
    const replayRatio = opts.requiredReplays === 0 ? 1 : replays / opts.requiredReplays;
    logOdds += Math.log(3) * (replays + (replayRatio === 1 ? 1 : 0));
    if (counterFactualNormal === true) logOdds += Math.log(2);
    if (counterFactualNormal === false) logOdds -= Math.log(2);
    const confidence = 1 / (1 + Math.exp(-logOdds));

    // Anomalous iff: distance exceeds threshold AND majority of replays held
    // AND counter-factual didn't disprove (or wasn't requested).
    const anomalous =
        firstDist.total >= stats.anomalyThreshold &&
        replayRatio >= 0.5 &&
        counterFactualNormal !== false;

    return {
        verdict: {
            anomalous,
            distance: firstDist.total,
            threshold: stats.anomalyThreshold,
            confidence,
            features: firstFeatures,
            explanation: anomalous
                ? `distance ${firstDist.total.toFixed(2)}σ ≥ ${stats.anomalyThreshold}, replays=${replays}/${opts.requiredReplays}, cf=${counterFactualNormal ?? 'skipped'}`
                : `rejected: distance=${firstDist.total.toFixed(2)}σ replays=${replays}/${opts.requiredReplays} cf=${counterFactualNormal ?? 'skipped'}`,
        },
        probes,
        replays,
        counterFactualNormal,
        breakdown: firstDist,
    };
}

/**
 * Convenience: turn an evaluate() result into a partial DetectorProvenance
 * block ready to attach to a DetectorResult.
 */
export function provenanceFromEvaluation(
    eval_: Awaited<ReturnType<typeof evaluate>>,
    baselineSampleSize: number,
    oraclesUsed: string[] = ['baseline', 'replay', 'counter-factual'],
): import('@/types').DetectorProvenance {
    return {
        oraclesUsed,
        probeCount: eval_.probes,
        replayConfirmations: eval_.replays,
        baselineSampleSize,
        distanceScore: eval_.breakdown?.total,
        anomalyThreshold: eval_.verdict?.threshold,
        features: eval_.breakdown
            ? {
                statusDelta: eval_.breakdown.contributions.status,
                lengthZ: eval_.breakdown.contributions.length,
                wordCountZ: eval_.breakdown.contributions.wordCount,
                responseTimeZ: eval_.breakdown.contributions.responseTime,
                simhashZ: eval_.breakdown.contributions.simhash,
                headersZ: eval_.breakdown.contributions.headers,
                domStructureZ: eval_.breakdown.contributions.domStructure,
                newTokensZ: eval_.breakdown.contributions.newTokens,
                unseenCount: eval_.breakdown.unseenTokens.length,
            }
            : undefined,
        generatedAt: new Date().toISOString(),
    };
}
