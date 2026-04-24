// InjectProof — Response-manifold baseline cluster
// For each (endpoint, parameter) pair the oracle first learns the natural
// range of responses under *benign* inputs. An attack response is anomalous
// only when it falls outside that learned manifold.
//
// We keep the statistics cheap and online: per-axis mean + variance via
// Welford's algorithm, a compact vocabulary set, and a frozen list of
// observed simhashes. The threshold is learned from benign-vs-benign
// distances (k-sigma), not hardcoded.
//
// Replaces `baseline.body.length` diff heuristics in the legacy detectors.

import type { BaselineSample, ResponseFeatures } from '@/types';
import { extractFeatures, tokenize, simhashHamming, collectBaselineVocabulary } from './features';

// ============================================================
// Benign-variant generator
// ============================================================

/**
 * Build a short list of benign input variants for a parameter. These are
 * deliberately *not* attack payloads — the goal is to stress the response
 * manifold with inputs the target considers legitimate, so later attack
 * responses have a high-variance backdrop to stand out against.
 */
export function benignVariants(originalValue: string, paramName: string): Array<{ value: string; label: string }> {
    const variants: Array<{ value: string; label: string }> = [];
    variants.push({ value: originalValue, label: 'original' });
    if (originalValue !== '') variants.push({ value: '', label: 'empty' });
    variants.push({ value: 'test', label: 'literal-test' });

    // Numeric type probe
    if (/^\d+$/.test(originalValue)) {
        variants.push({ value: String(parseInt(originalValue, 10) + 1), label: 'numeric-inc' });
        variants.push({ value: '0', label: 'numeric-zero' });
    } else {
        variants.push({ value: '123', label: 'numeric-swap' });
    }

    // Same-length random
    if (originalValue.length > 0) {
        const rand = Array.from({ length: Math.min(originalValue.length, 16) }, () =>
            String.fromCharCode(97 + Math.floor(seeded(paramName) * 26)),
        ).join('');
        variants.push({ value: rand, label: 'same-length-random' });
    }

    // Longer value
    variants.push({ value: 'benign-' + paramName.slice(0, 8), label: 'labeled-benign' });

    return variants;
}

// Tiny deterministic RNG — we want identical baseline across replay runs
// so scan determinism (Phase 4 gate) is achievable.
function seeded(seed: string): number {
    let h = 2166136261;
    for (let i = 0; i < seed.length; i++) {
        h ^= seed.charCodeAt(i);
        h = Math.imul(h, 16777619);
    }
    // xorshift to spread
    h ^= h << 13;
    h ^= h >>> 17;
    h ^= h << 5;
    return ((h >>> 0) % 1_000_000) / 1_000_000;
}

// ============================================================
// Welford per-axis statistics
// ============================================================

interface WelfordAxis {
    count: number;
    mean: number;
    m2: number; // sum of squared deltas; variance = m2/(count-1)
}

function emptyAxis(): WelfordAxis {
    return { count: 0, mean: 0, m2: 0 };
}

function update(axis: WelfordAxis, value: number): void {
    axis.count++;
    const delta = value - axis.mean;
    axis.mean += delta / axis.count;
    axis.m2 += delta * (value - axis.mean);
}

function stddev(axis: WelfordAxis, floor = 1): number {
    if (axis.count < 2) return floor;
    const variance = axis.m2 / (axis.count - 1);
    // Numerical-stability floor only: we never want to divide by 0 on a
    // perfectly-stable axis, but the floor must be tiny enough not to mask
    // real anomalies. Tests previously required `< 5` on a [100,102,98,101,99]
    // sample — the true stddev is ~1.58 — so a floor of 16 was wrong.
    return Math.max(Math.sqrt(variance), floor);
}

// ============================================================
// BaselineCluster
// ============================================================

export interface BaselineClusterStats {
    sampleCount: number;
    length: { mean: number; stddev: number };
    wordCount: { mean: number; stddev: number };
    responseTimeMs: { mean: number; stddev: number };
    simhashMean: number;
    simhashStddev: number;
    statusClasses: Set<number>;
    headerSetHashes: Set<string>;
    domHashes: Set<string>;
    vocabulary: Set<string>;
    simhashes: string[];
    /** k-sigma threshold for "anomalous" learned from benign-vs-benign simhash variance. */
    anomalyThreshold: number;
}

export class BaselineCluster {
    readonly samples: BaselineSample[] = [];
    private lengthStat = emptyAxis();
    private wcStat = emptyAxis();
    private timeStat = emptyAxis();
    private simhashAxis = emptyAxis(); // tracks mean hamming from centroid
    readonly statusClasses = new Set<number>();
    readonly headerSetHashes = new Set<string>();
    readonly domHashes = new Set<string>();
    readonly simhashes: string[] = [];
    private vocab = new Set<string>();
    private centroidSimhash: string | null = null;

    addSample(sample: BaselineSample, body: string): void {
        this.samples.push(sample);
        this.simhashes.push(sample.features.contentSimhash);
        update(this.lengthStat, sample.features.length);
        update(this.wcStat, sample.features.wordCount);
        update(this.timeStat, sample.features.responseTimeMs);
        this.statusClasses.add(Math.floor(sample.features.status / 100));
        this.headerSetHashes.add(sample.features.headerSetHash);
        if (sample.features.domStructureHash) this.domHashes.add(sample.features.domStructureHash);
        for (const t of tokenize(body)) this.vocab.add(t);

        // Centroid = median simhash by min pairwise hamming; approximate with first sample
        if (!this.centroidSimhash) this.centroidSimhash = sample.features.contentSimhash;
        else {
            const d = simhashHamming(this.centroidSimhash, sample.features.contentSimhash);
            update(this.simhashAxis, d);
        }
    }

    /** Snapshot for downstream distance function. */
    stats(): BaselineClusterStats {
        const simhashMean = this.simhashAxis.mean;
        const simhashStd = stddev(this.simhashAxis, 1);
        const lStd = stddev(this.lengthStat, 1);
        const wStd = stddev(this.wcStat, 1);
        const tStd = stddev(this.timeStat, 5);

        // Adaptive anomaly threshold — replaces the hardcoded 3.0σ constant.
        // For each benign sample we compute its composite z-score from the
        // cluster centroid (the same axes the distance function uses). The
        // threshold is set at mean + 2.5σ of that within-cluster distribution,
        // clamped to [2.0, 8.0]. A tightly-grouped endpoint (all responses
        // nearly identical) gets a tighter threshold; a high-variance endpoint
        // (e.g., dynamic ads) gets a looser one — both calibrated from data.
        let anomalyThreshold = 3.0;
        if (this.samples.length >= 4 && this.centroidSimhash) {
            const selfScores = this.samples.map((s, i) => {
                const lenZ = Math.min(Math.abs(s.features.length - this.lengthStat.mean) / lStd, 6);
                const wcZ = Math.min(Math.abs(s.features.wordCount - this.wcStat.mean) / wStd, 6);
                const tZ = Math.min(Math.max(0, s.features.responseTimeMs - this.timeStat.mean) / tStd, 6);
                const hamming = simhashHamming(this.centroidSimhash!, this.simhashes[i]);
                const simZ = Math.min(simhashStd > 0 ? hamming / simhashStd : hamming / 8, 6);
                return Math.sqrt(lenZ ** 2 + wcZ ** 2 + tZ ** 2 + simZ ** 2);
            });
            const n = selfScores.length;
            const mean = selfScores.reduce((s, v) => s + v, 0) / n;
            const variance = selfScores.reduce((s, v) => s + (v - mean) ** 2, 0) / Math.max(n - 1, 1);
            anomalyThreshold = Math.min(Math.max(mean + 2.5 * Math.sqrt(variance), 2.0), 8.0);
        }

        return {
            sampleCount: this.samples.length,
            length: { mean: this.lengthStat.mean, stddev: lStd },
            wordCount: { mean: this.wcStat.mean, stddev: wStd },
            responseTimeMs: { mean: this.timeStat.mean, stddev: tStd },
            simhashMean,
            simhashStddev: simhashStd,
            statusClasses: new Set(this.statusClasses),
            headerSetHashes: new Set(this.headerSetHashes),
            domHashes: new Set(this.domHashes),
            vocabulary: new Set(this.vocab),
            simhashes: [...this.simhashes],
            anomalyThreshold,
        };
    }

    vocabulary(): ReadonlySet<string> {
        return this.vocab;
    }
}

// ============================================================
// Build a baseline from a request function
// ============================================================

export interface BaselineBuildInput {
    paramName: string;
    paramValue: string;
    /** Caller-supplied request that sends one benign variant and returns the raw response payload. */
    probe: (variant: { value: string; label: string }) => Promise<{
        status: number;
        headers: Record<string, string>;
        body: string;
        responseTimeMs: number;
    } | null>;
    /** Hard ceiling on how many variants to send (default 7). */
    maxVariants?: number;
    /** Minimum samples required to consider the baseline usable (default 3). */
    minSamples?: number;
}

/**
 * Run all benign variants against the target, extract features for each
 * response, build the cluster, and return it along with the token
 * vocabulary. If too few samples succeed (network flaky, target down) we
 * return null so the caller can decide to skip this (endpoint, param)
 * rather than produce noisy verdicts from a bad baseline.
 */
export async function buildBaseline(input: BaselineBuildInput): Promise<BaselineCluster | null> {
    const variants = benignVariants(input.paramValue, input.paramName).slice(0, input.maxVariants ?? 7);
    const cluster = new BaselineCluster();
    const bodies: string[] = [];

    for (const variant of variants) {
        const res = await input.probe(variant);
        if (!res) continue;
        bodies.push(res.body);
        const features = extractFeatures({
            status: res.status,
            headers: res.headers,
            body: res.body,
            responseTimeMs: res.responseTimeMs,
        });
        const sample: BaselineSample = {
            requestAt: new Date().toISOString(),
            features,
            variant: variant.label,
        };
        cluster.addSample(sample, res.body);
    }

    // Refresh vocab with collectBaselineVocabulary (cheap sanity)
    const fullVocab = collectBaselineVocabulary(bodies);
    for (const t of fullVocab) cluster.vocabulary(); // no-op, vocab already populated

    if (cluster.samples.length < (input.minSamples ?? 3)) return null;
    return cluster;
}
