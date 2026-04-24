// InjectProof — Info-gain frontier for state-aware exploration
// Replaces the depth/count-capped BFS of crawler.ts with a priority queue
// ordered by expected information gain. The crawler still does the actual
// fetching — this module decides *what to fetch next* given the current
// observation state.
//
// EIG for a candidate URL u given observed state S is approximated as:
//   EIG(u) = α · novelty(u)     — how different u looks from everything in S
//          + β · distance(u)    — how close u is to high-risk endpoints
//          + γ · coverage(u)    — how much new (form, endpoint) surface u exposes
//          − δ · cost(u)        — fetch-time penalty based on observed latency
//
// Weights are kept in config so they can be tuned against the bench report.

import { segmentsOf } from './markov';

export interface FrontierItem {
    url: string;
    method: string;
    /** Where we found this URL — used in provenance + to diversify discovery sources. */
    source: string;
    depth: number;
    /** Caller-supplied priority boost, e.g. for admin/login paths. */
    priorityBoost?: number;
}

export interface ObservationState {
    visited: Set<string>;
    /** URLs that yielded forms — sources of high potential novelty. */
    formBearing: Set<string>;
    /** URLs where prior probes already produced a finding. Nearby URLs inherit risk. */
    findingUrls: Set<string>;
    /** Average fetch latency (ms) — penalizes slow targets. */
    avgLatencyMs: number;
}

export interface FrontierWeights {
    novelty: number;
    riskDistance: number;
    coverage: number;
    cost: number;
}

const DEFAULT_WEIGHTS: FrontierWeights = {
    novelty: 1.0,
    riskDistance: 1.5,
    coverage: 1.2,
    cost: 0.3,
};

// ============================================================
// Scoring
// ============================================================

function segmentJaccard(a: string, b: string): number {
    const as = new Set(segmentsOf(a).map((s) => s.toLowerCase()));
    const bs = new Set(segmentsOf(b).map((s) => s.toLowerCase()));
    if (as.size === 0 && bs.size === 0) return 1;
    let inter = 0;
    for (const x of as) if (bs.has(x)) inter++;
    return inter / Math.max(as.size + bs.size - inter, 1);
}

function novelty(url: string, state: ObservationState): number {
    if (state.visited.size === 0) return 1;
    let maxSim = 0;
    let checked = 0;
    // Sample up to 16 visited URLs to keep novelty O(1) per scoring call.
    for (const v of state.visited) {
        if (checked >= 16) break;
        const sim = segmentJaccard(url, v);
        if (sim > maxSim) maxSim = sim;
        checked++;
    }
    return 1 - maxSim;
}

function riskDistance(url: string, state: ObservationState): number {
    // High-risk paths attract probes — each finding-bearing ancestor contributes.
    const segs = new Set(segmentsOf(url).map((s) => s.toLowerCase()));
    let score = 0;
    for (const f of state.findingUrls) {
        const fSegs = segmentsOf(f).map((s) => s.toLowerCase());
        for (const seg of fSegs) if (segs.has(seg)) score += 0.4;
        if (score >= 1) break;
    }
    // Admin-ish URLs get a tiny, universal bump — not a pattern rule, just a
    // prior based on empirical scanner outcomes.
    const ADMIN_SEGS = new Set(['admin', 'login', 'dashboard', 'manage', 'config', 'api']);
    for (const s of segs) if (ADMIN_SEGS.has(s)) score += 0.2;
    return Math.min(score, 2);
}

function coverage(item: FrontierItem, state: ObservationState): number {
    // A URL found in a <form> action is richer than a URL found in <a href>.
    const sourceBoost =
        item.source === 'form' ? 1.0 : item.source === 'xhr' || item.source === 'fetch' ? 0.8 : 0.5;
    const depthPenalty = Math.max(0, 1 - item.depth * 0.1);
    return sourceBoost * depthPenalty + (state.formBearing.has(item.url) ? 0.3 : 0);
}

function costPenalty(state: ObservationState): number {
    // Latency scales in seconds; a 1s average adds cost 1.0.
    return state.avgLatencyMs / 1000;
}

// ============================================================
// Score + PQ
// ============================================================

export interface ScoredItem extends FrontierItem {
    eig: number;
    components: {
        novelty: number;
        risk: number;
        coverage: number;
        cost: number;
    };
}

export function score(
    item: FrontierItem,
    state: ObservationState,
    weights: FrontierWeights = DEFAULT_WEIGHTS,
): ScoredItem {
    const components = {
        novelty: novelty(item.url, state),
        risk: riskDistance(item.url, state),
        coverage: coverage(item, state),
        cost: costPenalty(state),
    };
    const eig =
        components.novelty * weights.novelty +
        components.risk * weights.riskDistance +
        components.coverage * weights.coverage -
        components.cost * weights.cost +
        (item.priorityBoost ?? 0);
    return { ...item, eig, components };
}

/**
 * Priority queue maintaining items by EIG. Not a full heap — the queue sizes
 * are small (~O(100)) so linear extractmax is fine and keeps code simple.
 */
export class FrontierQueue {
    private items: ScoredItem[] = [];
    private seen = new Set<string>();

    constructor(
        private state: ObservationState,
        private weights: FrontierWeights = DEFAULT_WEIGHTS,
    ) {}

    enqueue(item: FrontierItem): boolean {
        const key = `${item.method}:${item.url}`;
        if (this.seen.has(key)) return false;
        this.seen.add(key);
        this.items.push(score(item, this.state, this.weights));
        return true;
    }

    /** Re-score everything; useful after a batch of crawl observations. */
    rescore(): void {
        this.items = this.items.map((it) => score(it, this.state, this.weights));
    }

    dequeue(): ScoredItem | null {
        if (this.items.length === 0) return null;
        let idx = 0;
        for (let i = 1; i < this.items.length; i++) {
            if (this.items[i].eig > this.items[idx].eig) idx = i;
        }
        const [item] = this.items.splice(idx, 1);
        return item;
    }

    size(): number {
        return this.items.length;
    }

    /** Snapshot for diagnostics / provenance. */
    snapshot(): ScoredItem[] {
        return [...this.items].sort((a, b) => b.eig - a.eig);
    }
}
