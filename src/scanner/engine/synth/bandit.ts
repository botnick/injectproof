// InjectProof — Thompson-sampling bandit for technique selection
// Given a confirmed SQLi on a parameter, which extraction technique to use
// next (UNION / error / boolean / time / stacked / OOB)? Trying UNION first
// and falling through a static order (as the legacy code does) wastes
// requests on whatever your stack happens to rank highest.
//
// The bandit learns per-target, per-technique reward distributions online,
// samples from each technique's posterior Beta distribution, and pulls the
// arm with the highest sample. Classic Thompson sampling — no-regret,
// asymptotically optimal, zero hyperparameters.

export type BanditArm =
    | 'union'
    | 'error'
    | 'boolean-blind'
    | 'time-blind'
    | 'stacked'
    | 'oob';

interface ArmStats {
    /** Successes: Beta distribution α - 1 (pseudo-count of "this technique yielded info"). */
    alpha: number;
    /** Failures: Beta distribution β - 1. */
    beta: number;
    /** Running mean reward in arbitrary units (info-bits per request). */
    meanReward: number;
    pulls: number;
}

const PRIOR_ALPHA: Record<BanditArm, number> = {
    union: 3,          // UNION is fast when it works — optimistic prior
    error: 2,
    'boolean-blind': 2,
    'time-blind': 1.5,  // slow — mild negative prior
    stacked: 1.2,
    oob: 1.2,
};
const PRIOR_BETA: Record<BanditArm, number> = {
    union: 2,
    error: 2,
    'boolean-blind': 2,
    'time-blind': 2,
    stacked: 3,         // often blocked
    oob: 3,             // needs OOB infra
};

// ============================================================
// Bandit class
// ============================================================

export class TechniqueBandit {
    private stats: Record<BanditArm, ArmStats>;

    constructor() {
        this.stats = {
            union: this.init('union'),
            error: this.init('error'),
            'boolean-blind': this.init('boolean-blind'),
            'time-blind': this.init('time-blind'),
            stacked: this.init('stacked'),
            oob: this.init('oob'),
        };
    }

    private init(arm: BanditArm): ArmStats {
        return { alpha: PRIOR_ALPHA[arm], beta: PRIOR_BETA[arm], meanReward: 0, pulls: 0 };
    }

    /**
     * Pick the next arm to pull. Samples θ_k ~ Beta(α_k, β_k) for each arm
     * and returns argmax θ — Thompson sampling.
     */
    pick(available: BanditArm[] = Object.keys(this.stats) as BanditArm[]): BanditArm {
        let best: BanditArm = available[0];
        let bestSample = -1;
        for (const arm of available) {
            const s = this.stats[arm];
            const sample = sampleBeta(s.alpha, s.beta);
            if (sample > bestSample) {
                bestSample = sample;
                best = arm;
            }
        }
        return best;
    }

    /**
     * Record a reward in [0, 1] — 1 means "technique yielded useful info per
     * request," 0 means "technique wasted the request." Updates both the
     * Bernoulli posterior and the running reward mean.
     */
    update(arm: BanditArm, reward: number): void {
        const s = this.stats[arm];
        s.pulls++;
        s.meanReward += (reward - s.meanReward) / s.pulls;
        const clamped = Math.max(0, Math.min(1, reward));
        // Beta update: α += reward, β += (1 - reward)
        s.alpha += clamped;
        s.beta += 1 - clamped;
    }

    snapshot(): Record<BanditArm, ArmStats> {
        const out = {} as Record<BanditArm, ArmStats>;
        for (const k of Object.keys(this.stats) as BanditArm[]) out[k] = { ...this.stats[k] };
        return out;
    }
}

// ============================================================
// Beta sampling via two Gamma draws (Marsaglia-Tsang)
// ============================================================

function sampleBeta(alpha: number, beta: number): number {
    const x = sampleGamma(alpha);
    const y = sampleGamma(beta);
    const sum = x + y;
    return sum === 0 ? 0.5 : x / sum;
}

function sampleGamma(shape: number): number {
    if (shape < 1) {
        // Johnk's generator — sufficient for the 1.2–3 prior range we use.
        const u = Math.random();
        return sampleGamma(shape + 1) * Math.pow(u, 1 / shape);
    }
    const d = shape - 1 / 3;
    const c = 1 / Math.sqrt(9 * d);
    for (;;) {
        let x: number, v: number;
        do {
            x = randomNormal();
            v = 1 + c * x;
        } while (v <= 0);
        v = v * v * v;
        const u = Math.random();
        if (u < 1 - 0.0331 * x * x * x * x) return d * v;
        if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
    }
}

// Box-Muller
let spareNormal: number | null = null;
function randomNormal(): number {
    if (spareNormal !== null) {
        const v = spareNormal;
        spareNormal = null;
        return v;
    }
    const u1 = Math.random();
    const u2 = Math.random();
    const r = Math.sqrt(-2 * Math.log(u1));
    const theta = 2 * Math.PI * u2;
    spareNormal = r * Math.sin(theta);
    return r * Math.cos(theta);
}
