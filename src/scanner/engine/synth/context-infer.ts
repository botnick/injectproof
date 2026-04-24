// InjectProof — Context inference by probe triangulation
// Replaces the legacy "32 hardcoded ContextProbe enum" from sqli-adaptive.ts.
// Method: send orthogonal marker probes, measure the oracle verdict for each,
// combine the observations via Bayesian update over a prior distribution
// across possible (context, dbms) pairs. Output is a *distribution*, not a
// single choice — downstream synthesis samples weighted.
//
// The key observation: every context responds differently to different
// breakers. A numeric context is untouched by `'` but breaks on unbalanced
// parens; a single-quote string context is the opposite. Cross-referencing
// which markers move the oracle lets us identify the context without ever
// enumerating "if error matches /near line 1/ then context = ..." rules.

import type { BaselineCluster } from '../oracle/baseline';
import type { DbmsFamily, InjectionContext } from './grammar';
import { evaluate } from '../oracle/verdict';

// ============================================================
// Marker catalog — which marker is diagnostic of which context
// ============================================================

interface MarkerDiagnostic {
    marker: string;
    /**
     * For each context, the expected anomaly verdict when this marker is sent.
     * +1 = marker should trigger anomaly in this context
     *  0 = neutral — no strong prior
     * -1 = marker should NOT trigger anomaly (if it does, this context is unlikely)
     */
    signals: Partial<Record<InjectionContext, 1 | 0 | -1>>;
}

const MARKERS: MarkerDiagnostic[] = [
    {
        marker: "'",
        signals: {
            'where-string-single': 1,
            'insert-string': 1,
            'update-string': 1,
            'like': 1,
            'where-string-double': -1,
            'where-numeric': -1,
            'where-backtick': -1,
            'order-by': 0,
        },
    },
    {
        marker: '"',
        signals: {
            'where-string-double': 1,
            'where-string-single': -1,
            'where-numeric': -1,
        },
    },
    {
        marker: '`',
        signals: {
            'where-backtick': 1,
            'where-string-single': -1,
        },
    },
    {
        marker: '\\',
        signals: {
            'where-string-single': 1,
            'where-string-double': 1,
            'like': 1,
        },
    },
    {
        marker: "')",
        signals: {
            'where-paren-string': 1,
            'where-string-single': 0,
        },
    },
    {
        marker: ')',
        signals: {
            'where-paren-numeric': 1,
            'where-numeric': -1,
        },
    },
    {
        marker: '/*',
        signals: {
            // Generic — flags anything that accepts raw SQL tokens.
            'where-string-single': 0,
            'where-numeric': 0,
        },
    },
    {
        marker: ' AND 1=1',
        signals: {
            'where-numeric': 1,
            'order-by': 1,
            'limit': 1,
        },
    },
    {
        marker: ' ORDER BY 1',
        signals: {
            'order-by': 1,
            'where-numeric': -1,
        },
    },
];

// ============================================================
// DBMS fingerprint markers
// ============================================================

interface DbmsToken {
    token: string;
    /** Specificity [0,1]: how uniquely diagnostic this token is for this DBMS.
     *  High (>0.8) = near-unique to this DBMS; Low (<0.3) = shared across many. */
    specificity: number;
}

interface DbmsDiagnostic {
    marker: string;
    family: DbmsFamily;
    /** Base-rate prior — rough market-share estimate, sums to ~1 across families. */
    prior: number;
    signalTokens: DbmsToken[];
}

// Token specificity reflects how uniquely the token identifies a DBMS.
// Highly specific tokens (e.g. "pg_sleep", "ora-00933") dominate the score;
// generic tokens (e.g. "error", "sql") contribute minimally.
const DBMS_MARKERS: DbmsDiagnostic[] = [
    {
        marker: "' AND @@version--",
        family: 'mssql',
        prior: 0.20,
        signalTokens: [
            { token: 'microsoft sql server', specificity: 1.00 },
            { token: 'mssql',                specificity: 0.95 },
            { token: 'sql server',            specificity: 0.82 },
            { token: 'sqlstate',              specificity: 0.45 },
            { token: 'unclosed quotation',    specificity: 0.70 },
            { token: 'incorrect syntax',      specificity: 0.60 },
            { token: 'microsoft',             specificity: 0.15 },
        ],
    },
    {
        marker: "' AND version()--",
        family: 'postgresql',
        prior: 0.22,
        signalTokens: [
            { token: 'postgresql',            specificity: 1.00 },
            { token: 'pg_query',              specificity: 0.95 },
            { token: 'pg_exec',               specificity: 0.95 },
            { token: 'unterminated quoted',   specificity: 0.70 },
            { token: 'pdo::query',            specificity: 0.40 },
            { token: 'postgres',              specificity: 0.85 },
        ],
    },
    {
        marker: "' AND VERSION()--",
        family: 'mysql',
        prior: 0.35,
        signalTokens: [
            { token: 'mysql',                 specificity: 0.90 },
            { token: 'mariadb',               specificity: 0.90 },
            { token: 'mysqli',                specificity: 0.95 },
            { token: 'mysql_fetch',           specificity: 0.95 },
            { token: 'you have an error in your sql', specificity: 0.85 },
            { token: "near '",               specificity: 0.50 },
        ],
    },
    {
        marker: "' AND SQLITE_VERSION()--",
        family: 'sqlite',
        prior: 0.10,
        signalTokens: [
            { token: 'sqlite',                specificity: 1.00 },
            { token: 'sqlite3',               specificity: 1.00 },
            { token: 'sqlite_exec',           specificity: 1.00 },
            { token: 'no such table',         specificity: 0.55 },
        ],
    },
    {
        marker: "' AND BANNER FROM v$version--",
        family: 'oracle',
        prior: 0.13,
        signalTokens: [
            { token: 'oracle',                specificity: 0.85 },
            { token: 'ora-0',                 specificity: 0.95 },
            { token: 'pl/sql',                specificity: 0.90 },
            { token: 'oci_execute',           specificity: 0.95 },
            { token: 'oracle database',       specificity: 0.98 },
        ],
    },
];

// ============================================================
// Core inference
// ============================================================

export interface ContextInferenceInput {
    cluster: BaselineCluster;
    probe: (payload: string) => Promise<{
        status: number;
        headers: Record<string, string>;
        body: string;
        responseTimeMs: number;
    } | null>;
    /** If caller has a strong prior (e.g. from a previous scan), pass it here. */
    prior?: Partial<Record<InjectionContext, number>>;
}

export interface ContextPosterior {
    context: InjectionContext;
    weight: number;
}

export interface ContextInferenceResult {
    contexts: ContextPosterior[];
    dbms: DbmsFamily;
    /** How many probes were consumed. Contributes to DetectorProvenance.probeCount. */
    probesUsed: number;
}

/**
 * Infer the injection context distribution for a parameter by sending
 * marker probes and updating a Dirichlet-like posterior over contexts from
 * the oracle's verdicts.
 */
export async function inferContext(input: ContextInferenceInput): Promise<ContextInferenceResult> {
    const posteriors: Record<InjectionContext, number> = {
        'where-string-single': 1,
        'where-string-double': 1,
        'where-numeric': 1,
        'where-paren-string': 0.5,
        'where-paren-numeric': 0.5,
        'where-backtick': 0.3,
        'order-by': 0.8,
        'limit': 0.3,
        'insert-string': 0.2,
        'update-string': 0.2,
        'like': 0.4,
        'in-numeric': 0.3,
        'having': 0.2,
        'stacked': 0.1,
        'json-string': 0.1,
        'rest-path': 0.2,
    };
    if (input.prior) {
        for (const k of Object.keys(input.prior) as InjectionContext[]) {
            posteriors[k] = Math.max(posteriors[k], input.prior[k] ?? 0);
        }
    }

    let probesUsed = 0;

    // For each marker, the update rule:
    //   if oracle says anomalous → multiply contexts with signal=1 by α (>1)
    //                              multiply contexts with signal=-1 by β (<1)
    //   if oracle says NOT anomalous → swap multipliers
    // This is log-linear Bayesian update with α = 3, β = 0.33.
    for (const mk of MARKERS) {
        const res = await input.probe(mk.marker);
        probesUsed++;
        if (!res) continue;

        // We don't need a full replay for context inference — a single shot
        // against the baseline cluster is cheap and adequate.
        const result = await evaluate(
            {
                cluster: input.cluster,
                attack: async () => res,
                benign: async () => res,
                initialResponse: res,
            },
            { requiredReplays: 0, requireCounterFactual: false },
        );

        const anomalous = Boolean(result.verdict?.anomalous);
        for (const [ctx, signal] of Object.entries(mk.signals) as Array<[InjectionContext, 1 | 0 | -1]>) {
            if (signal === 0) continue;
            if (anomalous) {
                posteriors[ctx] *= signal === 1 ? 3 : 0.33;
            } else {
                posteriors[ctx] *= signal === 1 ? 0.33 : 3;
            }
        }
    }

    // Normalize → distribution sums to 1
    const total = Object.values(posteriors).reduce((s, v) => s + v, 0) || 1;
    const contexts: ContextPosterior[] = (Object.entries(posteriors) as Array<[InjectionContext, number]>)
        .map(([context, weight]) => ({ context, weight: weight / total }))
        .filter((c) => c.weight > 0.01)
        .sort((a, b) => b.weight - a.weight);

    // ── DBMS fingerprint phase — Bayesian weighted scoring ─────
    // Posterior ∝ prior × likelihood where likelihood is the product of
    // specificity weights for matching tokens. Log-linear update prevents
    // underflow and keeps the update incremental across probes.
    const dbmsPosteriors: Record<string, number> = {};
    for (const dm of DBMS_MARKERS) dbmsPosteriors[dm.family] = Math.log(dm.prior);

    for (const dm of DBMS_MARKERS) {
        const res = await input.probe(dm.marker);
        probesUsed++;
        if (!res) continue;
        const lower = res.body.toLowerCase();
        // Weighted score: sum specificity of matching tokens — each matching token
        // amplifies the log-posterior for this family.
        const score = dm.signalTokens.reduce(
            (acc, t) => acc + (lower.includes(t.token) ? t.specificity : 0),
            0,
        );
        if (score > 0) dbmsPosteriors[dm.family] += score * 2; // log-scale update
    }

    // Normalise via log-sum-exp for numerical stability
    const maxLog = Math.max(...Object.values(dbmsPosteriors));
    const sumExp = Object.values(dbmsPosteriors).reduce((s, v) => s + Math.exp(v - maxLog), 0);
    const dbmsRanked = (Object.entries(dbmsPosteriors) as Array<[DbmsFamily, number]>)
        .map(([fam, logP]) => ({ fam, prob: Math.exp(logP - maxLog) / sumExp }))
        .sort((a, b) => b.prob - a.prob);

    // Only commit to a family if its posterior is decisively highest (> 2× the second)
    const topFam = dbmsRanked[0];
    const runnerUp = dbmsRanked[1];
    const dbms: DbmsFamily = topFam && (!runnerUp || topFam.prob > runnerUp.prob * 2)
        ? topFam.fam
        : 'unknown';

    return { contexts, dbms, probesUsed };
}

// ============================================================
// Convenience: collapse posterior into a single top pick
// ============================================================

export function topContext(result: ContextInferenceResult): InjectionContext {
    return result.contexts[0]?.context ?? 'where-string-single';
}
