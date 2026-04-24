// InjectProof — Finding validation contracts
// Zod schemas enforcing required fields on findings produced by the adaptive
// engine. Legacy rule-based detectors that pre-date provenance are validated
// under a looser schema; new oracle-driven detectors must emit full provenance
// or `validateFinding` will downgrade them to `candidate`.
//
// This file is the single source of truth for the runtime shape of a finding.
// The TypeScript interfaces in @/types/index.ts stay for ergonomics, but any
// value crossing the detector → persistence boundary should go through
// `validateFinding(result)` first.

import { z } from 'zod';
import type { DetectorResult } from '@/types';

// ============================================================
// Shared enums (kept in sync with @/types)
// ============================================================

const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const ConfidenceSchema = z.enum(['high', 'medium', 'low']);

// ============================================================
// Provenance — proof-of-work attached to every oracle finding
// ============================================================

export const DetectorProvenanceSchema = z.object({
    oraclesUsed: z.array(z.string()).min(1),
    probeCount: z.number().int().nonnegative(),
    replayConfirmations: z.number().int().nonnegative(),
    baselineSampleSize: z.number().int().nonnegative(),
    distanceScore: z.number().optional(),
    features: z.record(z.string(), z.number()).optional(),
    anomalyThreshold: z.number().optional(),
    generatedAt: z.string(),
});

// ============================================================
// Base finding — fields every detector must emit
// ============================================================

const BaseFindingSchema = z.object({
    found: z.boolean(),
    title: z.string().min(3),
    description: z.string().min(3),
    category: z.string().min(1),
    severity: SeveritySchema,
    confidence: ConfidenceSchema,
    affectedUrl: z.string().url(),
    httpMethod: z.string().min(1),
});

// ============================================================
// Category-specific required fields
// These enforce that a SQLi finding cannot ship without a technique,
// an XSS finding cannot ship without a sink context, etc. Adding a
// missing category here means "we do not yet require rich fields for
// this category" — safe to extend incrementally as detectors are
// migrated to the oracle engine.
// ============================================================

const SqliExtras = z.object({
    category: z.literal('sqli'),
    /** DBMS family confirmed during probing. Null = unknown at report time. */
    dbms: z.string().nullable().optional(),
    /** Parsed/inferred injection context, e.g. 'where-string-single-quote'. */
    injectionContext: z.string().optional(),
    /** Which technique actually produced evidence. */
    technique: z.enum(['union', 'error', 'boolean-blind', 'time-blind', 'stacked', 'oob']).optional(),
});

const XssExtras = z.object({
    category: z.literal('xss'),
    /** Sink context where reflection was observed. */
    sinkContext: z.enum(['html', 'attr', 'js', 'url', 'css', 'template']).optional(),
    /** Proof that the payload altered the DOM structure, not just echoed text. */
    reflectionProof: z.string().optional(),
});

const GenericExtras = z.object({
    category: z.string().refine((c) => c !== 'sqli' && c !== 'xss', {
        message: 'use the dedicated schema for sqli/xss',
    }),
});

// ============================================================
// Validation entry points
// ============================================================

export type ValidationVerdict =
    | { level: 'confirmed'; finding: DetectorResult; provenance: z.infer<typeof DetectorProvenanceSchema> }
    | { level: 'candidate'; finding: DetectorResult; reason: string }
    | { level: 'rejected'; errors: string[] };

/**
 * Validate a detector result. Returns one of three verdicts:
 *
 * - `confirmed`: passes base shape + category-specific required fields + has a
 *   valid provenance block. Safe to persist with status='confirmed'.
 * - `candidate`: passes base shape but lacks provenance or category extras.
 *   Still persistable, but status should default to 'candidate' / needs human
 *   triage.
 * - `rejected`: fails base shape. Drop and log — the detector is emitting
 *   malformed output and must be fixed.
 */
export function validateFinding(result: DetectorResult): ValidationVerdict {
    const base = BaseFindingSchema.safeParse(result);
    if (!base.success) {
        return {
            level: 'rejected',
            errors: base.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
        };
    }

    const extrasSchema =
        result.category === 'sqli'
            ? SqliExtras
            : result.category === 'xss'
                ? XssExtras
                : GenericExtras;
    const extras = extrasSchema.safeParse(result);
    if (!extras.success) {
        return {
            level: 'candidate',
            finding: result,
            reason: `missing category-specific fields: ${extras.error.issues
                .map((i) => i.path.join('.'))
                .join(', ')}`,
        };
    }

    if (!result.provenance) {
        return {
            level: 'candidate',
            finding: result,
            reason: 'no provenance attached — finding predates oracle migration',
        };
    }

    const prov = DetectorProvenanceSchema.safeParse(result.provenance);
    if (!prov.success) {
        return {
            level: 'candidate',
            finding: result,
            reason: `invalid provenance: ${prov.error.issues.map((i) => i.path.join('.')).join(', ')}`,
        };
    }

    return { level: 'confirmed', finding: result, provenance: prov.data };
}

/**
 * Convenience helper for the Phase 1 oracle: returns true only if the finding
 * is eligible for status='confirmed' persistence.
 */
export function isConfirmedFinding(result: DetectorResult): boolean {
    return validateFinding(result).level === 'confirmed';
}
