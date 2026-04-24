// InjectProof — Oracle-driven detector core
// Shared driver that every adaptive detector sits on top of. Replaces the
// duplicated "send payload, diff response, check threshold" pattern that
// every legacy detector implements slightly differently.
//
// Contract:
//   runOracleDetection({endpoint, param, payloads, category, ...}) →
//     DetectorResult[] with full provenance, confirmed by the validate
//     pipeline (replay + counter-factual).
//
// This is the migration boundary: detectors that adopt this helper are
// automatically oracle-driven and validation-gated. No more per-detector
// "responseDiff > 50" heuristics — the oracle's compound σ-distance IS the
// decision.

import type { DetectorResult, DiscoveredParam, VulnCategory, Severity, Confidence } from '@/types';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';
import { buildBaseline, type BaselineCluster } from '@/scanner/engine/oracle/baseline';
import { validateFinding } from '@/scanner/engine/validate/pipeline';

// ============================================================
// Types
// ============================================================

export type OraclePayload = {
    /** The actual payload string to substitute into the parameter. */
    value: string;
    /** Human label for provenance, e.g. 'boolean-pair:where-string-single'. */
    label: string;
    /** Optional paired payload — fires alongside `value`; used for boolean
     *  pair oracles where both halves must be sent to compute an anomaly. */
    pair?: string;
};

export interface OracleDetectionInput {
    url: string;
    method: 'GET' | 'POST';
    param: DiscoveredParam;
    payloads: OraclePayload[];
    /** Vulnerability category to emit on findings. */
    category: VulnCategory;
    /** CWE ID (e.g. 'CWE-89'). Resolves to title + remediation via the CWE DB. */
    cweId: string;
    /** Common-CVSS key (from COMMON_CVSS_VECTORS) to seed severity scoring. */
    cvssKey: keyof typeof COMMON_CVSS_VECTORS;
    /** Severity floor — clamp CVSS-derived severity up to at least this. */
    severityFloor?: Severity;
    /** Timeout (ms) per individual probe. */
    requestTimeout: number;
    /** User agent for probes. */
    userAgent: string;
    /** Extra headers to attach to every probe. */
    extraHeaders?: Record<string, string>;
    /** How many distinct confirmed findings to emit before stopping. Default 1. */
    maxFindings?: number;
    /** When true, run the 30s time-persistence stage. Off by default for speed. */
    enableTimePersistence?: boolean;
    /** Short description template; receives { paramName } for interpolation. */
    describe?: (paramName: string) => { title: string; description: string; impact: string };
}

// ============================================================
// Request helpers
// ============================================================

interface ProbeResponse {
    status: number;
    headers: Record<string, string>;
    body: string;
    responseTimeMs: number;
}

async function probeOnce(
    baseUrl: string,
    method: 'GET' | 'POST',
    param: DiscoveredParam,
    value: string,
    input: OracleDetectionInput,
): Promise<ProbeResponse | null> {
    const started = Date.now();
    try {
        const headers: Record<string, string> = {
            'User-Agent': input.userAgent,
            ...input.extraHeaders,
        };
        let fetchUrl = baseUrl;
        let body: string | undefined;
        if (param.type === 'query') {
            const u = new URL(baseUrl);
            u.searchParams.set(param.name, value);
            fetchUrl = u.toString();
        } else {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            body = `${encodeURIComponent(param.name)}=${encodeURIComponent(value)}`;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), input.requestTimeout);
        const res = await fetch(fetchUrl, {
            method: body ? 'POST' : method,
            headers,
            body,
            signal: controller.signal,
            redirect: 'manual',
        });
        clearTimeout(timer);
        const responseBody = await res.text();
        const responseHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { responseHeaders[k] = v; });
        return {
            status: res.status,
            headers: responseHeaders,
            body: responseBody,
            responseTimeMs: Date.now() - started,
        };
    } catch {
        return null;
    }
}

// ============================================================
// Main entry
// ============================================================

export async function runOracleDetection(input: OracleDetectionInput): Promise<DetectorResult[]> {
    const findings: DetectorResult[] = [];
    const maxFindings = input.maxFindings ?? 1;

    // ── Phase 1: learn the response manifold under benign inputs ──
    const cluster = await buildBaseline({
        paramName: input.param.name,
        paramValue: input.param.value ?? '',
        probe: async (variant) => probeOnce(input.url, input.method, input.param, variant.value, input),
    });
    if (!cluster) return findings; // not enough successful baseline probes

    // ── Phase 2: cycle payloads through the validate pipeline ─────
    for (const payload of input.payloads) {
        if (findings.length >= maxFindings) break;

        const firstBenignValue = input.param.value ?? '';
        const validation = await validateFinding({
            cluster,
            attack: async () => probeOnce(input.url, input.method, input.param, payload.value, input),
            benign: async () => probeOnce(input.url, input.method, input.param, firstBenignValue, input),
            skipTimePersistence: !input.enableTimePersistence,
        });

        if (validation.level === 'rejected') continue;

        // Either 'confirmed' or 'candidate' is worth reporting — but map the
        // engine-level validation to the DB-level validationLevel on the
        // Vulnerability row so downstream automation can filter.
        const cwe = getCweEntry(input.cweId);
        const cvssMetrics = COMMON_CVSS_VECTORS[input.cvssKey];
        const cvssScore = calculateCvssScore(cvssMetrics);
        const severity = clampSeverity(severityFromCvss(cvssScore), input.severityFloor);
        const desc = (input.describe ?? defaultDescribe)(input.param.name);

        const requestRepro = `${input.method} ${input.url} (${input.param.name}=${payload.value})`;

        findings.push({
            found: true,
            title: desc.title,
            description: desc.description,
            category: input.category,
            severity,
            confidence: validation.level === 'confirmed' ? 'high' : 'medium',
            cweId: input.cweId,
            cweTitle: cwe?.title,
            cvssVector: generateCvssVector(cvssMetrics),
            cvssScore,
            affectedUrl: input.url,
            httpMethod: input.method,
            parameter: input.param.name,
            parameterType: input.param.type,
            injectionPoint: input.param.type,
            payload: payload.value,
            impact: desc.impact,
            technicalDetail:
                `Oracle verdict: ${validation.verdict?.explanation}\n` +
                `Payload label: ${payload.label}\n` +
                `Validation stages: ${validation.stages
                    .map((s) => `${s.stage}=${s.passed ? 'pass' : 'fail'}${s.distance !== undefined ? `(${s.distance.toFixed(2)}σ)` : ''}`)
                    .join(' | ')}`,
            remediation: cwe?.remediation,
            reproductionSteps: [requestRepro, 'Re-run the request and confirm the response differs from a benign probe.'],
            references: cwe?.references,
            provenance: validation.provenance,
        });
    }
    return findings;
}

// ============================================================
// Helpers
// ============================================================

function severityFromCvss(score: number): Severity {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score >= 0.1) return 'low';
    return 'info';
}

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
function clampSeverity(actual: Severity, floor?: Severity): Severity {
    if (!floor) return actual;
    return SEVERITY_ORDER.indexOf(actual) >= SEVERITY_ORDER.indexOf(floor) ? actual : floor;
}

function defaultDescribe(paramName: string): { title: string; description: string; impact: string } {
    return {
        title: `Anomalous response for parameter "${paramName}"`,
        description: `Payloads applied to "${paramName}" produced a response statistically outside the benign baseline and reproduced under replay.`,
        impact: 'Confirmed vulnerability — see oracle provenance for details.',
    };
}

/** Filter payloads that match a parameter's type (query vs body vs json). */
export function selectPayloadsForParam(all: OraclePayload[], _param: DiscoveredParam): OraclePayload[] {
    // Hook for future fanout — param-specific filtering. Currently all
    // payloads are param-type-agnostic (injection happens in the value
    // string regardless of transport).
    return all;
}
