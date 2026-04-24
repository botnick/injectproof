// InjectProof — Policy schema
// Dynamic policy loaded from YAML/JSON/DB rather than hardcoded rules.
// เป็น single source of truth สำหรับ "scan นี้ทำอะไรได้/ไม่ได้" ถูกอ่านโดย:
//   - detector runner      → enable/disable detector plugin
//   - request pipeline     → path allowlist/denylist + rate limit + budget
//   - payload synthesis    → allowed payload risk classes
//   - recovery engine      → budget for 403/WAF retries
//   - report exporter      → which formats + retention
//   - safety layer         → kill switch + secret redaction rules
//
// Policy มีลำดับชั้น: default ←← profile (passive_only / enterprise_full /
// ci_fast / spa_deep / authenticated_standard / …) ←← tenant ←← target ←← scan.
// ระดับต่ำกว่า override ระดับสูงกว่า (เหมือน CSS specificity).

import { z } from 'zod';

// ────────────────────────────────────────────────────────────
// Enums + sub-schemas
// ────────────────────────────────────────────────────────────

export const DetectorId = z.string().regex(/^[a-z][a-z0-9_-]*$/, 'must be kebab/snake id');

export const PayloadRiskClass = z.enum([
    'passive',             // pure observation, no probes
    'benign-probe',        // baseline + marker probes with no side effects
    'differential',        // boolean-pair / time-based with low side effect
    'error-trigger',       // may produce error responses in logs
    'active-high',         // SQL/XSS probes that may write minor state
    'dangerous',           // anything that could touch data at rest (blocked by default)
]);
export type PayloadRiskClass = z.infer<typeof PayloadRiskClass>;

export const SeverityOverride = z.enum(['critical', 'high', 'medium', 'low', 'info']);

// Glob pattern list. `*` matches segment, `**` matches any depth.
export const PathPattern = z.string().min(1);

export const HttpMethod = z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);

export const ReportFormat = z.enum(['markdown', 'json', 'html', 'sarif', 'pdf', 'jira', 'github-code-scanning']);

// ────────────────────────────────────────────────────────────
// Top-level schema
// ────────────────────────────────────────────────────────────

// Zod v4 quirk: `.default({})` on a nested z.object does NOT re-parse the
// inner defaults; it substitutes the literal value. We instead explicitly
// parse `{}` once per subtree so inner defaults apply consistently.
const ScopeSub = z.object({
    allowedPaths: z.array(PathPattern).default(['**']),
    deniedPaths: z.array(PathPattern).default([]),
    allowedMethods: z.array(HttpMethod).default(['GET', 'HEAD', 'OPTIONS', 'POST']),
    allowLabTargets: z.boolean().default(false),
    allowPrivateHosts: z.boolean().default(false),
});
const DetectorsSub = z.object({
    enabled: z.array(DetectorId).default([]),
    disabled: z.array(DetectorId).default([]),
    mode: z.enum(['allowlist', 'denylist']).default('denylist'),
    overrides: z.record(
        DetectorId,
        z.object({
            severity: SeverityOverride.optional(),
            confidenceMultiplier: z.number().min(0.1).max(2).default(1),
            extraPayloadBudget: z.number().int().min(0).default(0),
        }),
    ).default({}),
});
const BudgetSub = z.object({
    maxRequests: z.number().int().min(1).default(5_000),
    maxBytes: z.number().int().min(1_024).default(200 * 1024 * 1024),
    maxWallMs: z.number().int().min(1_000).default(60 * 60_000),
    requestsPerSecond: z.number().min(0.1).max(1_000).default(10),
    concurrency: z.number().int().min(1).max(64).default(4),
    requestTimeoutMs: z.number().int().min(500).max(120_000).default(30_000),
});
const RiskSub = z.object({
    maxPayloadClass: PayloadRiskClass.default('differential'),
    allowDangerousActions: z.boolean().default(false),
    dangerousActionKeywords: z.array(z.string()).default([
        'delete', 'destroy', 'remove', 'drop', 'purge',
        'logout', 'signout',
        'payment', 'transfer', 'checkout',
        'invite', 'reset', 'disable', 'revoke',
    ]),
});
const RecoverySub = z.object({
    enabled: z.boolean().default(true),
    maxRetries: z.number().int().min(0).max(10).default(5),
    circuitBreakerThreshold: z.number().int().min(1).default(5),
    circuitBreakerCooldownMs: z.number().int().min(1_000).default(60_000),
    allowBrowserHandoff: z.boolean().default(true),
});
const EvidenceSub = z.object({
    retainDays: z.number().int().min(1).max(3650).default(90),
    encryptSensitive: z.boolean().default(true),
    redactPii: z.boolean().default(true),
    maxBodyBytes: z.number().int().min(256).default(65_536),
});
const ReportSub = z.object({
    formats: z.array(ReportFormat).default(['markdown', 'json', 'html']),
    includeFalsePositiveNotes: z.boolean().default(true),
    includeRemediationSnippets: z.boolean().default(true),
});
const MiscSub = z.object({
    slowStart: z.boolean().default(true),
    requireExplicitMutationApproval: z.boolean().default(true),
});

export const ScanPolicySchema = z.object({
    /** Human-readable policy id. */
    id: z.string().min(1),
    version: z.string().default('1.0.0'),
    /** parent profile this policy inherits from. */
    extends: z.string().optional(),
    description: z.string().optional(),

    scope: ScopeSub.default(() => ScopeSub.parse({})),
    detectors: DetectorsSub.default(() => DetectorsSub.parse({})),
    budget: BudgetSub.default(() => BudgetSub.parse({})),
    risk: RiskSub.default(() => RiskSub.parse({})),
    recovery: RecoverySub.default(() => RecoverySub.parse({})),
    evidence: EvidenceSub.default(() => EvidenceSub.parse({})),
    report: ReportSub.default(() => ReportSub.parse({})),
    misc: MiscSub.default(() => MiscSub.parse({})),
});

export type ScanPolicy = z.infer<typeof ScanPolicySchema>;

// ────────────────────────────────────────────────────────────
// Built-in profiles
// ────────────────────────────────────────────────────────────

export const BUILTIN_PROFILES: Record<string, ScanPolicy> = {
    passive_only: ScanPolicySchema.parse({
        id: 'passive_only',
        description: 'สังเกตการณ์อย่างเดียว ไม่ probe',
        risk: { maxPayloadClass: 'passive', allowDangerousActions: false },
        detectors: { mode: 'allowlist', enabled: ['headers', 'cors', 'info_disclosure'] },
        budget: { maxRequests: 500, maxBytes: 20 * 1024 * 1024, maxWallMs: 15 * 60_000, requestsPerSecond: 5 },
    }),
    ci_fast: ScanPolicySchema.parse({
        id: 'ci_fast',
        description: 'สแกนเร็วสำหรับ CI — ใช้ detector พื้นฐาน',
        risk: { maxPayloadClass: 'benign-probe' },
        budget: { maxRequests: 1_000, maxBytes: 50 * 1024 * 1024, maxWallMs: 10 * 60_000, concurrency: 8 },
        detectors: { mode: 'allowlist', enabled: ['sqli_oracle', 'xss_oracle', 'headers', 'cors', 'open_redirect'] },
    }),
    api_only: ScanPolicySchema.parse({
        id: 'api_only',
        description: 'ตรวจเฉพาะ REST/GraphQL API',
        scope: { allowedPaths: ['/api/**', '/graphql', '/graphql/**'] },
        detectors: { mode: 'allowlist', enabled: ['sqli_oracle', 'ssrf_oracle', 'cors', 'headers'] },
    }),
    spa_deep: ScanPolicySchema.parse({
        id: 'spa_deep',
        description: 'ใช้ headless browser ลึก ๆ สำหรับ SPA',
        budget: { maxRequests: 3_000, maxWallMs: 45 * 60_000 },
    }),
    authenticated_standard: ScanPolicySchema.parse({
        id: 'authenticated_standard',
        description: 'มาตรฐานสำหรับ authenticated scan',
        risk: { maxPayloadClass: 'differential' },
    }),
    enterprise_full: ScanPolicySchema.parse({
        id: 'enterprise_full',
        description: 'สแกนครบทุกมิติสำหรับ engagement ภายในที่มี ScopeApproval',
        risk: { maxPayloadClass: 'active-high' },
        budget: { maxRequests: 10_000, maxBytes: 500 * 1024 * 1024, maxWallMs: 3 * 60 * 60_000 },
    }),
    high_safety: ScanPolicySchema.parse({
        id: 'high_safety',
        description: 'เซฟสุด — ใช้กับระบบ production ที่ยังไม่แน่ใจ',
        risk: { maxPayloadClass: 'benign-probe', allowDangerousActions: false },
        budget: { maxRequests: 1_500, requestsPerSecond: 2, concurrency: 2 },
        misc: { slowStart: true, requireExplicitMutationApproval: true },
    }),
    staging_deep: ScanPolicySchema.parse({
        id: 'staging_deep',
        description: 'staging — เปิด detector เต็มแต่จำกัด budget',
        risk: { maxPayloadClass: 'error-trigger' },
    }),
    compliance_mapping: ScanPolicySchema.parse({
        id: 'compliance_mapping',
        description: 'เน้นจับหมวด OWASP/CWE เพื่อรายงาน compliance',
        report: { formats: ['markdown', 'sarif', 'pdf'], includeRemediationSnippets: true },
    }),
};

// ────────────────────────────────────────────────────────────
// Helpers for merge / inherit
// ────────────────────────────────────────────────────────────

/**
 * Deep-merge override on top of base. Arrays replace; objects recurse; scalars
 * replace. Used by loader to compose default → profile → tenant → scan.
 */
export function mergePolicies(base: ScanPolicy, override: Partial<ScanPolicy>): ScanPolicy {
    const merged = { ...base };
    for (const [k, v] of Object.entries(override)) {
        if (v === undefined) continue;
        const current = (merged as Record<string, unknown>)[k];
        if (Array.isArray(v)) {
            (merged as Record<string, unknown>)[k] = [...v];
        } else if (typeof v === 'object' && v !== null && !Array.isArray(current)) {
            (merged as Record<string, unknown>)[k] = { ...(current as object), ...(v as object) };
        } else {
            (merged as Record<string, unknown>)[k] = v;
        }
    }
    // Re-validate to enforce constraints after merge.
    return ScanPolicySchema.parse(merged);
}

/**
 * Canonical "do nothing more restrictive than legacy" policy — used when
 * caller passes nothing, so existing scans keep working without opt-in.
 */
export const LEGACY_PASSTHROUGH: ScanPolicy = ScanPolicySchema.parse({
    id: 'legacy_passthrough',
    description: 'No-op policy for back-compat scans',
    risk: { maxPayloadClass: 'active-high' },
    budget: { maxRequests: 50_000, maxBytes: 2_147_483_647, maxWallMs: 24 * 60 * 60_000, concurrency: 16, requestsPerSecond: 100 },
    recovery: { enabled: false },
});
