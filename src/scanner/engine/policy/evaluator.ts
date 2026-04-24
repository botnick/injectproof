// InjectProof — Policy evaluator
// Pure functions over a `ScanPolicy` that answer hot-path questions:
//   isDetectorEnabled(policy, id)
//   pathAllowed(policy, url)
//   methodAllowed(policy, method)
//   payloadRiskAllowed(policy, cls)
//   actionLooksDangerous(policy, intent)
//   reportFormatAllowed(policy, format)
//
// Evaluator เก็บ cache เฉพาะ glob matcher regex เพื่อไม่ต้อง compile ซ้ำทุก
// request. ไม่มี I/O. ไม่มี side effect.

import type { ScanPolicy, PayloadRiskClass } from './schema';

// ────────────────────────────────────────────────────────────
// Glob matcher
// ────────────────────────────────────────────────────────────

const globCache = new Map<string, RegExp>();

/** Convert a glob with `*` / `**` into a RegExp. */
function globToRegex(pattern: string): RegExp {
    const cached = globCache.get(pattern);
    if (cached) return cached;
    // Escape regex meta except for * which we translate.
    let re = '';
    let i = 0;
    while (i < pattern.length) {
        const c = pattern[i];
        if (c === '*') {
            if (pattern[i + 1] === '*') {
                re += '.*';
                i += 2;
                continue;
            }
            re += '[^/]*';
            i++;
            continue;
        }
        if (/[\\.+?()|{}\[\]^$]/.test(c)) re += '\\' + c;
        else re += c;
        i++;
    }
    const compiled = new RegExp('^' + re + '$');
    globCache.set(pattern, compiled);
    return compiled;
}

function matchesAny(patterns: string[], path: string): boolean {
    for (const p of patterns) {
        if (globToRegex(p).test(path)) return true;
    }
    return false;
}

// ────────────────────────────────────────────────────────────
// Risk rank (for compare)
// ────────────────────────────────────────────────────────────

const RISK_RANK: Record<PayloadRiskClass, number> = {
    passive: 0,
    'benign-probe': 1,
    differential: 2,
    'error-trigger': 3,
    'active-high': 4,
    dangerous: 5,
};

// ────────────────────────────────────────────────────────────
// Public queries
// ────────────────────────────────────────────────────────────

export function isDetectorEnabled(policy: ScanPolicy, id: string): boolean {
    const { mode, enabled, disabled } = policy.detectors;
    if (disabled.includes(id)) return false;
    if (mode === 'allowlist') return enabled.includes(id);
    return true; // denylist default-on
}

export function pathAllowed(policy: ScanPolicy, url: string): boolean {
    let path: string;
    try {
        path = new URL(url).pathname;
    } catch {
        path = url;
    }
    if (matchesAny(policy.scope.deniedPaths, path)) return false;
    if (policy.scope.allowedPaths.length === 0) return true;
    return matchesAny(policy.scope.allowedPaths, path);
}

export function methodAllowed(policy: ScanPolicy, method: string): boolean {
    return policy.scope.allowedMethods.includes(method.toUpperCase() as ScanPolicy['scope']['allowedMethods'][number]);
}

export function payloadRiskAllowed(policy: ScanPolicy, cls: PayloadRiskClass): boolean {
    return RISK_RANK[cls] <= RISK_RANK[policy.risk.maxPayloadClass];
}

/**
 * ตรวจว่า action/intent นี้ "ดูเหมือน" state-changing ที่อันตราย (เช่น delete,
 * logout, checkout). ใช้ keyword list + policy flag ประกอบกัน — ไม่ใช่
 * if/else hardcode เพราะ keyword list อยู่ใน policy เอง.
 */
export function actionLooksDangerous(
    policy: ScanPolicy,
    intent: { method: string; url: string; formText?: string; paramNames?: string[] },
): { dangerous: boolean; reason?: string } {
    const kws = policy.risk.dangerousActionKeywords.map((k) => k.toLowerCase());
    const corpus = [
        intent.method.toUpperCase(),
        (intent.url ?? '').toLowerCase(),
        (intent.formText ?? '').toLowerCase(),
        ...(intent.paramNames ?? []).map((n) => n.toLowerCase()),
    ].join(' | ');

    const hit = kws.find((kw) => corpus.includes(kw));
    if (hit) {
        return {
            dangerous: true,
            reason: `keyword "${hit}" present and policy.risk.allowDangerousActions=${policy.risk.allowDangerousActions}`,
        };
    }
    // Method-only signal: DELETE always dangerous unless opted in.
    if (intent.method.toUpperCase() === 'DELETE') return { dangerous: true, reason: 'HTTP DELETE' };
    return { dangerous: false };
}

export function reportFormatAllowed(policy: ScanPolicy, format: string): boolean {
    return policy.report.formats.includes(format as ScanPolicy['report']['formats'][number]);
}

/**
 * ตรวจว่า budget ยังเหลือพอที่จะส่ง request อีก 1 ตัว. Consumer (runtime
 * tracker) ส่ง running totals เข้ามา; evaluator เป็น pure comparison.
 */
export function budgetRemaining(
    policy: ScanPolicy,
    used: { requests: number; bytes: number; wallMs: number },
): { ok: boolean; limiting?: 'requests' | 'bytes' | 'wallMs' } {
    if (used.requests >= policy.budget.maxRequests) return { ok: false, limiting: 'requests' };
    if (used.bytes >= policy.budget.maxBytes) return { ok: false, limiting: 'bytes' };
    if (used.wallMs >= policy.budget.maxWallMs) return { ok: false, limiting: 'wallMs' };
    return { ok: true };
}
