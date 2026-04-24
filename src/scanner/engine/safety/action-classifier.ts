// InjectProof — Action (intent) classifier
// Crawler ค้น endpoint + form + button ทุกแบบ; ก่อนจะ submit ต้องถามว่า
// "action นี้ read-only, state-changing, หรือ dangerous?"  ระบบไม่ใช้ if/else
// กวาด keyword เฉย ๆ — ใช้ feature extraction หลายแกนแล้ว aggregate เป็น
// score เพื่อ decide.
//
// ถ้า dangerous ในขณะที่ policy.risk.allowDangerousActions=false → skip action
// (ไม่ submit, ไม่ probe); ยังคงเก็บ observation แบบ passive ไว้ใน surface graph.

import type { ScanPolicy } from '../policy/schema';
import { actionLooksDangerous } from '../policy/evaluator';

export type ActionClass = 'read-only' | 'state-changing' | 'dangerous';

export interface ActionCandidate {
    method: string;
    url: string;
    formText?: string;
    buttonLabels?: string[];
    paramNames?: string[];
}

export interface ActionVerdict {
    class: ActionClass;
    score: number;
    signals: string[];
    /** policy + verdict ให้คำตอบ "ดำเนินการต่อได้หรือไม่" */
    allowed: boolean;
    reason?: string;
}

// ────────────────────────────────────────────────────────────
// Feature extractors — each returns a partial score + signal label
// ────────────────────────────────────────────────────────────

const METHOD_WEIGHT: Record<string, number> = {
    GET: 0, HEAD: 0, OPTIONS: 0,
    POST: 0.6,
    PUT: 0.8, PATCH: 0.8,
    DELETE: 1.0,
};

function methodSignal(method: string): { s: number; label: string } {
    const m = method.toUpperCase();
    const w = METHOD_WEIGHT[m] ?? 0.4;
    return { s: w, label: `method:${m}` };
}

function keywordSignal(candidate: ActionCandidate, keywords: string[]): { s: number; label?: string } {
    const corpus = [
        candidate.url.toLowerCase(),
        (candidate.formText ?? '').toLowerCase(),
        (candidate.buttonLabels ?? []).join(' ').toLowerCase(),
        (candidate.paramNames ?? []).join(' ').toLowerCase(),
    ].join(' | ');
    for (const kw of keywords) {
        if (corpus.includes(kw.toLowerCase())) return { s: 0.7, label: `keyword:${kw}` };
    }
    return { s: 0 };
}

function paramSignal(candidate: ActionCandidate): { s: number; label?: string } {
    const params = candidate.paramNames ?? [];
    if (params.some((p) => /^(_token|_csrf|authenticity_token|csrfmiddlewaretoken)$/i.test(p))) {
        return { s: 0.5, label: 'csrf-token-present' };
    }
    return { s: 0 };
}

function pathSignal(candidate: ActionCandidate): { s: number; label?: string } {
    try {
        const { pathname } = new URL(candidate.url);
        // REST-style verbs in path
        if (/\/(delete|remove|logout|signout|destroy|revoke|disable|reset)(\/|$|\?)/i.test(pathname))
            return { s: 0.8, label: 'path-verb-destructive' };
        if (/\/(create|update|edit|save|submit|send|add|invite|enable|confirm)(\/|$|\?)/i.test(pathname))
            return { s: 0.4, label: 'path-verb-mutating' };
    } catch {
        /* ignore */
    }
    return { s: 0 };
}

// ────────────────────────────────────────────────────────────
// Aggregate
// ────────────────────────────────────────────────────────────

/**
 * Classify an action using multiple weak signals. Score is bounded to [0, 1]:
 *   score < 0.3  → read-only
 *   score < 0.7  → state-changing
 *   score ≥ 0.7  → dangerous
 * Policy flag `allowDangerousActions` decides whether a dangerous action is
 * actually submitted by the crawler.
 */
export function classifyAction(policy: ScanPolicy, candidate: ActionCandidate): ActionVerdict {
    const signals: string[] = [];
    let score = 0;

    const m = methodSignal(candidate.method);
    score += m.s;
    signals.push(m.label);

    const k = keywordSignal(candidate, policy.risk.dangerousActionKeywords);
    if (k.label) {
        score += k.s;
        signals.push(k.label);
    }

    const p = paramSignal(candidate);
    if (p.label) {
        score += p.s;
        signals.push(p.label);
    }

    const pth = pathSignal(candidate);
    if (pth.label) {
        score += pth.s;
        signals.push(pth.label);
    }

    // Policy-provided extra check — lets the policy author inject keywords.
    const dang = actionLooksDangerous(policy, {
        method: candidate.method,
        url: candidate.url,
        formText: candidate.formText,
        paramNames: candidate.paramNames,
    });
    if (dang.dangerous) {
        score = Math.max(score, 0.85);
        signals.push(`policy:${dang.reason ?? 'keyword'}`);
    }

    // Clip to [0, 1]. We do NOT divide here — individual signal weights are
    // tuned so that a single strong signal (e.g. DELETE method or a
    // policy-flagged keyword) already puts the score in the dangerous tier.
    score = Math.min(1, score);

    let cls: ActionClass;
    if (score >= 0.7) cls = 'dangerous';
    else if (score >= 0.3) cls = 'state-changing';
    else cls = 'read-only';

    let allowed = true;
    let reason: string | undefined;
    if (cls === 'dangerous' && !policy.risk.allowDangerousActions) {
        allowed = false;
        reason = 'dangerous action blocked by policy (risk.allowDangerousActions=false)';
    } else if (cls === 'state-changing' && policy.misc.requireExplicitMutationApproval) {
        allowed = false;
        reason = 'mutation requires explicit approval (policy.misc.requireExplicitMutationApproval=true)';
    }

    return { class: cls, score: Number(score.toFixed(3)), signals, allowed, reason };
}
