import { describe, it, expect } from 'vitest';
import {
    ScanPolicySchema, BUILTIN_PROFILES, mergePolicies, LEGACY_PASSTHROUGH,
} from './schema';
import {
    isDetectorEnabled, pathAllowed, methodAllowed, payloadRiskAllowed,
    actionLooksDangerous, budgetRemaining, reportFormatAllowed,
} from './evaluator';
import { loadPolicy } from './loader';
import { createScratchDir, removeDir, writeTextFile, pathJoin } from '@/lib/platform';

describe('schema', () => {
    it('parses an empty object with defaults', () => {
        const p = ScanPolicySchema.parse({ id: 'x' });
        expect(p.risk.maxPayloadClass).toBe('differential');
        expect(p.budget.maxRequests).toBeGreaterThan(0);
    });

    it('rejects invalid values', () => {
        expect(() => ScanPolicySchema.parse({ id: 'x', budget: { maxRequests: -1 } })).toThrow();
    });

    it('has built-in profiles', () => {
        expect(BUILTIN_PROFILES.passive_only.risk.maxPayloadClass).toBe('passive');
        expect(BUILTIN_PROFILES.ci_fast.budget.concurrency).toBe(8);
        expect(BUILTIN_PROFILES.enterprise_full.risk.maxPayloadClass).toBe('active-high');
    });

    it('mergePolicies deep-merges scalars and objects', () => {
        const merged = mergePolicies(BUILTIN_PROFILES.passive_only, {
            budget: { maxRequests: 42 },
        } as unknown as Partial<ReturnType<typeof BUILTIN_PROFILES.passive_only.budget.concurrency extends never ? never : () => void>>);
        expect(merged.budget.maxRequests).toBe(42);
        expect(merged.risk.maxPayloadClass).toBe('passive');
    });

    it('LEGACY_PASSTHROUGH permits active-high', () => {
        expect(LEGACY_PASSTHROUGH.risk.maxPayloadClass).toBe('active-high');
    });
});

describe('evaluator', () => {
    const policy = ScanPolicySchema.parse({
        id: 't',
        scope: {
            allowedPaths: ['/api/**'],
            deniedPaths: ['/api/admin/**'],
            allowedMethods: ['GET', 'POST'],
        },
        detectors: { mode: 'allowlist', enabled: ['sqli_oracle'] },
        report: { formats: ['markdown', 'json'] },
    });

    it('isDetectorEnabled honors allowlist + disabled list', () => {
        expect(isDetectorEnabled(policy, 'sqli_oracle')).toBe(true);
        expect(isDetectorEnabled(policy, 'xss_oracle')).toBe(false);
        const deny = ScanPolicySchema.parse({ id: 't2', detectors: { disabled: ['sqli_oracle'] } });
        expect(isDetectorEnabled(deny, 'sqli_oracle')).toBe(false);
        expect(isDetectorEnabled(deny, 'xss_oracle')).toBe(true);
    });

    it('pathAllowed honors allow/deny globs', () => {
        expect(pathAllowed(policy, 'http://h/api/users/1')).toBe(true);
        expect(pathAllowed(policy, 'http://h/api/admin/x')).toBe(false);
        expect(pathAllowed(policy, 'http://h/other')).toBe(false);
    });

    it('methodAllowed honors list', () => {
        expect(methodAllowed(policy, 'GET')).toBe(true);
        expect(methodAllowed(policy, 'DELETE')).toBe(false);
    });

    it('payloadRiskAllowed ranks correctly', () => {
        expect(payloadRiskAllowed(policy, 'passive')).toBe(true);
        expect(payloadRiskAllowed(policy, 'benign-probe')).toBe(true);
        expect(payloadRiskAllowed(policy, 'differential')).toBe(true);
        expect(payloadRiskAllowed(policy, 'error-trigger')).toBe(false);
        expect(payloadRiskAllowed(policy, 'dangerous')).toBe(false);
    });

    it('actionLooksDangerous flags DELETE and destructive keywords', () => {
        expect(actionLooksDangerous(policy, { method: 'DELETE', url: '/api/users/1' }).dangerous).toBe(true);
        expect(actionLooksDangerous(policy, { method: 'POST', url: '/api/users/delete' }).dangerous).toBe(true);
        expect(actionLooksDangerous(policy, { method: 'GET', url: '/api/users' }).dangerous).toBe(false);
    });

    it('reportFormatAllowed honors list', () => {
        expect(reportFormatAllowed(policy, 'markdown')).toBe(true);
        expect(reportFormatAllowed(policy, 'pdf')).toBe(false);
    });

    it('budgetRemaining reports limiting axis', () => {
        expect(budgetRemaining(policy, { requests: 0, bytes: 0, wallMs: 0 }).ok).toBe(true);
        expect(budgetRemaining(policy, {
            requests: policy.budget.maxRequests, bytes: 0, wallMs: 0,
        }).limiting).toBe('requests');
    });
});

describe('loader', () => {
    it('loads a built-in profile by name', async () => {
        const p = await loadPolicy({ kind: 'profile', name: 'ci_fast' });
        expect(p.budget.concurrency).toBe(8);
    });

    it('loads an inline object and merges override', async () => {
        const p = await loadPolicy(
            { kind: 'object', value: { id: 'x', extends: 'passive_only', risk: { maxPayloadClass: 'benign-probe' } } },
            { override: { budget: { maxRequests: 7 } as unknown as ReturnType<typeof ScanPolicySchema.parse>['budget'] } },
        );
        expect(p.budget.maxRequests).toBe(7);
        expect(p.risk.maxPayloadClass).toBe('benign-probe');
    });

    it('loads a JSON file', async () => {
        const dir = await createScratchDir('policy-');
        const path = pathJoin(dir, 'policy.json');
        await writeTextFile(path, JSON.stringify({
            id: 'from-file',
            risk: { maxPayloadClass: 'passive' },
        }));
        const p = await loadPolicy({ kind: 'file', path });
        expect(p.id).toBe('from-file');
        expect(p.risk.maxPayloadClass).toBe('passive');
        await removeDir(dir);
    });

    it('kind=legacy returns passthrough', async () => {
        const p = await loadPolicy({ kind: 'legacy' });
        expect(p.id).toBe('legacy_passthrough');
    });
});
