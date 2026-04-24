import { describe, it, expect } from 'vitest';
import { validateFinding, isConfirmedFinding, DetectorProvenanceSchema } from './contracts';
import type { DetectorResult, DetectorProvenance } from '@/types';

const validProvenance: DetectorProvenance = {
    oraclesUsed: ['baseline', 'replay'],
    probeCount: 12,
    replayConfirmations: 3,
    baselineSampleSize: 8,
    distanceScore: 4.2,
    anomalyThreshold: 2.5,
    generatedAt: '2026-04-24T00:00:00Z',
};

function makeFinding(overrides: Partial<DetectorResult> = {}): DetectorResult {
    return {
        found: true,
        title: 'SQL injection in login form',
        description: 'Boolean-based SQL injection in the username parameter.',
        category: 'sqli',
        severity: 'critical',
        confidence: 'high',
        affectedUrl: 'http://example.com/login',
        httpMethod: 'POST',
        provenance: validProvenance,
        ...overrides,
    };
}

describe('DetectorProvenanceSchema', () => {
    it('accepts a well-formed provenance', () => {
        expect(DetectorProvenanceSchema.safeParse(validProvenance).success).toBe(true);
    });

    it('rejects provenance missing oraclesUsed', () => {
        const { oraclesUsed: _unused, ...rest } = validProvenance;
        void _unused;
        expect(DetectorProvenanceSchema.safeParse(rest).success).toBe(false);
    });

    it('rejects provenance with negative probeCount', () => {
        expect(
            DetectorProvenanceSchema.safeParse({ ...validProvenance, probeCount: -1 }).success,
        ).toBe(false);
    });
});

describe('validateFinding', () => {
    it('confirms a well-formed SQLi finding with provenance', () => {
        const v = validateFinding(makeFinding());
        expect(v.level).toBe('confirmed');
    });

    it('downgrades to candidate when provenance is missing', () => {
        const finding = makeFinding();
        delete finding.provenance;
        const v = validateFinding(finding);
        expect(v.level).toBe('candidate');
        if (v.level === 'candidate') expect(v.reason).toContain('provenance');
    });

    it('rejects a finding missing a title', () => {
        const v = validateFinding(makeFinding({ title: '' }));
        expect(v.level).toBe('rejected');
    });

    it('rejects a finding with an invalid URL', () => {
        const v = validateFinding(makeFinding({ affectedUrl: 'not-a-url' }));
        expect(v.level).toBe('rejected');
    });

    it('accepts a non-sqli/xss finding under the generic schema', () => {
        const v = validateFinding(
            makeFinding({
                category: 'open_redirect',
                title: 'Open redirect on /go',
                description: 'Redirects to arbitrary URL',
            }),
        );
        expect(v.level).toBe('confirmed');
    });
});

describe('isConfirmedFinding', () => {
    it('returns true only for confirmed findings', () => {
        expect(isConfirmedFinding(makeFinding())).toBe(true);
        const withoutProv = makeFinding();
        delete withoutProv.provenance;
        expect(isConfirmedFinding(withoutProv)).toBe(false);
    });
});
