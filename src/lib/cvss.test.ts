import { describe, it, expect } from 'vitest';
import {
    calculateCvssScore,
    generateCvssVector,
    parseCvssVector,
    getSeverityFromScore,
    COMMON_CVSS_VECTORS,
} from './cvss';
import type { CvssMetrics } from '@/types';

describe('cvss — known vectors', () => {
    it('scores CVE-2021-44228 Log4Shell-shaped vector at 10.0', () => {
        const metrics: CvssMetrics = {
            attackVector: 'N',
            attackComplexity: 'L',
            privilegesRequired: 'N',
            userInteraction: 'N',
            scope: 'C',
            confidentialityImpact: 'H',
            integrityImpact: 'H',
            availabilityImpact: 'H',
        };
        expect(calculateCvssScore(metrics)).toBe(10.0);
    });

    it('scores SQLi common vector as critical (9.0+)', () => {
        const score = calculateCvssScore(COMMON_CVSS_VECTORS.sqli);
        expect(score).toBeGreaterThanOrEqual(9.0);
        expect(getSeverityFromScore(score)).toBe('critical');
    });

    it('scores reflected XSS as medium', () => {
        const score = calculateCvssScore(COMMON_CVSS_VECTORS.xss_reflected);
        expect(getSeverityFromScore(score)).toBe('medium');
    });

    it('scores all-N impact as 0.0', () => {
        const metrics: CvssMetrics = {
            attackVector: 'N',
            attackComplexity: 'L',
            privilegesRequired: 'N',
            userInteraction: 'N',
            scope: 'U',
            confidentialityImpact: 'N',
            integrityImpact: 'N',
            availabilityImpact: 'N',
        };
        expect(calculateCvssScore(metrics)).toBe(0);
    });

    it('round-trips through generate → parse → calculate', () => {
        const original = COMMON_CVSS_VECTORS.cmd_injection;
        const vector = generateCvssVector(original);
        const parsed = parseCvssVector(vector);
        expect(parsed).not.toBeNull();
        expect(parsed).toEqual(original);
        expect(calculateCvssScore(parsed!)).toBe(calculateCvssScore(original));
    });

    it('rejects a malformed vector', () => {
        expect(parseCvssVector('not a vector')).toEqual({
            attackVector: undefined,
            attackComplexity: undefined,
            privilegesRequired: undefined,
            userInteraction: undefined,
            scope: undefined,
            confidentialityImpact: undefined,
            integrityImpact: undefined,
            availabilityImpact: undefined,
        });
    });
});

describe('cvss — severity thresholds', () => {
    it.each([
        [9.0, 'critical'],
        [9.9, 'critical'],
        [7.0, 'high'],
        [8.9, 'high'],
        [4.0, 'medium'],
        [6.9, 'medium'],
        [0.1, 'low'],
        [3.9, 'low'],
        [0.0, 'info'],
    ])('score %s maps to %s', (score, expected) => {
        expect(getSeverityFromScore(score)).toBe(expected);
    });
});
