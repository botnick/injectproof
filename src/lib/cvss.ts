// VibeCode — CVSS v3.1 Calculator
// Full implementation of CVSS v3.1 scoring algorithm
// Reference: https://www.first.org/cvss/v3.1/specification-document

import type { CvssMetrics, Severity } from '@/types';

// ============================================================
// CVSS v3.1 Base Score Weights
// ============================================================

const AV_WEIGHTS: Record<string, number> = {
    N: 0.85, // Network
    A: 0.62, // Adjacent
    L: 0.55, // Local
    P: 0.2,  // Physical
};

const AC_WEIGHTS: Record<string, number> = {
    L: 0.77, // Low
    H: 0.44, // High
};

const PR_WEIGHTS_UNCHANGED: Record<string, number> = {
    N: 0.85, // None
    L: 0.62, // Low
    H: 0.27, // High
};

const PR_WEIGHTS_CHANGED: Record<string, number> = {
    N: 0.85, // None
    L: 0.68, // Low
    H: 0.50, // High
};

const UI_WEIGHTS: Record<string, number> = {
    N: 0.85, // None
    R: 0.62, // Required
};

const CIA_WEIGHTS: Record<string, number> = {
    N: 0,    // None
    L: 0.22, // Low
    H: 0.56, // High
};

// ============================================================
// CVSS v3.1 Score Calculation
// ============================================================

/**
 * Calculate CVSS v3.1 Base Score from metrics
 * @param metrics - CVSS v3.1 base metrics
 * @returns Score from 0.0 to 10.0
 */
export function calculateCvssScore(metrics: CvssMetrics): number {
    const av = AV_WEIGHTS[metrics.attackVector] ?? 0;
    const ac = AC_WEIGHTS[metrics.attackComplexity] ?? 0;
    const pr = metrics.scope === 'C'
        ? PR_WEIGHTS_CHANGED[metrics.privilegesRequired] ?? 0
        : PR_WEIGHTS_UNCHANGED[metrics.privilegesRequired] ?? 0;
    const ui = UI_WEIGHTS[metrics.userInteraction] ?? 0;

    const c = CIA_WEIGHTS[metrics.confidentialityImpact] ?? 0;
    const i = CIA_WEIGHTS[metrics.integrityImpact] ?? 0;
    const a = CIA_WEIGHTS[metrics.availabilityImpact] ?? 0;

    // Impact Sub Score (ISS)
    const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

    // Impact
    let impact: number;
    if (metrics.scope === 'U') {
        impact = 6.42 * iss;
    } else {
        impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    }

    // Exploitability
    const exploitability = 8.22 * av * ac * pr * ui;

    // Base Score
    if (impact <= 0) return 0;

    let baseScore: number;
    if (metrics.scope === 'U') {
        baseScore = Math.min(impact + exploitability, 10);
    } else {
        baseScore = Math.min(1.08 * (impact + exploitability), 10);
    }

    return roundUp(baseScore);
}

/**
 * Round up to one decimal place (CVSS spec requires this)
 */
function roundUp(value: number): number {
    return Math.ceil(value * 10) / 10;
}

/**
 * Generate CVSS v3.1 vector string from metrics
 * @param metrics - CVSS v3.1 base metrics
 * @returns Vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 */
export function generateCvssVector(metrics: CvssMetrics): string {
    return `CVSS:3.1/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}/S:${metrics.scope}/C:${metrics.confidentialityImpact}/I:${metrics.integrityImpact}/A:${metrics.availabilityImpact}`;
}

/**
 * Parse a CVSS v3.1 vector string into metrics
 * @param vector - CVSS vector string
 * @returns Parsed metrics or null if invalid
 */
export function parseCvssVector(vector: string): CvssMetrics | null {
    try {
        const parts = vector.replace('CVSS:3.1/', '').split('/');
        const map: Record<string, string> = {};
        for (const part of parts) {
            const [key, value] = part.split(':');
            map[key] = value;
        }

        return {
            attackVector: map.AV as CvssMetrics['attackVector'],
            attackComplexity: map.AC as CvssMetrics['attackComplexity'],
            privilegesRequired: map.PR as CvssMetrics['privilegesRequired'],
            userInteraction: map.UI as CvssMetrics['userInteraction'],
            scope: map.S as CvssMetrics['scope'],
            confidentialityImpact: map.C as CvssMetrics['confidentialityImpact'],
            integrityImpact: map.I as CvssMetrics['integrityImpact'],
            availabilityImpact: map.A as CvssMetrics['availabilityImpact'],
        };
    } catch {
        return null;
    }
}

/**
 * Get severity rating from CVSS score
 * @param score - CVSS v3.1 score (0.0 - 10.0)
 * @returns Severity string
 */
export function getSeverityFromScore(score: number): Severity {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score >= 0.1) return 'low';
    return 'info';
}

/**
 * Get CVSS score range description
 */
export function getScoreLabel(score: number): string {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
}

/**
 * Get color for CVSS score
 */
export function getScoreColor(score: number): string {
    if (score >= 9.0) return '#dc2626';
    if (score >= 7.0) return '#ea580c';
    if (score >= 4.0) return '#d97706';
    if (score >= 0.1) return '#2563eb';
    return '#6b7280';
}

// ============================================================
// Common CVSS Vectors for Auto-scoring
// ============================================================

export const COMMON_CVSS_VECTORS: Record<string, CvssMetrics> = {
    // XSS Reflected
    xss_reflected: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'C',
        confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
    },
    // XSS Stored
    xss_stored: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L',
        userInteraction: 'R', scope: 'C',
        confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
    },
    // SQL Injection
    sqli: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H',
    },
    // SSRF
    ssrf: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'C',
        confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N',
    },
    // Path Traversal
    path_traversal: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N',
    },
    // Open Redirect
    open_redirect: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'C',
        confidentialityImpact: 'L', integrityImpact: 'L', availabilityImpact: 'N',
    },
    // Missing Security Headers
    headers_missing: {
        attackVector: 'N', attackComplexity: 'H', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'U',
        confidentialityImpact: 'N', integrityImpact: 'L', availabilityImpact: 'N',
    },
    // CORS Misconfiguration
    cors_misconfig: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'C',
        confidentialityImpact: 'H', integrityImpact: 'N', availabilityImpact: 'N',
    },
    // Information Disclosure
    info_disclosure: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'L', integrityImpact: 'N', availabilityImpact: 'N',
    },
    // Command Injection / RCE
    cmd_injection: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'H',
    },
    // JWT alg=none
    jwt_alg_none: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'H', integrityImpact: 'H', availabilityImpact: 'N',
    },
    // IDOR
    idor: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'L',
        userInteraction: 'N', scope: 'U',
        confidentialityImpact: 'H', integrityImpact: 'L', availabilityImpact: 'N',
    },
    // CSRF
    csrf: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'U',
        confidentialityImpact: 'N', integrityImpact: 'H', availabilityImpact: 'N',
    },
    // Clickjacking
    clickjacking: {
        attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N',
        userInteraction: 'R', scope: 'U',
        confidentialityImpact: 'N', integrityImpact: 'L', availabilityImpact: 'N',
    },
};
