// InjectProof — Scan-diff report
// "What changed vs. the previous scan of this target." Killer feature for
// reviewing employee work: prove the fix landed (finding missing) or
// regressed (old finding back) rather than paging through two full reports.

import prisma from '@/lib/prisma';

export interface DiffFinding {
    id: string;
    category: string;
    severity: string;
    affectedUrl: string;
    parameter: string | null;
    title: string;
}

export interface ScanDiff {
    previousScanId: string | null;
    currentScanId: string;
    newFindings: DiffFinding[];    // present in current, absent in previous
    fixedFindings: DiffFinding[];  // present in previous, absent in current
    stillOpen: DiffFinding[];      // present in both
    regressions: DiffFinding[];    // previously 'fixed' status, now back
    summary: {
        delta: number;       // newFindings − fixedFindings
        fixRate: number;     // fixedFindings / (fixedFindings + stillOpen)
    };
}

// Two findings match if they share (category, affectedUrl path, parameter).
// Severity is allowed to differ — same bug at different severity is the same bug.
function matchKey(f: { category: string; affectedUrl: string; parameter: string | null }): string {
    try {
        const path = new URL(f.affectedUrl).pathname;
        return `${f.category}::${path}::${f.parameter ?? ''}`;
    } catch {
        return `${f.category}::${f.affectedUrl}::${f.parameter ?? ''}`;
    }
}

/**
 * Compute the diff between `currentScanId` and the *previous scan of the
 * same target*. If no previous scan exists, returns every finding as new.
 */
export async function computeScanDiff(currentScanId: string): Promise<ScanDiff> {
    const current = await prisma.scan.findUnique({
        where: { id: currentScanId },
        select: { id: true, targetId: true, startedAt: true },
    });
    if (!current) throw new Error(`Scan ${currentScanId} not found`);

    const previous = await prisma.scan.findFirst({
        where: {
            targetId: current.targetId,
            id: { not: current.id },
            status: 'completed',
            startedAt: { lt: current.startedAt ?? undefined },
        },
        orderBy: { startedAt: 'desc' },
        select: { id: true },
    });

    const currFindings = await prisma.vulnerability.findMany({
        where: { scanId: current.id },
        select: { id: true, category: true, severity: true, affectedUrl: true, parameter: true, title: true, status: true },
    });

    if (!previous) {
        return {
            previousScanId: null,
            currentScanId: current.id,
            newFindings: currFindings.map(toDiffFinding),
            fixedFindings: [],
            stillOpen: [],
            regressions: [],
            summary: { delta: currFindings.length, fixRate: 0 },
        };
    }

    const prevFindings = await prisma.vulnerability.findMany({
        where: { scanId: previous.id },
        select: { id: true, category: true, severity: true, affectedUrl: true, parameter: true, title: true, status: true },
    });

    const currMap = new Map(currFindings.map((f) => [matchKey(f), f]));
    const prevMap = new Map(prevFindings.map((f) => [matchKey(f), f]));

    const newFindings: DiffFinding[] = [];
    const fixedFindings: DiffFinding[] = [];
    const stillOpen: DiffFinding[] = [];
    const regressions: DiffFinding[] = [];

    for (const [key, f] of currMap) {
        const prev = prevMap.get(key);
        if (!prev) newFindings.push(toDiffFinding(f));
        else {
            stillOpen.push(toDiffFinding(f));
            if (prev.status === 'fixed') regressions.push(toDiffFinding(f));
        }
    }
    for (const [key, f] of prevMap) {
        if (!currMap.has(key) && f.status !== 'false_positive' && f.status !== 'accepted') {
            fixedFindings.push(toDiffFinding(f));
        }
    }

    const denom = fixedFindings.length + stillOpen.length;
    return {
        previousScanId: previous.id,
        currentScanId: current.id,
        newFindings,
        fixedFindings,
        stillOpen,
        regressions,
        summary: {
            delta: newFindings.length - fixedFindings.length,
            fixRate: denom === 0 ? 0 : fixedFindings.length / denom,
        },
    };
}

function toDiffFinding(f: {
    id: string;
    category: string;
    severity: string;
    affectedUrl: string;
    parameter: string | null;
    title: string;
}): DiffFinding {
    return {
        id: f.id,
        category: f.category,
        severity: f.severity,
        affectedUrl: f.affectedUrl,
        parameter: f.parameter,
        title: f.title,
    };
}

// ============================================================
// Render
// ============================================================

export function renderScanDiffMarkdown(diff: ScanDiff): string {
    const lines: string[] = [];
    lines.push(`# Scan diff — ${diff.currentScanId.slice(0, 8)}`);
    lines.push('');
    if (!diff.previousScanId) {
        lines.push('_No prior completed scan for this target — every finding is new._');
        lines.push('');
    } else {
        lines.push(`Previous: ${diff.previousScanId.slice(0, 8)}`);
        lines.push('');
        lines.push(`- **Delta**: ${diff.summary.delta >= 0 ? '+' : ''}${diff.summary.delta}`);
        lines.push(`- **Fix rate**: ${(diff.summary.fixRate * 100).toFixed(1)}%`);
        lines.push('');
    }
    lines.push(`## New findings (${diff.newFindings.length})`);
    for (const f of diff.newFindings) lines.push(`- **${f.severity.toUpperCase()}** ${f.category} · ${f.title}`);
    lines.push('');
    lines.push(`## Fixed findings (${diff.fixedFindings.length})`);
    for (const f of diff.fixedFindings) lines.push(`- ~~${f.title}~~`);
    lines.push('');
    lines.push(`## Still open (${diff.stillOpen.length})`);
    for (const f of diff.stillOpen) lines.push(`- ${f.title}`);
    lines.push('');
    if (diff.regressions.length > 0) {
        lines.push(`## ⚠️ Regressions (${diff.regressions.length})`);
        for (const f of diff.regressions) lines.push(`- ${f.title}`);
        lines.push('');
    }
    return lines.join('\n');
}
