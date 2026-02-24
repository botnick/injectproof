// InjectProof — Report Router
// Generates, lists, retrieves, downloads, and deletes pentest reports

import { z } from 'zod';
import { router, protectedProcedure, pentesterProcedure } from '@/server/trpc';
import { TRPCError } from '@trpc/server';

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   HELPERS — Grouping & Deduplication
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

interface VulnGroup {
    category: string;
    cweId: string;
    cweTitle: string;
    severity: string;
    cvssScore: number | null;
    count: number;
    params: string[];
    urls: string[];
    remediation: string;
    description: string;
    samplePayload: string;
    sampleRequest?: string;
    sampleResponse?: string;
    mappedOwasp?: string[];
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/** Group vulns by CWE+category, dedup, keep only essential info */
function groupVulns(vulnerabilities: any[]): VulnGroup[] {
    const map: Record<string, VulnGroup> = {};

    for (const v of vulnerabilities) {
        const key = `${v.cweId || ''}::${v.category}`;

        if (!map[key]) {
            map[key] = {
                category: v.category,
                cweId: v.cweId || '',
                cweTitle: v.cweTitle || '',
                severity: v.severity,
                cvssScore: v.cvssScore,
                count: 0,
                params: [],
                urls: [],
                remediation: v.remediation || '',
                description: v.description || '',
                samplePayload: v.payload || '',
                sampleRequest: v.request || '',
                sampleResponse: v.response || '',
                mappedOwasp: v.mappedOwasp || [],
            };
        }

        const g = map[key];
        g.count++;

        // Keep highest severity
        const cur = SEV_ORDER.indexOf(g.severity);
        const vIdx = SEV_ORDER.indexOf(v.severity);
        if (vIdx >= 0 && vIdx < cur) {
            g.severity = v.severity;
            g.cvssScore = v.cvssScore ?? g.cvssScore;
        }

        // Track unique params (max 10)
        if (v.parameter && !g.params.includes(v.parameter) && g.params.length < 10) {
            g.params.push(v.parameter);
        }

        // Track unique URLs (max 5)
        const shortUrl = (v.affectedUrl || '').replace(/^https?:\/\/[^/]+/, '');
        if (shortUrl && !g.urls.includes(shortUrl) && g.urls.length < 5) {
            g.urls.push(shortUrl);
        }

        // Keep first non-empty remediation/payload/evidence
        if (!g.remediation && v.remediation) g.remediation = v.remediation;
        if (!g.samplePayload && v.payload) g.samplePayload = v.payload;
        if (!g.sampleRequest && v.request) g.sampleRequest = v.request;
        if (!g.sampleResponse && v.response) g.sampleResponse = v.response;
        if ((!g.mappedOwasp || g.mappedOwasp.length === 0) && v.mappedOwasp) g.mappedOwasp = v.mappedOwasp;
    }

    return Object.values(map).sort(
        (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
}

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   REPORT BUILDERS — Differentiated by Type
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

function buildMarkdownReport(scan: any, vulnerabilities: any[], type: string): string {
    const L: string[] = [];
    const now = new Date().toISOString();
    const groups = groupVulns(vulnerabilities);

    const riskScore = (scan.criticalCount * 10) + (scan.highCount * 7) + (scan.mediumCount * 4) + (scan.lowCount * 1);
    let riskLevel = 'Low';
    if (riskScore >= 50) riskLevel = 'Critical';
    else if (riskScore >= 30) riskLevel = 'High';
    else if (riskScore >= 15) riskLevel = 'Medium';

    L.push(`# Pentest Report: ${scan.target?.name || 'Target'}`);
    L.push(`**Type:** ${type.toUpperCase()}`);
    L.push(`**Target:** ${scan.target?.baseUrl || 'Unknown'}`);
    L.push(`**Generated:** ${now}`);
    L.push(`**Risk Level:** ${riskLevel} (Score: ${riskScore})`);
    L.push('');

    L.push(`## Summary`);
    L.push(`| Critical | High | Medium | Low | Info | Total |`);
    L.push(`|----------|------|--------|-----|------|-------|`);
    L.push(`| ${scan.criticalCount} | ${scan.highCount} | ${scan.mediumCount} | ${scan.lowCount} | ${scan.infoCount} | ${vulnerabilities.length} |`);
    L.push('');

    if (type === 'executive') {
        L.push(`## Executive Summary`);
        L.push(`This scan discovered ${vulnerabilities.length} issues across ${scan.totalUrls} endpoints.`);
        L.push(`The overall risk level is **${riskLevel}**.`);
        L.push('');

        const critHigh = groups.filter(g => g.severity === 'critical' || g.severity === 'high');
        if (critHigh.length > 0) {
            L.push(`### Top Priority Issues`);
            critHigh.forEach((g, i) => {
                L.push(`${i + 1}. **[${g.severity.toUpperCase()}]** ${g.cweTitle || g.category} (${g.count} occurrences)`);
            });
            L.push('');
        }
        L.push(`### High-Level Remediation`);
        L.push(`It is recommended to prioritize Critical and High severity issues immediately. Medium issues should be scheduled for the next patch cycle.`);
        return L.join('\n');
    }

    if (type === 'compliance') {
        L.push(`## Compliance & Standards Mapping`);
        L.push(`| Severity | Vulnerability | OWASP Mapping | CWE | Count |`);
        L.push(`|----------|---------------|---------------|-----|-------|`);
        groups.forEach(g => {
            const owasp = g.mappedOwasp && g.mappedOwasp.length > 0 ? g.mappedOwasp.join(', ') : 'N/A';
            L.push(`| ${g.severity.toUpperCase()} | ${g.cweTitle || g.category} | ${owasp} | ${g.cweId || 'N/A'} | ${g.count} |`);
        });
        L.push('');
    }

    if (type === 'technical' || type === 'full') {
        L.push(`## Detailed Findings`);
        L.push('');
        groups.forEach((g, idx) => {
            const sevTag = g.severity.toUpperCase();
            L.push(`### ${idx + 1}. [${sevTag}] ${g.cweId ? g.cweId + ' — ' : ''}${g.cweTitle || g.category}`);
            L.push('');
            if (g.count > 1) L.push(`**Occurrences:** ${g.count}`);
            if (g.params.length > 0) L.push(`**Parameters:** \`${g.params.join('`, `')}\``);
            if (g.urls.length > 0) L.push(`**Affected Paths:**\n- ${g.urls.join('\n- ')}`);
            L.push('');
            L.push(`**Description:**\n${g.description}`);
            L.push('');

            if (g.samplePayload) {
                L.push(`**Payload:** \`${g.samplePayload}\``);
                L.push('');
            }
            if (type === 'full') {
                if (g.sampleRequest) {
                    L.push(`**Proof of Concept (Request):**\n\`\`\`http\n${g.sampleRequest}\n\`\`\``);
                    L.push('');
                }
                if (g.sampleResponse) {
                    L.push(`**Proof of Concept (Response Snippet):**\n\`\`\`http\n${g.sampleResponse.slice(0, 500)}${g.sampleResponse.length > 500 ? '...\n[Truncated]' : ''}\n\`\`\``);
                    L.push('');
                }
            }
            if (g.remediation) {
                L.push(`**Remediation:**\n${g.remediation}`);
                L.push('');
            }
            L.push('---');
            L.push('');
        });
    }

    return L.join('\n');
}

function buildJsonReport(scan: any, vulnerabilities: any[], type: string): string {
    const groups = groupVulns(vulnerabilities);
    const riskScore = (scan.criticalCount * 10) + (scan.highCount * 7) + (scan.mediumCount * 4) + (scan.lowCount * 1);

    const base = {
        meta: { reportType: type, reportVersion: '1.0', generatedAt: new Date().toISOString(), platform: 'InjectProof' },
        target: { name: scan.target?.name, baseUrl: scan.target?.baseUrl },
        scan: {
            id: scan.id, type: scan.scanType, status: scan.status,
            duration: scan.duration, totalUrls: scan.totalUrls,
        },
        summary: {
            riskScore, total: vulnerabilities.length, uniqueTypes: groups.length,
            critical: scan.criticalCount, high: scan.highCount,
            medium: scan.mediumCount, low: scan.lowCount, info: scan.infoCount,
        }
    };

    if (type === 'executive') return JSON.stringify(base, null, 2);

    const findings = groups.map(g => {
        const item: any = {
            category: g.category, cweId: g.cweId, cweTitle: g.cweTitle,
            severity: g.severity, cvssScore: g.cvssScore, occurrences: g.count,
        };
        if (type === 'compliance' || type === 'full' || type === 'technical') {
            item.mappedOwasp = g.mappedOwasp;
        }
        if (type === 'technical' || type === 'full') {
            item.parameters = g.params;
            item.affectedPaths = g.urls;
            item.samplePayload = g.samplePayload;
            item.remediation = g.remediation;
        }
        if (type === 'full') {
            item.sampleRequest = g.sampleRequest;
            item.sampleResponse = g.sampleResponse;
        }
        return item;
    });

    return JSON.stringify({ ...base, findings }, null, 2);
}

function buildHtmlReport(scan: any, vulnerabilities: any[], type: string): string {
    const groups = groupVulns(vulnerabilities);
    const riskScore = (scan.criticalCount * 10) + (scan.highCount * 7) + (scan.mediumCount * 4) + (scan.lowCount * 1);
    let riskLevel = 'Low';
    if (riskScore >= 50) riskLevel = 'Critical';
    else if (riskScore >= 30) riskLevel = 'High';
    else if (riskScore >= 15) riskLevel = 'Medium';

    const sc: Record<string, string> = {
        critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#60a5fa', info: '#94a3b8',
    };

    const styles = `
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#080c18;color:#cbd5e1;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6;padding:40px 20px}
    .w{max-width:1100px;margin:0 auto;background:#0a0f1e;border:1px solid rgba(255,255,255,0.05);border-radius:24px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,0.4)}
    h1{font-size:32px;color:#f8fafc;margin-bottom:8px;font-weight:800;letter-spacing:-0.02em}
    h2{font-size:20px;color:#f8fafc;margin:32px 0 16px;padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.06);font-weight:600}
    h3{font-size:16px;color:#e2e8f0;margin:24px 0 12px;font-weight:600}
    p{margin-bottom:16px}
    .badge-wrap{margin-bottom:24px;display:flex;gap:12px;flex-wrap:wrap}
    .badge{padding:4px 12px;border-radius:100px;font-size:12px;font-weight:600;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);color:#94a3b8}
    .badge-brand{background:rgba(99,102,241,0.1);color:#818cf8;border-color:rgba(99,102,241,0.2)}
    .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}
    .st{background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.04);border-radius:16px;padding:20px;text-align:center;box-shadow:inset 0 1px 0 rgba(255,255,255,0.02)}
    .st .n{font-size:32px;font-weight:800;line-height:1}
    .st .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;margin-top:8px;font-weight:600}
    .st.c .n{color:#f87171} .st.h .n{color:#fb923c} .st.m .n{color:#fbbf24} .st.lo .n{color:#60a5fa} .st.i .n{color:#94a3b8}
    table{width:100%;border-collapse:collapse;font-size:13px;margin:16px 0;background:rgba(255,255,255,0.01);border-radius:12px;overflow:hidden}
    th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#94a3b8;padding:12px 16px;background:rgba(255,255,255,0.03);border-bottom:1px solid rgba(255,255,255,0.06)}
    td{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.03);color:#cbd5e1;vertical-align:top}
    tr:last-child td{border-bottom:none}
    .sev{display:inline-flex;align-items:center;justify-content:center;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700}
    .finding-card{background:rgba(255,255,255,0.015);border:1px solid rgba(255,255,255,0.04);border-radius:16px;padding:24px;margin-bottom:20px}
    .finding-header{display:flex;align-items:flex-start;gap:16px;margin-bottom:16px}
    .finding-title{flex:1}
    .finding-title h4{font-size:16px;color:#f8fafc;margin-bottom:4px;word-break:break-word}
    .finding-meta{font-size:12px;color:#64748b;display:flex;gap:16px;flex-wrap:wrap}
    .code-block{background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.05);border-radius:12px;padding:16px;font-family:'Courier New',Courier,monospace;font-size:12px;color:#a5b4fc;overflow-x:auto;margin:12px 0;white-space:pre-wrap;word-break:break-all}
    .code-label{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:0.1em;color:#64748b;margin-bottom:4px;margin-top:16px}
    .risk-score{display:flex;align-items:center;gap:12px;background:rgba(255,255,255,0.03);padding:16px 24px;border-radius:16px;border:1px solid rgba(255,255,255,0.05)}
    .risk-score .num{font-size:24px;font-weight:800;color:#f8fafc}
    .risk-critical{color:#f87171} .risk-high{color:#fb923c} .risk-medium{color:#fbbf24} .risk-low{color:#60a5fa}
    .ft{text-align:center;margin-top:40px;padding-top:20px;border-top:1px solid rgba(255,255,255,0.05);color:#475569;font-size:12px}
    
    @media print {
        body{background:#fff;color:#1e293b;padding:0}
        .w{background:#fff;border:none;box-shadow:none;margin:0;max-width:none}
        h1,h2,h3,h4,.risk-score .num,.finding-title h4{color:#000}
        .st{background:#f8fafc;border-color:#e2e8f0;box-shadow:none}
        .code-block{background:#f1f5f9;color:#334155;border-color:#e2e8f0}
        th{background:#f8fafc;color:#475569;border-color:#e2e8f0}
        td{color:#334155;border-color:#f1f5f9}
        .badge,.finding-card{border-color:#e2e8f0;background:#fff}
        .sev,.badge{print-color-adjust: exact;-webkit-print-color-adjust: exact;}
    }
    `;

    // 1. Executive Summary Details
    const execSummary = `
        <h2>Executive Summary</h2>
        <div class="risk-score">
            <div>Overall Risk Score: <span class="num">${riskScore}</span></div>
            <div class="badge risk-${riskLevel.toLowerCase()}">${riskLevel} Risk</div>
        </div>
        <p style="margin-top:16px;color:#94a3b8">The assessment identified <strong>${vulnerabilities.length}</strong> vulnerabilities across <strong>${groups.length}</strong> unique types. There are <strong>${scan.criticalCount} Critical</strong> and <strong>${scan.highCount} High</strong> severity issues that require immediate attention.</p>
    `;

    // 2. Compliance Table
    let complianceTable = '';
    if (type === 'compliance' || type === 'full') {
        const rows = groups.map(g => {
            const c = sc[g.severity] || '#888';
            const owasp = g.mappedOwasp?.length ? g.mappedOwasp.join(', ') : 'Not Mapped';
            return `<tr>
                <td><span class="sev" style="background:${c}15;color:${c};border:1px solid ${c}40">${g.severity.toUpperCase()}</span></td>
                <td><strong>${esc(g.cweTitle || g.category)}</strong><br><span style="font-size:11px;color:#64748b">${esc(g.cweId || '')}</span></td>
                <td>${esc(owasp)}</td>
                <td>Fail</td>
            </tr>`;
        }).join('');

        complianceTable = `
            <h2>Compliance Matrix</h2>
            <table>
                <thead><tr><th>Severity</th><th>Vulnerability</th><th>OWASP Standard</th><th>Status</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        `;
    }

    // 3. Technical Details
    let techDetails = '';
    if (type === 'technical' || type === 'full') {
        const cards = groups.map((g, i) => {
            const c = sc[g.severity] || '#888';

            let evidenceBlocks = '';
            if (g.samplePayload) {
                evidenceBlocks += `<div class="code-label">Sample Payload</div><div class="code-block">${esc(g.samplePayload)}</div>`;
            }
            if (type === 'full') {
                if (g.sampleRequest) {
                    evidenceBlocks += `<div class="code-label">Request Pattern (Sample)</div><div class="code-block">${esc(g.sampleRequest)}</div>`;
                }
                if (g.sampleResponse) {
                    const truncated = g.sampleResponse.length > 500 ? g.sampleResponse.slice(0, 500) + '\n\n...[Response Truncated]' : g.sampleResponse;
                    evidenceBlocks += `<div class="code-label">Response Excerpt (Sample)</div><div class="code-block" style="color:#6ee7b7">${esc(truncated)}</div>`;
                }
            }

            const paths = g.urls.length > 0 ? `<strong>Affected Paths:</strong> ${g.urls.map(u => '<code>' + esc(u) + '</code>').join(' ')}` : '';
            const params = g.params.length > 0 ? `<strong style="margin-left:16px">Parameters:</strong> ${g.params.map(p => '<code>' + esc(p) + '</code>').join(' ')}` : '';

            return `
            <div class="finding-card">
                <div class="finding-header">
                    <span class="sev" style="background:${c}15;color:${c};border:1px solid ${c}40;padding:4px 12px">${g.severity.toUpperCase()}</span>
                    <div class="finding-title">
                        <h4>${i + 1}. ${esc(g.cweTitle || g.category)}</h4>
                        <div class="finding-meta">
                            <span>${g.cweId || 'No CWE'}</span>
                            <span>${g.count} Occurrences</span>
                        </div>
                    </div>
                </div>
                <p style="font-size:13px;color:#94a3b8;white-space:pre-wrap">${esc(g.description)}</p>
                
                ${(paths || params) ? `<div style="font-size:12px;background:rgba(255,255,255,0.02);padding:10px 14px;border-radius:8px;margin:12px 0">${paths}${params}</div>` : ''}
                
                ${evidenceBlocks}
                
                ${g.remediation ? `<div style="margin-top:16px;border-top:1px dashed rgba(255,255,255,0.1);padding-top:16px"><strong style="color:#e2e8f0;font-size:13px">Remediation Recommendation:</strong><p style="font-size:13px;color:#94a3b8;margin-top:4px;white-space:pre-wrap">${esc(g.remediation)}</p></div>` : ''}
            </div>
            `;
        }).join('');

        techDetails = `
            <h2>Technical Findings</h2>
            ${cards}
        `;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>${esc(type.toUpperCase())} Report — ${esc(scan.target?.name || 'Target')}</title>
<style>${styles}</style>
</head>
<body>
<div class="w">
    <div class="badge-wrap">
        <span class="badge badge-brand">InjectProof Security Platform</span>
        <span class="badge" style="text-transform:uppercase">${esc(type)} REPORT</span>
        <span class="badge">${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</span>
    </div>
    
    <h1>${esc(scan.target?.name || 'Unknown Target')}</h1>
    <p style="color:#94a3b8;font-size:15px;margin-bottom:32px">${esc(scan.target?.baseUrl || '')}</p>

    <div class="stats">
        <div class="st c"><div class="n">${scan.criticalCount}</div><div class="l">Critical</div></div>
        <div class="st h"><div class="n">${scan.highCount}</div><div class="l">High</div></div>
        <div class="st m"><div class="n">${scan.mediumCount}</div><div class="l">Medium</div></div>
        <div class="st lo"><div class="n">${scan.lowCount}</div><div class="l">Low</div></div>
        <div class="st i"><div class="n">${scan.infoCount}</div><div class="l">Info</div></div>
    </div>

    ${execSummary}
    ${complianceTable}
    ${techDetails}

    <div class="ft">Automated Security Analysis by InjectProof</div>
</div>
</body>
</html>`;
}

function esc(s: string): string {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ROUTER
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

export const reportRouter = router({
    generate: pentesterProcedure
        .input(z.object({
            scanId: z.string().uuid(),
            format: z.enum(['json', 'md', 'html', 'pdf']).default('md'),
            title: z.string().optional(),
            type: z.enum(['executive', 'technical', 'compliance', 'full']).default('technical'),
            sections: z.array(z.string()).optional(),
        }))
        .mutation(async ({ ctx, input }) => {
            const scan = await ctx.prisma.scan.findUnique({
                where: { id: input.scanId },
                include: {
                    target: true,
                    vulnerabilities: {
                        include: { evidence: true },
                        orderBy: { severity: 'asc' },
                    },
                },
            });

            if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

            let content: string;
            if (input.format === 'json') {
                content = buildJsonReport(scan, scan.vulnerabilities, input.type);
            } else if (input.format === 'html') {
                content = buildHtmlReport(scan, scan.vulnerabilities, input.type);
            } else {
                content = buildMarkdownReport(scan, scan.vulnerabilities, input.type);
            }

            const reportTitle = input.title || `${scan.target?.name || 'Target'} — ${input.type.toUpperCase()} Report`;

            const report = await ctx.prisma.report.create({
                data: {
                    title: reportTitle,
                    type: input.type,
                    format: input.format,
                    status: 'completed',
                    scanIds: JSON.stringify([input.scanId]),
                    targetIds: JSON.stringify([scan.targetId]),
                    filePath: content,
                    fileSize: Buffer.byteLength(content, 'utf-8'),
                    generatedById: ctx.user!.userId,
                },
            });

            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'generate_report',
                    resource: 'report',
                    resourceId: report.id,
                    details: JSON.stringify({ scanId: input.scanId, format: input.format, type: input.type }),
                },
            });

            return report;
        }),

    list: protectedProcedure
        .input(z.object({
            page: z.number().int().min(1).default(1),
            pageSize: z.number().int().min(1).max(100).default(20),
            format: z.string().optional(),
            type: z.string().optional(),
            status: z.string().optional(),
        }).optional())
        .query(async ({ ctx, input }) => {
            const page = input?.page ?? 1;
            const pageSize = input?.pageSize ?? 20;
            const skip = (page - 1) * pageSize;

            const where: any = {};
            if (input?.format) where.format = input.format;
            if (input?.type) where.type = input.type;
            if (input?.status) where.status = input.status;

            const [items, total] = await Promise.all([
                ctx.prisma.report.findMany({
                    where,
                    orderBy: { createdAt: 'desc' },
                    skip,
                    take: pageSize,
                    include: {
                        generatedBy: { select: { id: true, name: true, email: true } },
                    },
                }),
                ctx.prisma.report.count({ where }),
            ]);

            return { items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) };
        }),

    getById: protectedProcedure
        .input(z.object({ id: z.string().uuid() }))
        .query(async ({ ctx, input }) => {
            const report = await ctx.prisma.report.findUnique({
                where: { id: input.id },
                include: {
                    generatedBy: { select: { id: true, name: true, email: true } },
                },
            });

            if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
            return report;
        }),

    download: protectedProcedure
        .input(z.object({ id: z.string().uuid() }))
        .query(async ({ ctx, input }) => {
            const report = await ctx.prisma.report.findUnique({ where: { id: input.id } });
            if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });

            return {
                content: report.filePath || '',
                format: report.format,
                title: report.title,
                fileSize: report.fileSize,
            };
        }),

    delete: pentesterProcedure
        .input(z.object({ id: z.string().uuid() }))
        .mutation(async ({ ctx, input }) => {
            const report = await ctx.prisma.report.findUnique({ where: { id: input.id } });
            if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });

            await ctx.prisma.report.delete({ where: { id: input.id } });

            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'delete_report',
                    resource: 'report',
                    resourceId: input.id,
                    details: JSON.stringify({ title: report.title, format: report.format }),
                },
            });

            return { success: true };
        }),
});
