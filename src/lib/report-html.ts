// InjectProof — HTML report template
// ===================================
// Self-contained HTML → PDF renderer. Consumed by the /api/scan/[id]/report.pdf
// endpoint; Puppeteer converts this HTML to PDF. Bilingual (EN + TH), corporate-
// layout, PrintCSS-optimised (page breaks around finding cards, header/footer
// on every page, title/ToC at front).
//
// Rendering happens server-side so the PDF is deterministic — no browser /
// font differences between reviewers. Fonts are inlined via system default
// sans-serif with IBM Plex fallback (matches the product's UI).

import type { Vulnerability, Scan, Target } from '@/generated/prisma/client';

export interface ReportInput {
    scan: Scan;
    target: Target;
    vulnerabilities: Vulnerability[];
    /** Human display name of the organisation running the scan. */
    organisationName?: string;
    /** Name of the scanner operator. */
    operatorName?: string;
    /** Generated-at timestamp (ISO). Defaults to now. */
    generatedAt?: string;
}

// ── Severity helpers ─────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLOR: Record<string, string> = {
    critical: '#dc2626',
    high:     '#ea580c',
    medium:   '#ca8a04',
    low:      '#2563eb',
    info:     '#64748b',
};
const SEVERITY_LABEL_TH: Record<string, string> = {
    critical: 'วิกฤต',
    high:     'สูง',
    medium:   'กลาง',
    low:      'ต่ำ',
    info:     'ข้อมูล',
};

function escapeHtml(s: string | null | undefined): string {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function preformat(s: string | null | undefined, maxLen = 4000): string {
    if (!s) return '<em style="color:#94a3b8">— no content captured —</em>';
    const truncated = s.length > maxLen ? s.slice(0, maxLen) + '\n\n[…truncated]' : s;
    return `<pre class="code">${escapeHtml(truncated)}</pre>`;
}

function fmtDate(d: Date | string | undefined | null): string {
    if (!d) return '—';
    const date = typeof d === 'string' ? new Date(d) : d;
    return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function parseJsonArray(s: string | null | undefined): string[] {
    if (!s) return [];
    try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; }
}

// ── Section builders ─────────────────────────────────────────────────────

function buildSummaryTable(vulns: Vulnerability[]): string {
    const buckets: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) buckets[v.severity] = (buckets[v.severity] ?? 0) + 1;
    const total = vulns.length;

    return `
    <table class="summary">
      <thead>
        <tr>
          <th>Severity · ระดับความรุนแรง</th>
          <th style="text-align:right">Count · จำนวน</th>
          <th style="text-align:right">% of Total</th>
        </tr>
      </thead>
      <tbody>
        ${(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => `
          <tr>
            <td>
              <span class="sev-dot" style="background:${SEVERITY_COLOR[sev]}"></span>
              <strong>${sev.toUpperCase()}</strong> · ${SEVERITY_LABEL_TH[sev]}
            </td>
            <td style="text-align:right">${buckets[sev] ?? 0}</td>
            <td style="text-align:right">${total ? ((buckets[sev] ?? 0) * 100 / total).toFixed(1) : '0.0'}%</td>
          </tr>
        `).join('')}
        <tr class="total-row">
          <td><strong>Total · ทั้งหมด</strong></td>
          <td style="text-align:right"><strong>${total}</strong></td>
          <td style="text-align:right">100%</td>
        </tr>
      </tbody>
    </table>
    `;
}

function buildCategoryChart(vulns: Vulnerability[]): string {
    const byCat: Record<string, number> = {};
    for (const v of vulns) byCat[v.category] = (byCat[v.category] ?? 0) + 1;
    const entries = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) return '';
    const max = entries[0][1];
    return `
    <table class="cat-chart">
      <tbody>
        ${entries.map(([cat, n]) => `
          <tr>
            <td class="cat-name">${escapeHtml(cat)}</td>
            <td class="cat-bar-cell">
              <div class="cat-bar" style="width:${(n * 100 / max).toFixed(1)}%"></div>
            </td>
            <td class="cat-count">${n}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    `;
}

function buildFindingCard(v: Vulnerability, index: number): string {
    const refs = parseJsonArray(v.references);
    const reproSteps = parseJsonArray(v.reproductionSteps);
    const owasp = parseJsonArray(v.mappedOwasp);
    const asvs = parseJsonArray(v.mappedOwaspAsvs);
    const nist = parseJsonArray(v.mappedNist);
    const sevColor = SEVERITY_COLOR[v.severity] ?? '#64748b';
    const sevTh = SEVERITY_LABEL_TH[v.severity] ?? v.severity;

    return `
    <section class="finding" style="border-left: 6px solid ${sevColor}">
      <div class="finding-head">
        <div class="finding-idx">#${index + 1}</div>
        <div class="finding-title">
          <h3>${escapeHtml(v.title)}</h3>
          <div class="finding-sub">
            <span class="sev-pill" style="background:${sevColor}">${v.severity.toUpperCase()} · ${sevTh}</span>
            ${v.confidence ? `<span class="pill pill-gray">Confidence: ${escapeHtml(v.confidence)}</span>` : ''}
            ${v.cvssScore ? `<span class="pill pill-gray">CVSS ${v.cvssScore.toFixed(1)}</span>` : ''}
            ${v.cweId ? `<span class="pill pill-blue">${escapeHtml(v.cweId)}</span>` : ''}
            ${v.validationLevel ? `<span class="pill pill-${v.validationLevel === 'confirmed' ? 'green' : 'amber'}">${escapeHtml(v.validationLevel)}</span>` : ''}
          </div>
        </div>
      </div>

      <div class="finding-body">
        <div class="grid-2">
          <div class="kv"><div class="k">Category · หมวดหมู่</div><div class="v">${escapeHtml(v.category)}</div></div>
          <div class="kv"><div class="k">Status · สถานะ</div><div class="v">${escapeHtml(v.status)}</div></div>
          <div class="kv"><div class="k">Affected URL · URL ที่พบ</div><div class="v code-inline">${escapeHtml(v.affectedUrl)}</div></div>
          <div class="kv"><div class="k">Parameter · พารามิเตอร์</div><div class="v code-inline">${escapeHtml(v.parameter ?? '(endpoint-level)')}${v.parameterType ? ` <span class="dim">[${escapeHtml(v.parameterType)}]</span>` : ''}</div></div>
          <div class="kv"><div class="k">HTTP Method</div><div class="v code-inline">${escapeHtml(v.httpMethod ?? '—')}</div></div>
          <div class="kv"><div class="k">Response Code / Time</div><div class="v">${v.responseCode ?? '—'} / ${v.responseTime ?? '—'} ms</div></div>
        </div>

        <div class="section">
          <h4>Description · คำอธิบาย</h4>
          <p>${escapeHtml(v.description)}</p>
        </div>

        ${v.impact ? `
        <div class="section">
          <h4>Business Impact · ผลกระทบทางธุรกิจ</h4>
          <p>${escapeHtml(v.impact)}</p>
        </div>` : ''}

        ${v.technicalDetail ? `
        <div class="section">
          <h4>Technical Detail · รายละเอียดเชิงเทคนิค</h4>
          <p>${escapeHtml(v.technicalDetail)}</p>
        </div>` : ''}

        ${v.payload ? `
        <div class="section">
          <h4>Proving Payload · payload ที่ใช้พิสูจน์</h4>
          ${preformat(v.payload, 800)}
        </div>` : ''}

        ${v.requestArtifact ? `
        <div class="section">
          <h4>Request · HTTP Request</h4>
          ${preformat(v.requestArtifact, 3000)}
        </div>` : ''}

        ${v.responseArtifact ? `
        <div class="section">
          <h4>Response · HTTP Response Excerpt</h4>
          ${preformat(v.responseArtifact, 3000)}
        </div>` : ''}

        ${reproSteps.length > 0 ? `
        <div class="section">
          <h4>Reproduction Steps · ขั้นตอนทำซ้ำ</h4>
          <ol>
            ${reproSteps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
          </ol>
        </div>` : ''}

        ${v.remediation ? `
        <div class="section remediation">
          <h4>Remediation · วิธีแก้ไข</h4>
          <pre class="code remediation-code">${escapeHtml(v.remediation)}</pre>
        </div>` : ''}

        ${(owasp.length > 0 || asvs.length > 0 || nist.length > 0 || v.cvssVector) ? `
        <div class="section">
          <h4>Compliance Mappings · การจับคู่มาตรฐาน</h4>
          <table class="mapping">
            ${v.cvssVector ? `<tr><td>CVSS Vector</td><td class="code-inline">${escapeHtml(v.cvssVector)}</td></tr>` : ''}
            ${owasp.length > 0 ? `<tr><td>OWASP Top 10</td><td>${owasp.map(escapeHtml).join(', ')}</td></tr>` : ''}
            ${asvs.length > 0 ? `<tr><td>OWASP ASVS</td><td>${asvs.map(escapeHtml).join(', ')}</td></tr>` : ''}
            ${nist.length > 0 ? `<tr><td>NIST 800-53</td><td>${nist.map(escapeHtml).join(', ')}</td></tr>` : ''}
          </table>
        </div>` : ''}

        ${refs.length > 0 ? `
        <div class="section">
          <h4>References · อ้างอิง</h4>
          <ul class="refs">
            ${refs.map(r => `<li><code>${escapeHtml(r)}</code></li>`).join('')}
          </ul>
        </div>` : ''}
      </div>
    </section>
    `;
}

// ── Main template ────────────────────────────────────────────────────────

export function buildReportHtml(input: ReportInput): string {
    const { scan, target, vulnerabilities, organisationName, operatorName } = input;
    const sortedVulns = [...vulnerabilities].sort((a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
    const gen = input.generatedAt ?? new Date().toISOString();
    const scanDuration = scan.completedAt && scan.startedAt
        ? Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)
        : null;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Assessment Report — ${escapeHtml(target.name)}</title>
  <style>
    @page {
      size: A4;
      margin: 22mm 16mm 22mm 16mm;
      @top-left {
        content: "InjectProof — Security Assessment Report";
        font-family: 'IBM Plex Sans', 'Segoe UI', 'Helvetica Neue', sans-serif;
        font-size: 9pt;
        color: #64748b;
      }
      @top-right {
        content: "${escapeHtml(target.name)}";
        font-family: 'IBM Plex Sans', 'Segoe UI', 'Helvetica Neue', sans-serif;
        font-size: 9pt;
        color: #64748b;
      }
      @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'IBM Plex Mono', 'Menlo', monospace;
        font-size: 8pt;
        color: #94a3b8;
      }
    }
    * { box-sizing: border-box; }
    body {
      font-family: 'IBM Plex Sans', 'IBM Plex Sans Thai', 'Segoe UI', 'Helvetica Neue', sans-serif;
      font-size: 10.5pt; line-height: 1.55;
      color: #1e293b; background: white;
      margin: 0; padding: 0;
    }
    h1, h2, h3, h4 {
      font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
      margin-top: 0; color: #0f172a;
    }
    h1 { font-size: 24pt; font-weight: 700; letter-spacing: -0.01em; }
    h2 { font-size: 16pt; font-weight: 600; margin: 18pt 0 8pt; border-bottom: 1.5pt solid #e2e8f0; padding-bottom: 6pt; page-break-after: avoid; }
    h3 { font-size: 13pt; font-weight: 600; margin: 0 0 4pt; page-break-after: avoid; }
    h4 { font-size: 11pt; font-weight: 600; color: #334155; margin: 12pt 0 4pt; page-break-after: avoid; }
    p { margin: 0 0 8pt; }
    code, .code-inline { font-family: 'IBM Plex Mono', 'Menlo', 'Consolas', monospace; font-size: 9.5pt; background: #f1f5f9; padding: 1pt 4pt; border-radius: 2pt; }
    pre.code {
      font-family: 'IBM Plex Mono', 'Menlo', monospace; font-size: 9pt; line-height: 1.45;
      background: #f8fafc; color: #334155;
      padding: 8pt 10pt; border-radius: 3pt; border: 1pt solid #e2e8f0;
      white-space: pre-wrap; word-break: break-all; overflow-wrap: anywhere;
      margin: 4pt 0;
    }
    .dim { color: #94a3b8; font-weight: normal; }

    /* Cover */
    .cover {
      page-break-after: always;
      min-height: 240mm;
      display: flex; flex-direction: column; justify-content: center;
      padding: 40pt 0;
    }
    .cover .brand { font-size: 14pt; letter-spacing: 0.08em; color: #64748b; text-transform: uppercase; margin-bottom: 40pt; }
    .cover h1 { font-size: 30pt; margin-bottom: 10pt; }
    .cover .subtitle { font-size: 14pt; color: #475569; margin-bottom: 30pt; }
    .cover-meta { margin-top: 60pt; border-top: 1.5pt solid #e2e8f0; padding-top: 20pt; }
    .cover-meta table { width: 100%; border-collapse: collapse; }
    .cover-meta td { padding: 6pt 0; vertical-align: top; }
    .cover-meta td:first-child { width: 35%; color: #64748b; font-size: 9.5pt; text-transform: uppercase; letter-spacing: 0.04em; }
    .cover-meta td:last-child { font-weight: 500; }
    .confidential {
      margin-top: 40pt; padding: 10pt 14pt;
      background: #fef2f2; border: 1pt solid #fecaca; border-radius: 4pt;
      font-size: 9.5pt; color: #7f1d1d;
    }

    /* Summary */
    table.summary, table.cat-chart, table.mapping {
      width: 100%; border-collapse: collapse;
      margin: 8pt 0 16pt; font-size: 10pt;
    }
    table.summary th, table.summary td { padding: 8pt 10pt; border-bottom: 0.5pt solid #e2e8f0; }
    table.summary th { background: #f8fafc; text-align: left; font-weight: 600; font-size: 9pt; color: #475569; text-transform: uppercase; letter-spacing: 0.04em; }
    table.summary .total-row { background: #f8fafc; font-weight: 600; }
    .sev-dot { display: inline-block; width: 8pt; height: 8pt; border-radius: 50%; margin-right: 6pt; vertical-align: middle; }

    /* Category chart */
    table.cat-chart .cat-name { padding: 3pt 6pt; width: 30%; font-size: 9.5pt; color: #475569; vertical-align: middle; }
    table.cat-chart .cat-bar-cell { padding: 3pt 6pt; }
    table.cat-chart .cat-bar { background: #3b82f6; height: 8pt; border-radius: 2pt; min-width: 4pt; }
    table.cat-chart .cat-count { padding: 3pt 6pt; width: 8%; text-align: right; font-family: 'IBM Plex Mono', monospace; font-size: 9pt; color: #475569; }

    /* Finding card */
    .finding {
      page-break-inside: avoid;
      margin: 14pt 0; padding: 12pt 16pt;
      background: white; border-radius: 4pt;
      border: 0.5pt solid #e2e8f0;
    }
    .finding-head { display: table; width: 100%; margin-bottom: 10pt; }
    .finding-idx {
      display: table-cell; width: 40pt; vertical-align: top;
      font-family: 'IBM Plex Mono', monospace; font-size: 14pt; color: #64748b; font-weight: 500;
    }
    .finding-title { display: table-cell; vertical-align: top; }
    .finding-sub { margin-top: 4pt; }
    .sev-pill, .pill {
      display: inline-block; margin-right: 4pt; padding: 1.5pt 7pt;
      border-radius: 10pt; font-size: 8.5pt; font-weight: 600;
      color: white;
    }
    .pill-gray { background: #64748b; }
    .pill-blue { background: #2563eb; }
    .pill-green { background: #16a34a; }
    .pill-amber { background: #d97706; }
    .grid-2 {
      display: grid; grid-template-columns: 1fr 1fr; gap: 6pt 16pt;
      margin-bottom: 10pt;
    }
    .kv .k { font-size: 8.5pt; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; margin-bottom: 1pt; }
    .kv .v { font-size: 10pt; color: #1e293b; word-break: break-word; }
    .section { margin-top: 10pt; }
    .section h4 { margin-bottom: 4pt; }
    .section ol, .section ul { margin: 4pt 0 8pt 16pt; padding: 0; }
    .section ol li, .section ul li { margin-bottom: 3pt; }
    .remediation pre.code { background: #ecfdf5; border-color: #a7f3d0; color: #064e3b; }
    .refs code { font-size: 8.5pt; word-break: break-all; }
    table.mapping td { padding: 3pt 8pt 3pt 0; vertical-align: top; font-size: 9.5pt; }
    table.mapping td:first-child { color: #64748b; width: 24%; text-transform: uppercase; font-size: 8.5pt; letter-spacing: 0.04em; }

    /* No findings */
    .no-findings {
      text-align: center; padding: 40pt 20pt;
      background: #f0fdf4; border: 1pt solid #bbf7d0; border-radius: 6pt;
      color: #166534;
    }
    .no-findings h3 { color: #15803d; margin-bottom: 6pt; }

    /* Appendix */
    .appendix { margin-top: 20pt; font-size: 9.5pt; color: #475569; }
    .appendix h2 { font-size: 13pt; }
    .appendix p { margin-bottom: 6pt; }
  </style>
</head>
<body>

  <!-- ━━━━━━━━━ COVER ━━━━━━━━━ -->
  <div class="cover">
    <div class="brand">InjectProof Security Assessment</div>
    <h1>${escapeHtml(target.name)}</h1>
    <div class="subtitle">${escapeHtml(target.baseUrl)}</div>
    <div class="subtitle" style="color:#94a3b8;font-size:11pt">รายงานผลการทดสอบความปลอดภัย (Security Assessment Report)</div>

    <div class="cover-meta">
      <table>
        <tr><td>Scan ID</td><td class="code-inline">${escapeHtml(scan.id)}</td></tr>
        <tr><td>Target Environment</td><td>${escapeHtml(target.environment)} · ${escapeHtml(target.criticality)}</td></tr>
        <tr><td>Scan Started</td><td>${fmtDate(scan.startedAt)}</td></tr>
        <tr><td>Scan Completed</td><td>${fmtDate(scan.completedAt)}${scanDuration != null ? ` <span class="dim">(${scanDuration}s)</span>` : ''}</td></tr>
        <tr><td>Scan Status</td><td>${escapeHtml(scan.status)}</td></tr>
        <tr><td>Total Findings</td><td><strong>${vulnerabilities.length}</strong></td></tr>
        ${organisationName ? `<tr><td>Organisation</td><td>${escapeHtml(organisationName)}</td></tr>` : ''}
        ${operatorName ? `<tr><td>Operator / ผู้ทดสอบ</td><td>${escapeHtml(operatorName)}</td></tr>` : ''}
        <tr><td>Report Generated</td><td>${fmtDate(gen)}</td></tr>
      </table>
    </div>

    <div class="confidential">
      <strong>CONFIDENTIAL · เอกสารลับ</strong> — This report contains sensitive technical detail about
      security vulnerabilities in the target system. Distribute only to authorised engineering and
      security personnel. Unauthorised disclosure may be grounds for disciplinary action and may
      expose the organisation to further risk.
      <br><br>
      เอกสารฉบับนี้มีรายละเอียดเกี่ยวกับช่องโหว่ด้านความปลอดภัย
      กรุณาเผยแพร่เฉพาะผู้ที่ได้รับอนุญาตเท่านั้น
    </div>
  </div>

  <!-- ━━━━━━━━━ EXECUTIVE SUMMARY ━━━━━━━━━ -->
  <h2>Executive Summary · สรุปสำหรับผู้บริหาร</h2>
  <p>
    This report documents the findings of an automated security assessment performed by the
    InjectProof scanner against <strong>${escapeHtml(target.name)}</strong> (${escapeHtml(target.baseUrl)}).
    The scan completed on ${fmtDate(scan.completedAt)} and identified
    <strong>${vulnerabilities.length}</strong> issue(s) across
    <strong>${Object.keys(vulnerabilities.reduce<Record<string, true>>((acc, v) => (acc[v.category] = true, acc), {})).length}</strong>
    vulnerability categories.
  </p>
  <p>
    รายงานฉบับนี้สรุปผลการทดสอบความปลอดภัยแบบอัตโนมัติของระบบ <strong>${escapeHtml(target.name)}</strong>
    โดย InjectProof scanner ระหว่างการตรวจพบช่องโหว่ทั้งสิ้น
    <strong>${vulnerabilities.length}</strong> รายการ
    ใน <strong>${Object.keys(vulnerabilities.reduce<Record<string, true>>((acc, v) => (acc[v.category] = true, acc), {})).length}</strong>
    หมวดหมู่ ควรดำเนินการแก้ไขก่อนนำระบบขึ้น production เพื่อป้องกันความเสี่ยงด้านการเงิน ชื่อเสียง และการถูกบังคับใช้กฎหมาย (PDPA/GDPR)
  </p>

  ${buildSummaryTable(sortedVulns)}

  ${sortedVulns.length > 0 ? `
  <h3>Findings by Category · แบ่งตามประเภท</h3>
  ${buildCategoryChart(sortedVulns)}
  ` : ''}

  <!-- ━━━━━━━━━ FINDINGS ━━━━━━━━━ -->
  ${sortedVulns.length === 0 ? `
    <h2>Findings · รายการช่องโหว่</h2>
    <div class="no-findings">
      <h3>No security issues detected in this scan run</h3>
      <p>ไม่พบช่องโหว่ในการสแกนรอบนี้</p>
      <p style="margin-top:12pt;font-size:9pt;color:#15803d">
        Absence of findings does not prove absence of vulnerabilities. Additional manual pentest
        rounds are recommended for high-criticality systems.
      </p>
    </div>
  ` : `
    <h2 style="page-break-before: always">Detailed Findings · รายละเอียดช่องโหว่</h2>
    ${sortedVulns.map((v, i) => buildFindingCard(v, i)).join('')}
  `}

  <!-- ━━━━━━━━━ APPENDIX ━━━━━━━━━ -->
  <div class="appendix" style="page-break-before: always">
    <h2>Appendix · ภาคผนวก</h2>
    <h3>Scan Configuration</h3>
    <table class="mapping">
      <tr><td>Target Base URL</td><td class="code-inline">${escapeHtml(target.baseUrl)}</td></tr>
      <tr><td>Max Crawl Depth</td><td>${target.maxCrawlDepth ?? '—'}</td></tr>
      <tr><td>Max URLs</td><td>${target.maxUrls ?? '—'}</td></tr>
      <tr><td>Request Timeout</td><td>${target.requestTimeout ?? '—'} ms</td></tr>
      <tr><td>Auth Type</td><td>${escapeHtml(target.authType ?? 'none')}</td></tr>
    </table>

    <h3>Methodology · วิธีการทดสอบ</h3>
    <p>
      InjectProof uses an oracle-driven detection engine: every candidate finding is verified
      via baseline response comparison, counter-factual probing, and multi-technique replay. This
      reduces false positives relative to signature-only scanners while keeping broad coverage.
    </p>
    <p>
      การตรวจจับใช้ oracle-driven engine ซึ่งจะยืนยันผลการพบช่องโหว่แต่ละจุดผ่านการเปรียบเทียบ baseline,
      การทดสอบแบบ counter-factual, และการ replay หลายเทคนิค เพื่อลด false positive
    </p>

    <h3>Severity Reference · ความหมายของระดับความรุนแรง</h3>
    <table class="mapping">
      <tr><td style="color:${SEVERITY_COLOR.critical}"><strong>CRITICAL</strong></td><td>Immediate exploitation is possible and impact is severe (full DB compromise, RCE, admin takeover). Fix before prod.</td></tr>
      <tr><td style="color:${SEVERITY_COLOR.high}"><strong>HIGH</strong></td><td>Exploitation is straightforward and consequences are serious (data exfiltration, privilege escalation). Fix in the current sprint.</td></tr>
      <tr><td style="color:${SEVERITY_COLOR.medium}"><strong>MEDIUM</strong></td><td>Exploitation requires specific conditions or impact is limited. Fix in the next 1–2 sprints.</td></tr>
      <tr><td style="color:${SEVERITY_COLOR.low}"><strong>LOW</strong></td><td>Minor issue with limited impact. Fix in routine maintenance.</td></tr>
      <tr><td style="color:${SEVERITY_COLOR.info}"><strong>INFO</strong></td><td>Informational. Review and document but no urgent action required.</td></tr>
    </table>

    <h3>Generated by</h3>
    <p>InjectProof v1.0 — <span class="code-inline">${escapeHtml(scan.id)}</span> — ${fmtDate(gen)}</p>
  </div>

</body>
</html>
`;
}
