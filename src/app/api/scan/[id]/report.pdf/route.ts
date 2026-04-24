// InjectProof — Scan report PDF endpoint
// =======================================
// GET /api/scan/:id/report.pdf → downloads a corporate-grade PDF containing
// executive summary + per-finding detail + remediation + appendix.
//
// Flow: render HTML template → spawn Puppeteer → page.pdf() → return bytes.
// All data is pulled from Prisma by scan ID; auth is enforced via the same
// JWT cookie the UI uses, so the endpoint is a 1:1 replacement for a
// "share this report" link handed to a manager.

import { NextRequest } from 'next/server';
import prisma from '@/lib/prisma';
import { verifyToken } from '@/lib/auth';
import { buildReportHtml } from '@/lib/report-html';
import { HeadlessBrowser } from '@/scanner/headless-browser';

export const dynamic = 'force-dynamic';

export async function GET(
    req: NextRequest,
    { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
    // ── Authentication ───────────────────────────────────────────────
    // The report contains sensitive technical detail — only authenticated
    // users can download. Fails closed if the cookie is missing or invalid.
    const token = req.cookies.get('vc_token')?.value;
    if (!token) {
        return new Response(JSON.stringify({ error: 'authentication required' }), {
            status: 401, headers: { 'content-type': 'application/json' },
        });
    }
    const user = await verifyToken(token);
    if (!user) {
        return new Response(JSON.stringify({ error: 'session expired' }), {
            status: 401, headers: { 'content-type': 'application/json' },
        });
    }

    const { id: scanId } = await params;

    // ── Load data ────────────────────────────────────────────────────
    const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: {
            target: true,
            vulnerabilities: { orderBy: [{ severity: 'asc' }, { createdAt: 'asc' }] },
        },
    });
    if (!scan) {
        return new Response(JSON.stringify({ error: 'scan not found' }), {
            status: 404, headers: { 'content-type': 'application/json' },
        });
    }

    // Fetch operator name (startedBy) for the cover page.
    const operator = scan.startedById
        ? await prisma.user.findUnique({ where: { id: scan.startedById }, select: { name: true, email: true } })
        : null;

    // ── Render HTML ──────────────────────────────────────────────────
    const html = buildReportHtml({
        scan,
        target: scan.target,
        vulnerabilities: scan.vulnerabilities,
        operatorName: operator?.name ?? operator?.email ?? undefined,
    });

    // ── HTML → PDF via Puppeteer ─────────────────────────────────────
    // We spawn a dedicated browser for this request — cheap compared to
    // caching across requests, and avoids contaminating the scanner pool.
    // Note: printBackground=true so CSS background colours (severity pills,
    // code blocks) actually render in the PDF.
    const browser = new HeadlessBrowser({
        allowLocalFallback: true,
        navigationTimeout: 30_000,
    });

    try {
        await browser.connect();
        const page = await browser.newPage();

        // Use data: URL to avoid file-system tempfile + permission issues on
        // Windows. The HTML self-contains all CSS (no external assets).
        await page.setContent(html, { waitUntil: 'networkidle0', timeout: 30_000 });

        const pdfBuffer = await page.pdf({
            format: 'A4',
            printBackground: true,
            preferCSSPageSize: true,
            displayHeaderFooter: false, // our @page CSS already provides header/footer
            margin: { top: '0', right: '0', bottom: '0', left: '0' },
        });

        await browser.closePage(page);
        await browser.disconnect();

        // Filename: <target-slug>-<scan-id>-<date>.pdf
        const date = new Date(scan.completedAt ?? scan.startedAt ?? new Date()).toISOString().slice(0, 10);
        const slug = scan.target.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
        const filename = `${slug}-${scan.id.slice(0, 8)}-${date}.pdf`;

        return new Response(pdfBuffer as BodyInit, {
            status: 200,
            headers: {
                'content-type': 'application/pdf',
                'content-disposition': `attachment; filename="${filename}"`,
                'cache-control': 'private, no-store',
            },
        });
    } catch (err) {
        try { await browser.disconnect(); } catch { /* already disconnected */ }
        const msg = err instanceof Error ? err.message : String(err);
        return new Response(JSON.stringify({
            error: 'PDF generation failed',
            reason: msg,
        }), {
            status: 500,
            headers: { 'content-type': 'application/json' },
        });
    }
}
