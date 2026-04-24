// InjectProof — Broken Access Control (BAC) / IDOR Scanner
// =========================================================
// OWASP Top 10 A01:2021 is #1 for 4 consecutive years. It's also the class
// of vulnerability that billion-baht corporate apps fail at most often —
// developers forget `if (user.id !== resource.ownerId) throw 403`.
//
// This module tests four concrete BAC classes:
//
//  1) UNAUTH BAC — endpoint reachable without auth returns data that the
//     same endpoint gates for authenticated users. We strip the Cookie /
//     Authorization header and re-issue; if the body is highly similar to
//     the authenticated response, we've found unauthenticated exposure.
//
//  2) VERTICAL BAC — low-privilege user reaches admin-only paths. We
//     pattern-match admin-looking URLs (/admin, /dashboard, /settings,
//     /users, /config) seen during crawl and probe them with the scan's
//     standard session; a 200/3xx response without an auth wall is a hit.
//
//  3) IDOR — numeric / UUID identifiers in URL path segments and query
//     params. We increment / decrement / swap identifiers and watch for
//     "found another user's resource" signal (response stable, content
//     diverges from reference = we're reading someone else's data).
//
//  4) HORIZONTAL BAC — OPTIONAL when two sets of credentials are supplied
//     via config.secondaryAuthHeaders. We replay endpoint-for-endpoint with
//     user-B's session and compare. Unlike IDOR (same URL, different ID),
//     horizontal BAC is (same URL, different session, same resource) — any
//     response that's the SAME for both users when it shouldn't be is a
//     finding (both see the admin page) AND any response that's DIFFERENT
//     but not 403 when it should be (user-B sees user-A's profile).
//
// Detection uses the trigram-Jaccard responseRatio() helper from sqli-exploiter
// — same similarity oracle we use for blind SQLi, which means the signal is
// consistent across the scanner.

import type { CrawledEndpoint, DetectorResult, Confidence } from '@/types';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';

// ============================================================
// CONFIG
// ============================================================

export interface BacScanConfig {
    requestTimeout: number;
    userAgent: string;
    /** Primary auth (the scan's main session). */
    authHeaders?: Record<string, string>;
    customHeaders?: Record<string, string>;
    /** Optional secondary user for horizontal BAC. If set, we replay every
     *  endpoint with these headers and compare to the primary response. */
    secondaryAuthHeaders?: Record<string, string>;
    /** Cap endpoints tested per class (keeps scan time bounded). */
    maxEndpointsPerClass?: number;
    /** Enable IDOR numeric enumeration. Default: true. */
    enableIdor?: boolean;
    /** Enable vertical BAC probes. Default: true. */
    enableVerticalBac?: boolean;
    /** Enable horizontal BAC replays. Default: true (runs if secondaryAuthHeaders set). */
    enableHorizontalBac?: boolean;
    /** Enable unauth probes. Default: true. */
    enableUnauth?: boolean;
    onLog?: (msg: string) => void;
}

// ============================================================
// RESPONSE SIMILARITY
// ============================================================
// Trigram-shingle Jaccard — same heuristic as sqli-exploiter.responseRatio.
// Duplicated here (rather than exported from exploiter) to keep the BAC
// module standalone; scanner compose layer shouldn't create circular imports.

function responseRatio(a: string, b: string): number {
    if (a === b) return 1;
    if (!a.length || !b.length) return 0;
    const tokA = a.match(/[\w<>/"'=.\-]+/g) ?? [];
    const tokB = b.match(/[\w<>/"'=.\-]+/g) ?? [];
    if (tokA.length === 0 || tokB.length === 0) {
        return Math.min(a.length, b.length) / Math.max(a.length, b.length);
    }
    const shingle = (toks: string[], n: number): Set<string> => {
        if (toks.length < n) return new Set([toks.join(' ')]);
        const out = new Set<string>();
        for (let i = 0; i <= toks.length - n; i++) out.add(toks.slice(i, i + n).join(' '));
        return out;
    };
    const N = 3;
    const sa = shingle(tokA, N);
    const sb = shingle(tokB, N);
    let inter = 0;
    for (const s of sa) if (sb.has(s)) inter++;
    const union = sa.size + sb.size - inter;
    return union === 0 ? 0 : inter / union;
}

// ============================================================
// HTTP HELPERS
// ============================================================

interface Response { body: string; status: number; time: number; headers: Record<string, string> }

async function doRequest(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: string | undefined,
    timeout: number,
): Promise<Response | null> {
    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), timeout);
        const start = Date.now();
        const res = await fetch(url, { method, headers, body, signal: controller.signal, redirect: 'follow' });
        clearTimeout(t);
        const respHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { respHeaders[k] = v; });
        return { body: await res.text(), status: res.status, time: Date.now() - start, headers: respHeaders };
    } catch {
        return null;
    }
}

// ============================================================
// AUTH-WALL DETECTION
// ============================================================
// A response is gated by authentication if ANY of these signatures hit.
// Order matters: status codes first (cheap), content signatures second.

const AUTH_WALL_SIGNATURES = [
    /please\s+(log|sign)\s*in/i,
    /session\s+(expired|invalid|timeout)/i,
    /unauthori[sz]ed/i,
    /authentication\s+required/i,
    /redirecting.*to.*(login|signin)/i,
    /<form[^>]*action=["']?[^"']*(login|signin)/i,
    /csrf/i, // CSRF-error pages usually accompany auth walls
    /access\s+denied/i,
    /forbidden/i,
    /กรุณาเข้าสู่ระบบ/i, // Thai: "please login"
    /ไม่มีสิทธิ์เข้าถึง/i, // Thai: "no access permission"
];

function looksLikeAuthWall(res: Response): boolean {
    if (res.status === 401 || res.status === 403) return true;
    // 302/303 to a login URL
    if (res.status >= 300 && res.status < 400) {
        const loc = res.headers['location'] ?? '';
        if (/login|signin|auth/i.test(loc)) return true;
    }
    return AUTH_WALL_SIGNATURES.some(p => p.test(res.body));
}

// ============================================================
// ADMIN-PATH HEURISTIC
// ============================================================

const ADMIN_PATH_PATTERNS = [
    /\/admin(\/|$)/i,
    /\/administrator(\/|$)/i,
    /\/dashboard(\/|$)/i,
    /\/manage(\/|$)/i,
    /\/management(\/|$)/i,
    /\/control(panel|-panel)?(\/|$)/i,
    /\/settings(\/|$)/i,
    /\/config(\/|$)/i,
    /\/users?\/?$/i,
    /\/accounts?\/?$/i,
    /\/system(\/|$)/i,
    /\/internal(\/|$)/i,
    /\/staff(\/|$)/i,
    /\/backoffice(\/|$)/i,
    /\/superadmin(\/|$)/i,
    /\/root(\/|$)/i,
];

function isAdminPath(url: string): boolean {
    try {
        const p = new URL(url).pathname;
        return ADMIN_PATH_PATTERNS.some(re => re.test(p));
    } catch {
        return false;
    }
}

// ============================================================
// IDOR: ID enumeration
// ============================================================
// Extract id-looking segments from URL path + query and propose neighbours
// to try. Two classes of ids we handle:
//   1) Numeric (integer >= 1) — propose +1, -1, +10, 1 (first user).
//   2) UUID-looking — harder to guess blindly; propose zero-UUID + known
//      "admin" UUIDs. Low hit-rate but cheap.

interface IdSlot {
    kind: 'path' | 'query';
    locator: string; // path segment index or query-param name
    originalValue: string;
    type: 'numeric' | 'uuid' | 'short-hex';
}

function discoverIdSlots(url: string): IdSlot[] {
    const slots: IdSlot[] = [];
    let parsed: URL;
    try { parsed = new URL(url); } catch { return slots; }

    // Path segments
    const segs = parsed.pathname.split('/').filter(Boolean);
    segs.forEach((seg, idx) => {
        if (/^\d+$/.test(seg)) slots.push({ kind: 'path', locator: String(idx), originalValue: seg, type: 'numeric' });
        else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) slots.push({ kind: 'path', locator: String(idx), originalValue: seg, type: 'uuid' });
        else if (/^[0-9a-f]{24,32}$/i.test(seg)) slots.push({ kind: 'path', locator: String(idx), originalValue: seg, type: 'short-hex' });
    });

    // Query params — only those that *look* like ID carriers (name has id/uid/account).
    parsed.searchParams.forEach((v, k) => {
        const nameLooksId = /^(id|uid|user_?id|account_?id|order_?id|doc_?id|report_?id|ref|_id)$/i.test(k);
        if (!nameLooksId) return;
        if (/^\d+$/.test(v)) slots.push({ kind: 'query', locator: k, originalValue: v, type: 'numeric' });
        else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) slots.push({ kind: 'query', locator: k, originalValue: v, type: 'uuid' });
    });

    return slots;
}

function mutateId(slot: IdSlot, url: string, replacement: string): string {
    const parsed = new URL(url);
    if (slot.kind === 'path') {
        const segs = parsed.pathname.split('/');
        // Account for leading empty segment from leading slash.
        const segIdx = segs.indexOf(slot.originalValue);
        if (segIdx === -1) return url;
        segs[segIdx] = replacement;
        parsed.pathname = segs.join('/');
    } else {
        parsed.searchParams.set(slot.locator, replacement);
    }
    return parsed.toString();
}

function proposeIdMutations(slot: IdSlot): string[] {
    if (slot.type === 'numeric') {
        const n = Number(slot.originalValue);
        // +1 catches linear enumeration; -1 if original > 1; 1 catches the
        // canonical "first user" (usually admin); +10 for leap over current user's row.
        const out = new Set<string>();
        if (n >= 1 && n !== 1) out.add('1');
        out.add(String(n + 1));
        if (n > 1) out.add(String(n - 1));
        out.add(String(n + 10));
        return Array.from(out);
    }
    if (slot.type === 'uuid') {
        return [
            '00000000-0000-0000-0000-000000000000', // zero UUID
            '11111111-1111-1111-1111-111111111111', // sequential low
        ];
    }
    return [];
}

// ============================================================
// MAIN SCANNER
// ============================================================

export async function runBacScan(
    endpoints: CrawledEndpoint[],
    config: BacScanConfig,
): Promise<DetectorResult[]> {
    const findings: DetectorResult[] = [];
    const log = (msg: string) => { config.onLog?.(msg); };
    const maxPerClass = config.maxEndpointsPerClass ?? 50;
    const cwe = getCweEntry('CWE-284') ?? getCweEntry('CWE-285') ?? getCweEntry('CWE-639');

    const baseHeaders = (auth: Record<string, string> | undefined): Record<string, string> => ({
        'User-Agent': config.userAgent,
        'Accept': 'text/html,application/json,*/*',
        ...(config.customHeaders ?? {}),
        ...(auth ?? {}),
    });

    // Only test GET endpoints for BAC — BAC for POST/PUT/DELETE needs the
    // full request body (which we don't always have from the crawl) and
    // risks mutating state. GET is the clean test.
    const getEndpoints = endpoints.filter(e => (e.method ?? 'GET').toUpperCase() === 'GET');
    log(`[BAC] Starting — ${getEndpoints.length} GET endpoints eligible`);

    // ── Class 1: UNAUTH BAC ──────────────────────────────────────
    // Only useful when the scan has authHeaders (otherwise there's no auth
    // to strip and test). Skip the whole class if the scan is unauthenticated.
    if ((config.enableUnauth ?? true) && config.authHeaders && Object.keys(config.authHeaders).length > 0) {
        log(`[BAC] Class 1 (UNAUTH) — probing ${Math.min(getEndpoints.length, maxPerClass)} endpoints`);
        for (const ep of getEndpoints.slice(0, maxPerClass)) {
            const [authed, unauthed] = await Promise.all([
                doRequest(ep.url, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout),
                doRequest(ep.url, 'GET', baseHeaders({}), undefined, config.requestTimeout),
            ]);
            if (!authed || !unauthed) continue;
            // Auth-wall on unauth response is the CORRECT outcome — skip.
            if (looksLikeAuthWall(unauthed)) continue;
            // 4xx+ on unauth is also fine (denied without a pretty page).
            if (unauthed.status >= 400) continue;
            // Both 200 AND body highly similar → we just read authed data without auth.
            if (authed.status < 400) {
                const ratio = responseRatio(authed.body, unauthed.body);
                if (ratio > 0.85) {
                    findings.push(buildUnauthFinding(ep.url, ep.method ?? 'GET', authed, unauthed, ratio, cwe));
                    log(`[BAC] UNAUTH hit: ${ep.url} (similarity ${ratio.toFixed(2)})`);
                }
            }
        }
    }

    // ── Class 2: VERTICAL BAC ────────────────────────────────────
    // Crawler-observed admin-looking paths. If the scan's (low-priv)
    // session returns a non-auth-walled response, that's vertical BAC.
    if (config.enableVerticalBac ?? true) {
        const adminEndpoints = getEndpoints.filter(e => isAdminPath(e.url));
        log(`[BAC] Class 2 (VERTICAL) — ${adminEndpoints.length} admin-looking paths`);
        for (const ep of adminEndpoints.slice(0, maxPerClass)) {
            const res = await doRequest(ep.url, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout);
            if (!res) continue;
            if (res.status >= 400) continue;
            if (looksLikeAuthWall(res)) continue;
            // Extra gate: body shouldn't be the public home page pattern (low-priv
            // apps often redirect admin paths to the index). Check for admin-ish
            // content markers.
            const hasAdminContent = /admin|dashboard|users|settings|manage|config/i.test(res.body);
            if (!hasAdminContent) continue;
            findings.push(buildVerticalBacFinding(ep.url, ep.method ?? 'GET', res, cwe));
            log(`[BAC] VERTICAL hit: ${ep.url}`);
        }
    }

    // ── Class 3: IDOR (ID enumeration) ───────────────────────────
    if (config.enableIdor ?? true) {
        log(`[BAC] Class 3 (IDOR) — scanning for numeric/UUID slots`);
        let probed = 0;
        for (const ep of getEndpoints) {
            if (probed >= maxPerClass) break;
            const slots = discoverIdSlots(ep.url);
            if (slots.length === 0) continue;
            const reference = await doRequest(ep.url, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout);
            if (!reference || reference.status >= 400 || looksLikeAuthWall(reference)) continue;

            for (const slot of slots) {
                for (const replacement of proposeIdMutations(slot)) {
                    if (replacement === slot.originalValue) continue;
                    const mutatedUrl = mutateId(slot, ep.url, replacement);
                    const res = await doRequest(mutatedUrl, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout);
                    probed++;
                    if (!res || res.status >= 400 || looksLikeAuthWall(res)) continue;
                    const ratio = responseRatio(reference.body, res.body);
                    // SAME structure (ratio > 0.6) but DIFFERENT content (ratio < 0.95).
                    // Pure same (>=0.95) = same resource echoed, not IDOR. Pure different
                    // (<0.6) = unrelated page / error. The sweet spot is "same template,
                    // different record" — classic IDOR.
                    if (ratio > 0.6 && ratio < 0.95) {
                        findings.push(buildIdorFinding(ep.url, mutatedUrl, slot, replacement, res, ratio, cwe));
                        log(`[BAC] IDOR hit: ${ep.url} → ${mutatedUrl} (ratio ${ratio.toFixed(2)})`);
                        break; // one proof per endpoint is enough
                    }
                }
            }
        }
    }

    // ── Class 4: HORIZONTAL BAC (requires 2 sessions) ────────────
    if ((config.enableHorizontalBac ?? true) && config.secondaryAuthHeaders && Object.keys(config.secondaryAuthHeaders).length > 0) {
        log(`[BAC] Class 4 (HORIZONTAL) — replaying with secondary session`);
        for (const ep of getEndpoints.slice(0, maxPerClass)) {
            const [a, b] = await Promise.all([
                doRequest(ep.url, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout),
                doRequest(ep.url, 'GET', baseHeaders(config.secondaryAuthHeaders), undefined, config.requestTimeout),
            ]);
            if (!a || !b) continue;
            // B got 403/401 → correct authorization → not a finding.
            if (looksLikeAuthWall(b) || b.status >= 400) continue;
            // A was error → can't compare.
            if (a.status >= 400) continue;
            const ratio = responseRatio(a.body, b.body);
            // If B gets a similar-but-distinct page on an endpoint bound to A's
            // identity (e.g. /profile), B has read A's data = horizontal BAC.
            if (ratio > 0.6 && ratio < 0.95 && !isAdminPath(ep.url)) {
                findings.push(buildHorizontalBacFinding(ep.url, ep.method ?? 'GET', a, b, ratio, cwe));
                log(`[BAC] HORIZONTAL hit: ${ep.url} (ratio ${ratio.toFixed(2)})`);
            }
        }
    }

    log(`[BAC] Scan complete — ${findings.length} finding(s)`);
    return findings;
}

// ============================================================
// FINDING BUILDERS
// ============================================================

function buildUnauthFinding(url: string, method: string, authed: Response, unauthed: Response, ratio: number, cwe: ReturnType<typeof getCweEntry>): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli; // temporary — BAC often equals SQLi severity for data exposure
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `Unauthenticated Access to Protected Endpoint: ${new URL(url).pathname}`,
        description:
            `The endpoint ${url} returns substantively the same content whether the caller is authenticated ` +
            `or not (${Math.round(ratio * 100)}% response similarity). This means any unauthenticated user can ` +
            `read data that the application believes is access-controlled.`,
        category: 'access-control',
        severity: 'high',
        confidence: ratio > 0.95 ? 'high' : 'medium',
        cweId: cwe?.id ?? 'CWE-306',
        cweTitle: cwe?.title ?? 'Missing Authentication for Critical Function',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: method,
        parameter: '(whole endpoint)',
        parameterType: 'query',
        injectionPoint: 'authorization',
        payload: '(no Authorization / Cookie header)',
        request: `# Authenticated request\nGET ${url}\n\n# Unauthenticated request (Authorization / Cookie stripped)\nGET ${url}`,
        response: `# Authenticated response (status ${authed.status}, ${authed.body.length} bytes)\n# Unauthenticated response (status ${unauthed.status}, ${unauthed.body.length} bytes)\n# Jaccard similarity: ${ratio.toFixed(3)}\n\n${unauthed.body.slice(0, 1500)}`,
        responseCode: unauthed.status,
        responseTime: unauthed.time,
        impact:
            'Any internet user who knows this URL can read application data that the application intended to ' +
            'gate behind authentication. Depending on the endpoint this may expose PII, internal system state, ' +
            'financial records, or administrative configuration — and because no auth is required, the attack ' +
            'is trivially automatable and leaves no usable audit trail.',
        technicalDetail:
            `Both the authenticated (status ${authed.status}) and unauthenticated (status ${unauthed.status}) ` +
            `requests to ${url} returned response bodies with ${Math.round(ratio * 100)}% trigram-Jaccard ` +
            `similarity. A correctly-gated endpoint should return 401 Unauthorized, 403 Forbidden, or a redirect ` +
            `to a login page when the Authorization/Cookie header is absent.`,
        remediation:
            'Add an authentication middleware that runs before the endpoint handler. ' +
            'Framework examples:\n' +
            '  Express/Next.js:  app.use(requireAuth) or withAuth(handler)\n' +
            '  Spring:           @PreAuthorize("isAuthenticated()")\n' +
            '  Rails:            before_action :authenticate_user!\n' +
            '  Laravel:          middleware(\'auth\')\n\n' +
            'As a defence-in-depth measure, add an authorisation-check unit test that sends a no-auth request ' +
            'to every route and asserts the response is 401/403/302.',
        reproductionSteps: [
            `Issue an authenticated GET to ${url} — observe normal response.`,
            `Issue the same GET without any Authorization / Cookie header.`,
            `Compare responses — they are ${Math.round(ratio * 100)}% similar; protected content was served unauthenticated.`,
        ],
        references: [
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
            'https://cwe.mitre.org/data/definitions/306.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html',
        ],
        mappedOwasp: ['A01:2021'],
        mappedOwaspAsvs: ['V4.1.1', 'V4.1.3'],
        mappedNist: ['AC-3', 'AC-6'],
    };
}

function buildVerticalBacFinding(url: string, method: string, res: Response, cwe: ReturnType<typeof getCweEntry>): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `Vertical Privilege Escalation: ${new URL(url).pathname} reachable by low-privilege user`,
        description:
            `The administrative endpoint ${url} returned a ${res.status} response with admin-looking content ` +
            `to the session used in this scan. If the scan's session belongs to a non-admin user, this is a ` +
            `vertical privilege escalation — the role check is missing or incorrect.`,
        category: 'access-control',
        severity: 'high',
        confidence: 'medium',
        cweId: cwe?.id ?? 'CWE-269',
        cweTitle: cwe?.title ?? 'Improper Privilege Management',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: method,
        parameter: '(whole endpoint)',
        parameterType: 'query',
        injectionPoint: 'authorization',
        payload: '(low-priv session; should have been rejected)',
        request: `GET ${url}\nCookie/Authorization: (scan's session — non-admin)`,
        response: res.body.slice(0, 1500),
        responseCode: res.status,
        responseTime: res.time,
        impact:
            'A non-admin user can reach admin-only functionality. Depending on what this endpoint does this may ' +
            'allow the attacker to modify system configuration, enumerate other users, grant themselves roles, ' +
            'or exfiltrate all user data.',
        technicalDetail:
            `Endpoint path matched admin-pattern regex; response returned status ${res.status} with content ` +
            `containing admin-related keywords. The application should require an admin role for this path.`,
        remediation:
            'Add a role-based access control check to every admin-path handler (or, better, to a route-group ' +
            'middleware so it\'s impossible to forget):\n' +
            '  if (!user.roles.includes(\'admin\')) return res.status(403).end();\n\n' +
            'Write a regression test that sends every admin endpoint as a non-admin user and asserts 403.',
        reproductionSteps: [
            `Log in as a non-admin user.`,
            `Navigate to ${url}.`,
            `Observe admin content served without a 403 wall.`,
        ],
        references: [
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
            'https://cwe.mitre.org/data/definitions/269.html',
        ],
        mappedOwasp: ['A01:2021'],
        mappedOwaspAsvs: ['V4.2.1'],
        mappedNist: ['AC-3', 'AC-6'],
    };
}

function buildIdorFinding(originalUrl: string, mutatedUrl: string, slot: IdSlot, replacement: string, res: Response, ratio: number, cwe: ReturnType<typeof getCweEntry>): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `Insecure Direct Object Reference (IDOR) on ${slot.kind} ID "${slot.originalValue}" → "${replacement}"`,
        description:
            `The ID-carrying ${slot.kind} slot at ${originalUrl} accepts modified values and returns ` +
            `a different record with the same template (${Math.round(ratio * 100)}% similarity). ` +
            `This is a classic IDOR — the application is trusting the caller-supplied ID and not checking ` +
            `whether the authenticated user owns that resource.`,
        category: 'access-control',
        severity: 'high',
        confidence: ratio > 0.8 ? 'high' : 'medium',
        cweId: 'CWE-639',
        cweTitle: 'Authorization Bypass Through User-Controlled Key',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: originalUrl,
        httpMethod: 'GET',
        parameter: slot.kind === 'query' ? slot.locator : `path-segment[${slot.locator}]`,
        parameterType: slot.kind === 'query' ? 'query' : 'path',
        injectionPoint: 'idor',
        payload: replacement,
        request: `# Original\nGET ${originalUrl}\n\n# Mutated (ID swapped)\nGET ${mutatedUrl}`,
        response: res.body.slice(0, 1500),
        responseCode: res.status,
        responseTime: res.time,
        impact:
            'The attacker can read (and potentially modify, if the endpoint also supports POST/PUT/DELETE) ' +
            'records belonging to other users. For a user-profile endpoint this means every user\'s profile ' +
            'is scrapable by incrementing an integer. For an order / invoice / report endpoint this means ' +
            'competitive-sensitive data is exposed. This is a PDPA-reportable incident if PII is involved.',
        technicalDetail:
            `Original ID: ${slot.originalValue} (${slot.type}) in ${slot.kind} slot. ` +
            `Replacement: ${replacement}. ` +
            `Both responses returned status ${res.status}; trigram-Jaccard similarity ${ratio.toFixed(3)} — ` +
            `above the "different record on same template" threshold (0.6–0.95).`,
        remediation:
            'Replace the direct object reference with an indirect reference OR enforce an ownership check ' +
            'before returning data:\n\n' +
            '  // BAD — trusts the ID\n' +
            '  const order = await Order.findById(req.params.id);\n' +
            '  return res.json(order);\n\n' +
            '  // GOOD — ownership check\n' +
            '  const order = await Order.findOne({ _id: req.params.id, ownerId: req.user.id });\n' +
            '  if (!order) return res.status(404).end();\n' +
            '  return res.json(order);\n\n' +
            'Prefer opaque IDs (UUID, ULID) over sequential integers — makes enumeration strictly harder ' +
            'even if the ownership check is forgotten.',
        reproductionSteps: [
            `Authenticate as any user.`,
            `Request ${originalUrl} — observe your own resource.`,
            `Request ${mutatedUrl} — observe somebody else's resource returned without a permission check.`,
        ],
        references: [
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
            'https://cwe.mitre.org/data/definitions/639.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
        ],
        mappedOwasp: ['A01:2021'],
        mappedOwaspAsvs: ['V4.2.1'],
        mappedNist: ['AC-3', 'AC-6'],
    };
}

function buildHorizontalBacFinding(url: string, method: string, a: Response, b: Response, ratio: number, cwe: ReturnType<typeof getCweEntry>): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `Horizontal Access Control Violation: user B can read user A's data at ${new URL(url).pathname}`,
        description:
            `Two different authenticated sessions received different-but-structurally-similar (${Math.round(ratio * 100)}% ` +
            `similarity) responses from ${url}. If this endpoint is bound to the authenticated user's identity ` +
            `(e.g. /profile, /my-orders), it should return DIFFERENT data for different users — OR return a 403 ` +
            `if user B is trying to read user A's record.`,
        category: 'access-control',
        severity: 'high',
        confidence: 'medium',
        cweId: 'CWE-639',
        cweTitle: cwe?.title ?? 'Authorization Bypass Through User-Controlled Key',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: method,
        parameter: '(whole endpoint)',
        parameterType: 'query',
        injectionPoint: 'authorization',
        payload: '(session B credentials)',
        request: `# Request as user A\nGET ${url}\n\n# Request as user B (secondaryAuthHeaders)\nGET ${url}`,
        response: `# User A response (${a.body.length} bytes)\n# User B response (${b.body.length} bytes, status ${b.status})\n# Similarity ${ratio.toFixed(3)}\n\n${b.body.slice(0, 1500)}`,
        responseCode: b.status,
        responseTime: b.time,
        impact:
            'User B can read data belonging to user A. This is a direct breach of the confidentiality guarantee ' +
            'the application owes every user of the system. If the application handles PII, financial, health, ' +
            'or corporate-confidential data, this vulnerability is regulatorily reportable (PDPA, GDPR, HIPAA, ' +
            'PCI-DSS) and likely triggers user-notification + fine obligations.',
        technicalDetail:
            `Horizontal BAC detected by dual-session replay: user A's request and user B's request to the same ` +
            `URL (${url}) returned responses with ${ratio.toFixed(3)} Jaccard similarity. For a user-scoped ` +
            `endpoint the correct behaviour is: responses should differ substantially (each user's data) AND ` +
            `B should see a 403 if the resource is A-specific.`,
        remediation:
            'Every endpoint handler that returns user-scoped data must filter by the authenticated user\'s ID. ' +
            'Prefer framework-level patterns that make it the default:\n\n' +
            '  // Rails/Pundit\n' +
            '  def show; @order = authorize Order.find(params[:id]); end\n\n' +
            '  // Express policy middleware\n' +
            '  router.get(\'/order/:id\', isOwner(Order), handler)\n\n' +
            '  // Django REST Framework\n' +
            '  class OrderViewSet(ModelViewSet):\n' +
            '      permission_classes = [IsOwner]\n' +
            '      def get_queryset(self): return Order.objects.filter(owner=self.request.user)',
        reproductionSteps: [
            `Authenticate as user A and call ${url}.`,
            `Authenticate as user B (with the secondaryAuthHeaders) and call the same ${url}.`,
            `Compare responses. Both returned 200 with ${Math.round(ratio * 100)}% structural similarity — user B has read user A's resource.`,
        ],
        references: [
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
            'https://cwe.mitre.org/data/definitions/639.html',
        ],
        mappedOwasp: ['A01:2021'],
        mappedOwaspAsvs: ['V4.2.1', 'V4.2.2'],
        mappedNist: ['AC-3', 'AC-6'],
    };
}
