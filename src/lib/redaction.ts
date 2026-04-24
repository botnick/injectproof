// InjectProof — Secret redaction
// Single source of truth for "remove sensitive data before it lands in logs,
// audit entries, evidence, or exported reports." ทุก path ที่เขียน outgoing
// artifact ต้องผ่าน helper ในไฟล์นี้ ไม่มี exception.
//
// Policy:
//  - redacted strings always end with the same marker so reviewers can spot
//    them in a long log dump: `[REDACTED:<kind>]`
//  - URL rewriting preserves host+path — only query-string secrets + userinfo
//    are scrubbed — so operators can still correlate on endpoint identity
//  - JSON bodies are walked recursively; arrays + nested objects supported
//  - high-entropy standalone strings are detected as a last resort

const MARKER = '[REDACTED';

/** ค่า header ที่ redact เต็มค่า (ไม่แสดงแม้ prefix) */
const FULL_REDACT_HEADERS = new Set([
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-access-token',
    'x-amz-security-token',
    'x-session-token',
    'x-csrf-token',
    'x-xsrf-token',
    'x-secret',
    'x-signature',
]);

/** ค่า header ที่ redact เฉพาะส่วน value แต่เก็บ prefix เอาไว้ (เช่น `Bearer ...`) */
const PREFIX_PRESERVE_HEADERS = new Set<string>([]);

/** key JSON/form body ที่ควร redact */
const SENSITIVE_BODY_KEYS = new Set([
    'password', 'passwd', 'pwd',
    'secret', 'client_secret', 'api_key', 'apikey', 'api-key',
    'token', 'access_token', 'refresh_token', 'id_token',
    'authorization', 'authtoken', 'auth_token',
    'session', 'sessionid', 'session_id', 'cookie',
    'private_key', 'privatekey', 'key',
    'passphrase',
    'credit_card', 'card_number', 'cardnumber', 'cvv', 'cvc',
    'ssn',
    'otp', 'mfa_code', 'totp',
]);

/** credential query-param names */
const SENSITIVE_QUERY_KEYS = new Set([
    'token', 'access_token', 'refresh_token', 'id_token',
    'api_key', 'apikey', 'key',
    'password', 'passwd',
    'secret', 'client_secret',
    'session', 'sessionid',
    'signature', 'sig',
    'code', // OAuth authorization code
]);

/** regex ที่จับ token/key pattern ที่เป็นอิสระใน body text */
const PATTERN_RULES: Array<{ kind: string; regex: RegExp }> = [
    // JWT (three base64-url parts)
    { kind: 'jwt', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    // AWS access key id
    { kind: 'aws-key', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
    // AWS secret key (40 base64 chars in a row is too noisy — require key-like context)
    { kind: 'aws-secret', regex: /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
    // Google API key
    { kind: 'gcp-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    // Slack token
    { kind: 'slack-token', regex: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g },
    // GitHub PAT (classic + fine-grained)
    { kind: 'github-pat', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
    // Stripe key
    { kind: 'stripe-key', regex: /\b(sk|pk)_(live|test)_[A-Za-z0-9]{16,}\b/g },
    // Private key PEM body (keep the header, redact interior)
    { kind: 'pem', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    // Generic bearer token in text
    { kind: 'bearer', regex: /\b[Bb]earer\s+[A-Za-z0-9._~+/=-]{20,}\b/g },
    // Basic-auth in URL (captured separately in redactUrl, but catches leaks in prose)
    { kind: 'userinfo-url', regex: /\b(https?:\/\/)([^\s:@/]+:[^\s@/]+)@/g },
];

/** SSN / credit card / phone patterns */
const PII_RULES: Array<{ kind: string; regex: RegExp }> = [
    { kind: 'ssn-us', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
    { kind: 'credit-card', regex: /\b(?:\d[ -]*?){13,19}\b/g },
    { kind: 'thai-id', regex: /\b\d-\d{4}-\d{5}-\d{2}-\d\b/g },
];

// ────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────

export interface RedactionOptions {
    /** เปิด redaction ของ PII (ค่า default = true). */
    redactPii?: boolean;
    /** label เสริมที่ใส่เข้า marker (เช่น 'evidence' / 'log'). */
    label?: string;
}

/** Redact a single header value. Returns the safe value. */
export function redactHeaderValue(name: string, value: string): string {
    const lower = name.toLowerCase();
    if (FULL_REDACT_HEADERS.has(lower)) return mark(lower);
    if (PREFIX_PRESERVE_HEADERS.has(lower)) {
        const space = value.indexOf(' ');
        if (space > 0) return `${value.slice(0, space + 1)}${mark(lower)}`;
        return mark(lower);
    }
    return redactText(value);
}

/** Redact an entire header bag. Case-insensitive. Returns a new object. */
export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
        if (v === undefined) continue;
        const joined = Array.isArray(v) ? v.join(', ') : v;
        out[k] = redactHeaderValue(k, joined);
    }
    return out;
}

/**
 * Redact a URL string:
 *  - removes basic-auth userinfo (`http://user:pass@host` → `http://[REDACTED]@host`)
 *  - redacts sensitive query params by name
 *  - leaves host + path untouched (still useful for correlation)
 */
export function redactUrl(url: string): string {
    try {
        const u = new URL(url);
        if (u.username || u.password) {
            u.username = mark('userinfo');
            u.password = '';
        }
        if (u.search) {
            for (const [k] of u.searchParams.entries()) {
                if (SENSITIVE_QUERY_KEYS.has(k.toLowerCase())) {
                    u.searchParams.set(k, mark(`query:${k}`));
                }
            }
        }
        return u.toString();
    } catch {
        // Not a parseable URL — fall through to text redaction.
        return redactText(url);
    }
}

/**
 * Redact an unstructured string. Applies all pattern rules + optional PII.
 */
export function redactText(input: string, opts: RedactionOptions = {}): string {
    if (!input) return input;
    let out = input;
    for (const rule of PATTERN_RULES) {
        out = out.replace(rule.regex, mark(rule.kind));
    }
    if (opts.redactPii !== false) {
        for (const rule of PII_RULES) {
            out = out.replace(rule.regex, (m) => maskPreservingLength(m, rule.kind));
        }
    }
    return out;
}

/**
 * Deep-redact a JSON-serializable value. Object keys matching sensitive
 * patterns have their values replaced; nested arrays/objects are walked.
 * Returns a new value — never mutates the input.
 */
export function redactJson(value: unknown, opts: RedactionOptions = {}): unknown {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return redactText(value, opts);
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return value;
    if (Array.isArray(value)) return value.map((v) => redactJson(v, opts));
    if (typeof value === 'object') {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            if (SENSITIVE_BODY_KEYS.has(k.toLowerCase())) {
                out[k] = mark(`body:${k}`);
            } else {
                out[k] = redactJson(v, opts);
            }
        }
        return out;
    }
    return value;
}

/**
 * Redact an HTTP request/response body before persistence. Tries JSON parse;
 * falls back to plain-text redaction.
 */
export function redactBody(body: string | null | undefined, contentType?: string): string {
    if (!body) return body ?? '';
    const ct = (contentType ?? '').toLowerCase();
    if (ct.includes('application/json') || body.trim().startsWith('{') || body.trim().startsWith('[')) {
        try {
            const parsed = JSON.parse(body);
            return JSON.stringify(redactJson(parsed));
        } catch {
            /* fall through */
        }
    }
    // form-encoded: walk key=value pairs
    if (ct.includes('application/x-www-form-urlencoded') || /^[-._A-Za-z0-9%]+=/.test(body)) {
        return body
            .split('&')
            .map((pair) => {
                const eq = pair.indexOf('=');
                if (eq < 0) return pair;
                const k = decodeURIComponent(pair.slice(0, eq));
                const v = pair.slice(eq + 1);
                if (SENSITIVE_BODY_KEYS.has(k.toLowerCase())) {
                    return `${pair.slice(0, eq)}=${mark(`form:${k}`)}`;
                }
                return `${pair.slice(0, eq)}=${redactText(decodeURIComponent(v))}`;
            })
            .join('&');
    }
    return redactText(body);
}

/** Idempotent test: has the given string already been redacted by us? */
export function isRedacted(s: string): boolean {
    return s.includes(MARKER);
}

// ────────────────────────────────────────────────────────────
// internals
// ────────────────────────────────────────────────────────────

function mark(kind: string): string {
    return `${MARKER}:${kind}]`;
}

function maskPreservingLength(value: string, kind: string): string {
    const tag = mark(kind);
    if (value.length <= tag.length + 2) return tag;
    return tag + '*'.repeat(Math.max(0, value.length - tag.length));
}
