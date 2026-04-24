// InjectProof — Oracle feature extraction
// Turns an HTTP response into a compact, numerical feature vector the
// baseline cluster and distance function can reason about without keeping
// full response bodies in memory.
//
// Every function here is pure and deterministic. Extraction is the one piece
// of the oracle pipeline that must stay cheap — we extract features for
// *every* request during baseline building and during probing, so per-call
// cost dominates scanner throughput.

import { createHash } from 'node:crypto';
import type { ResponseFeatures } from '@/types';

// ============================================================
// Tokenization
// ============================================================

/**
 * Cheap, allocation-light tokenizer. Splits on any non-alphanumeric run,
 * lowercases, drops empties and single characters. Good enough for simhash
 * and new-token set comparison without pulling a full NLP library.
 */
export function tokenize(text: string): string[] {
    const out: string[] = [];
    let start = -1;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        const isWord =
            (c >= 48 && c <= 57) ||
            (c >= 65 && c <= 90) ||
            (c >= 97 && c <= 122) ||
            c === 95; // underscore
        if (isWord) {
            if (start < 0) start = i;
        } else {
            if (start >= 0) {
                if (i - start >= 2) out.push(text.slice(start, i).toLowerCase());
                start = -1;
            }
        }
    }
    if (start >= 0 && text.length - start >= 2) out.push(text.slice(start).toLowerCase());
    return out;
}

// ============================================================
// Simhash (Charikar, 64-bit)
// ============================================================

/**
 * 64-bit simhash over token-frequency weights. Produces a stable fingerprint
 * such that Hamming distance correlates with content similarity — used by
 * the oracle to detect meaningful response differences without caring about
 * tiny textual deltas (timestamps, CSRF tokens, etc.).
 *
 * Hash-per-token is MD5-of-token split into two 32-bit halves combined via
 * XOR into 64 bits. MD5 isn't cryptographic here — it's just a cheap,
 * deterministic 128-bit hash with good dispersion.
 */
export function simhash64(tokens: string[]): string {
    const bits = new Float64Array(64);
    const counts = new Map<string, number>();
    for (const t of tokens) counts.set(t, (counts.get(t) ?? 0) + 1);

    for (const [token, weight] of counts) {
        const h = hashTo64(token);
        for (let i = 0; i < 64; i++) {
            const bit = (i < 32) ? (h.lo >>> i) & 1 : (h.hi >>> (i - 32)) & 1;
            bits[i] += bit ? weight : -weight;
        }
    }

    let hi = 0 >>> 0;
    let lo = 0 >>> 0;
    for (let i = 0; i < 64; i++) {
        if (bits[i] > 0) {
            if (i < 32) lo |= 1 << i;
            else hi |= 1 << (i - 32);
        }
    }
    return (
        (hi >>> 0).toString(16).padStart(8, '0') +
        (lo >>> 0).toString(16).padStart(8, '0')
    );
}

function hashTo64(s: string): { hi: number; lo: number } {
    const buf = createHash('md5').update(s).digest();
    return {
        lo: buf.readUInt32LE(0),
        hi: buf.readUInt32LE(4),
    };
}

/**
 * Hamming distance between two 64-bit simhashes encoded as 16-char hex.
 * Returns 0 (identical) through 64 (bit-for-bit inverse).
 */
export function simhashHamming(a: string, b: string): number {
    if (a.length !== 16 || b.length !== 16) return 64;
    let total = 0;
    for (let i = 0; i < 16; i += 8) {
        const x = parseInt(a.slice(i, i + 8), 16);
        const y = parseInt(b.slice(i, i + 8), 16);
        total += popcount32(x ^ y);
    }
    return total;
}

function popcount32(n: number): number {
    n = n - ((n >>> 1) & 0x55555555);
    n = (n & 0x33333333) + ((n >>> 2) & 0x33333333);
    n = (n + (n >>> 4)) & 0x0f0f0f0f;
    return (n * 0x01010101) >>> 24;
}

// ============================================================
// DOM structure fingerprint
// ============================================================

/**
 * Structural fingerprint of an HTML document — SHA-256 over k-shingles of
 * tag sequences, independent of text content. Two pages with the same
 * layout but different text get the same fingerprint. Attacks that alter
 * the DOM (inject a new `<script>`, `<iframe>`) change it.
 *
 * Shingle width of 3 balances sensitivity and robustness to comment noise.
 */
export function domStructureHash(html: string, shingleWidth = 3): string {
    const tags: string[] = [];
    const tagRe = /<\s*([a-zA-Z][a-zA-Z0-9-]*)/g;
    let m: RegExpExecArray | null;
    while ((m = tagRe.exec(html)) !== null) {
        tags.push(m[1].toLowerCase());
        if (tags.length > 2000) break; // cap — adversarial responses shouldn't DoS us
    }
    if (tags.length === 0) return 'empty';
    if (tags.length < shingleWidth) return createHash('sha256').update(tags.join('|')).digest('hex').slice(0, 32);

    const shingles: string[] = [];
    for (let i = 0; i <= tags.length - shingleWidth; i++) {
        shingles.push(tags.slice(i, i + shingleWidth).join('>'));
    }
    shingles.sort();
    return createHash('sha256').update(shingles.join('|')).digest('hex').slice(0, 32);
}

// ============================================================
// Header fingerprint
// ============================================================

/**
 * SHA-256 prefix of the sorted header-name set (values ignored). Catches
 * class-of-page changes (missing security headers, new cookie) without
 * noisy diffs on value-only changes like `X-Request-Id`.
 */
export function headerSetHash(headers: Record<string, string>): string {
    const keys = Object.keys(headers).map((k) => k.toLowerCase()).sort();
    return createHash('sha256').update(keys.join(',')).digest('hex').slice(0, 16);
}

// ============================================================
// Main feature extractor
// ============================================================

export interface ExtractInput {
    status: number;
    headers: Record<string, string>;
    body: string;
    responseTimeMs: number;
    /** Existing baseline token set, used to populate `newTokens` on candidate responses. */
    baselineTokens?: ReadonlySet<string>;
}

/**
 * Extract the full feature vector for a response. Optionally computes the
 * `newTokens` delta against a provided baseline token set — that's the
 * oracle signal for "words that showed up in an attack response but never
 * appeared in any benign response" (SQL error strings, stack traces).
 */
export function extractFeatures(input: ExtractInput): ResponseFeatures {
    const tokens = tokenize(input.body);
    const tokenSet = new Set(tokens);
    const simhash = simhash64(tokens);
    const contentType = (input.headers['content-type'] ?? input.headers['Content-Type'] ?? '').split(';')[0].trim();
    const domHash = contentType.includes('html') ? domStructureHash(input.body) : undefined;

    let newTokens: string[] | undefined;
    if (input.baselineTokens) {
        const unseen: string[] = [];
        for (const t of tokenSet) {
            if (!input.baselineTokens.has(t)) unseen.push(t);
        }
        newTokens = unseen.slice(0, 64); // cap to avoid log bloat on huge bodies
    }

    return {
        status: input.status,
        length: input.body.length,
        wordCount: tokens.length,
        contentSimhash: simhash,
        domStructureHash: domHash,
        responseTimeMs: input.responseTimeMs,
        headerSetHash: headerSetHash(input.headers),
        contentType,
        newTokens,
    };
}

/**
 * Collect every token ever seen across a set of baseline samples. Used to
 * build the baseline vocabulary that `extractFeatures` diffs against when
 * measuring a candidate response.
 */
export function collectBaselineVocabulary(bodies: string[]): Set<string> {
    const vocab = new Set<string>();
    for (const body of bodies) {
        for (const t of tokenize(body)) vocab.add(t);
    }
    return vocab;
}
