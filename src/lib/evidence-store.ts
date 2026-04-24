// InjectProof — Evidence store with content-addressable layout + at-rest encryption
// Replaces ad-hoc "stuff a string into a Prisma column" artifact handling.
// Every finding's request/response/screenshot/DOM artifact is written to:
//
//   EVIDENCE_DIR/<scanId>/<vulnId>/<type>-<n>.<ext>[.enc]
//
// with a SHA-256 hash recorded in the Evidence row for tamper detection.
// Sensitive content (extracted credentials, schema dumps) is AES-256-GCM
// encrypted under EVIDENCE_KEY so a stolen DB file can't leak customer data.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

const ALGO = 'aes-256-gcm';

// ============================================================
// Key loading
// ============================================================

function loadKey(): Buffer {
    const raw = process.env.EVIDENCE_KEY;
    if (!raw) {
        throw new Error(
            'EVIDENCE_KEY is not set. Generate one with `node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"` and add to .env. Encrypted evidence columns require this.',
        );
    }
    const buf = Buffer.from(raw, 'base64');
    if (buf.length !== 32) {
        throw new Error(`EVIDENCE_KEY must decode to 32 bytes for AES-256, got ${buf.length}`);
    }
    return buf;
}

let keyCache: Buffer | null = null;
function key(): Buffer {
    if (!keyCache) keyCache = loadKey();
    return keyCache;
}

// ============================================================
// Hashing
// ============================================================

export function sha256Hex(data: string | Buffer): string {
    return createHash('sha256').update(data).digest('hex');
}

// ============================================================
// AES-GCM helpers
// ============================================================

/** Encrypt and return a base64 bundle: `{iv}.{ciphertext}.{authTag}`. */
export function encryptString(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGO, key(), iv);
    const encrypted = Buffer.concat([cipher.update(plain, 'utf-8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [iv.toString('base64'), encrypted.toString('base64'), tag.toString('base64')].join('.');
}

export function decryptString(bundle: string): string {
    const [ivB64, ctB64, tagB64] = bundle.split('.');
    if (!ivB64 || !ctB64 || !tagB64) throw new Error('malformed encryption bundle');
    const iv = Buffer.from(ivB64, 'base64');
    const ct = Buffer.from(ctB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const decipher = createDecipheriv(ALGO, key(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
}

// ============================================================
// On-disk artifact store
// ============================================================

export interface StoreInput {
    scanId: string;
    vulnId: string;
    type: 'request' | 'response' | 'screenshot' | 'dom_snapshot' | 'timing_log' | 'execution_trace' | 'replay_script' | 'raw_trace';
    order?: number;
    content: Buffer | string;
    mimeType?: string;
    /** If true, encrypt at rest. Defaults to true for extracted-data artifacts. */
    sensitive?: boolean;
}

export interface StoredArtifact {
    filePath: string;
    hash: string;
    size: number;
    encryption: 'aes-256-gcm' | null;
}

/**
 * Write an artifact to the evidence directory, compute its SHA-256, and
 * optionally encrypt. Returns the path + hash so the caller can persist a
 * matching Evidence row.
 */
export async function storeArtifact(input: StoreInput): Promise<StoredArtifact> {
    const root = process.env.EVIDENCE_DIR ?? './evidence';
    const dir = resolve(root, input.scanId, input.vulnId);
    await mkdir(dir, { recursive: true });

    const ext =
        input.type === 'screenshot' ? '.png' :
            input.type === 'dom_snapshot' ? '.html' :
                input.type === 'request' || input.type === 'response' ? '.http' :
                    '.txt';

    const order = input.order ?? 0;
    const baseName = `${input.type}-${order}${ext}`;
    const buf =
        typeof input.content === 'string' ? Buffer.from(input.content, 'utf-8') : input.content;
    const hash = sha256Hex(buf);

    const encryptThis = input.sensitive ?? false;
    if (encryptThis) {
        const iv = randomBytes(12);
        const cipher = createCipheriv(ALGO, key(), iv);
        const encrypted = Buffer.concat([cipher.update(buf), cipher.final()]);
        const tag = cipher.getAuthTag();
        const combined = Buffer.concat([iv, tag, encrypted]);
        const filePath = join(dir, baseName + '.enc');
        await writeFile(filePath, combined);
        return { filePath, hash, size: buf.length, encryption: 'aes-256-gcm' };
    }

    const filePath = join(dir, baseName);
    await writeFile(filePath, buf);
    return { filePath, hash, size: buf.length, encryption: null };
}

export async function readArtifact(filePath: string, encryption: 'aes-256-gcm' | null): Promise<Buffer> {
    const raw = await readFile(filePath);
    if (!encryption) return raw;
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ct = raw.subarray(28);
    const decipher = createDecipheriv(ALGO, key(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ============================================================
// Safer helper: ensure parent dir exists before raw writes
// ============================================================

export async function ensureDir(filePath: string): Promise<void> {
    await mkdir(dirname(filePath), { recursive: true });
}
