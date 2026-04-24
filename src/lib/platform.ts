// InjectProof — Cross-platform filesystem / process / env abstraction
// ตัวกลางเดียวที่โค้ดทุกจุดของ InjectProof ใช้เวลาต้องแตะ disk, spawn process,
// หรืออ่าน env. ออกแบบให้ Windows และ Linux ทำงานเหมือนกัน 100 %:
//   - ห้ามใช้ `/tmp` literal ที่อื่น
//   - ห้ามใช้ path separator แบบ fix ('/' หรือ '\\')
//   - ห้าม spawn 'bash' หรือ 'sh' โดยตรง — ใช้ resolveCommand ก่อน
//   - ทุกไฟล์ที่เขียนต้อง normalize line-ending ตาม platform หรือ pin เป็น LF
//
// ไฟล์นี้ห้าม import จาก `@/lib/config` หรือจุดอื่นที่อาจวน dep — เป็น bedrock.

import { tmpdir, homedir, platform as osPlatform, EOL as OS_EOL } from 'node:os';
import { resolve, join, normalize, sep, isAbsolute, dirname, basename } from 'node:path';
import { mkdir, writeFile, readFile, stat, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn, type SpawnOptions } from 'node:child_process';

// ────────────────────────────────────────────────────────────
// Platform flags
// ────────────────────────────────────────────────────────────

export const IS_WINDOWS = osPlatform() === 'win32';
export const IS_LINUX = osPlatform() === 'linux';
export const IS_MACOS = osPlatform() === 'darwin';

/** Line-ending policy: pin to LF for repo artifacts unless caller explicitly asks for OS default. */
export const LF = '\n';
export const OS_LINE_ENDING = OS_EOL;

// ────────────────────────────────────────────────────────────
// Path helpers
// ────────────────────────────────────────────────────────────

/**
 * Join paths in a way that normalizes separators for the current OS.
 * ใช้แทน manual `'/'` concatenation ทุกที่.
 */
export function pathJoin(...parts: string[]): string {
    return normalize(join(...parts));
}

/**
 * Resolve against cwd, platform-safe.
 */
export function pathResolve(...parts: string[]): string {
    return resolve(...parts);
}

/** Expand a leading `~` to the user's home. */
export function expandHome(path: string): string {
    if (path.startsWith('~/') || path === '~') {
        return join(homedir(), path.slice(1));
    }
    return path;
}

/** True if path is absolute on the current OS (handles both `/foo` and `C:\\foo`). */
export function isAbsolutePath(path: string): boolean {
    return isAbsolute(path);
}

/** Canonicalize a filesystem path so equality comparisons are stable. */
export function canonicalize(path: string): string {
    return normalize(resolve(expandHome(path)));
}

/** Platform-independent path equality. */
export function samePath(a: string, b: string): boolean {
    const ca = canonicalize(a);
    const cb = canonicalize(b);
    return IS_WINDOWS ? ca.toLowerCase() === cb.toLowerCase() : ca === cb;
}

export { sep as PATH_SEP, dirname, basename };

// ────────────────────────────────────────────────────────────
// Temp / cache / data directories
// ────────────────────────────────────────────────────────────

/**
 * Return the OS temp directory, never a hardcoded `/tmp` (Linux) or
 * `C:\\Users\\X\\AppData\\Local\\Temp` (Windows).
 */
export function systemTempDir(): string {
    return tmpdir();
}

/** Create a scratch subdir under the system temp — useful for bench runs. */
export async function createScratchDir(prefix = 'injectproof-'): Promise<string> {
    const base = pathJoin(systemTempDir(), `${prefix}${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    await mkdir(base, { recursive: true });
    return base;
}

/** Recursively remove a directory if present. */
export async function removeDir(path: string): Promise<void> {
    if (!existsSync(path)) return;
    await rm(path, { recursive: true, force: true });
}

// ────────────────────────────────────────────────────────────
// File ops (safe wrappers)
// ────────────────────────────────────────────────────────────

/**
 * Write text with pinned LF line endings unless caller asks otherwise.
 * ทำให้ diff บน Windows ไม่โดน CRLF-noise.
 */
export async function writeTextFile(
    path: string,
    content: string,
    opts: { ensureDir?: boolean; lineEnding?: 'lf' | 'os' } = {},
): Promise<void> {
    if (opts.ensureDir ?? true) await mkdir(dirname(path), { recursive: true });
    const text =
        opts.lineEnding === 'os'
            ? content.replace(/\r?\n/g, OS_LINE_ENDING)
            : content.replace(/\r\n/g, LF);
    await writeFile(path, text, 'utf-8');
}

export async function readTextFile(path: string): Promise<string> {
    const buf = await readFile(path);
    return buf.toString('utf-8');
}

export async function fileExists(path: string): Promise<boolean> {
    try {
        await stat(path);
        return true;
    } catch {
        return false;
    }
}

// ────────────────────────────────────────────────────────────
// Command resolution + safe spawn
// ────────────────────────────────────────────────────────────

/**
 * Resolve the OS-correct executable name. Example usage:
 *   resolveCommand('npx') → 'npx.cmd' on Windows, 'npx' elsewhere.
 * Caller must pass only commands they intend to run — this helper does not
 * validate against PATH.
 */
export function resolveCommand(name: string): string {
    if (!IS_WINDOWS) return name;
    const lower = name.toLowerCase();
    // Common Node tooling ships .cmd shims on Windows; others use .exe.
    const CMD_SHIMS = new Set(['npm', 'npx', 'yarn', 'pnpm', 'tsx', 'prisma', 'next', 'vitest']);
    if (CMD_SHIMS.has(lower)) return `${name}.cmd`;
    return name;
}

/**
 * Spawn a child process with cross-platform defaults.
 *  - uses shell=true on Windows so `.cmd` shims resolve
 *  - captures stdout + stderr into strings (bounded buffer)
 *  - throws on timeout (default 30s) or non-zero exit (opt-out)
 */
export interface SpawnResult {
    code: number;
    stdout: string;
    stderr: string;
    durationMs: number;
}

export interface SpawnBoundedOptions extends Omit<SpawnOptions, 'stdio' | 'shell'> {
    timeoutMs?: number;
    /** Max bytes captured per stream (default 1 MiB). Caller can opt out with Infinity. */
    maxBufferBytes?: number;
    /** Throw when exit code ≠ 0. Default true. */
    throwOnNonZero?: boolean;
}

export async function spawnBounded(
    command: string,
    args: string[],
    opts: SpawnBoundedOptions = {},
): Promise<SpawnResult> {
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const maxBuf = opts.maxBufferBytes ?? 1_048_576;
    const started = Date.now();
    const resolved = resolveCommand(command);
    // Use shell ONLY when we actually need the Windows shim resolution (.cmd
    // / .bat). Regular binaries like `node`, `python`, `git` run fine with
    // `shell: false` on Windows and avoid the cmd.exe quote-mangling that
    // breaks `node -e "..."` style invocations.
    const needsShell = IS_WINDOWS && /\.(cmd|bat)$/i.test(resolved);

    return new Promise<SpawnResult>((resolveP, rejectP) => {
        const child = spawn(resolved, args, {
            ...opts,
            stdio: ['ignore', 'pipe', 'pipe'],
            shell: needsShell,
        });

        let outBytes = 0;
        let errBytes = 0;
        const outChunks: Buffer[] = [];
        const errChunks: Buffer[] = [];
        let killed = false;

        const timer = setTimeout(() => {
            killed = true;
            child.kill('SIGKILL');
            rejectP(new Error(`spawnBounded: ${command} exceeded ${timeoutMs} ms`));
        }, timeoutMs);

        child.stdout?.on('data', (c: Buffer) => {
            outBytes += c.length;
            if (outBytes <= maxBuf) outChunks.push(c);
        });
        child.stderr?.on('data', (c: Buffer) => {
            errBytes += c.length;
            if (errBytes <= maxBuf) errChunks.push(c);
        });

        child.on('error', (err) => {
            clearTimeout(timer);
            rejectP(err);
        });

        child.on('close', (code) => {
            clearTimeout(timer);
            if (killed) return;
            const result: SpawnResult = {
                code: code ?? -1,
                stdout: Buffer.concat(outChunks).toString('utf-8'),
                stderr: Buffer.concat(errChunks).toString('utf-8'),
                durationMs: Date.now() - started,
            };
            const shouldThrow = opts.throwOnNonZero ?? true;
            if (shouldThrow && result.code !== 0) {
                rejectP(
                    new Error(
                        `spawnBounded: ${command} exited ${result.code}\nstderr: ${result.stderr.slice(0, 400)}`,
                    ),
                );
                return;
            }
            resolveP(result);
        });
    });
}

// ────────────────────────────────────────────────────────────
// Env helpers — read-only. `lib/config.ts` owns validation.
// ────────────────────────────────────────────────────────────

/** Read an env var with a default. Does no validation. */
export function env(name: string, defaultValue?: string): string | undefined {
    const v = process.env[name];
    if (v === undefined || v === '') return defaultValue;
    return v;
}

/** Boolean env var: "1", "true", "yes", "on" → true (case-insensitive). */
export function envBool(name: string, defaultValue = false): boolean {
    const v = env(name);
    if (v === undefined) return defaultValue;
    return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

/** Numeric env var with default; returns default on parse failure. */
export function envNumber(name: string, defaultValue: number): number {
    const v = env(name);
    if (v === undefined) return defaultValue;
    const n = Number(v);
    return Number.isFinite(n) ? n : defaultValue;
}
