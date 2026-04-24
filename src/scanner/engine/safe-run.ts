// InjectProof — safeRun wrapper
// Replaces silent `catch {}` blocks across the scanner with a single helper
// that guarantees every caught error is persisted to ScanLog with full
// context and a structured stack trace. Returns the fallback value on error
// so callers can stay on the happy path while still yielding evidence of
// why a module dropped.
//
// Rule of thumb: every best-effort block in src/scanner/** should use this.

import { logScan, type LogLevel } from '@/scanner/engine/log';

export interface SafeRunOptions {
    scanId: string;
    /** High-level pipeline phase: 'crawling' | 'scanning' | 'exploitation' | ... */
    phase: string;
    /** Module name logged alongside. Prefer dotted form: 'detectors.sqli', 'easm.subdomain' */
    module: string;
    /** Severity of the failure log (default 'warn'). Use 'error' for unrecoverable drops. */
    level?: LogLevel;
    /** Extra structured context attached to the log row. */
    context?: Record<string, unknown>;
    /** Short human label for what the wrapped block was trying to do. */
    operation?: string;
}

export interface SafeRunResult<T> {
    ok: boolean;
    value: T | null;
    error: Error | null;
}

/**
 * Wrap a fallible async block. On throw, persist a structured ScanLog entry
 * and return null. Callers that need a non-null default should use
 * {@link safeRunOr} instead.
 */
export async function safeRun<T>(
    opts: SafeRunOptions,
    fn: () => Promise<T>,
): Promise<T | null> {
    try {
        return await fn();
    } catch (err) {
        await recordError(opts, err);
        return null;
    }
}

/**
 * Variant of {@link safeRun} that returns a fallback value instead of null.
 * Useful for reducers/accumulators where null would crash downstream code.
 */
export async function safeRunOr<T>(
    opts: SafeRunOptions,
    fallback: T,
    fn: () => Promise<T>,
): Promise<T> {
    try {
        return await fn();
    } catch (err) {
        await recordError(opts, err);
        return fallback;
    }
}

/**
 * Richest variant — returns explicit {ok, value, error} so the caller can
 * branch on success while still getting the logged error if they want it.
 */
export async function safeRunResult<T>(
    opts: SafeRunOptions,
    fn: () => Promise<T>,
): Promise<SafeRunResult<T>> {
    try {
        const value = await fn();
        return { ok: true, value, error: null };
    } catch (err) {
        const error = await recordError(opts, err);
        return { ok: false, value: null, error };
    }
}

async function recordError(opts: SafeRunOptions, err: unknown): Promise<Error> {
    const error = err instanceof Error ? err : new Error(String(err));
    const details: Record<string, unknown> = {
        phase: opts.phase,
        operation: opts.operation,
        error: {
            name: error.name,
            message: error.message,
            stack: error.stack,
        },
    };
    if (opts.context) details.context = opts.context;

    const prefix = opts.operation ? `${opts.operation}: ` : '';
    await logScan({
        scanId: opts.scanId,
        level: opts.level ?? 'warn',
        module: opts.module,
        message: `${prefix}${error.message}`,
        details,
    });
    return error;
}
