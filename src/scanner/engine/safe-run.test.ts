import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanLogEntry } from '@/scanner/engine/log';

// Typed mock so mock.calls[0]?.[0] is inferred as ScanLogEntry (not never).
const logScanMock = vi.fn<(entry: ScanLogEntry) => Promise<void>>(async () => undefined);

vi.mock('@/scanner/engine/log', () => ({
    logScan: logScanMock,
    addScanLog: vi.fn(async () => undefined),
}));

// Import after the mock is registered.
const { safeRun, safeRunOr, safeRunResult } = await import('./safe-run');

/** Read the entry passed to the most-recent logScan call. */
function lastLog(): ScanLogEntry {
    const call = logScanMock.mock.calls.at(-1);
    if (!call) throw new Error('logScan was never called');
    return call[0];
}

beforeEach(() => {
    logScanMock.mockClear();
});

describe('safeRun', () => {
    it('returns the resolved value on success without logging', async () => {
        const result = await safeRun(
            { scanId: 's1', phase: 'scanning', module: 'test' },
            async () => 42,
        );
        expect(result).toBe(42);
        expect(logScanMock).not.toHaveBeenCalled();
    });

    it('returns null on thrown error and logs a structured entry', async () => {
        const result = await safeRun(
            { scanId: 's1', phase: 'scanning', module: 'detectors.sqli', operation: 'probe' },
            async () => {
                throw new Error('boom');
            },
        );
        expect(result).toBeNull();
        expect(logScanMock).toHaveBeenCalledTimes(1);
        const call = lastLog();
        expect(call.scanId).toBe('s1');
        expect(call.level).toBe('warn');
        expect(call.module).toBe('detectors.sqli');
        expect(call.message).toContain('probe');
        expect(call.message).toContain('boom');
        expect(call.details?.phase).toBe('scanning');
        expect(call.details?.operation).toBe('probe');
        expect((call.details?.error as { message: string }).message).toBe('boom');
    });

    it('coerces non-Error throwables to Error for logging', async () => {
        await safeRun({ scanId: 's1', phase: 'x', module: 'm' }, async () => {
            throw 'string-thrown';
        });
        expect(logScanMock).toHaveBeenCalledTimes(1);
        expect(lastLog().message).toContain('string-thrown');
    });

    it('honors a custom level override', async () => {
        await safeRun(
            { scanId: 's1', phase: 'x', module: 'm', level: 'error' },
            async () => {
                throw new Error('fatal');
            },
        );
        expect(lastLog().level).toBe('error');
    });
});

describe('safeRunOr', () => {
    it('returns fallback on error', async () => {
        const out = await safeRunOr(
            { scanId: 's1', phase: 'x', module: 'm' },
            { fallback: true },
            async () => {
                throw new Error('nope');
            },
        );
        expect(out).toEqual({ fallback: true });
        expect(logScanMock).toHaveBeenCalled();
    });

    it('returns the real value on success', async () => {
        const out = await safeRunOr(
            { scanId: 's1', phase: 'x', module: 'm' },
            [] as number[],
            async () => [1, 2, 3],
        );
        expect(out).toEqual([1, 2, 3]);
        expect(logScanMock).not.toHaveBeenCalled();
    });
});

describe('safeRunResult', () => {
    it('returns ok=true with value on success', async () => {
        const r = await safeRunResult(
            { scanId: 's1', phase: 'x', module: 'm' },
            async () => 'yes',
        );
        expect(r.ok).toBe(true);
        expect(r.value).toBe('yes');
        expect(r.error).toBeNull();
    });

    it('returns ok=false with error on failure', async () => {
        const r = await safeRunResult(
            { scanId: 's1', phase: 'x', module: 'm' },
            async () => {
                throw new Error('bad');
            },
        );
        expect(r.ok).toBe(false);
        expect(r.value).toBeNull();
        expect(r.error).toBeInstanceOf(Error);
        expect(r.error?.message).toBe('bad');
    });
});
