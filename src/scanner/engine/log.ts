// InjectProof — Shared ScanLog writer
// Centralizes ScanLog persistence so every module logs through the same path.
// Previously duplicated inline in scanner/index.ts. Other modules are expected
// to import from here rather than re-implementing.

import prisma from '@/lib/prisma';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface ScanLogEntry {
    scanId: string;
    level: LogLevel;
    module: string;
    message: string;
    details?: Record<string, unknown>;
}

/**
 * Write a single ScanLog row. Failure to write is logged to stderr as a last
 * resort — the scan must not abort because its own log table is unavailable.
 */
export async function logScan(entry: ScanLogEntry): Promise<void> {
    try {
        await prisma.scanLog.create({
            data: {
                scanId: entry.scanId,
                level: entry.level,
                module: entry.module,
                message: entry.message,
                details: entry.details ? JSON.stringify(entry.details) : null,
            },
        });
    } catch (err) {
        // eslint-disable-next-line no-console
        console.error(
            `[scan-log] failed to persist log for scan=${entry.scanId} module=${entry.module}:`,
            err,
        );
    }
}

/**
 * Backwards-compatible positional form matching the existing callsite shape
 * in scanner/index.ts — lets us migrate callers incrementally.
 */
export async function addScanLog(
    scanId: string,
    level: LogLevel | string,
    module: string,
    message: string,
    details?: Record<string, unknown>,
): Promise<void> {
    return logScan({
        scanId,
        level: (level as LogLevel) ?? 'info',
        module,
        message,
        details,
    });
}
