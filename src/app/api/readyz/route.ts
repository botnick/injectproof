// InjectProof — /api/readyz
// Readiness probe: "process can service requests, including DB dependency".
// ใช้ Kubernetes readinessProbe. Fails if Prisma cannot round-trip a trivial
// SELECT 1 within the timeout.

import { NextResponse } from 'next/server';
import prisma from '@/lib/prisma';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(): Promise<NextResponse> {
    const started = Date.now();
    const checks: Record<string, { ok: boolean; latencyMs?: number; error?: string }> = {};

    try {
        const q = Date.now();
        await prisma.$queryRawUnsafe('SELECT 1');
        checks.database = { ok: true, latencyMs: Date.now() - q };
    } catch (err) {
        checks.database = {
            ok: false,
            error: err instanceof Error ? err.message : String(err),
        };
    }

    const allOk = Object.values(checks).every((c) => c.ok);
    return NextResponse.json(
        {
            ok: allOk,
            checks,
            totalMs: Date.now() - started,
            now: new Date().toISOString(),
        },
        {
            status: allOk ? 200 : 503,
            headers: { 'cache-control': 'no-store' },
        },
    );
}
