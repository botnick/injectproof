// InjectProof — /api/healthz
// Liveness probe: "process is up and responding". Does NOT touch DB.
// ใช้ Docker HEALTHCHECK, Kubernetes livenessProbe และ load-balancer health.

import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(): Promise<NextResponse> {
    return NextResponse.json(
        {
            ok: true,
            uptime: Math.round(process.uptime()),
            now: new Date().toISOString(),
            platform: process.platform,
            node: process.version,
        },
        {
            headers: { 'cache-control': 'no-store' },
        },
    );
}
