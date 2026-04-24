// InjectProof — SSE stream for live scan progress + logs
// Replaces 2s tRPC polling on the scan-detail page. Consumer opens an
// EventSource to /api/scan/<id>/events; the endpoint emits one event per
// ScanLog row + one `progress` event every few seconds + a terminal
// `done` event when the scan reaches completed/failed/cancelled status.
//
// No long-lived DB cursor — each tick polls for new rows since the last
// emitted timestamp. Cheap, trivially reconnectable.

import { NextRequest } from 'next/server';
import prisma from '@/lib/prisma';

export const dynamic = 'force-dynamic';

const TICK_MS = 2_000;
const MAX_SESSION_MS = 30 * 60 * 1_000; // safety — servers should close long-idle SSE

function sseEvent(event: string, data: unknown): string {
    return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

export async function GET(
    req: NextRequest,
    { params }: { params: Promise<{ id: string }> },
): Promise<Response> {
    const { id: scanId } = await params;

    const encoder = new TextEncoder();
    const started = Date.now();
    let lastLogTs = new Date(0);
    let lastStatus: string | null = null;

    const stream = new ReadableStream({
        async start(controller) {
            const keepalive = setInterval(() => {
                try {
                    controller.enqueue(encoder.encode(': keepalive\n\n'));
                } catch {
                    /* consumer closed */
                }
            }, 15_000);

            req.signal.addEventListener('abort', () => {
                clearInterval(keepalive);
                try {
                    controller.close();
                } catch {
                    /* already closed */
                }
            });

            try {
                while (!req.signal.aborted && Date.now() - started < MAX_SESSION_MS) {
                    const scan = await prisma.scan.findUnique({
                        where: { id: scanId },
                        select: {
                            status: true,
                            progress: true,
                            currentPhase: true,
                            currentModule: true,
                            currentUrl: true,
                            statusMessage: true,
                            heartbeatAt: true,
                        },
                    });
                    if (!scan) {
                        controller.enqueue(encoder.encode(sseEvent('error', { reason: 'scan not found' })));
                        break;
                    }

                    if (scan.status !== lastStatus) {
                        controller.enqueue(encoder.encode(sseEvent('progress', scan)));
                        lastStatus = scan.status;
                    } else {
                        controller.enqueue(encoder.encode(sseEvent('progress', scan)));
                    }

                    const newLogs = await prisma.scanLog.findMany({
                        where: { scanId, timestamp: { gt: lastLogTs } },
                        orderBy: { timestamp: 'asc' },
                        take: 200,
                    });
                    for (const log of newLogs) {
                        controller.enqueue(
                            encoder.encode(
                                sseEvent('log', {
                                    id: log.id,
                                    level: log.level,
                                    module: log.module,
                                    message: log.message,
                                    timestamp: log.timestamp,
                                }),
                            ),
                        );
                        if (log.timestamp > lastLogTs) lastLogTs = log.timestamp;
                    }

                    if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
                        controller.enqueue(encoder.encode(sseEvent('done', { status: scan.status })));
                        break;
                    }
                    await new Promise((r) => setTimeout(r, TICK_MS));
                }
            } catch (err) {
                controller.enqueue(
                    encoder.encode(sseEvent('error', { reason: err instanceof Error ? err.message : String(err) })),
                );
            } finally {
                clearInterval(keepalive);
                try {
                    controller.close();
                } catch {
                    /* already closed */
                }
            }
        },
    });

    return new Response(stream, {
        headers: {
            'content-type': 'text/event-stream',
            'cache-control': 'no-cache, no-transform',
            'connection': 'keep-alive',
            'x-accel-buffering': 'no',
        },
    });
}
