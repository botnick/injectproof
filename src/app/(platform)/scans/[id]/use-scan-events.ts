// InjectProof — useScanEvents hook
// Subscribes to /api/scan/[id]/events via EventSource and merges log + progress
// updates into local React state. Returns `{ progress, logs, connected, error }`
// so the page can render live without driving tRPC polls at 2s cadence.
//
// Uses EventSource, which handles reconnection automatically. If the browser
// doesn't support it, the hook reports `connected: false` and the caller falls
// back to the tRPC polling path.

'use client';

import { useEffect, useRef, useState } from 'react';

export interface ScanProgressEvent {
    status: string;
    progress: number;
    currentPhase: string | null;
    currentModule: string | null;
    currentUrl: string | null;
    statusMessage: string | null;
    heartbeatAt: string | Date | null;
}

export interface ScanLogEvent {
    id: string;
    level: 'debug' | 'info' | 'warn' | 'error';
    module: string;
    message: string;
    timestamp: string | Date;
}

export interface UseScanEventsResult {
    progress: ScanProgressEvent | null;
    logs: ScanLogEvent[];
    connected: boolean;
    error: string | null;
    /** Terminal status observed on the stream. Null until the server emits `done`. */
    terminal: string | null;
}

/**
 * Opens an SSE connection for scan events. Deduplicates logs by id so
 * reconnects don't surface the same entry twice.
 */
export function useScanEvents(scanId: string | null, enabled = true): UseScanEventsResult {
    const [progress, setProgress] = useState<ScanProgressEvent | null>(null);
    const [logs, setLogs] = useState<ScanLogEvent[]>([]);
    const [connected, setConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [terminal, setTerminal] = useState<string | null>(null);
    const seenLogIds = useRef<Set<string>>(new Set());
    const esRef = useRef<EventSource | null>(null);

    useEffect(() => {
        if (!enabled || !scanId) return;
        if (typeof window === 'undefined' || typeof EventSource === 'undefined') return;

        const url = `/api/scan/${encodeURIComponent(scanId)}/events`;
        const es = new EventSource(url);
        esRef.current = es;
        setError(null);

        es.onopen = () => setConnected(true);

        es.addEventListener('progress', (ev) => {
            try {
                setProgress(JSON.parse((ev as MessageEvent).data));
            } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
            }
        });

        es.addEventListener('log', (ev) => {
            try {
                const entry: ScanLogEvent = JSON.parse((ev as MessageEvent).data);
                if (seenLogIds.current.has(entry.id)) return;
                seenLogIds.current.add(entry.id);
                setLogs((prev) => [...prev, entry].slice(-500)); // cap to avoid memory bloat
            } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
            }
        });

        es.addEventListener('done', (ev) => {
            try {
                const { status } = JSON.parse((ev as MessageEvent).data) as { status: string };
                setTerminal(status);
            } catch { /* ignore */ }
            setConnected(false);
            es.close();
        });

        es.addEventListener('error', (ev) => {
            try {
                const data = (ev as MessageEvent).data;
                if (data) setError(typeof data === 'string' ? data : JSON.stringify(data));
            } catch { /* ignore */ }
            // EventSource retries automatically on transient errors; only
            // surface a hard-close when readyState is CLOSED.
            if (es.readyState === EventSource.CLOSED) setConnected(false);
        });

        return () => {
            es.close();
            esRef.current = null;
            setConnected(false);
        };
    }, [scanId, enabled]);

    return { progress, logs, connected, error, terminal };
}
