import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runOracleDetection, type OraclePayload } from './oracle-detector';
import type { CrawledEndpoint, DiscoveredParam } from '@/types';

// ------------------------------------------------------------
// Mock fetch — baseline returns a stable body; attack returns
// a body with visible DOM injection + new tokens.
// ------------------------------------------------------------

const originalFetch = globalThis.fetch;

beforeEach(() => {
    vi.clearAllMocks();
});

interface MockReply {
    status: number;
    body: string;
    headersMap?: Record<string, string>;
}

function mockFetch(handler: (url: string, init: RequestInit) => MockReply): void {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = typeof input === 'string' ? input : input.toString();
        const out = handler(urlStr, init ?? {});
        const headersMap = out.headersMap ?? { 'content-type': 'text/html' };
        return new Response(out.body, {
            status: out.status,
            headers: headersMap,
        });
    }) as typeof fetch;
}

function restoreFetch(): void {
    globalThis.fetch = originalFetch;
}

// ------------------------------------------------------------
// Helper to build a fake CrawledEndpoint
// ------------------------------------------------------------

function fakeEndpoint(): CrawledEndpoint {
    return {
        url: 'http://target.local/search',
        method: 'GET',
        params: [],
        forms: [],
        headers: {},
        depth: 0,
        source: 'test',
    };
}

function param(name: string, value = 'hello'): DiscoveredParam {
    return { name, type: 'query', value };
}

// ============================================================
// Tests
// ============================================================

describe('runOracleDetection', () => {
    it('returns no findings when every attack response is identical to baseline', async () => {
        mockFetch(() => ({
            body: '<html><body><h1>Welcome</h1><p>Home page</p></body></html>',
            status: 200,
        }));
        const payloads: OraclePayload[] = [
            { value: "' OR 1=1 --", label: 'sqli-1' },
        ];
        const findings = await runOracleDetection({
            url: 'http://target.local/page',
            method: 'GET',
            param: param('q'),
            payloads,
            category: 'sqli',
            cweId: 'CWE-89',
            cvssKey: 'sqli',
            requestTimeout: 1000,
            userAgent: 'test',
        });
        expect(findings).toEqual([]);
        restoreFetch();
    });

    it('emits a confirmed finding when attack response diverges structurally', async () => {
        mockFetch((_url, init) => {
            const body = (init.body ?? '').toString();
            const urlStr = _url;
            const hasAttack =
                body.includes("OR 1=1") ||
                urlStr.includes('OR%201%3D1') ||
                urlStr.includes("1%3D1");
            if (hasAttack) {
                return {
                    status: 500,
                    body: '<html><body><pre>MySQL error syntax fatal near line 1 stack traceback</pre></body></html>',
                    headersMap: { 'content-type': 'text/html', 'x-error': 'true' },
                };
            }
            return {
                status: 200,
                body: '<html><body><h1>Welcome</h1><p>Your profile is ready.</p></body></html>',
            };
        });

        const payloads: OraclePayload[] = [
            { value: "' OR 1=1 -- ", label: 'sqli-boolean' },
        ];
        const findings = await runOracleDetection({
            url: 'http://target.local/search',
            method: 'GET',
            param: param('q', 'hello'),
            payloads,
            category: 'sqli',
            cweId: 'CWE-89',
            cvssKey: 'sqli',
            severityFloor: 'high',
            requestTimeout: 1000,
            userAgent: 'test',
            enableTimePersistence: false,
        });

        expect(findings.length).toBe(1);
        const f = findings[0];
        expect(f.category).toBe('sqli');
        expect(f.severity === 'high' || f.severity === 'critical').toBe(true);
        expect(f.provenance).toBeTruthy();
        expect(f.provenance?.oraclesUsed).toContain('baseline');
        expect(f.payload).toBe("' OR 1=1 -- ");
        expect(f.technicalDetail).toMatch(/Oracle verdict/);
        restoreFetch();
    });

    it('stops at maxFindings', async () => {
        mockFetch((_url, init) => {
            const body = (init.body ?? '').toString();
            const urlStr = _url;
            const hasAttack = body.includes("' OR") || urlStr.includes('OR%');
            return hasAttack
                ? {
                    status: 500,
                    body: '<html><body><pre>MySQL syntax error fatal mysql near line 1</pre></body></html>',
                }
                : { status: 200, body: '<html><body><p>Home</p></body></html>' };
        });
        const payloads: OraclePayload[] = Array.from({ length: 5 }, (_, i) => ({
            value: `' OR ${i}=${i} -- `,
            label: `p${i}`,
        }));
        const findings = await runOracleDetection({
            url: 'http://target.local/p',
            method: 'GET',
            param: param('x', 'abc'),
            payloads,
            category: 'sqli',
            cweId: 'CWE-89',
            cvssKey: 'sqli',
            requestTimeout: 1000,
            userAgent: 'test',
            maxFindings: 2,
        });
        expect(findings.length).toBeLessThanOrEqual(2);
        restoreFetch();
    });

    it('returns no findings when baseline cannot be built', async () => {
        mockFetch(() => ({ status: 500, body: '' }));
        // 500 responses still succeed for fetch, so force unreachability:
        globalThis.fetch = vi.fn(async () => {
            throw new Error('network');
        }) as typeof fetch;
        const findings = await runOracleDetection({
            url: 'http://unreachable.local/p',
            method: 'GET',
            param: param('q'),
            payloads: [{ value: "' OR 1=1", label: 'p' }],
            category: 'sqli',
            cweId: 'CWE-89',
            cvssKey: 'sqli',
            requestTimeout: 500,
            userAgent: 'test',
        });
        expect(findings).toEqual([]);
        restoreFetch();
    });
});
