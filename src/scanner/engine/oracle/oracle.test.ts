import { describe, it, expect } from 'vitest';
import {
    tokenize,
    simhash64,
    simhashHamming,
    domStructureHash,
    headerSetHash,
    extractFeatures,
} from './features';
import { BaselineCluster, benignVariants, buildBaseline } from './baseline';
import { responseDistance, SUSPICIOUS_TOKENS } from './distance';
import { evaluate } from './verdict';

// ============================================================
// features.ts
// ============================================================

describe('tokenize', () => {
    it('splits on non-word runs and lowercases', () => {
        expect(tokenize('Hello, World! 123')).toEqual(['hello', 'world', '123']);
    });
    it('drops single-character tokens', () => {
        expect(tokenize('a bb ccc')).toEqual(['bb', 'ccc']);
    });
    it('handles underscores as part of a word', () => {
        expect(tokenize('my_var_name')).toEqual(['my_var_name']);
    });
});

describe('simhash64', () => {
    it('identical token sets produce identical hashes', () => {
        const h1 = simhash64(['alpha', 'beta', 'gamma']);
        const h2 = simhash64(['alpha', 'beta', 'gamma']);
        expect(h1).toBe(h2);
    });

    it('completely different token sets have high hamming distance', () => {
        const h1 = simhash64(['apple', 'banana', 'cherry', 'date', 'elderberry']);
        const h2 = simhash64(['zebra', 'yak', 'xenon', 'walrus', 'viper']);
        expect(simhashHamming(h1, h2)).toBeGreaterThan(15);
    });

    it('nearly-identical token sets have low hamming distance', () => {
        const base = Array.from({ length: 100 }, (_, i) => `token${i}`);
        const copy = [...base, 'token100'];
        expect(simhashHamming(simhash64(base), simhash64(copy))).toBeLessThan(6);
    });
});

describe('domStructureHash', () => {
    it('matches across different text content but same structure', () => {
        const a = '<html><body><h1>Hello</h1><p>First</p></body></html>';
        const b = '<html><body><h1>Bye</h1><p>Second</p></body></html>';
        expect(domStructureHash(a)).toBe(domStructureHash(b));
    });

    it('differs when a new script tag is injected', () => {
        const a = '<html><body><p>x</p></body></html>';
        const b = '<html><body><p>x</p><script>alert(1)</script></body></html>';
        expect(domStructureHash(a)).not.toBe(domStructureHash(b));
    });
});

describe('headerSetHash', () => {
    it('same header names → same hash regardless of values', () => {
        const a = { 'content-type': 'text/html', 'x-foo': '1' };
        const b = { 'Content-Type': 'application/json', 'X-Foo': '99' };
        expect(headerSetHash(a)).toBe(headerSetHash(b));
    });

    it('different header sets → different hash', () => {
        expect(headerSetHash({ a: '1', b: '2' })).not.toBe(headerSetHash({ a: '1', c: '2' }));
    });
});

describe('extractFeatures', () => {
    it('populates newTokens against a baseline vocabulary', () => {
        const baselineVocab = new Set(['welcome', 'home', 'page']);
        const features = extractFeatures({
            status: 200,
            headers: { 'content-type': 'text/html' },
            body: 'Welcome to the error page MySQL syntax',
            responseTimeMs: 50,
            baselineTokens: baselineVocab,
        });
        expect(features.newTokens).toEqual(expect.arrayContaining(['error', 'mysql', 'syntax']));
        expect(features.newTokens).not.toContain('welcome');
    });
});

// ============================================================
// baseline.ts
// ============================================================

describe('benignVariants', () => {
    it('always includes the original value', () => {
        const vs = benignVariants('abc', 'name');
        expect(vs.find((v) => v.value === 'abc')).toBeTruthy();
    });

    it('produces numeric-specific variants when original is numeric', () => {
        const vs = benignVariants('42', 'id');
        expect(vs.find((v) => v.label === 'numeric-inc')).toBeTruthy();
        expect(vs.find((v) => v.label === 'numeric-zero')).toBeTruthy();
    });
});

describe('BaselineCluster', () => {
    it('accumulates per-axis mean and stddev via Welford', () => {
        const c = new BaselineCluster();
        for (const len of [100, 102, 98, 101, 99]) {
            c.addSample(
                {
                    requestAt: '2026-04-24T00:00:00Z',
                    variant: 'v',
                    features: {
                        status: 200,
                        length: len,
                        wordCount: len / 5,
                        contentSimhash: '00000000ffffffff',
                        responseTimeMs: 50,
                        headerSetHash: 'h1',
                        contentType: 'text/html',
                    },
                },
                'body '.repeat(len / 5),
            );
        }
        const s = c.stats();
        expect(s.sampleCount).toBe(5);
        expect(s.length.mean).toBeCloseTo(100, 0);
        expect(s.length.stddev).toBeGreaterThan(0);
        expect(s.length.stddev).toBeLessThan(5);
    });
});

describe('buildBaseline', () => {
    it('returns null when too few probes succeed', async () => {
        const cluster = await buildBaseline({
            paramName: 'id',
            paramValue: '1',
            probe: async () => null,
            minSamples: 3,
        });
        expect(cluster).toBeNull();
    });

    it('builds a usable cluster from stable synthetic responses', async () => {
        const cluster = await buildBaseline({
            paramName: 'id',
            paramValue: '1',
            probe: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><p>hello world</p></body></html>',
                responseTimeMs: 40 + Math.random() * 10,
            }),
            minSamples: 3,
        });
        expect(cluster).not.toBeNull();
        expect(cluster!.samples.length).toBeGreaterThanOrEqual(3);
    });
});

// ============================================================
// distance.ts
// ============================================================

describe('responseDistance', () => {
    it('identical-to-baseline responses produce near-zero distance', () => {
        const cluster = new BaselineCluster();
        const feat = {
            status: 200,
            length: 200,
            wordCount: 30,
            contentSimhash: '0000000000000000',
            responseTimeMs: 50,
            headerSetHash: 'hX',
            contentType: 'text/html',
        };
        for (let i = 0; i < 5; i++) {
            cluster.addSample(
                { requestAt: '', variant: 'v', features: { ...feat } },
                'hello world page content',
            );
        }
        const stats = cluster.stats();
        const d = responseDistance(feat, stats, new Set(tokenize('hello world page content')), {});
        expect(d.total).toBeLessThan(stats.anomalyThreshold);
    });

    it('response with SQL error tokens and much larger size crosses threshold', () => {
        const cluster = new BaselineCluster();
        const base = {
            status: 200,
            length: 300,
            wordCount: 40,
            contentSimhash: '1111111111111111',
            responseTimeMs: 40,
            headerSetHash: 'hX',
            contentType: 'text/html',
        };
        for (let i = 0; i < 5; i++) {
            cluster.addSample(
                { requestAt: '', variant: 'v', features: { ...base, length: 300 + i } },
                'welcome user profile home',
            );
        }
        const stats = cluster.stats();
        const anomalous = {
            ...base,
            length: 1800,
            wordCount: 220,
            contentSimhash: 'eeeeeeee22222222',
            responseTimeMs: 40,
            status: 500,
        };
        const d = responseDistance(
            anomalous,
            stats,
            new Set(['sql', 'syntax', 'error', 'mysql', 'traceback', 'fatal']),
            { suspiciousTokens: SUSPICIOUS_TOKENS },
        );
        expect(d.total).toBeGreaterThan(stats.anomalyThreshold);
        expect(d.unseenTokens.length).toBeGreaterThan(0);
    });
});

// ============================================================
// verdict.ts (full oracle pipeline)
// ============================================================

describe('evaluate', () => {
    it('rejects a candidate whose first response is in-manifold', async () => {
        const cluster = new BaselineCluster();
        const benignFeatures = {
            status: 200,
            length: 100,
            wordCount: 15,
            contentSimhash: '0000000000000000',
            responseTimeMs: 50,
            headerSetHash: 'h',
            contentType: 'text/html',
        };
        for (let i = 0; i < 5; i++) {
            cluster.addSample(
                { requestAt: '', variant: 'v', features: { ...benignFeatures } },
                'welcome home',
            );
        }
        const attackResp = {
            status: 200,
            headers: { 'content-type': 'text/html' },
            body: 'welcome home',
            responseTimeMs: 50,
        };
        const r = await evaluate({
            cluster,
            attack: async () => attackResp,
            benign: async () => attackResp,
        });
        expect(r.verdict?.anomalous).toBe(false);
    });

    it('confirms a payload that produces a consistently anomalous response', async () => {
        // Build a consistent baseline by running the same benign-probe shape
        // through buildBaseline(). Matches how the scanner will use the oracle
        // in production (extracted features must match the bodies they came from).
        const cluster = await buildBaseline({
            paramName: 'q',
            paramValue: 'hello',
            probe: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><h1>Welcome</h1><p>Your profile page is ready.</p></body></html>',
                responseTimeMs: 40 + Math.floor(Math.random() * 5),
            }),
            minSamples: 3,
        });
        expect(cluster).not.toBeNull();

        const attackBody =
            '<html><body><h1>Server Error</h1><pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near line 1</pre></body></html>';
        const benignBody = '<html><body><h1>Welcome</h1><p>Your profile page is ready.</p></body></html>';

        const r = await evaluate({
            cluster: cluster!,
            attack: async () => ({
                status: 500,
                headers: { 'content-type': 'text/html' },
                body: attackBody,
                responseTimeMs: 40,
            }),
            benign: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: benignBody,
                responseTimeMs: 40,
            }),
        });
        expect(r.verdict?.anomalous).toBe(true);
        expect(r.replays).toBeGreaterThanOrEqual(1);
        expect(r.counterFactualNormal).toBe(true);
        expect(r.verdict!.confidence).toBeGreaterThan(0.8);
    });

    it('does NOT confirm when counter-factual also looks anomalous (target drift)', async () => {
        const cluster = await buildBaseline({
            paramName: 'q',
            paramValue: 'home',
            probe: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><h1>Home</h1></body></html>',
                responseTimeMs: 30,
            }),
            minSamples: 3,
        });
        expect(cluster).not.toBeNull();

        const driftedBody =
            'Some completely new content that does not resemble the baseline at all — rewritten page';

        const r = await evaluate({
            cluster: cluster!,
            attack: async () => ({
                status: 500,
                headers: { 'content-type': 'text/html' },
                body: driftedBody + ' MySQL syntax error stack traceback fatal',
                responseTimeMs: 40,
            }),
            benign: async () => ({
                status: 500,
                headers: { 'content-type': 'text/html' },
                body: driftedBody,
                responseTimeMs: 40,
            }),
        });
        expect(r.counterFactualNormal).toBe(false);
        expect(r.verdict?.anomalous).toBe(false);
    });
});
