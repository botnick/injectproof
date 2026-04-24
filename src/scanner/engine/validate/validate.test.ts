import { describe, it, expect } from 'vitest';
import { validateFinding, isolateOverlappingFindings } from './pipeline';
import { buildBaseline } from '../oracle/baseline';

describe('validateFinding pipeline', () => {
    it('confirms a payload that persistently triggers an anomaly', async () => {
        const cluster = await buildBaseline({
            paramName: 'q',
            paramValue: 'hello',
            probe: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><h1>Home</h1><p>Welcome back</p></body></html>',
                responseTimeMs: 30,
            }),
        });
        expect(cluster).not.toBeNull();

        const r = await validateFinding({
            cluster: cluster!,
            attack: async () => ({
                status: 500,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><pre>MySQL error syntax fatal stack traceback near line 1</pre></body></html>',
                responseTimeMs: 40,
            }),
            benign: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body><h1>Home</h1><p>Welcome back</p></body></html>',
                responseTimeMs: 30,
            }),
            skipTimePersistence: true,
        });
        expect(r.level).toBe('confirmed');
        expect(r.provenance.oraclesUsed).toContain('baseline');
    });

    it('rejects when replay probe returns in-manifold', async () => {
        const cluster = await buildBaseline({
            paramName: 'q',
            paramValue: 'home',
            probe: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body>Home</body></html>',
                responseTimeMs: 30,
            }),
        });
        expect(cluster).not.toBeNull();
        const r = await validateFinding({
            cluster: cluster!,
            attack: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body>Home</body></html>',
                responseTimeMs: 30,
            }),
            benign: async () => ({
                status: 200,
                headers: { 'content-type': 'text/html' },
                body: '<html><body>Home</body></html>',
                responseTimeMs: 30,
            }),
            skipTimePersistence: true,
        });
        expect(r.level).toBe('rejected');
    });
});

describe('isolateOverlappingFindings', () => {
    it('keeps only the highest-distance finding for duplicates', () => {
        const result = isolateOverlappingFindings([
            { id: 'f1', url: 'http://x/q', parameter: 'id', category: 'sqli', confidence: 0.8, distance: 5 },
            { id: 'f2', url: 'http://x/q', parameter: 'id', category: 'sqli', confidence: 0.9, distance: 9 },
            { id: 'f3', url: 'http://x/r', parameter: 'name', category: 'xss', confidence: 0.7, distance: 4 },
        ]);
        expect(result.keep.map((f) => f.id).sort()).toEqual(['f2', 'f3']);
        expect(result.suppress).toHaveLength(1);
        expect(result.suppress[0].supersededBy).toBe('f2');
    });

    it('keeps all findings when none overlap', () => {
        const result = isolateOverlappingFindings([
            { id: 'f1', url: 'http://x/a', category: 'sqli', confidence: 1, distance: 5 },
            { id: 'f2', url: 'http://x/b', category: 'xss', confidence: 1, distance: 5 },
        ]);
        expect(result.keep).toHaveLength(2);
        expect(result.suppress).toHaveLength(0);
    });
});
