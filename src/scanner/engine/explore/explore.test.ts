import { describe, it, expect } from 'vitest';
import { MarkovUrlModel, segmentsOf } from './markov';
import { FrontierQueue, score, type ObservationState } from './frontier';

// ============================================================
// markov.ts
// ============================================================

describe('segmentsOf', () => {
    it('drops empty segments and strips query/fragment', () => {
        expect(segmentsOf('/a/b/c?q=1#foo')).toEqual(['a', 'b', 'c']);
    });
});

describe('MarkovUrlModel', () => {
    it('tracks segments and distinct paths', () => {
        const m = new MarkovUrlModel();
        m.observe('http://x/admin');
        m.observe('http://x/admin/users');
        m.observe('http://x/admin/users'); // duplicate
        const s = m.stats();
        expect(s.distinctPaths).toBe(2);
        expect(s.segments).toBe(3);
    });

    it('falls back to seed corpus when model is empty', () => {
        const m = new MarkovUrlModel();
        const candidates = m.generateCandidates(20);
        expect(candidates).toContain('/admin');
        expect(candidates).toContain('/api');
    });

    it('generates plausible paths after observing a few examples', () => {
        const m = new MarkovUrlModel();
        for (const url of [
            'http://x/admin',
            'http://x/admin/users',
            'http://x/admin/settings',
            'http://x/api/v1/users',
            'http://x/api/v1/orders',
            'http://x/api/v2/products',
        ]) {
            m.observe(url);
        }
        const candidates = m.generateCandidates(30, false);
        // Model should at least propose some new paths
        expect(candidates.length).toBeGreaterThan(0);
    });
});

// ============================================================
// frontier.ts
// ============================================================

const emptyState = (): ObservationState => ({
    visited: new Set<string>(),
    formBearing: new Set<string>(),
    findingUrls: new Set<string>(),
    avgLatencyMs: 100,
});

describe('score', () => {
    it('returns high novelty when queue has not seen similar URLs', () => {
        const state = emptyState();
        const s = score(
            { url: 'http://x/fresh-path', method: 'GET', source: 'link', depth: 0 },
            state,
        );
        expect(s.components.novelty).toBe(1);
    });

    it('penalizes URLs sharing segments with already-visited ones', () => {
        const state = emptyState();
        state.visited.add('http://x/admin/users');
        const s1 = score(
            { url: 'http://x/admin/users', method: 'GET', source: 'link', depth: 0 },
            state,
        );
        const s2 = score(
            { url: 'http://x/other/totally-different', method: 'GET', source: 'link', depth: 0 },
            state,
        );
        expect(s1.components.novelty).toBeLessThan(s2.components.novelty);
    });

    it('adds a risk-distance bump when a URL shares segments with a finding', () => {
        const state = emptyState();
        state.findingUrls.add('http://x/admin/users');
        const near = score(
            { url: 'http://x/admin/posts', method: 'GET', source: 'link', depth: 0 },
            state,
        );
        const far = score(
            { url: 'http://x/about', method: 'GET', source: 'link', depth: 0 },
            state,
        );
        expect(near.components.risk).toBeGreaterThanOrEqual(far.components.risk);
    });

    it('form-sourced URLs score higher in coverage than link-sourced ones', () => {
        const state = emptyState();
        const form = score({ url: 'http://x/p', method: 'POST', source: 'form', depth: 0 }, state);
        const link = score({ url: 'http://x/p', method: 'GET', source: 'link', depth: 0 }, state);
        expect(form.components.coverage).toBeGreaterThan(link.components.coverage);
    });
});

describe('FrontierQueue', () => {
    it('dequeues the highest EIG item', () => {
        const state = emptyState();
        const q = new FrontierQueue(state);
        q.enqueue({ url: 'http://x/plain', method: 'GET', source: 'link', depth: 3 });
        q.enqueue({ url: 'http://x/admin', method: 'GET', source: 'form', depth: 0 });
        const first = q.dequeue();
        expect(first?.url).toBe('http://x/admin');
    });

    it('deduplicates the same (method, url) pair', () => {
        const q = new FrontierQueue(emptyState());
        expect(q.enqueue({ url: 'http://x/a', method: 'GET', source: 'link', depth: 0 })).toBe(true);
        expect(q.enqueue({ url: 'http://x/a', method: 'GET', source: 'link', depth: 0 })).toBe(false);
        expect(q.size()).toBe(1);
    });
});
