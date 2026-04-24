import { describe, it, expect } from 'vitest';
import { classifyChallenge } from './challenge-detect';
import { CircuitBreaker } from './circuit-breaker';
import { recover } from './recover-403';
import { rotateUa, pickUa, DESKTOP_UA_POOL } from './ua-pool';

describe('classifyChallenge', () => {
    it('200 is ok', () => {
        expect(classifyChallenge({ status: 200, headers: {} }).class).toBe('ok');
    });
    it('403 with cf-ray → cloudflare', () => {
        const v = classifyChallenge({ status: 403, headers: { 'cf-ray': 'abc' } });
        expect(v.class).toBe('403-cloudflare');
        expect(v.vendor).toBe('Cloudflare');
    });
    it('403 with cf_chl_def body → cloudflare-challenge', () => {
        const v = classifyChallenge({
            status: 403,
            headers: { server: 'cloudflare' },
            bodyPreview: 'window.cf_chl_def = ...',
        });
        expect(v.class).toBe('403-cloudflare-challenge');
    });
    it('403 with AkamaiGHost server', () => {
        const v = classifyChallenge({
            status: 403,
            headers: { server: 'AkamaiGHost', 'x-akamai-transformed': 'yes' },
        });
        expect(v.class).toBe('403-waf-akamai');
    });
    it('403 with x-amzn-requestid and Awselb → aws waf', () => {
        const v = classifyChallenge({
            status: 403,
            headers: { 'x-amzn-requestid': 'r', server: 'AwseLB' },
            bodyPreview: '<title>ERROR</title>',
        });
        expect(v.class).toBe('403-waf-aws');
    });
    it('403 with x-iinfo → imperva', () => {
        const v = classifyChallenge({
            status: 403,
            headers: { 'x-iinfo': 'a', server: 'incapsula' },
            bodyPreview: 'Request unsuccessful. Incident ID: 123',
        });
        expect(v.class).toBe('403-waf-imperva');
    });
    it('429 with retry-after', () => {
        const v = classifyChallenge({ status: 429, headers: { 'retry-after': '30' } });
        expect(v.class).toBe('429');
        expect(v.suggestedWaitMs).toBe(30_000);
    });
    it('503 with retry-after', () => {
        const v = classifyChallenge({ status: 503, headers: { 'retry-after': '5' } });
        expect(v.class).toBe('503-unavailable');
    });
    it('401 unauth', () => {
        expect(classifyChallenge({ status: 401, headers: {} }).class).toBe('401');
    });
    it('captcha keyword in body', () => {
        expect(classifyChallenge({
            status: 403, headers: {}, bodyPreview: '<p>please solve the captcha</p>',
        }).class).toBe('captcha');
    });
    it('unknown 418 → generic', () => {
        expect(classifyChallenge({ status: 418, headers: {} }).class).toBe('403-waf-generic');
    });
});

describe('CircuitBreaker', () => {
    it('opens after fail threshold and blocks further requests', () => {
        let t = 0;
        const b = new CircuitBreaker({ failThreshold: 3, cooldownMs: 1_000, now: () => t });
        for (let i = 0; i < 3; i++) {
            expect(b.allow('h')).toBe(true);
            b.record('h', 'fail');
        }
        expect(b.allow('h')).toBe(false);
    });

    it('half-open admits one probe after cooldown', () => {
        let t = 0;
        const b = new CircuitBreaker({ failThreshold: 2, cooldownMs: 1_000, now: () => t });
        b.record('h', 'fail'); b.record('h', 'fail');
        expect(b.allow('h')).toBe(false);
        t = 1_500;
        expect(b.allow('h')).toBe(true); // half-open
        b.record('h', 'success');
        expect(b.snapshot('h').state).toBe('closed');
    });

    it('half-open fail reopens', () => {
        let t = 0;
        const b = new CircuitBreaker({ failThreshold: 2, cooldownMs: 1_000, now: () => t });
        b.record('h', 'fail'); b.record('h', 'fail');
        t = 1_500;
        b.allow('h'); // transition to half-open
        b.record('h', 'fail');
        expect(b.snapshot('h').state).toBe('open');
    });
});

describe('rotateUa + pickUa', () => {
    it('rotates through the pool and wraps around', () => {
        const { ua, nextIndex } = rotateUa(-1);
        expect(ua).toBe(DESKTOP_UA_POOL[0].ua);
        const end = rotateUa(DESKTOP_UA_POOL.length - 1);
        expect(end.nextIndex).toBe(0);
    });
    it('pickUa is deterministic', () => {
        expect(pickUa(0).label).toBe(DESKTOP_UA_POOL[0].label);
    });
});

describe('recover driver', () => {
    it('short-circuits when host breaker is already open', async () => {
        const breaker = new CircuitBreaker({ failThreshold: 1 });
        breaker.record('h', 'fail');
        const res = await recover({
            verdict: { class: '403-cloudflare', signals: [], retryable: true, suggestedWaitMs: 0 },
            host: 'h',
            retry: async () => ({ status: 200, headers: {} }),
            breaker,
        });
        expect(res.recovered).toBe(false);
        expect(res.circuitOpen).toBe(true);
    });

    it('returns recovered when first step succeeds', async () => {
        const breaker = new CircuitBreaker();
        const res = await recover({
            verdict: { class: '403-cloudflare', signals: [], retryable: true, suggestedWaitMs: 0 },
            host: 'h',
            retry: async () => ({ status: 200, headers: {} }),
            breaker,
            sleep: async () => undefined,
        });
        expect(res.recovered).toBe(true);
        expect(res.stepsUsed.length).toBe(1);
    });

    it('walks all 6 active steps when each fails, then abandons', async () => {
        const breaker = new CircuitBreaker({ failThreshold: 99 });
        const res = await recover({
            verdict: { class: '403-waf-generic', signals: [], retryable: true, suggestedWaitMs: 0 },
            host: 'h',
            retry: async () => ({ status: 403, headers: {} }),
            budget: { maxRetries: 10, maxTotalWaitMs: 10_000, maxWallMs: 60_000 },
            breaker,
            sleep: async () => undefined,
        });
        expect(res.recovered).toBe(false);
        expect(res.stepsUsed).toContain('abandon');
    });

    it('stops early on retries budget exhausted', async () => {
        const breaker = new CircuitBreaker({ failThreshold: 99 });
        const res = await recover({
            verdict: { class: '403-waf-generic', signals: [], retryable: true, suggestedWaitMs: 0 },
            host: 'h',
            retry: async () => ({ status: 403, headers: {} }),
            budget: { maxRetries: 2, maxTotalWaitMs: 10_000, maxWallMs: 60_000 },
            breaker,
            sleep: async () => undefined,
        });
        expect(res.budgetExhausted).toBe(true);
    });

    it('emits onEvent for each attempt', async () => {
        const events: string[] = [];
        await recover({
            verdict: { class: '403-waf-generic', signals: [], retryable: true, suggestedWaitMs: 0 },
            host: 'h',
            retry: async () => ({ status: 200, headers: {} }),
            onEvent: (a) => events.push(a.step),
            breaker: new CircuitBreaker(),
            sleep: async () => undefined,
        });
        expect(events.length).toBeGreaterThanOrEqual(1);
    });
});
