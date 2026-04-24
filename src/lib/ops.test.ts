import { describe, it, expect } from 'vitest';
import { checkTargetUrl } from './ssrf-guard';
import { encryptString, decryptString, sha256Hex } from './evidence-store';
import { parseCron, nextFire } from '@/worker/scheduler';

// ============================================================
// ssrf-guard
// ============================================================

describe('checkTargetUrl', () => {
    it('rejects loopback literal', async () => {
        const r = await checkTargetUrl('http://127.0.0.1:8080');
        expect(r.allowed).toBe(false);
        expect(r.reason).toMatch(/private/);
    });

    it('rejects AWS metadata IP', async () => {
        const r = await checkTargetUrl('http://169.254.169.254/latest/meta-data/');
        expect(r.allowed).toBe(false);
    });

    it('rejects RFC1918 literal', async () => {
        const r = await checkTargetUrl('http://10.0.0.5');
        expect(r.allowed).toBe(false);
    });

    it('rejects "localhost" hostname', async () => {
        const r = await checkTargetUrl('http://localhost:3000');
        expect(r.allowed).toBe(false);
    });

    it('permits a public-looking IP literal', async () => {
        const r = await checkTargetUrl('http://8.8.8.8');
        expect(r.allowed).toBe(true);
    });

    it('allows localhost when labOverride is set', async () => {
        const r = await checkTargetUrl('http://localhost:8081', { labOverride: true });
        expect(r.allowed).toBe(true);
    });

    it('rejects unsupported protocols', async () => {
        const r = await checkTargetUrl('ftp://example.com');
        expect(r.allowed).toBe(false);
        expect(r.reason).toMatch(/protocol/);
    });
});

// ============================================================
// evidence-store
// ============================================================

describe('AES-GCM encrypt / decrypt', () => {
    it('round-trips a string through encrypt/decrypt', () => {
        const plain = 'extracted password: hunter2';
        const bundle = encryptString(plain);
        expect(bundle).not.toContain(plain);
        expect(decryptString(bundle)).toBe(plain);
    });

    it('produces different ciphertext for the same plaintext (random IV)', () => {
        const a = encryptString('same');
        const b = encryptString('same');
        expect(a).not.toBe(b);
    });

    it('throws on tampered ciphertext', () => {
        const bundle = encryptString('sensitive');
        const parts = bundle.split('.');
        const tampered = [parts[0], 'AAAAAAAAAAAAAAAAAAAAAA==', parts[2]].join('.');
        expect(() => decryptString(tampered)).toThrow();
    });
});

describe('sha256Hex', () => {
    it('matches the canonical SHA-256 of "hello"', () => {
        expect(sha256Hex('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });
});

// ============================================================
// scheduler — cron parser
// ============================================================

describe('parseCron', () => {
    it('handles star fields', () => {
        const c = parseCron('* * * * *');
        expect(c.minutes.size).toBe(60);
        expect(c.hours.size).toBe(24);
    });

    it('handles step expressions', () => {
        const c = parseCron('*/15 * * * *');
        expect([...c.minutes].sort((a, b) => a - b)).toEqual([0, 15, 30, 45]);
    });

    it('handles comma-separated and ranges', () => {
        const c = parseCron('0 9-17 1,15 * 1-5');
        expect(c.hours).toEqual(new Set([9, 10, 11, 12, 13, 14, 15, 16, 17]));
        expect(c.days).toEqual(new Set([1, 15]));
        expect(c.weekdays).toEqual(new Set([1, 2, 3, 4, 5]));
    });

    it('rejects malformed expressions', () => {
        expect(() => parseCron('garbage')).toThrow();
    });
});

describe('nextFire', () => {
    it('finds the next exact minute', () => {
        const from = new Date('2026-04-24T10:00:00Z');
        const next = nextFire('*/15 * * * *', from);
        expect(next).not.toBeNull();
        expect(next!.getUTCMinutes() % 15).toBe(0);
        expect(next!.getTime()).toBeGreaterThan(from.getTime());
    });

    it('returns a future date for daily schedule', () => {
        const from = new Date('2026-04-24T10:00:00Z');
        const next = nextFire('0 2 * * *', from);
        expect(next).not.toBeNull();
        // Scheduler uses local time (what ops humans expect). Verify minutes=0
        // and that the time is strictly after `from`.
        expect(next!.getMinutes()).toBe(0);
        expect(next!.getHours()).toBe(2);
        expect(next!.getTime()).toBeGreaterThan(from.getTime());
    });
});
