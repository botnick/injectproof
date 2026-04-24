import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { config, resetConfig, renderEnvHelp } from './config';

const SNAPSHOT = { ...process.env };

beforeEach(() => resetConfig());
afterEach(() => {
    // Restore env between tests — different tests stamp different values.
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, SNAPSHOT);
    resetConfig();
});

describe('config()', () => {
    it('throws when JWT_SECRET is missing, without echoing the value', () => {
        delete process.env.JWT_SECRET;
        process.env.DATABASE_URL = 'file:./x.db';
        expect(() => config()).toThrow(/JWT_SECRET/);
    });

    it('throws when JWT_SECRET is too short, and message does not contain the value', () => {
        process.env.JWT_SECRET = 'tooshort';
        process.env.DATABASE_URL = 'file:./x.db';
        try {
            config();
            throw new Error('should have thrown');
        } catch (e) {
            const msg = (e as Error).message;
            expect(msg).not.toContain('tooshort');
            expect(msg).toMatch(/JWT_SECRET/);
        }
    });

    it('returns typed object when env is valid', () => {
        process.env.JWT_SECRET = 'x'.repeat(48);
        process.env.DATABASE_URL = 'file:./x.db';
        process.env.SCANNER_MAX_CONCURRENT = '4';
        process.env.SCANNER_FSM = 'true';
        const c = config();
        expect(c.SCANNER_MAX_CONCURRENT).toBe(4);
        expect(c.SCANNER_FSM).toBe(true);
        expect(c.NEXT_PUBLIC_APP_NAME).toBe('InjectProof'); // default
    });

    it('returns cached object on subsequent calls without re-reading env', () => {
        process.env.JWT_SECRET = 'x'.repeat(48);
        process.env.DATABASE_URL = 'file:./x.db';
        const a = config();
        process.env.SCANNER_MAX_CONCURRENT = '99';
        const b = config();
        expect(b).toBe(a);
    });

    it('resetConfig re-reads on next call', () => {
        process.env.JWT_SECRET = 'x'.repeat(48);
        process.env.DATABASE_URL = 'file:./x.db';
        process.env.SCANNER_MAX_CONCURRENT = '1';
        expect(config().SCANNER_MAX_CONCURRENT).toBe(1);
        process.env.SCANNER_MAX_CONCURRENT = '8';
        resetConfig();
        expect(config().SCANNER_MAX_CONCURRENT).toBe(8);
    });
});

describe('renderEnvHelp', () => {
    it('contains Thai description when lang=th', () => {
        const out = renderEnvHelp('th');
        expect(out).toContain('JWT_SECRET');
        expect(out).toMatch(/กุญแจ/);
    });
    it('contains English description when lang=en', () => {
        const out = renderEnvHelp('en');
        expect(out).toContain('JWT signing secret');
    });
});
