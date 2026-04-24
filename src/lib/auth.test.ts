import { describe, it, expect } from 'vitest';
import {
    createToken,
    verifyToken,
    hashPassword,
    comparePassword,
    extractToken,
    hasRole,
    hasPermission,
} from './auth';

describe('auth — JWT round-trip', () => {
    it('signs and verifies a token with the same payload', async () => {
        const token = await createToken({
            userId: 'u1',
            email: 'a@b.c',
            role: 'pentester',
            name: 'Alice',
        });
        const decoded = await verifyToken(token);
        expect(decoded).not.toBeNull();
        expect(decoded?.userId).toBe('u1');
        expect(decoded?.email).toBe('a@b.c');
        expect(decoded?.role).toBe('pentester');
    });

    it('returns null on a tampered token', async () => {
        const token = await createToken({
            userId: 'u1',
            email: 'a@b.c',
            role: 'viewer',
            name: 'Alice',
        });
        const tampered = token.slice(0, -2) + (token.endsWith('aa') ? 'bb' : 'aa');
        expect(await verifyToken(tampered)).toBeNull();
    });

    it('returns null on a completely fake token', async () => {
        expect(await verifyToken('nope.nope.nope')).toBeNull();
    });
});

describe('auth — password hashing', () => {
    it('hashes then verifies the same password', async () => {
        const hash = await hashPassword('correct horse battery staple');
        expect(await comparePassword('correct horse battery staple', hash)).toBe(true);
    });

    it('rejects a different password against the same hash', async () => {
        const hash = await hashPassword('p1');
        expect(await comparePassword('p2', hash)).toBe(false);
    });

    it('produces distinct hashes for the same input (salted)', async () => {
        const h1 = await hashPassword('same');
        const h2 = await hashPassword('same');
        expect(h1).not.toBe(h2);
    });
});

describe('auth — token extraction', () => {
    it('extracts from Bearer header when present', () => {
        expect(extractToken(undefined, 'Bearer abc.def.ghi')).toBe('abc.def.ghi');
    });

    it('prefers Bearer header over cookie', () => {
        expect(
            extractToken('injectproof_token=cookieval', 'Bearer headerval'),
        ).toBe('headerval');
    });

    it('falls back to the named cookie', () => {
        expect(extractToken('injectproof_token=cval; other=x')).toBe('cval');
    });

    it('returns null when neither present', () => {
        expect(extractToken()).toBeNull();
    });

    it('returns null for a cookie header without the expected name', () => {
        expect(extractToken('sessionid=x; other=y')).toBeNull();
    });
});

describe('auth — role hierarchy', () => {
    it.each([
        ['admin', 'viewer', true],
        ['admin', 'admin', true],
        ['security_lead', 'pentester', true],
        ['pentester', 'security_lead', false],
        ['viewer', 'developer', false],
        ['developer', 'viewer', true],
        ['unknown-role', 'viewer', false],
        ['admin', 'unknown-role', false],
    ])('hasRole(%s, %s) === %s', (user, required, expected) => {
        expect(hasRole(user, required)).toBe(expected);
    });
});

describe('auth — permissions', () => {
    it('admin has every permission via wildcard', () => {
        expect(hasPermission('admin', 'manage_users')).toBe(true);
        expect(hasPermission('admin', 'any_random_thing')).toBe(true);
    });

    it('pentester can run scans but not manage users', () => {
        expect(hasPermission('pentester', 'run_scans')).toBe(true);
        expect(hasPermission('pentester', 'manage_users')).toBe(false);
    });

    it('viewer cannot run scans', () => {
        expect(hasPermission('viewer', 'run_scans')).toBe(false);
    });
});
