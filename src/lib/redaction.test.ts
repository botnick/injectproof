import { describe, it, expect } from 'vitest';
import {
    redactHeaderValue, redactHeaders, redactUrl,
    redactText, redactJson, redactBody, isRedacted,
} from './redaction';

describe('redactHeaderValue', () => {
    it('does not echo the Authorization value', () => {
        const out = redactHeaderValue('Authorization', 'Bearer CANARY123');
        expect(out).not.toContain('CANARY123');
        expect(out).toMatch(/REDACTED/);
    });
    it('redacts Cookie header', () => {
        const out = redactHeaderValue('Cookie', 'session=XYZ; theme=dark');
        expect(out).not.toContain('XYZ');
    });
    it('redacts X-API-Key', () => {
        expect(redactHeaderValue('X-API-Key', 'sk_live_abc')).toMatch(/REDACTED/);
    });
});

describe('redactHeaders', () => {
    it('is case-insensitive and redacts sensitive names', () => {
        const out = redactHeaders({
            AUTHORIZATION: 'Bearer A',
            'set-cookie': 'a=b',
            Accept: 'application/json',
        });
        expect(out.AUTHORIZATION).not.toContain('Bearer A');
        expect(out['set-cookie']).not.toContain('a=b');
        expect(out.Accept).toBe('application/json');
    });
});

describe('redactUrl', () => {
    it('strips userinfo', () => {
        const out = redactUrl('http://alice:pw@host.example/p?q=1');
        // The marker URL-encodes as %5BREDACTED%3Auserinfo%5D, which may
        // contain the substring "user"; assert on the literal username+password
        // pair instead.
        expect(out).not.toContain('alice:pw');
        expect(out).not.toContain('alice@');
        expect(out).toContain('host.example');
        expect(out).toMatch(/REDACTED/);
    });
    it('redacts sensitive query params', () => {
        const out = redactUrl('http://x/path?token=abc&name=ok&api_key=q');
        expect(out).not.toContain('abc');
        expect(out).not.toMatch(/api_key=q(?!\w)/);
        expect(out).toContain('name=ok');
    });
    it('returns safe text on non-URL input', () => {
        expect(redactUrl('not a url')).toBe('not a url');
    });
});

describe('redactText', () => {
    it('redacts JWT', () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.Abcdefghij_signature_blob';
        const out = redactText(`token=${jwt}`);
        expect(out).not.toContain(jwt);
    });
    it('redacts AWS access key id', () => {
        const out = redactText('AKIAABCDEFGHIJKLMNOP');
        expect(out).not.toContain('AKIAABCDEFGHIJKLMNOP');
    });
    it('redacts GitHub PAT', () => {
        const out = redactText('ghp_1234567890abcdefABCDEF1234567890abcdefAB');
        expect(out).not.toContain('ghp_');
    });
    it('redacts slack token', () => {
        const out = redactText('xoxb-111-222-333-abcdefghijklmnopqrstuvwx');
        expect(out).not.toContain('xoxb-111');
    });
    it('redacts PEM blocks', () => {
        const out = redactText('-----BEGIN PRIVATE KEY-----\nABCDEFG\n-----END PRIVATE KEY-----');
        expect(out).toMatch(/REDACTED/);
        expect(out).not.toContain('ABCDEFG');
    });
    it('redacts basic-auth URL inside prose', () => {
        const out = redactText('see http://u:p@host/path');
        expect(out).not.toContain('u:p');
    });
});

describe('redactJson', () => {
    it('redacts sensitive keys recursively', () => {
        const out = redactJson({ name: 'alice', token: 'x', nested: { password: 'p' }, arr: [{ secret: 'z' }] });
        const s = JSON.stringify(out);
        expect(s).toContain('alice');
        expect(s).not.toContain('"x"');
        expect(s).not.toContain('"p"');
        expect(s).not.toContain('"z"');
    });
});

describe('redactBody', () => {
    it('handles JSON body', () => {
        const out = redactBody('{"password":"p","name":"alice"}', 'application/json');
        expect(out).toContain('alice');
        expect(out).not.toContain('"p"');
    });
    it('handles form-encoded body', () => {
        const out = redactBody('password=hunter2&q=hi', 'application/x-www-form-urlencoded');
        expect(out).not.toContain('hunter2');
        expect(out).toContain('q=hi');
    });
    it('falls through to text redaction for unknown content type', () => {
        const out = redactBody('AKIAABCDEFGHIJKLMNOP is here');
        expect(out).not.toContain('AKIAABCDEFGHIJKLMNOP');
    });
});

describe('isRedacted', () => {
    it('detects the marker', () => {
        expect(isRedacted('hello [REDACTED:authorization]')).toBe(true);
        expect(isRedacted('hello world')).toBe(false);
    });
});
