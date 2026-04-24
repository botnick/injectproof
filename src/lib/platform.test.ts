import { describe, it, expect } from 'vitest';
import {
    pathJoin, pathResolve, expandHome, canonicalize, samePath,
    createScratchDir, removeDir, writeTextFile, readTextFile, fileExists,
    resolveCommand, env, envBool, envNumber, spawnBounded, IS_WINDOWS,
} from './platform';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

describe('platform paths', () => {
    it('pathJoin uses the current OS separator', () => {
        const out = pathJoin('a', 'b', 'c');
        expect(out).toBe(join('a', 'b', 'c'));
    });

    it('pathResolve returns absolute path', () => {
        expect(/^([A-Z]:\\|\/)/.test(pathResolve('a'))).toBe(true);
    });

    it('expandHome expands ~', () => {
        expect(expandHome('~/foo')).toBe(join(homedir(), 'foo'));
        expect(expandHome('~')).toBe(homedir());
        expect(expandHome('/tmp')).toBe('/tmp');
    });

    it('canonicalize resolves + expands + normalizes', () => {
        const out = canonicalize('~/a/../b');
        expect(out).toBe(join(homedir(), 'b'));
    });

    it('samePath is case-aware per OS', () => {
        const a = '/tmp/Foo';
        const b = '/tmp/foo';
        if (IS_WINDOWS) expect(samePath(a, b)).toBe(true);
        else expect(samePath(a, b)).toBe(false);
    });
});

describe('platform temp / fs', () => {
    it('createScratchDir creates a real subdir of tmpdir and fileExists reports true', async () => {
        const dir = await createScratchDir('injectproof-test-');
        expect(dir.startsWith(tmpdir())).toBe(true);
        expect(await fileExists(dir)).toBe(true);
        await removeDir(dir);
        expect(await fileExists(dir)).toBe(false);
    });

    it('writeTextFile + readTextFile round-trips with LF pinning', async () => {
        const dir = await createScratchDir('injectproof-rw-');
        const file = pathJoin(dir, 'a.txt');
        await writeTextFile(file, 'hello\r\nworld', { lineEnding: 'lf' });
        const out = await readTextFile(file);
        expect(out).toBe('hello\nworld');
        await removeDir(dir);
    });
});

describe('platform env helpers', () => {
    it('env returns defaultValue when unset', () => {
        delete process.env.__IP_TEST__;
        expect(env('__IP_TEST__', 'fallback')).toBe('fallback');
        process.env.__IP_TEST__ = 'present';
        expect(env('__IP_TEST__')).toBe('present');
        delete process.env.__IP_TEST__;
    });

    it('envBool accepts 1/true/yes/on', () => {
        for (const v of ['1', 'true', 'TRUE', 'yes', 'YES', 'on']) {
            process.env.__IP_BOOL__ = v;
            expect(envBool('__IP_BOOL__')).toBe(true);
        }
        for (const v of ['0', 'false', 'no', 'off']) {
            process.env.__IP_BOOL__ = v;
            expect(envBool('__IP_BOOL__')).toBe(false);
        }
        delete process.env.__IP_BOOL__;
    });

    it('envNumber falls back on parse failure', () => {
        process.env.__IP_N__ = 'not-a-number';
        expect(envNumber('__IP_N__', 42)).toBe(42);
        process.env.__IP_N__ = '17';
        expect(envNumber('__IP_N__', 0)).toBe(17);
        delete process.env.__IP_N__;
    });
});

describe('resolveCommand', () => {
    it('returns shim name on Windows else plain name', () => {
        const out = resolveCommand('npx');
        if (IS_WINDOWS) expect(out).toBe('npx.cmd');
        else expect(out).toBe('npx');
    });
});

describe('spawnBounded', () => {
    it('captures stdout from a simple node one-liner', async () => {
        const res = await spawnBounded('node', ['-e', 'process.stdout.write("ok")'], { timeoutMs: 10_000 });
        expect(res.code).toBe(0);
        expect(res.stdout).toBe('ok');
    }, 15_000);

    it('rejects when the child exceeds timeout', async () => {
        await expect(
            spawnBounded('node', ['-e', 'setTimeout(()=>{},30000)'], { timeoutMs: 200 }),
        ).rejects.toThrow(/exceeded/);
    }, 10_000);
});
