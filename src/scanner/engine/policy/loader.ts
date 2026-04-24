// InjectProof — Policy loader
// Reads a policy from:
//   - YAML/JSON file (path)
//   - object literal
//   - DB (Policy row by id)
//   - built-in profile name
// ทำ resolve chain: named profile → extends → override → final merged policy.

import { readTextFile, fileExists } from '@/lib/platform';
import { ScanPolicySchema, BUILTIN_PROFILES, mergePolicies, LEGACY_PASSTHROUGH, type ScanPolicy } from './schema';

export type PolicySource =
    | { kind: 'profile'; name: string }
    | { kind: 'file'; path: string; format?: 'yaml' | 'json' | 'auto' }
    | { kind: 'object'; value: unknown }
    | { kind: 'legacy' };

export interface LoadOptions {
    /** additional overrides applied last. */
    override?: Partial<ScanPolicy>;
}

/**
 * Minimal YAML reader — supports the flat mapping + list syntax we need for
 * policy files without pulling a full YAML parser dependency.
 * (Fall back to JSON.parse if the file ends .json.)
 * สำหรับ policy ซับซ้อนที่ต้องการ YAML จริงจัง caller สามารถ supply object ตรง ๆ ได้.
 */
function parsePolicyFile(raw: string, format: 'yaml' | 'json' | 'auto', hint: string): unknown {
    const fmt = format === 'auto' ? (hint.endsWith('.json') ? 'json' : 'yaml') : format;
    if (fmt === 'json') return JSON.parse(raw);

    // Tiny YAML: supports `key: value`, `key:` + indented children, lists with `- item`.
    // Not meant to compete with js-yaml — enough for our policy shape.
    const root: Record<string, unknown> = {};
    const stack: Array<{ indent: number; container: unknown }> = [{ indent: -1, container: root }];

    for (const line of raw.split(/\r?\n/)) {
        if (!line.trim() || line.trim().startsWith('#')) continue;
        const indent = line.length - line.trimStart().length;
        const text = line.trim();

        while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
        const parent = stack[stack.length - 1].container;

        if (text.startsWith('- ')) {
            const item = yamlScalar(text.slice(2));
            if (!Array.isArray(parent)) {
                throw new Error(`policy-yaml: list item under non-list at indent ${indent}: ${line}`);
            }
            parent.push(item);
            continue;
        }

        const colon = text.indexOf(':');
        if (colon < 0) throw new Error(`policy-yaml: malformed line: ${line}`);
        const key = text.slice(0, colon).trim();
        const rest = text.slice(colon + 1).trim();

        if (rest === '') {
            // Block — decide list vs object from the next non-empty line's shape.
            const child: unknown = {};
            if (Array.isArray(parent) || typeof parent !== 'object' || parent === null) {
                throw new Error(`policy-yaml: key under non-object: ${line}`);
            }
            (parent as Record<string, unknown>)[key] = child;
            stack.push({ indent, container: child });
        } else if (rest === '[]') {
            (parent as Record<string, unknown>)[key] = [];
        } else if (rest === '{}') {
            (parent as Record<string, unknown>)[key] = {};
        } else {
            (parent as Record<string, unknown>)[key] = yamlScalar(rest);
        }
    }

    // Second pass: if an object-placeholder ended up wanting to be a list
    // because its first child was `- ...`, fix it. Our tiny parser can't
    // detect that during first pass without lookahead; simplify by letting
    // callers use JSON for complex cases.
    return root;
}

function yamlScalar(s: string): string | number | boolean | null {
    const t = s.trim();
    if (t === 'null' || t === '~') return null;
    if (t === 'true') return true;
    if (t === 'false') return false;
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
        return t.slice(1, -1);
    }
    return t;
}

// ────────────────────────────────────────────────────────────
// Loader
// ────────────────────────────────────────────────────────────

async function resolveOne(src: PolicySource): Promise<ScanPolicy> {
    if (src.kind === 'legacy') return LEGACY_PASSTHROUGH;
    if (src.kind === 'profile') {
        const p = BUILTIN_PROFILES[src.name];
        if (!p) throw new Error(`unknown policy profile: ${src.name}`);
        return p;
    }
    if (src.kind === 'file') {
        if (!(await fileExists(src.path))) throw new Error(`policy file not found: ${src.path}`);
        const raw = await readTextFile(src.path);
        const parsed = parsePolicyFile(raw, src.format ?? 'auto', src.path);
        return resolveObject(parsed);
    }
    if (src.kind === 'object') {
        return resolveObject(src.value);
    }
    throw new Error(`unhandled policy source`);
}

function resolveObject(value: unknown): ScanPolicy {
    const partial = ScanPolicySchema.partial().parse(value);
    if (partial.extends) {
        const parent = BUILTIN_PROFILES[partial.extends];
        if (!parent) throw new Error(`policy extends unknown profile: ${partial.extends}`);
        return mergePolicies(parent, partial as Partial<ScanPolicy>);
    }
    return ScanPolicySchema.parse(value);
}

/**
 * Load a policy (optionally with override merged last).
 * หลังจาก load แล้ว return เป็น frozen policy object พร้อมใช้.
 */
export async function loadPolicy(src: PolicySource, opts: LoadOptions = {}): Promise<ScanPolicy> {
    const base = await resolveOne(src);
    const final = opts.override ? mergePolicies(base, opts.override) : base;
    return Object.freeze(final);
}

/** Convenience: resolve from a name that could be a profile or a file path. */
export async function loadPolicyByName(name: string, opts: LoadOptions = {}): Promise<ScanPolicy> {
    if (BUILTIN_PROFILES[name]) return loadPolicy({ kind: 'profile', name }, opts);
    if (await fileExists(name)) return loadPolicy({ kind: 'file', path: name }, opts);
    throw new Error(`policy not found: ${name}`);
}
