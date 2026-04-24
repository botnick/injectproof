#!/usr/bin/env node
/**
 * InjectProof — cross-platform env sanity check.
 * Reads `.env.example`, collects required (uncommented `KEY=`) entries,
 * and verifies `process.env` has a value for each. Exits 1 with a bilingual
 * (TH + EN) message on miss.
 *
 * Runs on Windows + Linux + macOS with plain Node 20 (no bash-isms).
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = typeof __dirname !== 'undefined' ? __dirname : dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const EXAMPLE = resolve(ROOT, '.env.example');

if (!existsSync(EXAMPLE)) {
    console.log('[envcheck] no .env.example present — skipping');
    process.exit(0);
}

const REQUIRED_PREFIXES = new Set([
    'DATABASE_URL',
    'JWT_SECRET',
    'EVIDENCE_KEY',
    'NEXT_PUBLIC_APP_NAME',
    'NEXT_PUBLIC_APP_URL',
]);

const text = readFileSync(EXAMPLE, 'utf-8');
const missing = [];
for (const line of text.split(/\r?\n/)) {
    const m = /^([A-Z_][A-Z0-9_]*)\s*=/.exec(line.trim());
    if (!m) continue;
    const key = m[1];
    if (!REQUIRED_PREFIXES.has(key)) continue;
    const val = process.env[key];
    if (val === undefined || val === '') missing.push(key);
}

if (missing.length > 0) {
    console.error('[envcheck] missing required env vars:');
    for (const k of missing) {
        console.error(`  - ${k}`);
    }
    console.error('');
    console.error('Fix / วิธีแก้:');
    console.error('  1. Copy .env.example to .env');
    console.error('  2. Set real values for the keys above.');
    console.error('  3. คัดลอก .env.example เป็น .env แล้วใส่ค่าจริง');
    process.exit(1);
}
console.log('[envcheck] all required env vars set');
