// InjectProof — Centralized config reader with zod validation
// ปกติ code อ่าน `process.env.X` กระจายทั่วไฟล์ ทำให้ตรวจยากว่า env var ตัว
// ไหนหายไป หรือ value ผิด format. ไฟล์นี้รวบ env ทั้งหมดของระบบเข้ามาใน
// object เดียว พร้อม schema + default + human description (EN + TH).
//
// Rule:
//  - ทุก key ที่ระบบใช้ ต้องมี entry ใน `ENV_SCHEMA`
//  - ทุกโมดูลอ่าน env ผ่าน `config()` ไม่ได้อ่าน `process.env` ตรง ๆ (ยกเว้น
//    `lib/platform.ts` ที่เป็น bedrock + `lib/auth.ts` ที่ bootstrap ก่อน
//    config layer)
//  - missing required key = throw at first call to config() with an actionable
//    message listing the key + description
//
// หมายเหตุ: ไม่ print value ออกมาใน error — กัน secret leak เวลา log.

import { z, type ZodTypeAny } from 'zod';
import { redactText } from './redaction';

// ────────────────────────────────────────────────────────────
// Schema
// ────────────────────────────────────────────────────────────

interface EntryMeta {
    description: string;
    descriptionTh: string;
    required?: boolean;
    secret?: boolean;
    default?: unknown;
    schema: ZodTypeAny;
}

const ENV_SCHEMA: Record<string, EntryMeta> = {
    DATABASE_URL: {
        description: 'Prisma datasource URL (SQLite path or Postgres URL).',
        descriptionTh: 'URL สำหรับ Prisma (ไฟล์ SQLite หรือ Postgres).',
        required: true,
        schema: z.string().min(1),
    },
    JWT_SECRET: {
        description: 'JWT signing secret. Must be ≥ 32 bytes.',
        descriptionTh: 'กุญแจเซ็น JWT ต้องมีความยาวอย่างน้อย 32 bytes.',
        required: true,
        secret: true,
        schema: z.string().min(32),
    },
    EVIDENCE_KEY: {
        description: '32-byte base64 AES-256 key for encrypted evidence at rest.',
        descriptionTh: 'กุญแจ AES-256 (32 bytes base64) สำหรับเข้ารหัส evidence.',
        required: false,
        secret: true,
        schema: z.string().refine(
            (s) => {
                try {
                    return Buffer.from(s, 'base64').length === 32;
                } catch {
                    return false;
                }
            },
            { message: 'must base64-decode to exactly 32 bytes' },
        ),
    },
    EVIDENCE_DIR: {
        description: 'Directory for on-disk evidence artifacts. Cross-platform path.',
        descriptionTh: 'โฟลเดอร์เก็บ evidence บนดิสก์ (รองรับทั้ง Win/Linux).',
        default: './evidence',
        schema: z.string(),
    },
    NEXT_PUBLIC_APP_NAME: {
        description: 'Display name shown in the UI.',
        descriptionTh: 'ชื่อที่แสดงใน UI.',
        default: 'InjectProof',
        schema: z.string(),
    },
    NEXT_PUBLIC_APP_URL: {
        description: 'Canonical app URL (for SSE + redirects).',
        descriptionTh: 'URL หลักของแอป (ใช้กับ SSE + redirect).',
        default: 'http://localhost:3000',
        schema: z.string().url(),
    },
    SCANNER_USER_AGENT: {
        description: 'HTTP User-Agent used by scanner probes.',
        descriptionTh: 'User-Agent ของ probe.',
        default: 'InjectProof-Scanner/1.0',
        schema: z.string(),
    },
    SCANNER_MAX_CONCURRENT: {
        description: 'Max concurrent scans per worker pool.',
        descriptionTh: 'จำนวน scan สูงสุดที่รันพร้อมกันต่อ worker pool.',
        default: 2,
        schema: z.coerce.number().int().min(1).max(64),
    },
    SCANNER_REQUEST_TIMEOUT: {
        description: 'Per-probe HTTP timeout in ms.',
        descriptionTh: 'timeout ของ probe (ms).',
        default: 30_000,
        schema: z.coerce.number().int().min(1_000).max(600_000),
    },
    SCANNER_MAX_CRAWL_DEPTH: {
        description: 'Default crawl depth cap.',
        descriptionTh: 'ความลึก crawl เริ่มต้น.',
        default: 10,
        schema: z.coerce.number().int().min(1).max(100),
    },
    SCANNER_MAX_URLS: {
        description: 'Default URL cap per scan.',
        descriptionTh: 'จำนวน URL สูงสุดต่อ scan.',
        default: 500,
        schema: z.coerce.number().int().min(1).max(100_000),
    },
    SCANNER_FSM: {
        description: 'Feature flag: enable formal FSM scan lifecycle.',
        descriptionTh: 'เปิดใช้ FSM สำหรับ scan lifecycle.',
        default: false,
        schema: z.coerce.boolean(),
    },
    SCANNER_KILL_SWITCH: {
        description: 'Feature flag: enable global kill switch checks in request pipeline.',
        descriptionTh: 'เปิดใช้ kill switch ใน request pipeline.',
        default: true,
        schema: z.coerce.boolean(),
    },
    SCANNER_RECOVERY: {
        description: 'Feature flag: enable 403/WAF/Cloudflare recovery engine.',
        descriptionTh: 'เปิดใช้ระบบฟื้นตัวจาก 403/WAF/Cloudflare.',
        default: true,
        schema: z.coerce.boolean(),
    },
    SCANNER_BUDGET: {
        description: 'Feature flag: enforce per-scan request budget.',
        descriptionTh: 'เปิดใช้ budget controller ของ scan.',
        default: true,
        schema: z.coerce.boolean(),
    },
    ENABLE_TENANTS: {
        description: 'Feature flag: multi-tenancy enforcement in tRPC.',
        descriptionTh: 'เปิดใช้ multi-tenancy ในระดับ tRPC.',
        default: false,
        schema: z.coerce.boolean(),
    },
    SCHEDULER_ENABLED: {
        description: 'Boot the cron scheduler on start.',
        descriptionTh: 'เปิดตัว cron scheduler ตอน boot.',
        default: false,
        schema: z.coerce.boolean(),
    },
    EASM_DEBUG: {
        description: 'EASM probe debug logging.',
        descriptionTh: 'log การ probe ของ EASM แบบ debug.',
        default: false,
        schema: z.coerce.boolean(),
    },
    NODE_ENV: {
        description: 'Node environment.',
        descriptionTh: 'สภาพแวดล้อม node.',
        default: 'development',
        schema: z.enum(['development', 'test', 'production']),
    },
    OTEL_EXPORTER_OTLP_ENDPOINT: {
        description: 'OpenTelemetry OTLP endpoint. When set, enables traces + metrics.',
        descriptionTh: 'endpoint ของ OpenTelemetry OTLP (ถ้าตั้ง ระบบจะส่ง trace/metrics).',
        default: undefined,
        schema: z.string().url().optional(),
    },
};

// ────────────────────────────────────────────────────────────
// Config object
// ────────────────────────────────────────────────────────────

export type ConfigShape = {
    DATABASE_URL: string;
    JWT_SECRET: string;
    EVIDENCE_KEY?: string;
    EVIDENCE_DIR: string;
    NEXT_PUBLIC_APP_NAME: string;
    NEXT_PUBLIC_APP_URL: string;
    SCANNER_USER_AGENT: string;
    SCANNER_MAX_CONCURRENT: number;
    SCANNER_REQUEST_TIMEOUT: number;
    SCANNER_MAX_CRAWL_DEPTH: number;
    SCANNER_MAX_URLS: number;
    SCANNER_FSM: boolean;
    SCANNER_KILL_SWITCH: boolean;
    SCANNER_RECOVERY: boolean;
    SCANNER_BUDGET: boolean;
    ENABLE_TENANTS: boolean;
    SCHEDULER_ENABLED: boolean;
    EASM_DEBUG: boolean;
    NODE_ENV: 'development' | 'test' | 'production';
    OTEL_EXPORTER_OTLP_ENDPOINT?: string;
};

let cached: ConfigShape | null = null;

/** Read + validate + cache the full config. Throws on first invalid value. */
export function config(): ConfigShape {
    if (cached) return cached;
    const raw: Record<string, unknown> = {};
    const errors: string[] = [];

    for (const [key, meta] of Object.entries(ENV_SCHEMA)) {
        const present = process.env[key];
        if (present === undefined || present === '') {
            if (meta.required) {
                errors.push(
                    `missing required env: ${key}\n  ${meta.description}\n  ${meta.descriptionTh}`,
                );
                continue;
            }
            if (meta.default !== undefined) raw[key] = meta.default;
            continue;
        }
        const parsed = meta.schema.safeParse(present);
        if (!parsed.success) {
            const reason = parsed.error.issues.map((i) => i.message).join(', ');
            // Never echo the actual value — could be a secret — use `redactText`.
            const safeValue = meta.secret ? '<redacted>' : redactText(present).slice(0, 64);
            errors.push(
                `invalid env: ${key} (got ${safeValue}) — ${reason}\n  ${meta.description}\n  ${meta.descriptionTh}`,
            );
            continue;
        }
        raw[key] = parsed.data;
    }

    if (errors.length > 0) {
        throw new Error(`Configuration error:\n  - ${errors.join('\n  - ')}`);
    }

    cached = raw as ConfigShape;
    return cached;
}

/** Reset the cache (tests only). */
export function resetConfig(): void {
    cached = null;
}

/**
 * Render an `.env.example`-style help document from the schema. Used by the
 * setup CLI and by the bench README.
 */
export function renderEnvHelp(lang: 'en' | 'th' = 'en'): string {
    const lines: string[] = ['# InjectProof env reference', ''];
    for (const [key, meta] of Object.entries(ENV_SCHEMA)) {
        const desc = lang === 'th' ? meta.descriptionTh : meta.description;
        lines.push(`# ${desc}`);
        const tag = meta.required ? 'required' : 'optional';
        const secret = meta.secret ? ', secret' : '';
        const def = meta.default === undefined ? '' : ` default=${JSON.stringify(meta.default)}`;
        lines.push(`# (${tag}${secret})${def}`);
        lines.push(`${key}=`);
        lines.push('');
    }
    return lines.join('\n');
}
