// InjectProof — HTTP challenge classifier
// รับ HTTP response (status + headers + body preview) แล้วจำแนกเป็นหนึ่งใน:
//   - ok                         ปกติ
//   - 403-plain                  403 ธรรมดา (backend policy ปฏิเสธ)
//   - 403-cloudflare             Cloudflare edge deny
//   - 403-cloudflare-challenge   CF managed challenge page (cf_chl_def, captcha)
//   - 403-waf-akamai             Akamai
//   - 403-waf-aws                AWS WAF
//   - 403-waf-generic            โดน WAF ระบุไม่ออก
//   - 429                        rate limited
//   - 503-unavailable            unavailable / maintenance
//   - 401                        ต้อง auth
//   - captcha                    human challenge
//
// เป็น classifier pure function ไม่แตะ network — input → verdict.

export type ChallengeClass =
    | 'ok'
    | '401'
    | '403-plain'
    | '403-cloudflare'
    | '403-cloudflare-challenge'
    | '403-waf-akamai'
    | '403-waf-aws'
    | '403-waf-imperva'
    | '403-waf-f5'
    | '403-waf-sucuri'
    | '403-waf-generic'
    | '429'
    | '503-unavailable'
    | 'captcha';

export interface ChallengeInput {
    status: number;
    headers: Record<string, string>;
    /** Body preview — first N bytes is enough; 4k is plenty. */
    bodyPreview?: string;
}

export interface ChallengeVerdict {
    class: ChallengeClass;
    vendor?: string;
    signals: string[];
    retryable: boolean;
    suggestedWaitMs: number;
}

// ────────────────────────────────────────────────────────────
// Vendor signatures
// ────────────────────────────────────────────────────────────

interface VendorRule {
    id: ChallengeClass;
    vendor: string;
    matchHeaders?: Array<[string, RegExp]>;
    matchBodyPatterns?: RegExp[];
    statusSet: number[];
    suggestedWaitMs: number;
}

const VENDORS: VendorRule[] = [
    {
        id: '403-cloudflare-challenge',
        vendor: 'Cloudflare',
        matchHeaders: [['server', /cloudflare/i], ['cf-mitigated', /challenge/i]],
        matchBodyPatterns: [/cf[_-]chl[_-]opt/i, /cf[_-]chl[_-]def/i, /challenges\.cloudflare\.com/i, /__cf_bm/],
        statusSet: [403, 503],
        suggestedWaitMs: 15_000,
    },
    {
        id: '403-cloudflare',
        vendor: 'Cloudflare',
        matchHeaders: [['cf-ray', /.+/i], ['server', /cloudflare/i]],
        matchBodyPatterns: [/cloudflare/i, /error code.*?1020/i, /access denied/i],
        statusSet: [403, 503],
        suggestedWaitMs: 10_000,
    },
    {
        id: '403-waf-akamai',
        vendor: 'Akamai',
        matchHeaders: [['server', /akamaighost/i], ['x-akamai-transformed', /.+/]],
        matchBodyPatterns: [/Reference #[0-9.]+/],
        statusSet: [403],
        suggestedWaitMs: 8_000,
    },
    {
        id: '403-waf-aws',
        vendor: 'AWS WAF',
        matchHeaders: [['server', /AwselB|AwsAlb|CloudFront/i], ['x-amzn-requestid', /.+/], ['x-amz-waf-action', /.+/]],
        matchBodyPatterns: [/request blocked/i, /<title>ERROR<\/title>/],
        statusSet: [403],
        suggestedWaitMs: 8_000,
    },
    {
        id: '403-waf-imperva',
        vendor: 'Imperva Incapsula',
        matchHeaders: [['server', /imperva|incapsula/i], ['x-iinfo', /.+/]],
        matchBodyPatterns: [/incident id/i, /incapsula/i],
        statusSet: [403],
        suggestedWaitMs: 8_000,
    },
    {
        id: '403-waf-f5',
        vendor: 'F5 BIG-IP',
        matchHeaders: [['server', /BigIP|BIGip/i]],
        matchBodyPatterns: [/The requested URL was rejected/i, /Support ID/i],
        statusSet: [403, 501],
        suggestedWaitMs: 5_000,
    },
    {
        id: '403-waf-sucuri',
        vendor: 'Sucuri',
        matchHeaders: [['server', /sucuri/i], ['x-sucuri-id', /.+/]],
        statusSet: [403],
        suggestedWaitMs: 6_000,
    },
];

// ────────────────────────────────────────────────────────────
// Classifier
// ────────────────────────────────────────────────────────────

function headerLower(headers: Record<string, string>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers ?? {})) out[k.toLowerCase()] = String(v ?? '');
    return out;
}

function matchVendor(rule: VendorRule, h: Record<string, string>, body: string): string[] {
    const signals: string[] = [];
    for (const [name, re] of rule.matchHeaders ?? []) {
        const v = h[name.toLowerCase()];
        if (v && re.test(v)) signals.push(`header:${name}=${re.source}`);
    }
    for (const re of rule.matchBodyPatterns ?? []) {
        if (re.test(body)) signals.push(`body:${re.source.slice(0, 40)}`);
    }
    return signals;
}

export function classifyChallenge(input: ChallengeInput): ChallengeVerdict {
    const h = headerLower(input.headers);
    const body = input.bodyPreview ?? '';
    const status = input.status;

    if (status === 429) {
        const retryAfter = Number(h['retry-after']);
        return {
            class: '429',
            signals: ['status:429'],
            retryable: true,
            suggestedWaitMs: Number.isFinite(retryAfter) ? retryAfter * 1000 : 10_000,
        };
    }
    if (status === 401) {
        return { class: '401', signals: ['status:401'], retryable: false, suggestedWaitMs: 0 };
    }
    if (status === 503) {
        const retryAfter = Number(h['retry-after']);
        // May be a CF challenge shape too — fall through to vendor matching below.
    }

    for (const rule of VENDORS) {
        if (!rule.statusSet.includes(status)) continue;
        const signals = matchVendor(rule, h, body);
        if (signals.length > 0) {
            return {
                class: rule.id,
                vendor: rule.vendor,
                signals,
                retryable: true,
                suggestedWaitMs: rule.suggestedWaitMs,
            };
        }
    }

    if (status === 503) {
        const retryAfter = Number(h['retry-after']);
        return {
            class: '503-unavailable',
            signals: ['status:503'],
            retryable: true,
            suggestedWaitMs: Number.isFinite(retryAfter) ? retryAfter * 1000 : 15_000,
        };
    }

    if (status === 403) {
        // Check if body text contains captcha keywords
        if (/captcha|recaptcha|hcaptcha|turnstile|challenge/i.test(body)) {
            return {
                class: 'captcha',
                signals: ['body:captcha'],
                retryable: false,
                suggestedWaitMs: 0,
            };
        }
        return {
            class: '403-plain',
            signals: ['status:403'],
            retryable: false,
            suggestedWaitMs: 0,
        };
    }

    if (status >= 200 && status < 400) {
        return { class: 'ok', signals: [], retryable: false, suggestedWaitMs: 0 };
    }

    return {
        class: '403-waf-generic',
        signals: [`status:${status}`],
        retryable: false,
        suggestedWaitMs: 5_000,
    };
}
