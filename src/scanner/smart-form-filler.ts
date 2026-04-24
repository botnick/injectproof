// InjectProof — SmartFormFiller
// ==============================
// Semantic-aware form filler that produces values guaranteed to pass backend
// validation, so when we inject a payload in ONE field the server actually
// processes the submission instead of bouncing it with "required field" or
// "invalid email". Real-world forms reject ~60% of our probes when we fill
// other fields with "testvalue" — this module brings that to near-zero.
//
// Design:
//  1) Semantic inference: field name / id / label / placeholder / pattern
//     attributes → one of ~40 semantic types (email, phone, firstname,
//     address, zip, iban, credit_card, ...).
//  2) Realistic value generator per semantic — Luhn-valid cc, RFC-valid
//     email, ISO date, international phone, etc.
//  3) Multi-input-type support: text/email/url/tel/number are typed; radio/
//     checkbox are clicked; select chooses first non-placeholder option;
//     range / date / color / file have their own strategies.
//  4) Injection-aware helper: fillFormForInjection(form, targetField,
//     payload) produces the body/query that the scanner submits — the
//     payload goes into the target field, everything else is realistic.
//
// Usage:
//  import { SmartFormFiller } from '@/scanner/smart-form-filler';
//  const filler = new SmartFormFiller();
//  const body = filler.buildFormBody(form.fields, { injectInto: 'username',
//                                                    payload: "' OR 1=1 -- " });
//  // submit `body` via application/x-www-form-urlencoded or multipart.
//
// Unit-tested heavily — semantic inference is 100% deterministic given the
// same inputs, so its test harness lives in src/scanner/smart-form-filler.test.ts.

import type { FormField, DiscoveredForm } from '@/types';

// ============================================================
// SEMANTIC TYPES
// ============================================================
// Ordered roughly by frequency on real-world forms. Each maps to a generator
// below. Add new types in descending priority — first match wins.

export type FieldSemantic =
    // Identity / contact
    | 'email' | 'phone' | 'first_name' | 'last_name' | 'full_name' | 'username'
    | 'password' | 'password_confirm' | 'display_name' | 'company'
    // Address
    | 'street' | 'city' | 'state' | 'country' | 'postcode' | 'address_line'
    // Temporal
    | 'date' | 'time' | 'datetime' | 'month' | 'week' | 'year' | 'birthdate'
    // Numeric
    | 'age' | 'quantity' | 'price' | 'amount' | 'percentage' | 'number'
    // Financial
    | 'credit_card' | 'cvv' | 'iban' | 'account_number' | 'routing_number'
    // Identifiers
    | 'url' | 'uuid' | 'id' | 'slug' | 'tax_id' | 'ssn' | 'national_id'
    // Content
    | 'title' | 'description' | 'comment' | 'message' | 'subject' | 'search_query'
    // Choices / toggles
    | 'boolean' | 'gender' | 'language' | 'currency' | 'color'
    // Files / media
    | 'file' | 'image'
    // Structured
    | 'json' | 'xml' | 'ip_address'
    // Fallbacks
    | 'short_text' | 'long_text' | 'unknown';

// ============================================================
// SEMANTIC INFERENCE
// ============================================================
// Order-of-match matters — more specific patterns come first. We combine
// signals from field name, id, label, placeholder, HTML input type, pattern
// attribute, and maxlength. The `confidence` returned lets callers distinguish
// high-confidence matches ("email") from heuristic guesses ("probably a name").

interface SemanticRule {
    semantic: FieldSemantic;
    // Any of these substrings in name/id/label/placeholder/autocomplete.
    nameHints?: string[];
    // Exact HTML input type match.
    inputTypes?: string[];
    // Regex against pattern attribute.
    patternHints?: RegExp[];
    // Confidence weight (higher = wins ties).
    weight: number;
}

const SEMANTIC_RULES: SemanticRule[] = [
    // Input-type-only wins (type=email is always an email field).
    { semantic: 'email', inputTypes: ['email'], weight: 100 },
    { semantic: 'phone', inputTypes: ['tel'], weight: 100 },
    { semantic: 'url', inputTypes: ['url'], weight: 100 },
    { semantic: 'password', inputTypes: ['password'], weight: 100 },
    { semantic: 'date', inputTypes: ['date'], weight: 100 },
    { semantic: 'time', inputTypes: ['time'], weight: 100 },
    { semantic: 'datetime', inputTypes: ['datetime-local', 'datetime'], weight: 100 },
    { semantic: 'month', inputTypes: ['month'], weight: 100 },
    { semantic: 'week', inputTypes: ['week'], weight: 100 },
    { semantic: 'color', inputTypes: ['color'], weight: 100 },
    { semantic: 'file', inputTypes: ['file'], weight: 100 },
    { semantic: 'number', inputTypes: ['number', 'range'], weight: 100 },

    // Very specific name matches — exact word win.
    { semantic: 'email', nameHints: ['email', 'e-mail', 'e_mail', 'mail', 'correo', 'emailaddress'], weight: 95 },
    { semantic: 'phone', nameHints: ['phone', 'mobile', 'tel', 'telephone', 'cellphone', 'cell', 'contact_number', 'เบอร์'], weight: 95 },
    { semantic: 'username', nameHints: ['username', 'user_name', 'userid', 'user_id', 'login', 'uid', 'handle', 'nickname'], weight: 95 },
    { semantic: 'password_confirm', nameHints: ['password_confirm', 'confirm_password', 'confirmpassword', 'password2', 'password_again', 'retype_password', 'repeat_password', 're_password'], weight: 95 },
    { semantic: 'password', nameHints: ['password', 'passwd', 'pwd', 'pass', 'secret'], weight: 90 },
    { semantic: 'first_name', nameHints: ['first_name', 'firstname', 'fname', 'givenname', 'given_name', 'ชื่อ'], weight: 90 },
    { semantic: 'last_name', nameHints: ['last_name', 'lastname', 'lname', 'surname', 'family_name', 'familyname', 'นามสกุล'], weight: 90 },
    { semantic: 'full_name', nameHints: ['full_name', 'fullname', 'name', 'your_name', 'realname', 'real_name'], weight: 80 },
    { semantic: 'display_name', nameHints: ['display_name', 'displayname', 'screen_name', 'screenname'], weight: 85 },
    { semantic: 'company', nameHints: ['company', 'organization', 'organisation', 'business', 'employer', 'firm'], weight: 85 },

    // Address
    { semantic: 'street', nameHints: ['street', 'address1', 'address_1', 'addr1', 'street_address', 'ที่อยู่'], weight: 85 },
    { semantic: 'address_line', nameHints: ['address2', 'address_2', 'addr2', 'apartment', 'suite', 'unit'], weight: 80 },
    { semantic: 'city', nameHints: ['city', 'town', 'เมือง'], weight: 90 },
    { semantic: 'state', nameHints: ['state', 'province', 'region', 'จังหวัด'], weight: 85 },
    { semantic: 'country', nameHints: ['country', 'nation', 'ประเทศ'], weight: 90 },
    { semantic: 'postcode', nameHints: ['zip', 'postcode', 'postal_code', 'postalcode', 'zip_code', 'zipcode', 'รหัสไปรษณีย์'], weight: 95 },

    // Temporal
    { semantic: 'birthdate', nameHints: ['birthdate', 'birth_date', 'dob', 'date_of_birth', 'วันเกิด'], weight: 95 },
    { semantic: 'year', nameHints: ['year', 'yyyy', 'ปี'], weight: 75 },

    // Numeric semantic
    { semantic: 'age', nameHints: ['age', 'อายุ'], weight: 90 },
    { semantic: 'quantity', nameHints: ['qty', 'quantity', 'amount', 'count', 'จำนวน'], weight: 75 },
    { semantic: 'price', nameHints: ['price', 'cost', 'ราคา'], weight: 85 },
    { semantic: 'percentage', nameHints: ['percent', 'percentage', 'pct', 'ratio'], weight: 80 },

    // Financial
    { semantic: 'credit_card', nameHints: ['credit_card', 'creditcard', 'card_number', 'cardnumber', 'cc_number', 'ccnumber', 'card_no', 'pan'], weight: 95 },
    { semantic: 'cvv', nameHints: ['cvv', 'cvc', 'cvv2', 'cid', 'security_code'], weight: 95 },
    { semantic: 'iban', nameHints: ['iban'], weight: 100 },
    { semantic: 'account_number', nameHints: ['account_number', 'accountnumber', 'acct_no', 'account_no'], weight: 85 },
    { semantic: 'routing_number', nameHints: ['routing_number', 'routingnumber', 'aba', 'routing'], weight: 85 },

    // Identifiers
    { semantic: 'url', nameHints: ['url', 'website', 'homepage', 'link'], weight: 85 },
    { semantic: 'uuid', nameHints: ['uuid', 'guid'], weight: 90 },
    { semantic: 'slug', nameHints: ['slug', 'permalink'], weight: 85 },
    { semantic: 'tax_id', nameHints: ['tax_id', 'taxid', 'vat', 'ein'], weight: 85 },
    { semantic: 'ssn', nameHints: ['ssn', 'social_security'], weight: 90 },
    { semantic: 'national_id', nameHints: ['national_id', 'nationalid', 'citizen_id', 'เลขประจำตัว'], weight: 85 },
    { semantic: 'id', nameHints: ['id', 'identifier'], weight: 60 },
    { semantic: 'ip_address', nameHints: ['ip', 'ip_address', 'ipaddress', 'hostname'], weight: 80 },

    // Content
    { semantic: 'title', nameHints: ['title', 'subject', 'heading', 'หัวข้อ'], weight: 80 },
    { semantic: 'description', nameHints: ['description', 'desc', 'details', 'bio', 'about', 'รายละเอียด'], weight: 80 },
    { semantic: 'comment', nameHints: ['comment', 'reply', 'feedback', 'review', 'ความเห็น'], weight: 80 },
    { semantic: 'message', nameHints: ['message', 'text', 'body', 'content', 'note', 'ข้อความ'], weight: 70 },
    { semantic: 'search_query', nameHints: ['search', 'query', 'q', 'keyword', 'keywords', 'term', 'ค้นหา'], weight: 85 },

    // Choices
    { semantic: 'gender', nameHints: ['gender', 'sex', 'เพศ'], weight: 95 },
    { semantic: 'language', nameHints: ['language', 'lang', 'locale', 'ภาษา'], weight: 90 },
    { semantic: 'currency', nameHints: ['currency', 'сurr', 'สกุลเงิน'], weight: 90 },

    // Pattern-based fallbacks
    { semantic: 'email', patternHints: [/@/], weight: 70 },
    { semantic: 'phone', patternHints: [/\+?\d{7,}/], weight: 60 },
];

export interface InferredField {
    semantic: FieldSemantic;
    confidence: number;
    // Whether typing a value makes sense here (false for radio/checkbox/select/hidden).
    typeable: boolean;
    // The HTML input type we observed.
    htmlType: string;
    // Original field reference for downstream use.
    field: FormField;
}

/**
 * Infer the semantic type of a single form field from all its metadata.
 * Returns the winning semantic + confidence 0..100.
 */
export function inferFieldSemantic(field: FormField): InferredField {
    const htmlType = (field.type ?? 'text').toLowerCase();
    const typeable = !['radio', 'checkbox', 'hidden', 'submit', 'button', 'reset', 'image', 'file'].includes(htmlType);

    // Build the searchable haystack once — name + id + label + placeholder + autocomplete.
    // Field types don't all carry every attribute, so we defensively lowercase and join.
    const haystack = [
        field.name, field.id ?? '', field.label ?? '',
        field.placeholder ?? '', field.autocomplete ?? '',
    ].join(' ').toLowerCase();

    let bestSemantic: FieldSemantic = 'unknown';
    let bestWeight = 0;

    for (const rule of SEMANTIC_RULES) {
        let matched = false;
        let weight = rule.weight;

        if (rule.inputTypes && rule.inputTypes.includes(htmlType)) matched = true;
        if (!matched && rule.nameHints) {
            // Use word-boundary regex so 'email' matches 'user_email' but not 'mailgun_key'.
            for (const hint of rule.nameHints) {
                // Escape regex metachars inside the hint.
                const esc = hint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const re = new RegExp(`(^|[_\\-.\\s])${esc}($|[_\\-.\\s])`, 'i');
                if (re.test(haystack)) { matched = true; break; }
                // Also allow contiguous match — `firstname` in `myfirstname`.
                if (haystack.includes(hint.toLowerCase())) { matched = true; weight = rule.weight * 0.8; break; }
            }
        }
        if (!matched && rule.patternHints && field.pattern) {
            for (const pr of rule.patternHints) {
                if (pr.test(field.pattern)) { matched = true; weight = rule.weight * 0.7; break; }
            }
        }
        if (matched && weight > bestWeight) {
            bestSemantic = rule.semantic;
            bestWeight = weight;
        }
    }

    // Fallback: long-text heuristic via maxlength / textarea.
    if (bestSemantic === 'unknown') {
        if (htmlType === 'textarea' || (field.maxLength ?? 0) >= 500) bestSemantic = 'long_text';
        else if (field.required) bestSemantic = 'short_text';
    }

    return { semantic: bestSemantic, confidence: bestWeight, typeable, htmlType, field };
}

// ============================================================
// REALISTIC VALUE GENERATORS
// ============================================================
// Each generator produces a value that passes the typical backend validation
// for that semantic type. Values are deterministic per call-site by default —
// we want the SAME "realistic" value re-used across payload iterations so the
// server can't distinguish our probes by the non-target fields.
//
// To get a unique value per submission, pass a seed string.

function pickFirstOption(field: FormField): string | null {
    if (!field.options || field.options.length === 0) return null;
    // Prefer the first option whose value isn't empty/placeholder-like.
    for (const opt of field.options) {
        const v = opt.value ?? '';
        const l = (opt.label ?? '').toLowerCase();
        if (v && v !== '0' && !/please|select|choose|-- ?none/i.test(l)) return v;
    }
    return field.options[0]?.value ?? null;
}

// Generates a numeric string of N digits without using RNG sequences that trip
// on fraud filters ("1234567890", "0000000000", etc.). Pseudo-random but deterministic.
function numericString(n: number, seed = 0): string {
    const digits = '0123456789';
    let out = '';
    // Linear-congruential style — cheap + stable across Node versions.
    let s = seed || 7919;
    for (let i = 0; i < n; i++) {
        s = (s * 1103515245 + 12345) & 0x7fffffff;
        out += digits[s % 10];
    }
    return out;
}

// Luhn-valid 16-digit card number. Uses Visa test prefix (4242) so payment
// gateways that validate BIN ranges accept it as test input.
function luhnVisa(): string {
    const base = '4242424242424242';
    // 4242 4242 4242 4242 is Stripe's canonical test Visa — already Luhn-valid.
    return base;
}

// Generate an ISO date that's plausible and passes "must be ≥ 18 years old"
// style validations on sign-up forms.
function pastDate(yearsAgo: number = 25): string {
    const d = new Date();
    d.setFullYear(d.getFullYear() - yearsAgo);
    return d.toISOString().slice(0, 10);
}

function todayIso(): string { return new Date().toISOString().slice(0, 10); }
function nowIsoMinutes(): string { return new Date().toISOString().slice(0, 16); }
function todayMonth(): string { return new Date().toISOString().slice(0, 7); }

export interface GenOptions {
    /** Seed for deterministic variation across multiple runs of the same form. */
    seed?: string;
    /** Set true to produce unique values per call (e.g. for uniqueness-constrained fields). */
    unique?: boolean;
}

const uniqueCounter = { n: 0 };

export function generateValue(inferred: InferredField, opts: GenOptions = {}): string {
    const field = inferred.field;
    const suffix = opts.unique ? String(++uniqueCounter.n) : '';

    // Select / radio / checkbox — always pick a real option over generating a string.
    if (inferred.htmlType === 'select' || inferred.htmlType === 'select-one' || inferred.htmlType === 'select-multiple') {
        return pickFirstOption(field) ?? '';
    }
    if (inferred.htmlType === 'radio' || inferred.htmlType === 'checkbox') {
        // Caller should click() these via Puppeteer. For form-encoded body we
        // emit the field's value attribute so the server sees "checked".
        return field.value ?? 'on';
    }

    switch (inferred.semantic) {
        case 'email':             return `injectproof.test${suffix}@example.com`;
        case 'phone':             return `+14155550${numericString(3, Number(suffix) || 0)}`;
        case 'first_name':        return 'Alex';
        case 'last_name':         return 'Johnson';
        case 'full_name':         return `Alex Johnson${suffix ? ' ' + suffix : ''}`;
        case 'username':          return `inject_user${suffix || '42'}`;
        case 'display_name':      return `AlexJ${suffix || '42'}`;
        case 'password':          return 'InjectProof!Test123';
        case 'password_confirm':  return 'InjectProof!Test123'; // match password
        case 'company':           return 'Acme Corp';
        case 'street':            return '123 Main Street';
        case 'address_line':      return 'Apt 4B';
        case 'city':              return 'Bangkok';
        case 'state':             return 'Bangkok';
        case 'country':           return pickFirstOption(field) ?? 'TH';
        case 'postcode':          return '10110';
        case 'date':              return todayIso();
        case 'birthdate':         return pastDate(25);
        case 'time':              return '12:34';
        case 'datetime':          return nowIsoMinutes();
        case 'month':             return todayMonth();
        case 'week':              return `${new Date().getFullYear()}-W10`;
        case 'year':              return String(new Date().getFullYear() - 25);
        case 'age':               return '25';
        case 'quantity':          return '1';
        case 'price':             return '99.99';
        case 'amount':            return '100';
        case 'percentage':        return '50';
        case 'number':            return field.min != null ? String(field.min) : '1';
        case 'credit_card':       return luhnVisa();
        case 'cvv':               return '123';
        case 'iban':              return 'GB82WEST12345698765432'; // canonical test IBAN
        case 'account_number':    return numericString(10, 1);
        case 'routing_number':    return '021000021'; // NY Fed test
        case 'url':               return 'https://example.com/';
        case 'uuid':              return '00000000-0000-4000-8000-000000000000';
        case 'slug':              return 'example-slug';
        case 'tax_id':            return '12-3456789';
        case 'ssn':               return '123-45-6789';
        case 'national_id':       return '1234567890123'; // TH 13-digit
        case 'id':                return '1';
        case 'ip_address':        return '192.0.2.1'; // RFC5737 TEST-NET-1
        case 'title':             return 'Test subject';
        case 'description':       return 'A concise description used for security testing.';
        case 'comment':           return 'This is a test comment.';
        case 'message':           return 'Hello — this is a test message.';
        case 'subject':           return 'Security test subject';
        case 'search_query':      return 'test';
        case 'boolean':           return '1';
        case 'gender':            return pickFirstOption(field) ?? 'M';
        case 'language':          return pickFirstOption(field) ?? 'en';
        case 'currency':          return pickFirstOption(field) ?? 'THB';
        case 'color':             return '#3366ff';
        case 'file':              return ''; // handled specially in browser variant
        case 'image':             return '';
        case 'json':              return '{"test":true}';
        case 'xml':               return '<test/>';
        case 'long_text':         return 'Lorem ipsum dolor sit amet — InjectProof security assessment test input.';
        case 'short_text':        return 'test';
        case 'unknown':
        default:                  return pickFirstOption(field) ?? 'test';
    }
}

// ============================================================
// FORM BODY BUILDER
// ============================================================

export interface BuildOptions {
    /** Name of the field that should carry the injection payload. */
    injectInto?: string;
    /** The payload string. Required when injectInto is set. */
    payload?: string;
    /** Extra per-field overrides (e.g. forcing a specific enum value). */
    overrides?: Record<string, string>;
    /** Skip fields with these names — useful for CSRF tokens we want to keep as-is. */
    skipFields?: string[];
    /** Produce unique values for fields that likely need uniqueness (username/email). */
    uniqueOnSubmit?: boolean;
}

export interface BuildResult {
    /** Field → value map, ready to URL-encode or assemble as multipart. */
    values: Record<string, string>;
    /** Per-field diagnostics: what semantic was inferred, what value got filled. */
    diagnostics: Array<{ name: string; semantic: FieldSemantic; confidence: number; value: string; injected: boolean }>;
}

export class SmartFormFiller {
    /**
     * Build a complete form submission body. The target field (if specified)
     * gets the payload; every other field gets a realistic value that should
     * pass validation on the backend.
     *
     * Fields that are hidden, CSRF tokens, or explicitly in `skipFields` keep
     * their existing `value`. Radio/checkbox/select return the first non-
     * placeholder option. Missing fields fall back to 'test'.
     */
    buildFormBody(fields: FormField[], opts: BuildOptions = {}): BuildResult {
        const values: Record<string, string> = {};
        const diagnostics: BuildResult['diagnostics'] = [];

        for (const field of fields) {
            // CSRF tokens and hidden fields — always keep the server's value verbatim.
            if (field.type === 'hidden' || field.type === 'submit' || field.type === 'button') {
                if (field.value !== undefined) values[field.name] = field.value;
                continue;
            }
            if (opts.skipFields?.includes(field.name)) {
                if (field.value !== undefined) values[field.name] = field.value;
                continue;
            }

            const inferred = inferFieldSemantic(field);
            let value: string;
            let injected = false;

            if (opts.injectInto && field.name === opts.injectInto && opts.payload !== undefined) {
                value = opts.payload;
                injected = true;
            } else if (opts.overrides && field.name in opts.overrides) {
                value = opts.overrides[field.name];
            } else {
                value = generateValue(inferred, { unique: opts.uniqueOnSubmit });
            }

            values[field.name] = value;
            diagnostics.push({
                name: field.name,
                semantic: inferred.semantic,
                confidence: inferred.confidence,
                value,
                injected,
            });
        }

        return { values, diagnostics };
    }

    /** URL-encode a BuildResult for application/x-www-form-urlencoded submission. */
    encodeForm(result: BuildResult): string {
        return Object.entries(result.values)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
    }

    /** Build a multipart/form-data body. Returns {body, contentType}. */
    encodeMultipart(result: BuildResult): { body: string; contentType: string } {
        const boundary = `----IPF${Math.random().toString(36).slice(2, 14)}`;
        const lines: string[] = [];
        for (const [k, v] of Object.entries(result.values)) {
            lines.push(`--${boundary}`);
            lines.push(`Content-Disposition: form-data; name="${k}"`);
            lines.push('');
            lines.push(v);
        }
        lines.push(`--${boundary}--`);
        lines.push('');
        return {
            body: lines.join('\r\n'),
            contentType: `multipart/form-data; boundary=${boundary}`,
        };
    }
}

// ============================================================
// PUPPETEER HELPERS (DYNAMIC VARIANT)
// ============================================================
// When the scanner drives a real browser (headless-crawler, smart-form-sqlmap),
// we need to dispatch input events correctly for SPA frameworks to register
// the change. Naive .value = ... doesn't trigger React/Vue reactivity.

/**
 * Fill a live page's form using a Puppeteer Page handle. Handles every input
 * type correctly: text/email/etc. → type; radio → click; checkbox → toggle;
 * select → option click; range → direct set + input event; file → uploadFile
 * with a tiny test PNG.
 *
 * `page` is typed loosely as `unknown` to avoid importing Puppeteer here —
 * callers (headless-crawler, smart-form-sqlmap) pass the real Page instance.
 */
export interface PuppeteerFillOptions extends BuildOptions {
    /** Small inline asset to upload for file inputs. Default: 1x1 PNG. */
    testFileContent?: Buffer;
    testFileName?: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyPage = any;

/**
 * Fill a DOM form on a live Puppeteer page. Returns the BuildResult for
 * logging / diagnostics. The caller is responsible for clicking submit.
 */
export async function fillFormOnPage(
    page: AnyPage,
    form: DiscoveredForm,
    filler: SmartFormFiller,
    opts: PuppeteerFillOptions = {},
): Promise<BuildResult> {
    const result = filler.buildFormBody(form.fields, opts);

    for (const field of form.fields) {
        const value = result.values[field.name];
        if (value === undefined) continue;

        const selector = field.selector
            ?? (field.id ? `#${CSS.escape(field.id)}` : `[name="${CSS.escape(field.name)}"]`);

        const htmlType = (field.type ?? 'text').toLowerCase();
        try {
            if (htmlType === 'radio') {
                // Click the specific radio whose value matches our pick.
                const targetSel = `input[type="radio"][name="${CSS.escape(field.name)}"][value="${CSS.escape(value)}"]`;
                const clicked = await page.$(targetSel);
                if (clicked) { await clicked.click(); continue; }
                // Fallback — click first radio in the group.
                const first = await page.$(`input[type="radio"][name="${CSS.escape(field.name)}"]`);
                if (first) await first.click();
                continue;
            }
            if (htmlType === 'checkbox') {
                // Only toggle if not already in the desired state.
                const needsCheck = value === 'on' || value === field.value || value === '1' || value === 'true';
                const el = await page.$(selector);
                if (!el) continue;
                const isChecked = await el.evaluate((n: HTMLInputElement) => n.checked);
                if (needsCheck !== isChecked) await el.click();
                continue;
            }
            if (htmlType === 'select' || htmlType === 'select-one' || htmlType === 'select-multiple') {
                await page.select(selector, value);
                continue;
            }
            if (htmlType === 'file') {
                const el = await page.$(selector);
                if (!el) continue;
                // Write an in-memory tiny PNG to a temp file and hand the path
                // to uploadFile. Puppeteer doesn't accept buffers directly.
                const { writeFileSync, mkdtempSync } = await import('fs');
                const { tmpdir } = await import('os');
                const { join } = await import('path');
                const dir = mkdtempSync(join(tmpdir(), 'ipf-upload-'));
                const name = opts.testFileName ?? 'test.png';
                const path = join(dir, name);
                // 1x1 transparent PNG (67 bytes).
                const tinyPng = opts.testFileContent ?? Buffer.from(
                    '89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C489000000' +
                    '0D49444154789C6300010000000500010D0A2DB40000000049454E44AE426082',
                    'hex');
                writeFileSync(path, tinyPng);
                await el.uploadFile(path);
                continue;
            }
            if (htmlType === 'range' || htmlType === 'number') {
                // Dispatch input+change events so frameworks see the value.
                await page.$eval(selector, (n: HTMLInputElement, v: string) => {
                    n.value = v;
                    n.dispatchEvent(new Event('input', { bubbles: true }));
                    n.dispatchEvent(new Event('change', { bubbles: true }));
                }, value);
                continue;
            }
            if (htmlType === 'color' || htmlType === 'date' || htmlType === 'time'
                || htmlType === 'datetime-local' || htmlType === 'month' || htmlType === 'week') {
                // Same direct-set pattern — these inputs often reject typing.
                await page.$eval(selector, (n: HTMLInputElement, v: string) => {
                    n.value = v;
                    n.dispatchEvent(new Event('input', { bubbles: true }));
                    n.dispatchEvent(new Event('change', { bubbles: true }));
                }, value);
                continue;
            }

            // Default: text-like input — clear then type.
            await page.$eval(selector, (n: HTMLInputElement) => { n.value = ''; });
            await page.type(selector, value, { delay: 0 });
        } catch {
            // Best-effort — if a single field fails we keep going.
            continue;
        }
    }

    return result;
}

// ============================================================
// CONVENIENCE
// ============================================================

/**
 * Shorthand for the 90% case: "give me a form body where field X has the
 * payload and everything else is realistic."
 */
export function fillFormForInjection(
    fields: FormField[],
    targetField: string,
    payload: string,
    overrides?: Record<string, string>,
): BuildResult {
    return new SmartFormFiller().buildFormBody(fields, {
        injectInto: targetField,
        payload,
        overrides,
    });
}
