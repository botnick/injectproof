// InjectProof — Intelligent Scanner Brain (Deep Recon Module)
// Classifies forms, discovers every interactive element, maps site architecture,
// and makes smart pentesting decisions using adaptive if/else logic.
// This module acts like an AI pentester — it understands what it sees and decides what to attack.

import * as cheerio from 'cheerio';
import type { CrawledEndpoint, DiscoveredForm, FormField, DiscoveredParam } from '@/types';
import { normalizeUrl, isSameOrigin, parseUrl } from '@/lib/utils';

// ============================================================
// TYPES
// ============================================================

export type FormClassification =
    | 'login' | 'registration' | 'search' | 'contact'
    | 'comment' | 'upload' | 'payment' | 'profile-edit'
    | 'password-reset' | 'password-change' | 'newsletter'
    | 'admin-action' | 'api-form' | 'filter' | 'settings'
    | 'delete-confirm' | 'data-entry' | 'unknown';

export type AttackPriority = 'critical' | 'high' | 'medium' | 'low' | 'skip';
export type InteractiveElementType = 'link' | 'button' | 'form' | 'ajax-trigger' | 'dropdown' | 'tab' | 'modal-trigger' | 'pagination' | 'sort' | 'filter' | 'file-upload';

export interface ClassifiedForm extends DiscoveredForm {
    classification: FormClassification;
    attackPriority: AttackPriority;
    csrfToken?: { name: string; value: string };
    hasFileUpload: boolean;
    hasCaptcha: boolean;
    hasPasswordField: boolean;
    hasEmailField: boolean;
    hasHiddenFields: boolean;
    estimatedPurpose: string;
    suggestedAttacks: string[];
    fieldAnalysis: FieldAnalysis[];
}

export interface FieldAnalysis {
    name: string;
    type: string;
    classification: 'injectable' | 'credential' | 'token' | 'identifier' | 'content' | 'file' | 'choice' | 'ignored';
    sqliPriority: number; // 0-10
    xssPriority: number;  // 0-10
    suggestedPayloadType: string;
}

export interface InteractiveElement {
    type: InteractiveElementType;
    selector: string;
    text: string;
    url?: string;
    action?: string;
    method?: string;
    attributes: Record<string, string>;
    attackRelevance: number; // 0-10
    notes: string;
}

export interface PageIntelligence {
    url: string;
    title: string;
    pageType: PageType;
    forms: ClassifiedForm[];
    interactiveElements: InteractiveElement[];
    ajaxEndpoints: AjaxEndpoint[];
    hiddenInputs: Array<{ name: string; value: string }>;
    comments: string[];           // HTML comments (often leak info)
    inlineScripts: string[];      // Inline JS (for endpoint discovery)
    technologies: string[];
    hasAuth: boolean;             // Requires authentication
    hasAdmin: boolean;            // Looks like admin page
    riskScore: number;            // 0-100
    attackPlan: AttackStep[];
}

export type PageType =
    | 'login' | 'dashboard' | 'listing' | 'detail' | 'search-results'
    | 'admin-panel' | 'settings' | 'profile' | 'registration'
    | 'error' | 'api-docs' | 'file-manager' | 'static' | 'unknown';

export interface AjaxEndpoint {
    url: string;
    method: string;
    params: string[];
    source: string; // where we found it (inline JS, onclick, etc.)
    confidence: number;
}

export interface AttackStep {
    priority: number;
    target: string;
    technique: string;
    reason: string;
    params: string[];
}

export interface DeepScanResult {
    pages: PageIntelligence[];
    siteMap: SiteNode[];
    totalForms: number;
    totalAjaxEndpoints: number;
    totalInteractiveElements: number;
    attackPlan: AttackStep[];
}

export interface SiteNode {
    url: string;
    title: string;
    depth: number;
    children: string[];
    pageType: PageType;
    riskScore: number;
}

// ============================================================
// FORM CLASSIFIER — Understands what every form does
// ============================================================

const FORM_CLASSIFICATION_RULES: Array<{
    classification: FormClassification;
    priority: AttackPriority;
    checks: Array<(form: DiscoveredForm, $form: cheerio.Cheerio<any>, $: cheerio.CheerioAPI) => boolean>;
    attacks: string[];
    purpose: string;
}> = [
        {
            classification: 'login',
            priority: 'critical',
            checks: [
                // Has password field + username/email field
                (f) => f.fields.some(ff => ff.type === 'password') && f.fields.some(ff => /user|email|login|account/i.test(ff.name)),
                // Form action contains login/auth keywords
                (f) => /login|signin|sign-in|auth|session/i.test(f.action),
                // Small form with password field
                (f) => f.fields.filter(ff => !ff.hidden).length <= 4 && f.fields.some(ff => ff.type === 'password'),
            ],
            attacks: ['sql-auth-bypass', 'sqli-username', 'sqli-password', 'brute-force', 'credential-stuffing', 'csrf-login'],
            purpose: 'User authentication — high-value target for auth bypass',
        },
        {
            classification: 'registration',
            priority: 'high',
            checks: [
                (f) => /register|signup|sign-up|create.account|join/i.test(f.action),
                (f) => f.fields.some(ff => ff.type === 'password') && f.fields.some(ff => /email/i.test(ff.name)) && f.fields.length > 3,
                (f) => f.fields.some(ff => /confirm.password|password2|re.?password/i.test(ff.name)),
            ],
            attacks: ['sqli-insert', 'xss-stored', 'mass-assignment', 'email-injection', 'duplicate-registration'],
            purpose: 'User registration — INSERT context SQLi, stored XSS',
        },
        {
            classification: 'search',
            priority: 'critical',
            checks: [
                (f) => /search|query|find|lookup|q=/i.test(f.action),
                (f) => f.fields.some(ff => /search|query|keyword|q$|term|s$/i.test(ff.name)),
                (_, $form) => $form.find('input[type="search"]').length > 0,
                (f) => f.method === 'GET' && f.fields.filter(ff => !ff.hidden).length <= 2,
            ],
            attacks: ['sqli-where-like', 'sqli-where-string', 'xss-reflected', 'ldap-injection', 'xpath-injection'],
            purpose: 'Search form — LIKE context SQLi, reflected XSS',
        },
        {
            classification: 'upload',
            priority: 'critical',
            checks: [
                (f) => f.fields.some(ff => ff.type === 'file'),
                (f) => /upload|import|attach|media/i.test(f.action),
                (f) => f.enctype === 'multipart/form-data',
            ],
            attacks: ['file-upload-webshell', 'path-traversal', 'xxe', 'ssrf-via-url', 'imagemagick-exploit'],
            purpose: 'File upload — webshell upload, path traversal',
        },
        {
            classification: 'comment',
            priority: 'high',
            checks: [
                (f) => f.fields.some(ff => /comment|message|body|content|text/i.test(ff.name) && (ff.type === 'textarea' || ff.type === 'text')),
                (f) => /comment|review|feedback|reply|post/i.test(f.action),
            ],
            attacks: ['xss-stored', 'sqli-insert', 'ssti', 'html-injection', 'crlf-injection'],
            purpose: 'Comment/feedback form — stored XSS, INSERT SQLi',
        },
        {
            classification: 'contact',
            priority: 'medium',
            checks: [
                (f) => /contact|support|ticket|inquiry/i.test(f.action),
                (f) => f.fields.some(ff => /email/i.test(ff.name)) && f.fields.some(ff => /message|body|content/i.test(ff.name)),
            ],
            attacks: ['email-injection', 'xss-stored', 'sqli-insert', 'smtp-injection'],
            purpose: 'Contact form — email injection, stored XSS',
        },
        {
            classification: 'profile-edit',
            priority: 'high',
            checks: [
                (f) => /profile|account|settings.*user|user.*edit|my.?account/i.test(f.action),
                (f) => f.fields.some(ff => /name|bio|about|avatar|phone/i.test(ff.name)),
            ],
            attacks: ['sqli-update', 'xss-stored', 'mass-assignment', 'idor', 'privilege-escalation'],
            purpose: 'Profile edit — UPDATE SQLi, stored XSS, IDOR',
        },
        {
            classification: 'password-change',
            priority: 'critical',
            checks: [
                (f) => f.fields.filter(ff => ff.type === 'password').length >= 2,
                (f) => /password|change.?pass|update.?pass/i.test(f.action),
                (f) => f.fields.some(ff => /old.?pass|current.?pass/i.test(ff.name)),
            ],
            attacks: ['csrf-password-change', 'brute-force-old-password', 'sqli-where-string'],
            purpose: 'Password change — CSRF, brute force current password',
        },
        {
            classification: 'password-reset',
            priority: 'high',
            checks: [
                (f) => /reset|forgot|recover|restore/i.test(f.action),
                (f) => f.fields.length <= 2 && f.fields.some(ff => /email|user/i.test(ff.name)),
            ],
            attacks: ['email-enumeration', 'host-header-injection', 'sqli-where-string', 'token-prediction'],
            purpose: 'Password reset — email enumeration, host header injection',
        },
        {
            classification: 'admin-action',
            priority: 'critical',
            checks: [
                (f) => /admin|manage|control|backend|dashboard/i.test(f.action),
                (f) => f.fields.some(ff => /role|permission|privilege|admin|ban|delete|approve/i.test(ff.name)),
            ],
            attacks: ['csrf-admin', 'sqli-where-string', 'privilege-escalation', 'idor', 'mass-assignment'],
            purpose: 'Admin action — CSRF, privilege escalation',
        },
        {
            classification: 'filter',
            priority: 'high',
            checks: [
                (f) => f.method === 'GET' && f.fields.some(ff => /sort|order|filter|category|type|status|page|limit/i.test(ff.name)),
                (f) => f.fields.some(ff => ff.type === 'select') && f.fields.filter(ff => !ff.hidden).length <= 5,
            ],
            attacks: ['sqli-order-by', 'sqli-limit', 'sqli-where-string', 'xss-reflected'],
            purpose: 'Filter/sort form — ORDER BY SQLi, LIMIT injection',
        },
        {
            classification: 'newsletter',
            priority: 'low',
            checks: [
                (f) => /subscribe|newsletter|mailing/i.test(f.action),
                (f) => f.fields.length <= 2 && f.fields.some(ff => ff.type === 'email' || /email/i.test(ff.name)),
            ],
            attacks: ['sqli-insert', 'email-injection'],
            purpose: 'Newsletter signup — INSERT SQLi',
        },
        {
            classification: 'payment',
            priority: 'high',
            checks: [
                (f) => /pay|checkout|order|purchase|billing|cart/i.test(f.action),
                (f) => f.fields.some(ff => /card|cc|cvv|expiry|billing|amount|price/i.test(ff.name)),
            ],
            attacks: ['price-manipulation', 'idor-order', 'race-condition', 'sqli-insert'],
            purpose: 'Payment form — price manipulation, race condition',
        },
        {
            classification: 'delete-confirm',
            priority: 'medium',
            checks: [
                (f) => /delete|remove|destroy|purge/i.test(f.action),
                (f) => f.fields.some(ff => /confirm|agree|delete/i.test(ff.name)),
            ],
            attacks: ['csrf-delete', 'idor', 'sqli-where-string'],
            purpose: 'Delete confirmation — CSRF, IDOR',
        },
        {
            classification: 'settings',
            priority: 'high',
            checks: [
                (f) => /settings|config|preferences|options/i.test(f.action),
            ],
            attacks: ['csrf-settings', 'mass-assignment', 'sqli-update', 'xss-stored'],
            purpose: 'Settings form — CSRF, mass assignment',
        },
    ];

export function classifyForm(form: DiscoveredForm, $form: cheerio.Cheerio<any>, $: cheerio.CheerioAPI): ClassifiedForm {
    // Run classification rules
    let bestClassification: FormClassification = 'unknown';
    let bestPriority: AttackPriority = 'medium';
    let suggestedAttacks: string[] = [];
    let estimatedPurpose = 'Unknown form purpose';

    for (const rule of FORM_CLASSIFICATION_RULES) {
        for (const check of rule.checks) {
            try {
                if (check(form, $form, $)) {
                    bestClassification = rule.classification;
                    bestPriority = rule.priority;
                    suggestedAttacks = rule.attacks;
                    estimatedPurpose = rule.purpose;
                    break;
                }
            } catch { continue; }
        }
        if (bestClassification !== 'unknown') break;
    }

    // Analyze each field
    const fieldAnalysis: FieldAnalysis[] = form.fields.map(f => analyzeField(f, bestClassification));

    // Detect special features
    const csrfField = form.fields.find(f => f.hidden && /csrf|token|nonce|_token|authenticity/i.test(f.name));
    const hasCaptcha = form.fields.some(f => /captcha|recaptcha|hcaptcha|g-recaptcha/i.test(f.name)) ||
        $form.find('[class*="captcha"],[id*="captcha"],[class*="recaptcha"]').length > 0;

    return {
        ...form,
        classification: bestClassification,
        attackPriority: bestPriority,
        csrfToken: csrfField ? { name: csrfField.name, value: csrfField.value || '' } : undefined,
        hasFileUpload: form.fields.some(f => f.type === 'file'),
        hasCaptcha,
        hasPasswordField: form.fields.some(f => f.type === 'password'),
        hasEmailField: form.fields.some(f => f.type === 'email' || /email/i.test(f.name)),
        hasHiddenFields: form.fields.some(f => f.hidden),
        estimatedPurpose,
        suggestedAttacks,
        fieldAnalysis,
    };
}

function analyzeField(field: FormField, formType: FormClassification): FieldAnalysis {
    const name = field.name.toLowerCase();
    const type = field.type.toLowerCase();

    // CSRF / Anti-tamper tokens — skip
    if (field.hidden && /csrf|token|nonce|_token|authenticity|__viewstate|__eventvalidation/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'token', sqliPriority: 0, xssPriority: 0, suggestedPayloadType: 'none' };
    }

    // Credentials
    if (type === 'password') {
        return { name: field.name, type: field.type, classification: 'credential', sqliPriority: formType === 'login' ? 10 : 3, xssPriority: 0, suggestedPayloadType: 'auth-bypass' };
    }

    // Username/email in login form — HIGH PRIORITY SQLi
    if (/user|email|login|account|username/i.test(name) && formType === 'login') {
        return { name: field.name, type: field.type, classification: 'credential', sqliPriority: 10, xssPriority: 2, suggestedPayloadType: 'auth-bypass' };
    }

    // Search fields — HIGH PRIORITY for LIKE SQLi + XSS
    if (/search|query|keyword|q$|term|s$|find/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'injectable', sqliPriority: 9, xssPriority: 8, suggestedPayloadType: 'where-like' };
    }

    // ID/numeric fields — HIGH PRIORITY for numeric SQLi
    if (/id$|_id|num|number|code|ref/i.test(name) && (type === 'hidden' || type === 'number' || type === 'text')) {
        return { name: field.name, type: field.type, classification: 'identifier', sqliPriority: 9, xssPriority: 1, suggestedPayloadType: 'where-numeric' };
    }

    // Sort/order fields — ORDER BY injection
    if (/sort|order|column|dir|direction/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'injectable', sqliPriority: 8, xssPriority: 2, suggestedPayloadType: 'order-by' };
    }

    // Content/text areas — XSS + INSERT SQLi
    if (type === 'textarea' || /message|body|content|comment|description|bio|about/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'content', sqliPriority: 6, xssPriority: 9, suggestedPayloadType: 'insert-string' };
    }

    // Category/type selects — WHERE string SQLi
    if (/category|type|status|role|group|dept/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'choice', sqliPriority: 7, xssPriority: 3, suggestedPayloadType: 'where-string' };
    }

    // Limit/page params — LIMIT injection
    if (/limit|page|offset|per.?page|size|count/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'injectable', sqliPriority: 6, xssPriority: 1, suggestedPayloadType: 'limit' };
    }

    // Date fields
    if (/date|from|to|start|end|created|updated/i.test(name) || type === 'date') {
        return { name: field.name, type: field.type, classification: 'injectable', sqliPriority: 5, xssPriority: 2, suggestedPayloadType: 'where-string' };
    }

    // Name fields — moderate priority
    if (/name|title|label|subject/i.test(name)) {
        return { name: field.name, type: field.type, classification: 'content', sqliPriority: 6, xssPriority: 7, suggestedPayloadType: 'where-string' };
    }

    // File fields
    if (type === 'file') {
        return { name: field.name, type: field.type, classification: 'file', sqliPriority: 0, xssPriority: 3, suggestedPayloadType: 'file-upload' };
    }

    // Hidden fields (non-token) — often contain IDs
    if (field.hidden) {
        return { name: field.name, type: field.type, classification: 'identifier', sqliPriority: 7, xssPriority: 1, suggestedPayloadType: 'where-numeric' };
    }

    // Default: generic injectable
    return { name: field.name, type: field.type, classification: 'injectable', sqliPriority: 5, xssPriority: 5, suggestedPayloadType: 'where-string' };
}

// ============================================================
// PAGE INTELLIGENCE — Understands what every page is
// ============================================================

export function analyzePageIntelligence(url: string, html: string, $: cheerio.CheerioAPI): PageIntelligence {
    const title = $('title').text().trim() || '';
    const pageType = classifyPage(url, title, html, $);

    // ── Classify all forms ──
    const forms: ClassifiedForm[] = [];
    $('form').each((_, el) => {
        const $form = $(el);
        const action = $form.attr('action') || url;
        const method = ($form.attr('method') || 'GET').toUpperCase();
        const enctype = $form.attr('enctype') || 'application/x-www-form-urlencoded';

        const fields: FormField[] = [];
        $form.find('input, textarea, select').each((_, input) => {
            const $input = $(input);
            const name = $input.attr('name');
            if (name) {
                fields.push({
                    name,
                    type: $input.is('textarea') ? 'textarea' : $input.is('select') ? 'select' : ($input.attr('type') || 'text'),
                    value: $input.attr('value') || $input.text() || '',
                    required: $input.attr('required') !== undefined,
                    hidden: $input.attr('type') === 'hidden',
                });
            }
        });

        let resolvedAction = action;
        try { resolvedAction = new URL(action, url).toString(); } catch { /* keep as-is */ }

        const rawForm: DiscoveredForm = { action: resolvedAction, method, fields, enctype };
        forms.push(classifyForm(rawForm, $form, $));
    });

    // ── Discover interactive elements ──
    const interactiveElements: InteractiveElement[] = [];

    // Buttons (not in forms)
    $('button:not(form button), [role="button"], a.btn, a.button, [class*="btn-"], [class*="button"]').each((_, el) => {
        const $el = $(el);
        const text = $el.text().trim().slice(0, 100);
        const href = $el.attr('href');
        const onclick = $el.attr('onclick') || '';
        const dataAction = $el.attr('data-action') || $el.attr('data-url') || $el.attr('data-href') || '';

        interactiveElements.push({
            type: 'button',
            selector: buildSelector($el),
            text,
            url: href || dataAction || undefined,
            attributes: extractAttrs($el),
            attackRelevance: calculateButtonRelevance(text, onclick, dataAction),
            notes: onclick ? `onclick: ${onclick.slice(0, 200)}` : (dataAction ? `data-action: ${dataAction}` : ''),
        });
    });

    // Dropdown menus / navigation
    $('nav a, .navbar a, .menu a, .nav a, [class*="dropdown"] a, [class*="nav-"] a').each((_, el) => {
        const $el = $(el);
        const href = $el.attr('href');
        if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
            interactiveElements.push({
                type: 'link',
                selector: buildSelector($el),
                text: $el.text().trim().slice(0, 100),
                url: href,
                attributes: extractAttrs($el),
                attackRelevance: 3,
                notes: 'Navigation link',
            });
        }
    });

    // Tabs
    $('[role="tab"], [data-toggle="tab"], [data-bs-toggle="tab"], .tab, .nav-tab').each((_, el) => {
        const $el = $(el);
        interactiveElements.push({
            type: 'tab',
            selector: buildSelector($el),
            text: $el.text().trim().slice(0, 100),
            url: $el.attr('href') || $el.attr('data-target') || undefined,
            attributes: extractAttrs($el),
            attackRelevance: 2,
            notes: 'Tab control',
        });
    });

    // Pagination
    $('a[href*="page="], a[href*="p="], a[href*="offset="], .pagination a, [class*="pager"] a').each((_, el) => {
        const $el = $(el);
        interactiveElements.push({
            type: 'pagination',
            selector: buildSelector($el),
            text: $el.text().trim().slice(0, 50),
            url: $el.attr('href') || undefined,
            attributes: extractAttrs($el),
            attackRelevance: 6, // Pagination params are often injectable
            notes: 'Pagination — check for LIMIT/OFFSET SQLi',
        });
    });

    // Sort links
    $('a[href*="sort="], a[href*="order="], a[href*="orderby="], th a, [class*="sort"] a').each((_, el) => {
        const $el = $(el);
        interactiveElements.push({
            type: 'sort',
            selector: buildSelector($el),
            text: $el.text().trim().slice(0, 50),
            url: $el.attr('href') || undefined,
            attributes: extractAttrs($el),
            attackRelevance: 8, // Sort params = ORDER BY injection
            notes: 'Sort control — ORDER BY SQLi target',
        });
    });

    // Modal triggers
    $('[data-toggle="modal"], [data-bs-toggle="modal"], [class*="modal-trigger"]').each((_, el) => {
        const $el = $(el);
        interactiveElements.push({
            type: 'modal-trigger',
            selector: buildSelector($el),
            text: $el.text().trim().slice(0, 100),
            attributes: extractAttrs($el),
            attackRelevance: 4,
            notes: `Modal: ${$el.attr('data-target') || $el.attr('data-bs-target') || ''}`,
        });
    });

    // ── Extract AJAX endpoints from inline JavaScript ──
    const ajaxEndpoints: AjaxEndpoint[] = [];
    const inlineScripts: string[] = [];

    $('script:not([src])').each((_, el) => {
        const code = $(el).html() || '';
        if (code.length > 10) {
            inlineScripts.push(code);

            // Find fetch/XMLHttpRequest/$.ajax URLs
            const patterns = [
                /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/g,
                /\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /XMLHttpRequest[^]*?\.open\s*\(\s*['"`](\w+)['"`]\s*,\s*['"`]([^'"`]+)['"`]/g,
                /axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /['"`](\/api\/[^'"`\s]+)['"`]/g,
                /['"`](\/[a-z0-9_-]+\.php[^'"`\s]*)['"`]/gi,
                /['"`](\/[a-z0-9_-]+\.asp[x]?[^'"`\s]*)['"`]/gi,
                /action\s*[:=]\s*['"`]([^'"`]+\.php[^'"`]*)['"`]/gi,
            ];

            for (const pattern of patterns) {
                let match;
                while ((match = pattern.exec(code)) !== null) {
                    const endpoint = match[2] || match[1];
                    if (endpoint && !endpoint.includes('{{') && !endpoint.startsWith('data:')) {
                        let resolvedUrl = endpoint;
                        try { resolvedUrl = new URL(endpoint, url).toString(); } catch { /* keep relative */ }

                        ajaxEndpoints.push({
                            url: resolvedUrl,
                            method: /post/i.test(match[0]) ? 'POST' : 'GET',
                            params: extractParamsFromUrl(endpoint),
                            source: 'inline-script',
                            confidence: endpoint.startsWith('/') ? 0.9 : 0.7,
                        });
                    }
                }
            }
        }
    });

    // Extract AJAX from onclick attributes
    $('[onclick]').each((_, el) => {
        const onclick = $(el).attr('onclick') || '';
        const urlMatch = onclick.match(/['"`](\/[^'"`\s]+)['"`]/);
        if (urlMatch) {
            let resolvedUrl = urlMatch[1];
            try { resolvedUrl = new URL(urlMatch[1], url).toString(); } catch { /* keep */ }
            ajaxEndpoints.push({
                url: resolvedUrl,
                method: /post/i.test(onclick) ? 'POST' : 'GET',
                params: extractParamsFromUrl(urlMatch[1]),
                source: 'onclick',
                confidence: 0.8,
            });
        }
    });

    // ── Extract data-* URLs ──
    $('[data-url], [data-href], [data-action], [data-src]').each((_, el) => {
        const $el = $(el);
        const dataUrl = $el.attr('data-url') || $el.attr('data-href') || $el.attr('data-action') || $el.attr('data-src') || '';
        if (dataUrl && !dataUrl.startsWith('#') && !dataUrl.startsWith('javascript:')) {
            let resolvedUrl = dataUrl;
            try { resolvedUrl = new URL(dataUrl, url).toString(); } catch { /* keep */ }
            ajaxEndpoints.push({
                url: resolvedUrl,
                method: 'GET',
                params: extractParamsFromUrl(dataUrl),
                source: 'data-attribute',
                confidence: 0.85,
            });
        }
    });

    // ── Extract HTML comments (info leak) ──
    const comments: string[] = [];
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let commentMatch;
    while ((commentMatch = commentRegex.exec(html)) !== null) {
        const comment = commentMatch[1].trim();
        if (comment.length > 5 && comment.length < 500 && !/^\s*(end|\/|if|else|\[)/i.test(comment)) {
            comments.push(comment);
        }
    }

    // ── Hidden inputs not in forms ──
    const hiddenInputs: Array<{ name: string; value: string }> = [];
    $('input[type="hidden"]:not(form input)').each((_, el) => {
        const name = $(el).attr('name');
        const value = $(el).attr('value') || '';
        if (name) hiddenInputs.push({ name, value });
    });

    // ── Detect technologies from HTML ──
    const technologies: string[] = [];
    if (html.includes('wp-content') || html.includes('wp-includes')) technologies.push('WordPress');
    if (html.includes('Joomla')) technologies.push('Joomla');
    if (html.includes('Drupal.settings')) technologies.push('Drupal');
    if ($('meta[name="generator"]').attr('content')?.includes('Laravel')) technologies.push('Laravel');
    if (html.includes('__next')) technologies.push('Next.js');
    if (html.includes('ng-app') || html.includes('ng-controller')) technologies.push('AngularJS');
    if (html.includes('react') || html.includes('__NEXT_DATA__')) technologies.push('React');
    if (html.includes('Vue.') || html.includes('v-bind') || html.includes('v-model')) technologies.push('Vue.js');
    if (html.includes('csrfmiddlewaretoken')) technologies.push('Django');
    if (html.includes('_token') && html.includes('laravel')) technologies.push('Laravel');
    if ($('[class*="shopify"]').length > 0) technologies.push('Shopify');

    // ── Auth detection ──
    const hasAuth = forms.some(f => f.classification === 'login') ||
        /login|signin|sign-in/i.test(url) ||
        $('input[type="password"]').length > 0;

    // ── Admin detection ──
    const hasAdmin = /admin|backend|manager|control.?panel|dashboard|cpanel|wp-admin/i.test(url) ||
        /admin/i.test(title);

    // ── Calculate risk score ──
    const riskScore = calculatePageRisk(forms, interactiveElements, ajaxEndpoints, pageType, hasAuth, hasAdmin);

    // ── Generate attack plan ──
    const attackPlan = generateAttackPlan(url, forms, interactiveElements, ajaxEndpoints, pageType);

    return {
        url,
        title,
        pageType,
        forms,
        interactiveElements,
        ajaxEndpoints: deduplicateEndpoints(ajaxEndpoints),
        hiddenInputs,
        comments,
        inlineScripts: inlineScripts.slice(0, 20),
        technologies,
        hasAuth,
        hasAdmin,
        riskScore,
        attackPlan,
    };
}

// ============================================================
// PAGE CLASSIFIER
// ============================================================

function classifyPage(url: string, title: string, html: string, $: cheerio.CheerioAPI): PageType {
    const combined = `${url} ${title}`.toLowerCase();

    if (/login|signin|sign-in|log.?in/i.test(combined)) return 'login';
    if (/register|signup|sign-up|create.account/i.test(combined)) return 'registration';
    if (/admin|backend|control.?panel|cpanel|wp-admin|manager/i.test(combined)) return 'admin-panel';
    if (/dashboard|overview|home|main/i.test(combined) && $('table, .card, .widget, .stat').length > 2) return 'dashboard';
    if (/settings|preferences|config/i.test(combined)) return 'settings';
    if (/profile|account|my.?page/i.test(combined)) return 'profile';
    if (/search|results|find|query/i.test(combined)) return 'search-results';
    if (/error|404|500|not.found|forbidden/i.test(combined)) return 'error';
    if (/api|swagger|openapi|docs.*api/i.test(combined)) return 'api-docs';
    if (/file|upload|media|gallery/i.test(combined) && $('input[type="file"]').length > 0) return 'file-manager';

    // Detect listing pages (tables, repeating items)
    const tableRows = $('table tbody tr').length;
    const listItems = $('ul li, ol li, .list-item, .item, .card').length;
    if (tableRows > 5 || listItems > 10) return 'listing';

    // Detect detail pages (single item with lots of content)
    const h1Count = $('h1').length;
    if (h1Count === 1 && $('article, .content, .detail, .post').length > 0) return 'detail';

    // Detect static pages (mostly text, no forms, no tables)
    if ($('form').length === 0 && tableRows === 0 && $('p').length > 5) return 'static';

    return 'unknown';
}

// ============================================================
// ATTACK PLAN GENERATOR
// ============================================================

function generateAttackPlan(
    url: string,
    forms: ClassifiedForm[],
    elements: InteractiveElement[],
    ajaxEndpoints: AjaxEndpoint[],
    pageType: PageType,
): AttackStep[] {
    const steps: AttackStep[] = [];
    let priority = 1;

    // Priority 1: Login forms (auth bypass)
    for (const form of forms.filter(f => f.classification === 'login')) {
        const usernameField = form.fields.find(f => /user|email|login/i.test(f.name));
        const passwordField = form.fields.find(f => f.type === 'password');
        if (usernameField) {
            steps.push({
                priority: priority++,
                target: form.action,
                technique: 'sql-auth-bypass',
                reason: `Login form detected → inject username field "${usernameField.name}" with auth bypass payloads`,
                params: [usernameField.name, passwordField?.name || ''].filter(Boolean),
            });
        }
    }

    // Priority 2: Search forms (LIKE/WHERE SQLi + reflected XSS)
    for (const form of forms.filter(f => f.classification === 'search')) {
        const searchField = form.fields.find(f => /search|query|q$|term/i.test(f.name));
        if (searchField) {
            steps.push({
                priority: priority++,
                target: form.action,
                technique: 'sqli-where-like + xss-reflected',
                reason: `Search form → LIKE context SQLi on "${searchField.name}" + reflected XSS`,
                params: [searchField.name],
            });
        }
    }

    // Priority 3: Sort/pagination elements (ORDER BY / LIMIT SQLi)
    for (const el of elements.filter(e => e.type === 'sort' || e.type === 'pagination')) {
        if (el.url) {
            const params = extractParamsFromUrl(el.url);
            steps.push({
                priority: priority++,
                target: el.url,
                technique: el.type === 'sort' ? 'sqli-order-by' : 'sqli-limit-offset',
                reason: `${el.type} control → ${el.type === 'sort' ? 'ORDER BY' : 'LIMIT/OFFSET'} injection`,
                params,
            });
        }
    }

    // Priority 4: File upload forms
    for (const form of forms.filter(f => f.classification === 'upload')) {
        steps.push({
            priority: priority++,
            target: form.action,
            technique: 'file-upload-webshell',
            reason: 'File upload form → test for webshell upload, path traversal in filename',
            params: form.fields.filter(f => f.type === 'file').map(f => f.name),
        });
    }

    // Priority 5: AJAX endpoints discovered from JS
    for (const ep of ajaxEndpoints.filter(e => e.confidence > 0.7)) {
        steps.push({
            priority: priority++,
            target: ep.url,
            technique: 'sqli-where-string + xss-reflected',
            reason: `Hidden AJAX endpoint found in ${ep.source} → test all params`,
            params: ep.params,
        });
    }

    // Priority 6: Comment/contact forms (stored XSS + INSERT SQLi)
    for (const form of forms.filter(f => f.classification === 'comment' || f.classification === 'contact')) {
        const injectableFields = form.fieldAnalysis.filter(f => f.xssPriority >= 7 || f.sqliPriority >= 6);
        steps.push({
            priority: priority++,
            target: form.action,
            technique: 'xss-stored + sqli-insert',
            reason: `${form.classification} form → stored XSS + INSERT SQLi`,
            params: injectableFields.map(f => f.name),
        });
    }

    // Priority 7: Profile/settings forms (UPDATE SQLi + CSRF)
    for (const form of forms.filter(f => f.classification === 'profile-edit' || f.classification === 'settings')) {
        steps.push({
            priority: priority++,
            target: form.action,
            technique: 'sqli-update + csrf + mass-assignment',
            reason: `${form.classification} form → UPDATE SQLi, CSRF, mass assignment`,
            params: form.fieldAnalysis.filter(f => f.sqliPriority >= 5).map(f => f.name),
        });
    }

    // Priority 8: Admin pages
    if (pageType === 'admin-panel') {
        for (const form of forms.filter(f => f.classification === 'admin-action')) {
            steps.push({
                priority: priority++,
                target: form.action,
                technique: 'csrf-admin + idor + privilege-escalation',
                reason: 'Admin action form → CSRF, IDOR, privilege escalation',
                params: form.fields.map(f => f.name),
            });
        }
    }

    // Priority 9: Filter forms
    for (const form of forms.filter(f => f.classification === 'filter')) {
        const filterFields = form.fields.filter(f => !f.hidden && !/csrf|token/i.test(f.name));
        steps.push({
            priority: priority++,
            target: form.action,
            technique: 'sqli-order-by + sqli-where-string',
            reason: 'Filter form → test ORDER BY, WHERE, and LIMIT injection on filter params',
            params: filterFields.map(f => f.name),
        });
    }

    // Priority 10: All remaining forms with injectable fields
    for (const form of forms.filter(f => !['login', 'search', 'upload', 'comment', 'contact', 'filter'].includes(f.classification))) {
        const highPriFields = form.fieldAnalysis.filter(f => f.sqliPriority >= 6 || f.xssPriority >= 6);
        if (highPriFields.length > 0) {
            steps.push({
                priority: priority++,
                target: form.action,
                technique: 'sqli + xss',
                reason: `${form.classification} form with ${highPriFields.length} injectable fields`,
                params: highPriFields.map(f => f.name),
            });
        }
    }

    return steps.sort((a, b) => a.priority - b.priority);
}

// ============================================================
// HELPERS
// ============================================================

function calculatePageRisk(
    forms: ClassifiedForm[],
    elements: InteractiveElement[],
    ajaxEndpoints: AjaxEndpoint[],
    pageType: PageType,
    hasAuth: boolean,
    hasAdmin: boolean,
): number {
    let score = 0;

    // Page type risk
    const typeRisk: Record<string, number> = {
        'login': 30, 'admin-panel': 35, 'file-manager': 30, 'search-results': 20,
        'dashboard': 15, 'registration': 20, 'settings': 15, 'profile': 10,
        'listing': 10, 'detail': 5, 'api-docs': 15, 'static': 2, 'error': 5, 'unknown': 5,
    };
    score += typeRisk[pageType] || 5;

    // Form risk
    for (const form of forms) {
        const formRisk: Record<string, number> = {
            critical: 20, high: 12, medium: 6, low: 3, skip: 0,
        };
        score += formRisk[form.attackPriority] || 5;
    }

    // Interactive elements
    score += Math.min(elements.filter(e => e.attackRelevance >= 6).length * 3, 15);

    // AJAX endpoints
    score += Math.min(ajaxEndpoints.length * 2, 10);

    // Auth/Admin bonus
    if (hasAuth) score += 10;
    if (hasAdmin) score += 15;

    return Math.min(score, 100);
}

function calculateButtonRelevance(text: string, onclick: string, dataAction: string): number {
    const combined = `${text} ${onclick} ${dataAction}`.toLowerCase();
    if (/delete|remove|destroy|drop/i.test(combined)) return 9;
    if (/admin|manage|export|backup/i.test(combined)) return 8;
    if (/submit|save|update|edit|modify/i.test(combined)) return 7;
    if (/search|filter|sort/i.test(combined)) return 6;
    if (/login|signin|register/i.test(combined)) return 5;
    if (/load|fetch|ajax|api/i.test(combined)) return 7;
    if (onclick || dataAction) return 5;
    return 3;
}

function buildSelector($el: cheerio.Cheerio<any>): string {
    const id = $el.attr('id');
    if (id) return `#${id}`;
    const cls = $el.attr('class')?.split(/\s+/).filter(c => c.length > 0 && c.length < 30).slice(0, 2).join('.');
    const tag = $el.prop('tagName')?.toLowerCase() || 'div';
    return cls ? `${tag}.${cls}` : tag;
}

function extractAttrs($el: cheerio.Cheerio<any>): Record<string, string> {
    const attrs: Record<string, string> = {};
    const el = $el[0];
    if (el && 'attribs' in el) {
        const attribs = (el as any).attribs || {};
        for (const [k, v] of Object.entries(attribs)) {
            if (['id', 'class', 'href', 'action', 'method', 'onclick', 'data-url', 'data-action', 'data-href', 'data-target', 'role', 'type'].includes(k)) {
                attrs[k] = String(v).slice(0, 200);
            }
        }
    }
    return attrs;
}

function extractParamsFromUrl(url: string): string[] {
    try {
        const parsed = new URL(url, 'http://placeholder');
        return Array.from(parsed.searchParams.keys());
    } catch {
        // Try regex for query params
        const matches = url.match(/[?&]([^=&]+)=/g);
        return matches ? matches.map(m => m.replace(/[?&=]/g, '')) : [];
    }
}

function deduplicateEndpoints(endpoints: AjaxEndpoint[]): AjaxEndpoint[] {
    const seen = new Set<string>();
    return endpoints.filter(ep => {
        const key = `${ep.method}:${ep.url}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}
