// VibeCode — Headless Crawler (JS-aware)
// Uses headless browser via 4-tier auto-detection to crawl JS-rendered pages
// Discovers dynamic links, AJAX endpoints, forms, and parameters
// that static crawling (fetch + cheerio) would miss entirely

import type { Page } from 'puppeteer';
import type { CrawledEndpoint, DiscoveredParam, DiscoveredForm, FormField } from '@/types';
import { normalizeUrl, isSameOrigin, parseUrl } from '@/lib/utils';
import { HeadlessBrowser, HeadlessBrowserError, type HeadlessBrowserConfig } from './headless-browser';
import type { CrawlConfig, CrawlResult } from './crawler';

// ============================================================
// Extended result with headless-specific data
// ============================================================

export interface HeadlessCrawlResult extends CrawlResult {
    /** Number of pages that required JS rendering */
    jsRenderedPages: number;
    /** Network requests intercepted during crawl (AJAX / fetch / XHR) */
    interceptedRequests: InterceptedRequest[];
    /** DOM snapshots keyed by URL */
    domSnapshots: Record<string, string>;
    /** Screenshot base64 data keyed by URL */
    screenshots: Record<string, string>;
}

export interface InterceptedRequest {
    url: string;
    method: string;
    resourceType: string;
    postData?: string;
    headers: Record<string, string>;
}

// ============================================================
// Main headless crawl function
// ============================================================

/**
 * Crawl a web application using a headless browser.
 *
 * **3-tier auto-detection:**
 * 1. 🐼 Lightpanda binary (Linux) — fastest, lightest
 * 2. 🌐 Remote CDP endpoint — if `cdpEndpoint` provided
 * 3. 🖥️ OS browser (last resort) — Edge (Win), Chrome (Linux/Mac)
 *
 * Discovers dynamically injected links, AJAX endpoints, forms, and parameters
 * that static crawling (fetch + cheerio) would miss entirely.
 */
export async function crawlTargetHeadless(
    config: CrawlConfig,
): Promise<HeadlessCrawlResult> {
    const startTime = Date.now();
    const visited = new Set<string>();
    const queue: Array<{ url: string; depth: number; source: string }> = [];
    const endpoints: CrawledEndpoint[] = [];
    const errors: string[] = [];
    const discoveredUrls: string[] = [];
    const interceptedRequests: InterceptedRequest[] = [];
    const domSnapshots: Record<string, string> = {};
    const screenshots: Record<string, string> = {};
    let jsRenderedPages = 0;

    // Seed the queue
    queue.push({ url: normalizeUrl(config.baseUrl), depth: 0, source: 'seed' });

    // Rate limiter delay
    const delay = Math.max(100, Math.floor(1000 / config.rateLimit));

    // Setup headless browser — auto-detects platform
    // Linux: uses cdpEndpoint (Lightpanda/remote Chrome)
    // Windows: auto-launches Edge/Chrome if no endpoint
    const browserConfig: HeadlessBrowserConfig = {
        cdpEndpoint: config.cdpEndpoint,
        allowLocalFallback: true,
        navigationTimeout: config.requestTimeout,
        userAgent: config.userAgent,
        extraHeaders: {
            ...config.customHeaders,
            ...config.authHeaders,
        },
    };

    const browser = new HeadlessBrowser(browserConfig);

    try {
        await browser.connect();
    } catch (error) {
        const msg = error instanceof HeadlessBrowserError
            ? error.message
            : `Headless browser connection failed: ${String(error)}`;
        errors.push(msg);
        return {
            endpoints,
            discoveredUrls,
            errors,
            duration: Date.now() - startTime,
            jsRenderedPages: 0,
            interceptedRequests: [],
            domSnapshots: {},
            screenshots: {},
        };
    }

    try {
        while (queue.length > 0 && visited.size < config.maxUrls) {
            const item = queue.shift();
            if (!item) break;

            const normalizedUrl = normalizeUrl(item.url);
            if (visited.has(normalizedUrl)) continue;
            if (item.depth > config.maxDepth) continue;
            if (!isSameOrigin(normalizedUrl, config.baseUrl)) continue;

            // Check exclude/include paths
            const urlPath = parseUrl(normalizedUrl)?.pathname || '';
            if (config.excludePaths?.some(p => urlPath.startsWith(p))) continue;
            if (config.includePaths?.length && !config.includePaths.some(p => urlPath.startsWith(p))) continue;

            visited.add(normalizedUrl);
            discoveredUrls.push(normalizedUrl);

            try {
                // Create page with network interception
                const page = await browser.newPage();
                const pageRequests: InterceptedRequest[] = [];

                // Intercept network requests to discover AJAX endpoints
                await page.setRequestInterception(true);
                page.on('request', (req) => {
                    const reqUrl = req.url();
                    const method = req.method();
                    const resourceType = req.resourceType();

                    // Track XHR/fetch requests — these are dynamic API calls
                    if (
                        resourceType === 'xhr' ||
                        resourceType === 'fetch' ||
                        resourceType === 'websocket'
                    ) {
                        const intercepted: InterceptedRequest = {
                            url: reqUrl,
                            method,
                            resourceType,
                            headers: req.headers(),
                        };
                        if (method !== 'GET') {
                            intercepted.postData = req.postData();
                        }
                        pageRequests.push(intercepted);
                    }

                    req.continue();
                });

                // Navigate
                await page.goto(normalizedUrl, {
                    waitUntil: 'networkidle2',
                    timeout: config.requestTimeout,
                });

                jsRenderedPages++;

                // Wait a bit for late JS to execute
                await sleep(500);

                // Get rendered HTML
                const html = await page.content();

                // Capture DOM snapshot
                domSnapshots[normalizedUrl] = html;

                // Capture screenshot (only for first 20 pages to save memory)
                if (Object.keys(screenshots).length < 20) {
                    try {
                        screenshots[normalizedUrl] = await browser.captureScreenshot(page);
                    } catch {
                        // Screenshot failure is non-critical
                    }
                }

                // Extract links from rendered DOM
                const links = await extractRenderedLinks(page, normalizedUrl);
                for (const link of links) {
                    if (!visited.has(normalizeUrl(link))) {
                        queue.push({ url: link, depth: item.depth + 1, source: normalizedUrl });
                    }
                }

                // Extract forms from rendered DOM
                const forms = await extractRenderedForms(page, normalizedUrl);

                // Extract params
                const params = [
                    ...extractQueryParams(normalizedUrl),
                    ...(await extractRenderedInputParams(page)),
                    ...(await extractRenderedMetaParams(page)),
                ];

                // Collect response headers from the page's main response
                const responseHeaders: Record<string, string> = {};
                const mainResponse = await page.goto(normalizedUrl, {
                    waitUntil: 'domcontentloaded',
                    timeout: config.requestTimeout,
                }).catch(() => null);

                if (mainResponse) {
                    const headers = mainResponse.headers();
                    for (const [key, value] of Object.entries(headers)) {
                        responseHeaders[key] = value;
                    }
                }

                // Build endpoint
                endpoints.push({
                    url: normalizedUrl,
                    method: 'GET',
                    params,
                    forms,
                    headers: responseHeaders,
                    depth: item.depth,
                    source: item.source,
                });

                // Add intercepted AJAX endpoints as separate endpoints
                for (const req of pageRequests) {
                    if (isSameOrigin(req.url, config.baseUrl) && !visited.has(normalizeUrl(req.url))) {
                        const ajaxParams: DiscoveredParam[] = extractQueryParams(req.url);

                        // Parse POST body params if available
                        if (req.postData) {
                            try {
                                const jsonBody = JSON.parse(req.postData);
                                for (const key of Object.keys(jsonBody)) {
                                    ajaxParams.push({
                                        name: key,
                                        type: 'json',
                                        value: String(jsonBody[key]),
                                    });
                                }
                            } catch {
                                // Form-encoded body
                                const bodyParams = new URLSearchParams(req.postData);
                                bodyParams.forEach((value, name) => {
                                    ajaxParams.push({ name, type: 'body', value });
                                });
                            }
                        }

                        endpoints.push({
                            url: req.url,
                            method: req.method,
                            params: ajaxParams,
                            forms: [],
                            headers: req.headers,
                            depth: item.depth + 1,
                            source: normalizedUrl,
                        });
                    }
                }

                // Add form action URLs to queue
                for (const form of forms) {
                    if (form.action && !visited.has(normalizeUrl(form.action))) {
                        queue.push({ url: form.action, depth: item.depth + 1, source: normalizedUrl });
                        endpoints.push({
                            url: form.action,
                            method: form.method.toUpperCase(),
                            params: form.fields.map(f => ({
                                name: f.name,
                                type: 'body' as const,
                                value: f.value,
                                required: f.required,
                            })),
                            forms: [form],
                            headers: responseHeaders,
                            depth: item.depth + 1,
                            source: normalizedUrl,
                        });
                    }
                }

                // Store intercepted requests
                interceptedRequests.push(...pageRequests);

                // Close the page
                await browser.closePage(page);

            } catch (error) {
                const errMsg = error instanceof Error ? error.message : String(error);
                errors.push(`[HeadlessCrawler] Error on ${normalizedUrl}: ${errMsg}`);
            }

            // Rate limiting
            await sleep(delay);
        }
    } finally {
        await browser.disconnect();
    }

    return {
        endpoints,
        discoveredUrls,
        errors,
        duration: Date.now() - startTime,
        jsRenderedPages,
        interceptedRequests,
        domSnapshots,
        screenshots,
    };
}

// ============================================================
// DOM extraction helpers (run inside Puppeteer page context)
// ============================================================

/** Extract all links from the rendered DOM */
async function extractRenderedLinks(page: Page, baseUrl: string): Promise<string[]> {
    const rawLinks = await page.evaluate(() => {
        const links: string[] = [];

        // <a href="...">
        document.querySelectorAll('a[href]').forEach(el => {
            const href = el.getAttribute('href');
            if (href) links.push(href);
        });

        // <area href="...">
        document.querySelectorAll('area[href]').forEach(el => {
            const href = el.getAttribute('href');
            if (href) links.push(href);
        });

        // <frame src="...">, <iframe src="...">
        document.querySelectorAll('frame[src], iframe[src]').forEach(el => {
            const src = el.getAttribute('src');
            if (src) links.push(src);
        });

        // data-href, data-url, data-link attributes (common in SPAs)
        document.querySelectorAll('[data-href], [data-url], [data-link]').forEach(el => {
            const href = el.getAttribute('data-href')
                || el.getAttribute('data-url')
                || el.getAttribute('data-link');
            if (href) links.push(href);
        });

        // onclick handlers with window.location or href patterns
        document.querySelectorAll('[onclick]').forEach(el => {
            const onclick = el.getAttribute('onclick') || '';
            const urlMatch = onclick.match(/(?:location\.href|window\.open|location\.assign|location\.replace)\s*\(\s*['"]([^'"]+)['"]/i);
            if (urlMatch?.[1]) links.push(urlMatch[1]);
        });

        return links;
    });

    // Resolve relative URLs
    const resolvedLinks: string[] = [];
    for (const link of rawLinks) {
        const resolved = resolveUrl(link, baseUrl);
        if (resolved) resolvedLinks.push(resolved);
    }

    return Array.from(new Set(resolvedLinks));
}

/** Extract forms from the rendered DOM */
async function extractRenderedForms(page: Page, baseUrl: string): Promise<DiscoveredForm[]> {
    const rawForms = await page.evaluate(() => {
        const forms: Array<{
            action: string;
            method: string;
            enctype: string;
            fields: Array<{
                name: string;
                type: string;
                value: string;
                required: boolean;
                hidden: boolean;
            }>;
        }> = [];

        document.querySelectorAll('form').forEach(form => {
            const fields: typeof forms[0]['fields'] = [];

            // Inputs
            form.querySelectorAll('input').forEach(input => {
                const name = input.getAttribute('name');
                if (name) {
                    fields.push({
                        name,
                        type: input.getAttribute('type') || 'text',
                        value: input.getAttribute('value') || '',
                        required: input.hasAttribute('required'),
                        hidden: input.getAttribute('type') === 'hidden',
                    });
                }
            });

            // Textareas
            form.querySelectorAll('textarea').forEach(ta => {
                const name = ta.getAttribute('name');
                if (name) {
                    fields.push({
                        name,
                        type: 'textarea',
                        value: ta.textContent || '',
                        required: ta.hasAttribute('required'),
                        hidden: false,
                    });
                }
            });

            // Selects
            form.querySelectorAll('select').forEach(select => {
                const name = select.getAttribute('name');
                if (name) {
                    const firstOpt = select.querySelector('option');
                    fields.push({
                        name,
                        type: 'select',
                        value: firstOpt?.getAttribute('value') || '',
                        required: select.hasAttribute('required'),
                        hidden: false,
                    });
                }
            });

            forms.push({
                action: form.getAttribute('action') || window.location.href,
                method: (form.getAttribute('method') || 'GET').toUpperCase(),
                enctype: form.getAttribute('enctype') || 'application/x-www-form-urlencoded',
                fields,
            });
        });

        return forms;
    });

    // Resolve form action URLs
    return rawForms.map(f => ({
        ...f,
        action: resolveUrl(f.action, baseUrl) || f.action,
        fields: f.fields as FormField[],
    }));
}

/** Extract standalone input params from rendered DOM */
async function extractRenderedInputParams(page: Page): Promise<DiscoveredParam[]> {
    return page.evaluate(() => {
        const params: Array<{ name: string; type: string; value: string; required: boolean }> = [];

        // Inputs outside forms
        document.querySelectorAll('input:not(form input)').forEach(el => {
            const name = el.getAttribute('name');
            if (name) {
                params.push({
                    name,
                    type: 'body',
                    value: el.getAttribute('value') || '',
                    required: el.hasAttribute('required'),
                });
            }
        });

        return params;
    }) as Promise<DiscoveredParam[]>;
}

/** Extract CSRF/token meta params from rendered DOM */
async function extractRenderedMetaParams(page: Page): Promise<DiscoveredParam[]> {
    return page.evaluate(() => {
        const params: Array<{ name: string; type: string; value: string }> = [];

        document.querySelectorAll('meta[name*="csrf"], meta[name*="token"], meta[name*="nonce"]').forEach(el => {
            const name = el.getAttribute('name') || '';
            const content = el.getAttribute('content') || '';
            if (name && content) {
                params.push({ name, type: 'header', value: content });
            }
        });

        return params;
    }) as Promise<DiscoveredParam[]>;
}

/** Extract query parameters from URL */
function extractQueryParams(url: string): DiscoveredParam[] {
    const parsed = parseUrl(url);
    if (!parsed) return [];

    const params: DiscoveredParam[] = [];
    parsed.searchParams.forEach((value, name) => {
        params.push({ name, type: 'query', value });
    });

    return params;
}

// ============================================================
// Utilities
// ============================================================

/** Resolve relative URL to absolute */
function resolveUrl(url: string, baseUrl: string): string | null {
    try {
        if (/^(data|javascript|mailto|tel):/i.test(url) || url.startsWith('#')) {
            return null;
        }
        return new URL(url, baseUrl).toString();
    } catch {
        return null;
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
