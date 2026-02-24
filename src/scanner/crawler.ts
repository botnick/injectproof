// InjectProof — Web Crawler
// Hybrid crawler with HTML parsing + link discovery + parameter extraction

import * as cheerio from 'cheerio';
import type { CrawledEndpoint, DiscoveredParam, DiscoveredForm, FormField } from '@/types';
import { normalizeUrl, isSameOrigin, parseUrl } from '@/lib/utils';

export interface CrawlConfig {
    baseUrl: string;
    maxDepth: number;
    maxUrls: number;
    requestTimeout: number;
    rateLimit: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    excludePaths?: string[];
    includePaths?: string[];
    authHeaders?: Record<string, string>;
    /** Enable headless browser crawling (Lightpanda/Chrome via CDP) */
    enableHeadless?: boolean;
    /** CDP WebSocket endpoint (e.g. ws://127.0.0.1:9222) */
    cdpEndpoint?: string;
}

export interface CrawlResult {
    endpoints: CrawledEndpoint[];
    discoveredUrls: string[];
    errors: string[];
    duration: number;
    /** Number of pages rendered via headless browser */
    jsRenderedPages?: number;
    /** Network requests intercepted during headless crawl */
    interceptedRequests?: Array<{ url: string; method: string; resourceType: string }>;
}

/**
 * Crawl a web application and discover endpoints, parameters, and forms
 */
export async function crawlTarget(config: CrawlConfig): Promise<CrawlResult> {
    const startTime = Date.now();
    const visited = new Set<string>();
    const queue: Array<{ url: string; depth: number; source: string }> = [];
    const endpoints: CrawledEndpoint[] = [];
    const errors: string[] = [];
    const discoveredUrls: string[] = [];

    // Seed the queue
    queue.push({ url: normalizeUrl(config.baseUrl), depth: 0, source: 'seed' });

    // Rate limiter
    const delay = Math.max(100, Math.floor(1000 / config.rateLimit));

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
            // Fetch the page
            const headers: Record<string, string> = {
                'User-Agent': config.userAgent,
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                ...config.customHeaders,
                ...config.authHeaders,
            };

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.requestTimeout);

            const response = await fetch(normalizedUrl, {
                method: 'GET',
                headers,
                redirect: 'follow',
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            const contentType = response.headers.get('content-type') || '';
            if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
                // Still record as an endpoint but don't parse
                endpoints.push({
                    url: normalizedUrl,
                    method: 'GET',
                    params: extractQueryParams(normalizedUrl),
                    forms: [],
                    headers: Object.fromEntries(response.headers.entries()),
                    depth: item.depth,
                    source: item.source,
                });
                continue;
            }

            const html = await response.text();
            const $ = cheerio.load(html);

            // Extract links
            const links = extractLinks($, normalizedUrl);
            for (const link of links) {
                if (!visited.has(normalizeUrl(link))) {
                    queue.push({ url: link, depth: item.depth + 1, source: normalizedUrl });
                }
            }

            // Extract forms
            const forms = extractForms($, normalizedUrl);

            // Extract params
            const params = [
                ...extractQueryParams(normalizedUrl),
                ...extractMetaParams($),
                ...extractInputParams($),
            ];

            // Extract script sources (for JS analysis)
            const scripts = extractScriptSources($, normalizedUrl);
            for (const script of scripts) {
                if (!visited.has(normalizeUrl(script))) {
                    queue.push({ url: script, depth: item.depth + 1, source: normalizedUrl });
                }
            }

            // Build endpoint
            endpoints.push({
                url: normalizedUrl,
                method: 'GET',
                params,
                forms,
                headers: Object.fromEntries(response.headers.entries()),
                depth: item.depth,
                source: item.source,
            });

            // Add form action URLs to queue
            for (const form of forms) {
                if (form.action && !visited.has(normalizeUrl(form.action))) {
                    queue.push({ url: form.action, depth: item.depth + 1, source: normalizedUrl });
                    // Also add POST endpoint for the form
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
                        headers: Object.fromEntries(response.headers.entries()),
                        depth: item.depth + 1,
                        source: normalizedUrl,
                    });
                }
            }
        } catch (error) {
            const errMsg = error instanceof Error ? error.message : String(error);
            errors.push(`[Crawler] Error fetching ${normalizedUrl}: ${errMsg}`);
        }

        // Rate limiting delay
        await new Promise(resolve => setTimeout(resolve, delay));
    }

    return {
        endpoints,
        discoveredUrls,
        errors,
        duration: Date.now() - startTime,
    };
}

// ============================================================
// Helper Functions
// ============================================================

/** Extract all links from HTML */
function extractLinks($: cheerio.CheerioAPI, baseUrl: string): string[] {
    const links: string[] = [];

    // <a href="...">
    $('a[href]').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
            const resolved = resolveUrl(href, baseUrl);
            if (resolved) links.push(resolved);
        }
    });

    // <area href="...">
    $('area[href]').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
            const resolved = resolveUrl(href, baseUrl);
            if (resolved) links.push(resolved);
        }
    });

    // <frame src="...">, <iframe src="...">
    $('frame[src], iframe[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
            const resolved = resolveUrl(src, baseUrl);
            if (resolved) links.push(resolved);
        }
    });

    // <meta http-equiv="refresh" content="...;url=...">
    $('meta[http-equiv="refresh"]').each((_, el) => {
        const content = $(el).attr('content') || '';
        const match = content.match(/url=["']?([^"'\s;]+)/i);
        if (match) {
            const resolved = resolveUrl(match[1], baseUrl);
            if (resolved) links.push(resolved);
        }
    });

    return Array.from(new Set(links));
}

/** Extract forms from HTML */
function extractForms($: cheerio.CheerioAPI, baseUrl: string): DiscoveredForm[] {
    const forms: DiscoveredForm[] = [];

    $('form').each((_, el) => {
        const $form = $(el);
        const action = $form.attr('action') || baseUrl;
        const method = ($form.attr('method') || 'GET').toUpperCase();
        const enctype = $form.attr('enctype') || 'application/x-www-form-urlencoded';

        const fields: FormField[] = [];

        // Input elements
        $form.find('input').each((_, input) => {
            const $input = $(input);
            const name = $input.attr('name');
            if (name) {
                fields.push({
                    name,
                    type: $input.attr('type') || 'text',
                    value: $input.attr('value') || '',
                    required: $input.attr('required') !== undefined,
                    hidden: $input.attr('type') === 'hidden',
                });
            }
        });

        // Textarea elements
        $form.find('textarea').each((_, textarea) => {
            const $textarea = $(textarea);
            const name = $textarea.attr('name');
            if (name) {
                fields.push({
                    name,
                    type: 'textarea',
                    value: $textarea.text(),
                    required: $textarea.attr('required') !== undefined,
                    hidden: false,
                });
            }
        });

        // Select elements
        $form.find('select').each((_, select) => {
            const $select = $(select);
            const name = $select.attr('name');
            if (name) {
                const firstOption = $select.find('option:first').attr('value') || '';
                fields.push({
                    name,
                    type: 'select',
                    value: firstOption,
                    required: $select.attr('required') !== undefined,
                    hidden: false,
                });
            }
        });

        forms.push({
            action: resolveUrl(action, baseUrl) || action,
            method,
            fields,
            enctype,
        });
    });

    return forms;
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

/** Extract meta-based parameters */
function extractMetaParams($: cheerio.CheerioAPI): DiscoveredParam[] {
    const params: DiscoveredParam[] = [];

    // CSRF tokens in meta tags
    $('meta[name*="csrf"], meta[name*="token"]').each((_, el) => {
        const name = $(el).attr('name') || '';
        const content = $(el).attr('content') || '';
        if (name && content) {
            params.push({ name, type: 'header', value: content });
        }
    });

    return params;
}

/** Extract input parameters outside of forms */
function extractInputParams($: cheerio.CheerioAPI): DiscoveredParam[] {
    const params: DiscoveredParam[] = [];

    // Standalone inputs (not in forms)
    $('input:not(form input)').each((_, el) => {
        const name = $(el).attr('name');
        if (name) {
            params.push({
                name,
                type: 'body',
                value: $(el).attr('value') || '',
                required: $(el).attr('required') !== undefined,
            });
        }
    });

    return params;
}

/** Extract script sources */
function extractScriptSources($: cheerio.CheerioAPI, baseUrl: string): string[] {
    const sources: string[] = [];

    $('script[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
            const resolved = resolveUrl(src, baseUrl);
            if (resolved) sources.push(resolved);
        }
    });

    return sources;
}

/** Resolve relative URL to absolute */
function resolveUrl(url: string, baseUrl: string): string | null {
    try {
        // Skip data:, javascript:, mailto:, tel:, #
        if (/^(data|javascript|mailto|tel):/i.test(url) || url.startsWith('#')) {
            return null;
        }
        return new URL(url, baseUrl).toString();
    } catch {
        return null;
    }
}
