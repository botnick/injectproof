// VibeCode — Vulnerability Detectors
// All detection modules consolidated: XSS, SQLi, SSRF, Headers, Info Disclosure,
// Path Traversal, Open Redirect, CORS, Auth Issues, JWT, Command Injection, SSTI

import type { CrawledEndpoint, DetectorResult, Confidence } from '@/types';
import {
    getXssPayloads, getSqliPayloads, getSsrfPayloads,
    getPathTraversalPayloads, getOpenRedirectPayloads,
    getCmdInjectionPayloads, getSstiPayloads,
    SECURITY_HEADERS_CHECKLIST, INFO_DISCLOSURE_HEADERS,
    CORS_TEST_ORIGINS, generateProbeToken,
} from '@/scanner/payloads';
import { buildRequestString, buildResponseString } from '@/lib/utils';
import { COMMON_CVSS_VECTORS, calculateCvssScore, generateCvssVector } from '@/lib/cvss';
import { getCweEntry } from '@/lib/cwe-database';
import { deepExploitSqli } from '@/scanner/sqli-exploiter';

interface DetectorConfig {
    baseUrl: string;
    requestTimeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
}

// ============================================================
// HELPER: Make test request
// ============================================================

async function makeRequest(
    url: string,
    method: string,
    config: DetectorConfig,
    body?: string,
    contentType?: string,
    extraHeaders?: Record<string, string>,
): Promise<{ status: number; headers: Record<string, string>; body: string; time: number; requestStr: string; responseStr: string } | null> {
    try {
        const headers: Record<string, string> = {
            'User-Agent': config.userAgent,
            ...config.customHeaders,
            ...config.authHeaders,
            ...extraHeaders,
        };
        if (contentType) headers['Content-Type'] = contentType;

        const startTime = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.requestTimeout);

        const fetchOpts: RequestInit = {
            method,
            headers,
            signal: controller.signal,
            redirect: 'manual',
        };

        if (body && method !== 'GET' && method !== 'HEAD') {
            fetchOpts.body = body;
        }

        const response = await fetch(url, fetchOpts);
        clearTimeout(timeoutId);

        const responseTime = Date.now() - startTime;
        const responseBody = await response.text();
        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((value, key) => {
            responseHeaders[key] = value;
        });

        const requestStr = buildRequestString(method, url, headers, body);
        const responseStr = buildResponseString(response.status, responseHeaders, responseBody);

        return {
            status: response.status,
            headers: responseHeaders,
            body: responseBody,
            time: responseTime,
            requestStr,
            responseStr,
        };
    } catch {
        return null;
    }
}

// ============================================================
// XSS DETECTOR
// ============================================================

export async function detectXss(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const probeToken = generateProbeToken();
    const payloads = getXssPayloads(probeToken);

    // Test each parameter
    const params = endpoint.params.filter(p => p.type === 'query' || p.type === 'body');

    for (const param of params) {
        for (const payload of payloads.slice(0, 10)) { // Limit for performance
            let testUrl = endpoint.url;
            let testBody: string | undefined;

            if (param.type === 'query') {
                const url = new URL(endpoint.url);
                url.searchParams.set(param.name, payload);
                testUrl = url.toString();
            } else {
                testBody = `${param.name}=${encodeURIComponent(payload)}`;
            }

            const response = await makeRequest(
                testUrl,
                param.type === 'query' ? 'GET' : 'POST',
                config,
                testBody,
                testBody ? 'application/x-www-form-urlencoded' : undefined,
            );

            if (!response) continue;

            // Check if payload is reflected in response
            const isReflected = response.body.includes(payload) ||
                response.body.includes(payload.replace(/'/g, '&#039;').replace(/"/g, '&quot;'));

            // Check for unencoded reflection (actual XSS)
            const dangerousReflection = response.body.includes(`<script>`) && response.body.includes(probeToken);
            const eventHandlerReflection = response.body.includes(`onerror=`) && response.body.includes(probeToken);
            const svgReflection = response.body.includes(`<svg`) && response.body.includes(probeToken);

            if (isReflected && (dangerousReflection || eventHandlerReflection || svgReflection)) {
                const cwe = getCweEntry('CWE-79');
                const cvssMetrics = COMMON_CVSS_VECTORS.xss_reflected;
                const cvssScore = calculateCvssScore(cvssMetrics);

                results.push({
                    found: true,
                    title: `Reflected XSS in parameter "${param.name}"`,
                    description: `The parameter "${param.name}" at ${endpoint.url} reflects user input without proper encoding, allowing JavaScript execution in the victim's browser.`,
                    category: 'xss',
                    severity: cvssScore >= 7 ? 'high' : 'medium',
                    confidence: dangerousReflection ? 'high' : 'medium',
                    cweId: 'CWE-79',
                    cweTitle: cwe?.title,
                    cvssVector: generateCvssVector(cvssMetrics),
                    cvssScore,
                    affectedUrl: endpoint.url,
                    httpMethod: param.type === 'query' ? 'GET' : 'POST',
                    parameter: param.name,
                    parameterType: param.type,
                    injectionPoint: 'reflected',
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    responseTime: response.time,
                    impact: 'An attacker can execute arbitrary JavaScript in the context of the victim\'s browser, potentially stealing session tokens, performing actions on behalf of the user, or redirecting to malicious sites.',
                    technicalDetail: `The payload "${payload}" was injected into the "${param.name}" parameter and reflected in the HTTP response without proper output encoding. The response contained executable JavaScript/HTML.`,
                    remediation: cwe?.remediation || 'Apply context-appropriate output encoding. Use Content Security Policy headers.',
                    reproductionSteps: [
                        `Navigate to: ${endpoint.url}`,
                        `Inject the payload into the "${param.name}" parameter: ${payload}`,
                        `Observe that the payload is reflected in the response and the JavaScript executes`,
                    ],
                    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
                    mappedOwasp: ['A03:2021'],
                    mappedOwaspAsvs: ['V5.3.3', 'V5.3.6'],
                    mappedNist: ['SI-10', 'SI-15'],
                });
                break; // Found XSS for this param, move to next
            }
        }
    }

    return results;
}

// ============================================================
// SQL INJECTION DETECTOR
// ============================================================

export async function detectSqli(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const payloads = getSqliPayloads();

    const SQL_ERROR_PATTERNS = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /MySqlException/i,
        /valid MySQL result/i,
        /PostgreSQL.*ERROR/i,
        /pg_query\(\)/i,
        /pg_exec\(\)/i,
        /Warning.*pg_/i,
        /ORA-\d{5}/i,
        /Oracle.*Driver/i,
        /Microsoft.*ODBC.*SQL Server/i,
        /SQLSTATE\[\w+\]/i,
        /SQLite.*error/i,
        /sqlite3\.OperationalError/i,
        /\[SQLite\]/i,
        /SQL Server.*Driver/i,
        /Unclosed quotation mark/i,
        /syntax error.*SQL/i,
        /JDBC.*Exception/i,
        /Hibernate.*Exception/i,
        /You have an error in your SQL syntax/i,
        /quoted string not properly terminated/i,
        /unterminated.*string/i,
    ];

    const params = endpoint.params.filter(p => p.type === 'query' || p.type === 'body');

    for (const param of params) {
        // Get baseline response (normal request)
        let baselineUrl = endpoint.url;
        if (param.type === 'query') {
            const url = new URL(endpoint.url);
            url.searchParams.set(param.name, param.value || 'test');
            baselineUrl = url.toString();
        }
        const baseline = await makeRequest(baselineUrl, endpoint.method, config);
        if (!baseline) continue;

        for (const payload of payloads.slice(0, 15)) {
            let testUrl = endpoint.url;
            let testBody: string | undefined;

            if (param.type === 'query') {
                const url = new URL(endpoint.url);
                url.searchParams.set(param.name, payload);
                testUrl = url.toString();
            } else {
                testBody = `${param.name}=${encodeURIComponent(payload)}`;
            }

            const response = await makeRequest(
                testUrl,
                param.type === 'query' ? 'GET' : 'POST',
                config,
                testBody,
                testBody ? 'application/x-www-form-urlencoded' : undefined,
            );

            if (!response) continue;

            // Check for SQL error messages
            const errorMatch = SQL_ERROR_PATTERNS.find(pattern => pattern.test(response.body));

            // Check for time-based (if using SLEEP payloads)
            const isTimeBased = payload.includes('SLEEP') || payload.includes('pg_sleep') || payload.includes('WAITFOR');
            const timeBasedConfirmed = isTimeBased && response.time > 4000;

            // Check for boolean-based (response difference)
            const isBooleanPayload = payload.includes("'1'='1") || payload.includes("1=1");
            const responseDiff = Math.abs(response.body.length - baseline.body.length);
            const booleanConfirmed = isBooleanPayload && responseDiff > 50;

            if (errorMatch || timeBasedConfirmed || booleanConfirmed) {
                const cwe = getCweEntry('CWE-89');
                const cvssMetrics = COMMON_CVSS_VECTORS.sqli;
                const cvssScore = calculateCvssScore(cvssMetrics);

                let detectionMethod = 'error-based';
                let confidence: Confidence = 'high';
                if (timeBasedConfirmed) { detectionMethod = 'time-based'; confidence = 'medium'; }
                if (booleanConfirmed) { detectionMethod = 'boolean-based'; confidence = 'medium'; }

                // ── Deep SQLi Exploitation (Havij-Style) ──────────────
                // Automatically attempt full DB enumeration when SQLi is confirmed
                let sqliExploitData: string | undefined;
                let deepTechnicalDetail = '';
                try {
                    const exploitResult = await deepExploitSqli(
                        endpoint.url,
                        param.type === 'query' ? 'GET' : 'POST',
                        param.name,
                        param.type,
                        {
                            requestTimeout: config.requestTimeout,
                            userAgent: config.userAgent,
                            customHeaders: config.customHeaders,
                            authHeaders: config.authHeaders,
                            maxDatabases: 10,
                            maxTablesPerDb: 20,
                            maxColumnsPerTable: 30,
                            maxRowsPerTable: 5,
                        },
                    );

                    if (exploitResult) {
                        sqliExploitData = JSON.stringify(exploitResult);
                        confidence = 'high'; // Exploitation proves it's real
                        detectionMethod = `${detectionMethod} + deep exploitation (${exploitResult.technique})`;

                        // Build rich technical detail
                        const totalTables = exploitResult.databases.reduce((s, d) => s + d.tables.length, 0);
                        const totalCols = exploitResult.databases.reduce((s, d) => s + d.tables.reduce((s2, t) => s2 + t.columns.length, 0), 0);
                        deepTechnicalDetail = `\n\n🔓 DEEP EXPLOITATION RESULTS:\n` +
                            `• DBMS: ${exploitResult.dbms}\n` +
                            `• Current DB: ${exploitResult.currentDatabase}\n` +
                            `• Current User: ${exploitResult.currentUser}\n` +
                            `• Server: ${exploitResult.hostname}\n` +
                            `• Technique: ${exploitResult.technique}\n` +
                            `• Columns in query: ${exploitResult.columnCount} (injectable: #${exploitResult.injectableColumn})\n` +
                            `• Databases found: ${exploitResult.databases.map(d => d.name).join(', ')}\n` +
                            `• Total tables extracted: ${totalTables}\n` +
                            `• Total columns extracted: ${totalCols}\n` +
                            `• Exploit steps: ${exploitResult.exploitLog.length}`;
                    }
                } catch {
                    // Deep exploitation is best-effort — basic detection still valid
                }

                results.push({
                    found: true,
                    title: `SQL Injection (${detectionMethod}) in parameter "${param.name}"`,
                    description: `The parameter "${param.name}" at ${endpoint.url} is vulnerable to SQL injection (${detectionMethod} detection). An attacker can manipulate SQL queries to access, modify, or delete database data.${sqliExploitData ? ' Full database structure was successfully extracted as proof of exploitation.' : ''}`,
                    category: 'sqli',
                    severity: 'critical',
                    confidence,
                    cweId: 'CWE-89',
                    cweTitle: cwe?.title,
                    cvssVector: generateCvssVector(cvssMetrics),
                    cvssScore,
                    affectedUrl: endpoint.url,
                    httpMethod: param.type === 'query' ? 'GET' : 'POST',
                    parameter: param.name,
                    parameterType: param.type,
                    injectionPoint: 'body',
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    responseTime: response.time,
                    timingEvidence: timeBasedConfirmed ? { expectedDelay: 5000, actualDelay: response.time } : undefined,
                    impact: 'Full database compromise: read, modify, or delete any data. Potential for OS command execution through database functions. Data exfiltration and privilege escalation.',
                    technicalDetail: `Detection method: ${detectionMethod}. ${errorMatch ? `SQL error pattern matched: ${errorMatch}` : ''} ${timeBasedConfirmed ? `Response time ${response.time}ms indicates successful SLEEP injection.` : ''} ${booleanConfirmed ? `Response body length difference: ${responseDiff} bytes indicates boolean-based injection.` : ''}${deepTechnicalDetail}`,
                    remediation: cwe?.remediation || 'Use parameterized queries. Never concatenate user input into SQL.',
                    sqliExploitData,
                    reproductionSteps: [
                        `Send a ${param.type === 'query' ? 'GET' : 'POST'} request to: ${endpoint.url}`,
                        `Set the "${param.name}" parameter to: ${payload}`,
                        `Observe the ${errorMatch ? 'SQL error in the response' : timeBasedConfirmed ? 'delayed response (>4s)' : 'different response body'}`,
                    ],
                    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
                    mappedOwasp: ['A03:2021'],
                    mappedOwaspAsvs: ['V5.3.4'],
                    mappedNist: ['SI-10'],
                });
                break;
            }
        }
    }

    return results;
}

// ============================================================
// SECURITY HEADERS DETECTOR
// ============================================================

export async function detectHeaderIssues(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    const response = await makeRequest(endpoint.url, 'GET', config);
    if (!response) return results;

    // Check missing security headers
    for (const check of SECURITY_HEADERS_CHECKLIST) {
        const headerValue = response.headers[check.header.toLowerCase()];

        if (!headerValue) {
            const cvssMetrics = COMMON_CVSS_VECTORS.headers_missing;
            const cvssScore = calculateCvssScore(cvssMetrics);

            results.push({
                found: true,
                title: `Missing Security Header: ${check.header}`,
                description: `The HTTP response from ${endpoint.url} does not include the "${check.header}" security header. ${check.description}.`,
                category: 'headers',
                severity: check.critical ? 'medium' : 'low',
                confidence: 'high',
                cweId: 'CWE-693',
                cweTitle: 'Protection Mechanism Failure',
                cvssVector: generateCvssVector(cvssMetrics),
                cvssScore,
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                responseCode: response.status,
                responseTime: response.time,
                impact: `Without the ${check.header} header, the application may be vulnerable to attacks that this header is designed to prevent.`,
                remediation: `Add the "${check.header}" header to all HTTP responses. Recommended value depends on the specific header and application requirements.`,
                reproductionSteps: [
                    `Send a GET request to: ${endpoint.url}`,
                    `Examine the response headers`,
                    `Note the absence of the "${check.header}" header`,
                ],
                mappedOwasp: ['A05:2021'],
                mappedOwaspAsvs: ['V14.4.1'],
                mappedNist: ['SC-8'],
            });
        }
    }

    // Check information disclosure headers
    for (const header of INFO_DISCLOSURE_HEADERS) {
        const value = response.headers[header.toLowerCase()];
        if (value) {
            results.push({
                found: true,
                title: `Information Disclosure via "${header}" Header`,
                description: `The HTTP response includes the "${header}" header with value "${value}", potentially revealing server technology information.`,
                category: 'info_disclosure',
                severity: 'info',
                confidence: 'high',
                cweId: 'CWE-200',
                cweTitle: 'Exposure of Sensitive Information',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                responseCode: response.status,
                responseTime: response.time,
                impact: 'Server technology information can help attackers identify known vulnerabilities for the specific software version.',
                remediation: `Remove or hide the "${header}" header in production. Configure the web server to suppress technology disclosure.`,
                reproductionSteps: [
                    `Send a GET request to: ${endpoint.url}`,
                    `Examine the "${header}" response header`,
                    `Value: ${value}`,
                ],
                mappedOwasp: ['A05:2021'],
                mappedNist: ['SI-11'],
            });
        }
    }

    // Check cookie security
    const setCookie = response.headers['set-cookie'];
    if (setCookie) {
        if (!setCookie.toLowerCase().includes('httponly')) {
            results.push({
                found: true,
                title: 'Cookie Missing HttpOnly Flag',
                description: `Cookies set by ${endpoint.url} lack the HttpOnly flag, making them accessible to JavaScript.`,
                category: 'headers',
                severity: 'medium',
                confidence: 'high',
                cweId: 'CWE-1004',
                cweTitle: 'Sensitive Cookie Without HttpOnly Flag',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                impact: 'Session cookies accessible via JavaScript can be stolen through XSS attacks.',
                remediation: 'Set the HttpOnly flag on all session cookies.',
                mappedOwasp: ['A05:2021'],
            });
        }

        if (!setCookie.toLowerCase().includes('secure')) {
            results.push({
                found: true,
                title: 'Cookie Missing Secure Flag',
                description: `Cookies set by ${endpoint.url} lack the Secure flag, allowing transmission over HTTP.`,
                category: 'headers',
                severity: 'medium',
                confidence: 'high',
                cweId: 'CWE-614',
                cweTitle: 'Sensitive Cookie Without Secure Attribute',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                impact: 'Session cookies may be intercepted by network attackers on non-HTTPS connections.',
                remediation: 'Set the Secure flag on all session cookies.',
                mappedOwasp: ['A05:2021'],
            });
        }

        if (!setCookie.toLowerCase().includes('samesite')) {
            results.push({
                found: true,
                title: 'Cookie Missing SameSite Attribute',
                description: `Cookies set by ${endpoint.url} lack the SameSite attribute, potentially enabling CSRF attacks.`,
                category: 'csrf',
                severity: 'medium',
                confidence: 'high',
                cweId: 'CWE-1275',
                cweTitle: 'Sensitive Cookie with Improper SameSite Attribute',
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                impact: 'Without SameSite, cookies may be sent with cross-site requests, enabling CSRF attacks.',
                remediation: 'Set SameSite=Strict or SameSite=Lax on all session cookies.',
                mappedOwasp: ['A01:2021'],
            });
        }
    }

    return results;
}

// ============================================================
// CORS DETECTOR
// ============================================================

export async function detectCors(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    for (const origin of CORS_TEST_ORIGINS) {
        const response = await makeRequest(endpoint.url, 'GET', config, undefined, undefined, {
            Origin: origin,
        });

        if (!response) continue;

        const acao = response.headers['access-control-allow-origin'];
        const acac = response.headers['access-control-allow-credentials'];

        if (acao === origin || acao === '*') {
            const isWithCredentials = acac?.toLowerCase() === 'true';
            const severity = isWithCredentials ? 'high' : 'medium';

            const cwe = getCweEntry('CWE-942');
            const cvssMetrics = COMMON_CVSS_VECTORS.cors_misconfig;
            const cvssScore = calculateCvssScore(cvssMetrics);

            results.push({
                found: true,
                title: `CORS Misconfiguration: ${acao === '*' ? 'Wildcard Origin' : 'Origin Reflection'}`,
                description: `The application at ${endpoint.url} allows cross-origin requests from ${origin}${isWithCredentials ? ' with credentials' : ''}. ${acao === '*' ? 'A wildcard (*) Access-Control-Allow-Origin header allows any origin.' : 'The server reflects the Origin header without proper validation.'}`,
                category: 'cors',
                severity,
                confidence: 'high',
                cweId: 'CWE-942',
                cweTitle: cwe?.title,
                cvssVector: generateCvssVector(cvssMetrics),
                cvssScore,
                affectedUrl: endpoint.url,
                httpMethod: 'GET',
                request: response.requestStr,
                response: response.responseStr,
                responseCode: response.status,
                responseTime: response.time,
                impact: `An attacker can make cross-origin requests to this endpoint from a malicious website${isWithCredentials ? ', including the user\'s cookies and credentials' : ''}. This may allow data theft or unauthorized actions.`,
                remediation: 'Use a strict allowlist for CORS origins. Never reflect arbitrary Origin headers. Avoid using wildcard (*) with credentials.',
                reproductionSteps: [
                    `Send a GET request to: ${endpoint.url}`,
                    `Include the header: Origin: ${origin}`,
                    `Observe that Access-Control-Allow-Origin is set to: ${acao}`,
                    isWithCredentials ? 'Note: Access-Control-Allow-Credentials is set to true' : '',
                ].filter(Boolean),
                mappedOwasp: ['A05:2021'],
                mappedOwaspAsvs: ['V14.5.3'],
                mappedNist: ['AC-4'],
            });
            break;
        }
    }

    return results;
}

// ============================================================
// SSRF DETECTOR
// ============================================================

export async function detectSsrf(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const payloads = getSsrfPayloads();

    const urlParams = endpoint.params.filter(p =>
        p.name.toLowerCase().includes('url') ||
        p.name.toLowerCase().includes('link') ||
        p.name.toLowerCase().includes('src') ||
        p.name.toLowerCase().includes('redirect') ||
        p.name.toLowerCase().includes('path') ||
        p.name.toLowerCase().includes('file') ||
        p.name.toLowerCase().includes('page') ||
        p.name.toLowerCase().includes('load') ||
        p.name.toLowerCase().includes('fetch') ||
        p.name.toLowerCase().includes('target') ||
        p.name.toLowerCase().includes('domain') ||
        p.name.toLowerCase().includes('host')
    );

    for (const param of urlParams) {
        for (const payload of payloads.slice(0, 8)) {
            let testUrl = endpoint.url;
            let testBody: string | undefined;

            if (param.type === 'query') {
                const url = new URL(endpoint.url);
                url.searchParams.set(param.name, payload);
                testUrl = url.toString();
            } else {
                testBody = `${param.name}=${encodeURIComponent(payload)}`;
            }

            const response = await makeRequest(
                testUrl,
                param.type === 'query' ? 'GET' : 'POST',
                config,
                testBody,
                testBody ? 'application/x-www-form-urlencoded' : undefined,
            );

            if (!response) continue;

            // Check for internal resource indicators
            const ssrfIndicators = [
                /root:.*:0:0/i,                     // /etc/passwd content
                /\[boot loader\]/i,                  // win.ini content
                /ami-id/i,                           // AWS metadata
                /instance-id/i,                      // Cloud metadata
                /127\.0\.0\.1/i,                     // Internal response
                /localhost/i,
                /internal server/i,
                /connection refused/i,
                /Name or service not known/i,
            ];

            const indicatorMatch = ssrfIndicators.find(p => p.test(response.body));

            if (indicatorMatch && response.status !== 404) {
                const cwe = getCweEntry('CWE-918');
                const cvssMetrics = COMMON_CVSS_VECTORS.ssrf;
                const cvssScore = calculateCvssScore(cvssMetrics);

                results.push({
                    found: true,
                    title: `Potential SSRF via parameter "${param.name}"`,
                    description: `The parameter "${param.name}" at ${endpoint.url} may be vulnerable to Server-Side Request Forgery. The server appears to make requests to user-supplied URLs.`,
                    category: 'ssrf',
                    severity: 'high',
                    confidence: 'medium',
                    cweId: 'CWE-918',
                    cweTitle: cwe?.title,
                    cvssVector: generateCvssVector(cvssMetrics),
                    cvssScore,
                    affectedUrl: endpoint.url,
                    httpMethod: param.type === 'query' ? 'GET' : 'POST',
                    parameter: param.name,
                    parameterType: param.type,
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    responseTime: response.time,
                    impact: 'An attacker may access internal network resources, cloud metadata services, or perform port scanning from the server.',
                    remediation: cwe?.remediation || 'Validate and sanitize all user-provided URLs. Use allowlists.',
                    reproductionSteps: [
                        `Send a request to: ${endpoint.url}`,
                        `Set the "${param.name}" parameter to: ${payload}`,
                        `Observe the response for internal resource indicators`,
                    ],
                    mappedOwasp: ['A10:2021'],
                    mappedOwaspAsvs: ['V12.6.1'],
                    mappedNist: ['SC-7', 'AC-4'],
                });
                break;
            }
        }
    }

    return results;
}

// ============================================================
// PATH TRAVERSAL DETECTOR
// ============================================================

export async function detectPathTraversal(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const payloads = getPathTraversalPayloads();

    const fileParams = endpoint.params.filter(p =>
        p.name.toLowerCase().includes('file') ||
        p.name.toLowerCase().includes('path') ||
        p.name.toLowerCase().includes('page') ||
        p.name.toLowerCase().includes('doc') ||
        p.name.toLowerCase().includes('template') ||
        p.name.toLowerCase().includes('include') ||
        p.name.toLowerCase().includes('dir') ||
        p.name.toLowerCase().includes('folder') ||
        p.name.toLowerCase().includes('name') ||
        p.name.toLowerCase().includes('img') ||
        p.name.toLowerCase().includes('download')
    );

    for (const param of fileParams) {
        for (const payload of payloads.slice(0, 8)) {
            let testUrl = endpoint.url;
            if (param.type === 'query') {
                const url = new URL(endpoint.url);
                url.searchParams.set(param.name, payload);
                testUrl = url.toString();
            }

            const response = await makeRequest(testUrl, 'GET', config);
            if (!response) continue;

            const traversalIndicators = [
                /root:.*:0:0/i,
                /\[boot loader\]/i,
                /\[extensions\]/i,
                /; for 16-bit app support/i,
                /\/home\//i,
                /daemon:.*:1:1/i,
                /www-data/i,
            ];

            const match = traversalIndicators.find(p => p.test(response.body));
            if (match) {
                const cwe = getCweEntry('CWE-22');
                const cvssMetrics = COMMON_CVSS_VECTORS.path_traversal;
                const cvssScore = calculateCvssScore(cvssMetrics);

                results.push({
                    found: true,
                    title: `Path Traversal via parameter "${param.name}"`,
                    description: `The parameter "${param.name}" at ${endpoint.url} is vulnerable to path traversal, allowing reading of arbitrary files on the server.`,
                    category: 'path_traversal',
                    severity: 'high',
                    confidence: 'high',
                    cweId: 'CWE-22',
                    cweTitle: cwe?.title,
                    cvssVector: generateCvssVector(cvssMetrics),
                    cvssScore,
                    affectedUrl: endpoint.url,
                    httpMethod: 'GET',
                    parameter: param.name,
                    parameterType: param.type,
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    responseTime: response.time,
                    impact: 'An attacker can read sensitive files on the server including configuration files, credentials, and source code.',
                    remediation: cwe?.remediation || 'Validate file paths against a restricted directory.',
                    reproductionSteps: [
                        `Send a GET request to: ${endpoint.url}`,
                        `Set the "${param.name}" parameter to: ${payload}`,
                        `Observe the file contents in the response`,
                    ],
                    mappedOwasp: ['A01:2021'],
                    mappedOwaspAsvs: ['V12.3.1'],
                    mappedNist: ['SI-10'],
                });
                break;
            }
        }
    }

    return results;
}

// ============================================================
// OPEN REDIRECT DETECTOR
// ============================================================

export async function detectOpenRedirect(
    endpoint: CrawledEndpoint,
    config: DetectorConfig
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const payloads = getOpenRedirectPayloads();

    const redirectParams = endpoint.params.filter(p =>
        p.name.toLowerCase().includes('url') ||
        p.name.toLowerCase().includes('redirect') ||
        p.name.toLowerCase().includes('return') ||
        p.name.toLowerCase().includes('next') ||
        p.name.toLowerCase().includes('goto') ||
        p.name.toLowerCase().includes('dest') ||
        p.name.toLowerCase().includes('continue') ||
        p.name.toLowerCase().includes('target') ||
        p.name.toLowerCase().includes('callback')
    );

    for (const param of redirectParams) {
        for (const payload of payloads.slice(0, 5)) {
            let testUrl = endpoint.url;
            if (param.type === 'query') {
                const url = new URL(endpoint.url);
                url.searchParams.set(param.name, payload);
                testUrl = url.toString();
            }

            const response = await makeRequest(testUrl, 'GET', config);
            if (!response) continue;

            const location = response.headers.location || '';
            if ((response.status >= 300 && response.status < 400) &&
                (location.includes('evil.com') || location.includes(payload))) {
                const cwe = getCweEntry('CWE-601');
                const cvssMetrics = COMMON_CVSS_VECTORS.open_redirect;
                const cvssScore = calculateCvssScore(cvssMetrics);

                results.push({
                    found: true,
                    title: `Open Redirect via parameter "${param.name}"`,
                    description: `The parameter "${param.name}" at ${endpoint.url} allows redirection to external sites.`,
                    category: 'open_redirect',
                    severity: 'medium',
                    confidence: 'high',
                    cweId: 'CWE-601',
                    cweTitle: cwe?.title,
                    cvssVector: generateCvssVector(cvssMetrics),
                    cvssScore,
                    affectedUrl: endpoint.url,
                    httpMethod: 'GET',
                    parameter: param.name,
                    parameterType: param.type,
                    payload,
                    request: response.requestStr,
                    response: response.responseStr,
                    responseCode: response.status,
                    responseTime: response.time,
                    impact: 'Attackers can redirect users to phishing sites while appearing to use a trusted domain.',
                    remediation: cwe?.remediation || 'Use allowlists for redirect destinations.',
                    reproductionSteps: [
                        `Send a GET request to: ${testUrl}`,
                        `Observe the 3xx redirect to: ${location}`,
                    ],
                    mappedOwasp: ['A01:2021'],
                    mappedOwaspAsvs: ['V5.1.5'],
                    mappedNist: ['SI-10'],
                });
                break;
            }
        }
    }

    return results;
}

// ============================================================
// EXPORT ALL DETECTORS
// ============================================================

export interface DetectorModule {
    name: string;
    id: string;
    detect: (endpoint: CrawledEndpoint, config: DetectorConfig) => Promise<DetectorResult[]>;
}

export const ALL_DETECTORS: DetectorModule[] = [
    { name: 'Cross-Site Scripting (XSS)', id: 'xss', detect: detectXss },
    { name: 'SQL Injection', id: 'sqli', detect: detectSqli },
    { name: 'Security Headers', id: 'headers', detect: detectHeaderIssues },
    { name: 'CORS Misconfiguration', id: 'cors', detect: detectCors },
    { name: 'Server-Side Request Forgery', id: 'ssrf', detect: detectSsrf },
    { name: 'Path Traversal', id: 'path_traversal', detect: detectPathTraversal },
    { name: 'Open Redirect', id: 'open_redirect', detect: detectOpenRedirect },
];
