// InjectProof — EASM: External Attack Surface Management
// Subdomain enum, cloud bucket hunting, leaked secret analysis, shadow API discovery
// These are ADDITIVE modules — they don't modify existing scanner behavior

import type { DetectorResult } from '@/types';
import { buildRequestString, buildResponseString } from '@/lib/utils';

interface EasmConfig {
    baseUrl: string;
    domain: string; // extracted domain (e.g., "example.com")
    requestTimeout: number;
    userAgent: string;
}

// ============================================================
// 1) SUBDOMAIN ENUMERATION (Passive + Active)
// ============================================================

/** Passive subdomain discovery via Certificate Transparency logs */
export async function enumerateSubdomains(config: EasmConfig): Promise<string[]> {
    const subdomains = new Set<string>();

    // Source 1: crt.sh (Certificate Transparency)
    try {
        const response = await fetch(
            `https://crt.sh/?q=%.${config.domain}&output=json`,
            { signal: AbortSignal.timeout(config.requestTimeout) }
        );
        if (response.ok) {
            const entries = await response.json() as Array<{ name_value: string }>;
            for (const entry of entries) {
                const names = entry.name_value.split('\n');
                for (const name of names) {
                    const clean = name.trim().toLowerCase().replace('*.', '');
                    if (clean.endsWith(config.domain) && !clean.includes(' ')) {
                        subdomains.add(clean);
                    }
                }
            }
        }
    } catch { /* crt.sh unavailable */ }

    // Source 2: DNS brute-force with common prefixes
    const commonPrefixes = [
        'api', 'dev', 'staging', 'stage', 'test', 'beta', 'admin', 'portal',
        'dashboard', 'app', 'www', 'mail', 'smtp', 'ftp', 'vpn', 'cdn',
        'static', 'assets', 'media', 'images', 'img', 'docs', 'wiki',
        'jenkins', 'gitlab', 'ci', 'cd', 'deploy', 'build', 'registry',
        'internal', 'intranet', 'corp', 'private', 'auth', 'sso', 'login',
        'api-v1', 'api-v2', 'api-v3', 'graphql', 'ws', 'socket', 'realtime',
        'monitor', 'metrics', 'grafana', 'kibana', 'elastic', 'prometheus',
        'backup', 'db', 'database', 'redis', 'cache', 'queue', 'worker',
        'sandbox', 'demo', 'preview', 'canary', 'edge', 'origin', 'legacy',
    ];

    for (const prefix of commonPrefixes) {
        const subdomain = `${prefix}.${config.domain}`;
        try {
            const response = await fetch(`https://${subdomain}`, {
                method: 'HEAD',
                signal: AbortSignal.timeout(3000),
                redirect: 'manual',
            });
            if (response.status > 0) subdomains.add(subdomain);
        } catch {
            try {
                const response = await fetch(`http://${subdomain}`, {
                    method: 'HEAD',
                    signal: AbortSignal.timeout(3000),
                    redirect: 'manual',
                });
                if (response.status > 0) subdomains.add(subdomain);
            } catch { /* not resolvable */ }
        }
    }

    // AltDNS-style permutations (subset for performance)
    const altPrefixes = ['dev-', 'stg-', 'prod-', 'int-', 'ext-'];
    const baseParts = config.domain.split('.');
    if (baseParts.length >= 2) {
        for (const alt of altPrefixes) {
            const permuted = `${alt}${baseParts[0]}.${baseParts.slice(1).join('.')}`;
            try {
                const r = await fetch(`https://${permuted}`, { method: 'HEAD', signal: AbortSignal.timeout(2000), redirect: 'manual' });
                if (r.status > 0) subdomains.add(permuted);
            } catch { /* not resolvable */ }
        }
    }

    return Array.from(subdomains);
}

// ============================================================
// 2) CLOUD BUCKET / STORAGE HUNTING
// ============================================================

interface BucketResult {
    provider: string;
    bucketUrl: string;
    accessible: boolean;
    listable: boolean;
    content?: string;
}

export async function huntCloudBuckets(config: EasmConfig): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const domainBase = config.domain.replace(/\./g, '-');
    const domainShort = config.domain.split('.')[0];

    const nameVariants = [
        domainBase, domainShort,
        `${domainBase}-backup`, `${domainBase}-assets`, `${domainBase}-uploads`,
        `${domainBase}-static`, `${domainBase}-media`, `${domainBase}-data`,
        `${domainBase}-dev`, `${domainBase}-staging`, `${domainBase}-prod`,
        `${domainBase}-logs`, `${domainBase}-config`, `${domainBase}-db`,
        `${domainShort}-backup`, `${domainShort}-dev`, `${domainShort}-prod`,
    ];

    const providers = [
        { name: 'AWS S3', urlTemplate: (n: string) => `https://${n}.s3.amazonaws.com`, listIndicator: '<ListBucketResult' },
        { name: 'AWS S3 (path)', urlTemplate: (n: string) => `https://s3.amazonaws.com/${n}`, listIndicator: '<ListBucketResult' },
        { name: 'GCP Storage', urlTemplate: (n: string) => `https://storage.googleapis.com/${n}`, listIndicator: '<ListBucketResult' },
        { name: 'Azure Blob', urlTemplate: (n: string) => `https://${n}.blob.core.windows.net/?comp=list`, listIndicator: '<EnumerationResults' },
        { name: 'DigitalOcean Spaces', urlTemplate: (n: string) => `https://${n}.nyc3.digitaloceanspaces.com`, listIndicator: '<ListBucketResult' },
    ];

    for (const variant of nameVariants) {
        for (const provider of providers) {
            const bucketUrl = provider.urlTemplate(variant);
            try {
                const response = await fetch(bucketUrl, {
                    method: 'GET',
                    signal: AbortSignal.timeout(5000),
                    headers: { 'User-Agent': config.userAgent },
                });

                const body = await response.text();
                const accessible = response.status !== 404 && response.status !== 0;
                const listable = body.includes(provider.listIndicator);

                if (accessible) {
                    results.push({
                        found: true,
                        title: `${provider.name} Bucket Exposed: ${variant}`,
                        description: `A cloud storage bucket named "${variant}" on ${provider.name} is ${listable ? 'PUBLICLY LISTABLE — all files can be enumerated' : `accessible (HTTP ${response.status})`}. This may contain sensitive data, backups, or credentials.`,
                        category: 'cloud_exposure',
                        severity: listable ? 'critical' : 'high',
                        confidence: listable ? 'high' : 'medium',
                        cweId: 'CWE-200',
                        cweTitle: 'Exposure of Sensitive Information',
                        affectedUrl: bucketUrl,
                        httpMethod: 'GET',
                        request: buildRequestString('GET', bucketUrl, { 'User-Agent': config.userAgent }),
                        response: buildResponseString(response.status, {}, body.substring(0, 2000)),
                        responseCode: response.status,
                        assetDiscoveryPath: `Domain permutation: ${config.domain} -> ${variant} -> ${provider.name}`,
                        impact: listable
                            ? 'CRITICAL: All files in this bucket can be listed and potentially downloaded by anyone. This may expose source code, database backups, credentials, PII, or confidential business data.'
                            : 'The bucket exists and responds, which may leak information. Access permissions should be verified.',
                        remediation: `Restrict bucket access using IAM policies. Enable bucket-level access controls. Block public listing. Remove sensitive data from public buckets.`,
                        reproductionSteps: [
                            `Navigate to: ${bucketUrl}`,
                            `Observe the response — ${listable ? 'files are listed in XML' : `HTTP ${response.status} indicates the bucket exists`}`,
                        ],
                        mappedOwasp: ['A05:2021'],
                        mappedNist: ['AC-3', 'SC-28'],
                    });
                }
            } catch { /* bucket doesn't exist or timeout */ }
        }
    }

    return results;
}

// ============================================================
// 3) LEAKED SECRET & SOURCE CODE ANALYSIS
// ============================================================

const SECRET_PATTERNS = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
    { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g, severity: 'critical' as const },
    { name: 'GitHub Token', pattern: /gh[pous]_[A-Za-z0-9_]{36,255}/g, severity: 'critical' as const },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' as const },
    { name: 'Slack Token', pattern: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/g, severity: 'high' as const },
    { name: 'Private Key', pattern: /-----BEGIN\s*(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: 'critical' as const },
    { name: 'JWT Secret', pattern: /(?:jwt_secret|JWT_SECRET|jwt_key|JWT_KEY)\s*[=:]\s*["']?([^\s"']+)["']?/gi, severity: 'critical' as const },
    { name: 'Database URL', pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s"']+/gi, severity: 'critical' as const },
    { name: 'Bearer Token in Code', pattern: /Bearer\s+[A-Za-z0-9\-_\.]{20,}/g, severity: 'high' as const },
    { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' as const },
    { name: 'SendGrid Key', pattern: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, severity: 'high' as const },
    { name: 'Twilio Key', pattern: /SK[a-f0-9]{32}/g, severity: 'high' as const },
    { name: 'Mailgun Key', pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'high' as const },
    { name: 'Internal URL', pattern: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s"']+/g, severity: 'medium' as const },
    { name: 'Hardcoded Password', pattern: /(?:password|passwd|pwd|secret)\s*[=:]\s*["']([^"']{4,})["']/gi, severity: 'high' as const },
];

/** Scan JavaScript files for leaked secrets */
export async function scanForLeakedSecrets(
    jsUrls: string[],
    config: EasmConfig,
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    for (const jsUrl of jsUrls.slice(0, 30)) { // Limit for performance
        try {
            const response = await fetch(jsUrl, {
                signal: AbortSignal.timeout(config.requestTimeout),
                headers: { 'User-Agent': config.userAgent },
            });
            if (!response.ok) continue;

            const content = await response.text();
            if (content.length > 5_000_000) continue; // Skip huge files

            // Check for source maps
            const hasSourceMap = content.includes('//# sourceMappingURL=') || content.includes('//@ sourceMappingURL=');

            for (const secretPattern of SECRET_PATTERNS) {
                const matches = content.match(secretPattern.pattern);
                if (matches && matches.length > 0) {
                    // Deduplicate
                    const uniqueMatches = Array.from(new Set(matches)).slice(0, 5);

                    results.push({
                        found: true,
                        title: `Leaked ${secretPattern.name} in JavaScript`,
                        description: `Found ${uniqueMatches.length} instance(s) of ${secretPattern.name} pattern in ${jsUrl}. ${hasSourceMap ? 'WARNING: Source map detected — full source code may be exposed.' : ''}`,
                        category: 'leaked_secret',
                        severity: secretPattern.severity,
                        confidence: 'high',
                        cweId: 'CWE-798',
                        cweTitle: 'Use of Hard-coded Credentials',
                        affectedUrl: jsUrl,
                        httpMethod: 'GET',
                        payload: uniqueMatches.map(m => m.substring(0, 8) + '***REDACTED***').join(', '),
                        responseCode: response.status,
                        sourceMapReconstructed: hasSourceMap,
                        assetDiscoveryPath: `JS file analysis: ${jsUrl}`,
                        impact: `Exposed ${secretPattern.name} can be used to access protected resources, APIs, or internal systems. If the key is still active, immediate revocation is required.`,
                        remediation: 'Immediately rotate the exposed credentials. Remove secrets from client-side code. Use environment variables and server-side token exchange patterns.',
                        reproductionSteps: [
                            `Access the JavaScript file: ${jsUrl}`,
                            `Search for the pattern: ${secretPattern.name}`,
                            `Found matches: ${uniqueMatches.map(m => m.substring(0, 12) + '...').join(', ')}`,
                        ],
                        mappedOwasp: ['A07:2021'],
                        mappedNist: ['IA-5', 'SC-12'],
                    });
                }
            }

            // Check source map availability
            if (hasSourceMap) {
                const mapMatch = content.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
                if (mapMatch) {
                    const mapUrl = mapMatch[1].startsWith('http') ? mapMatch[1] : new URL(mapMatch[1], jsUrl).toString();
                    try {
                        const mapResp = await fetch(mapUrl, { signal: AbortSignal.timeout(5000) });
                        if (mapResp.ok) {
                            results.push({
                                found: true,
                                title: `Exposed Source Map: ${mapUrl.split('/').pop()}`,
                                description: `A webpack/source map file is publicly accessible at ${mapUrl}. This exposes the original, unminified source code including possibly internal API endpoints, comments, and logic.`,
                                category: 'info_disclosure',
                                severity: 'medium',
                                confidence: 'high',
                                cweId: 'CWE-540',
                                cweTitle: 'Inclusion of Sensitive Information in Source Code',
                                affectedUrl: mapUrl,
                                httpMethod: 'GET',
                                responseCode: mapResp.status,
                                sourceMapReconstructed: true,
                                impact: 'Source maps expose the original, readable source code including internal API routes, business logic, developer comments, and potentially hardcoded secrets.',
                                remediation: 'Remove source maps from production builds. Configure the build tool to either not generate maps or only upload them to error tracking services.',
                                mappedOwasp: ['A05:2021'],
                            });
                        }
                    } catch { /* source map not accessible */ }
                }
            }
        } catch { /* JS file fetch failed */ }
    }

    return results;
}

// ============================================================
// 4) SHADOW API & ORPHANED ENDPOINT DISCOVERY
// ============================================================

export async function discoverShadowApis(config: EasmConfig): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];

    // Common API versioning patterns
    const versionPaths = [
        '/api/v1', '/api/v2', '/api/v3', '/api/v4',
        '/v1', '/v2', '/v3', '/v4',
        '/api/1.0', '/api/2.0', '/api/3.0',
        '/rest/v1', '/rest/v2',
    ];

    // Common orphaned/debug endpoints
    const orphanedPaths = [
        '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
        '/api-docs', '/api/docs', '/openapi.json', '/openapi.yaml',
        '/graphql', '/graphiql', '/playground',
        '/debug', '/debug/vars', '/debug/pprof',
        '/_debug', '/__debug',
        '/metrics', '/prometheus', '/health', '/healthz', '/ready', '/readyz',
        '/status', '/info', '/env', '/actuator', '/actuator/env', '/actuator/health',
        '/trace', '/dump', '/heapdump', '/threaddump',
        '/admin', '/administrator', '/admin/login', '/admin/dashboard',
        '/phpinfo.php', '/server-status', '/server-info',
        '/elmah.axd', '/trace.axd',
        '/.env', '/config.json', '/config.yml', '/config.yaml',
        '/wp-json', '/wp-admin', '/wp-login.php',
        '/robots.txt', '/sitemap.xml', '/.git/config', '/.svn/entries',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/test', '/testing', '/temp', '/tmp', '/old', '/bak', '/backup',
    ];

    const allPaths = [...versionPaths, ...orphanedPaths];
    const accessibleEndpoints: Array<{ path: string; status: number; body: string }> = [];

    for (const path of allPaths) {
        const url = `${config.baseUrl}${path}`;
        try {
            const response = await fetch(url, {
                method: 'GET',
                signal: AbortSignal.timeout(5000),
                headers: { 'User-Agent': config.userAgent },
                redirect: 'manual',
            });

            if (response.status !== 404 && response.status !== 0 && response.status < 500) {
                const body = await response.text();
                accessibleEndpoints.push({ path, status: response.status, body: body.substring(0, 2000) });
            }
        } catch { /* not accessible */ }
    }

    // Flag interesting findings
    for (const ep of accessibleEndpoints) {
        // Swagger/OpenAPI exposure
        if (ep.path.includes('swagger') || ep.path.includes('openapi') || ep.path.includes('api-docs') || ep.path.includes('graphiql') || ep.path.includes('playground')) {
            results.push({
                found: true,
                title: `Exposed API Documentation: ${ep.path}`,
                description: `API documentation endpoint is publicly accessible at ${config.baseUrl}${ep.path}. This reveals the full API surface including internal endpoints, parameters, and data structures.`,
                category: 'shadow_api',
                severity: 'medium',
                confidence: 'high',
                cweId: 'CWE-200',
                affectedUrl: `${config.baseUrl}${ep.path}`,
                httpMethod: 'GET',
                responseCode: ep.status,
                assetDiscoveryPath: `Shadow API scan: brute-force path discovery`,
                impact: 'Exposed API documentation reveals the complete attack surface including undocumented endpoints, parameter schemas, and authentication patterns.',
                remediation: 'Restrict API documentation to internal networks or authenticated users only.',
                mappedOwasp: ['A05:2021'],
            });
        }

        // Debug/actuator endpoints
        if (ep.path.includes('debug') || ep.path.includes('actuator') || ep.path.includes('metrics') || ep.path.includes('env') || ep.path.includes('dump')) {
            const hasSecrets = /password|secret|key|token|credential/i.test(ep.body);
            results.push({
                found: true,
                title: `Exposed Debug/Management Endpoint: ${ep.path}`,
                description: `A debug or management endpoint is publicly accessible at ${config.baseUrl}${ep.path}. ${hasSecrets ? 'WARNING: Response may contain credentials or secrets.' : ''}`,
                category: 'misconfig',
                severity: hasSecrets ? 'critical' : 'high',
                confidence: 'high',
                cweId: 'CWE-215',
                cweTitle: 'Insertion of Sensitive Information Into Debugging Code',
                affectedUrl: `${config.baseUrl}${ep.path}`,
                httpMethod: 'GET',
                response: ep.body,
                responseCode: ep.status,
                impact: 'Debug endpoints expose internal application state, environment variables, and potentially credentials. They can also enable remote code execution in some frameworks.',
                remediation: 'Disable debug endpoints in production. Use network-level controls to restrict access.',
                mappedOwasp: ['A05:2021'],
                mappedNist: ['CM-7', 'SI-11'],
            });
        }

        // Git/SVN exposure
        if (ep.path.includes('.git') || ep.path.includes('.svn') || ep.path === '/.env') {
            results.push({
                found: true,
                title: `Exposed Sensitive File: ${ep.path}`,
                description: `A sensitive file is publicly accessible: ${config.baseUrl}${ep.path}. This may expose source code repository, credentials, or configuration.`,
                category: 'info_disclosure',
                severity: 'critical',
                confidence: 'high',
                cweId: 'CWE-538',
                cweTitle: 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
                affectedUrl: `${config.baseUrl}${ep.path}`,
                httpMethod: 'GET',
                responseCode: ep.status,
                impact: ep.path.includes('.git')
                    ? 'Git repository exposure allows downloading the entire source code including commit history, credentials, and internal configuration.'
                    : 'Environment file exposure reveals database credentials, API keys, and application secrets.',
                remediation: 'Block access to sensitive files via web server configuration. Add .git, .env, .svn to deny rules.',
                mappedOwasp: ['A05:2021'],
                mappedNist: ['SC-28'],
            });
        }

        // Legacy API versions
        if (versionPaths.includes(ep.path)) {
            results.push({
                found: true,
                title: `Active Legacy API Endpoint: ${ep.path}`,
                description: `Legacy API version ${ep.path} is still responding (HTTP ${ep.status}). Older API versions may lack modern security controls, rate limiting, and authentication enforcement.`,
                category: 'shadow_api',
                severity: 'medium',
                confidence: 'medium',
                cweId: 'CWE-1059',
                affectedUrl: `${config.baseUrl}${ep.path}`,
                httpMethod: 'GET',
                responseCode: ep.status,
                assetDiscoveryPath: `Version enumeration: ${ep.path}`,
                impact: 'Legacy API versions may bypass modern authentication, have unpatched vulnerabilities, or expose deprecated functionality.',
                remediation: 'Deprecate and remove old API versions. If needed, apply the same security controls as the current version.',
                mappedOwasp: ['A08:2021'],
            });
        }
    }

    return results;
}
