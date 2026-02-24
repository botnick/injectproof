// InjectProof — Reconnaissance Scanner
// Admin panel finder, backup file scanner, and technology fingerprinting
// Goes beyond Havij with concurrent probing, smart response analysis,
// and comprehensive path dictionaries.

import type { DetectorResult, Confidence } from '@/types';
import { getCweEntry } from '@/lib/cwe-database';

// ============================================================
// TYPES
// ============================================================

export interface ReconConfig {
    baseUrl: string;
    requestTimeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
    concurrency?: number; // parallel requests (default: 10)
}

export interface ReconResult {
    adminPanels: AdminPanel[];
    backupFiles: BackupFile[];
    technologies: TechFingerprint[];
    findings: DetectorResult[];
}

export interface AdminPanel {
    url: string;
    status: number;
    hasLoginForm: boolean;
    title?: string;
    confidence: 'confirmed' | 'likely' | 'possible';
}

export interface BackupFile {
    url: string;
    status: number;
    contentLength: number;
    contentType: string;
}

export interface TechFingerprint {
    name: string;
    version?: string;
    category: 'server' | 'framework' | 'cms' | 'language' | 'cdn' | 'waf' | 'database' | 'analytics' | 'js-framework';
    evidence: string;
    confidence: Confidence;
}

// ============================================================
// ADMIN PANEL PATHS (300+)
// ============================================================

const ADMIN_PATHS = [
    // Generic
    '/admin', '/admin/', '/administrator', '/admin/login', '/admin/index',
    '/admin/dashboard', '/admin/panel', '/admin/cp', '/admin/home',
    '/admin.php', '/admin.html', '/admin.asp', '/admin.aspx', '/admin.jsp',
    '/login', '/login/', '/login.php', '/login.html', '/login.asp',
    '/signin', '/sign-in', '/auth/login', '/auth/signin',
    // WordPress
    '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-admin/admin.php',
    '/wp-admin/index.php', '/wp-content/', '/xmlrpc.php',
    // Joomla
    '/administrator', '/administrator/', '/administrator/index.php',
    // Drupal
    '/user/login', '/admin/config', '/admin/structure',
    // phpMyAdmin
    '/phpmyadmin', '/phpmyadmin/', '/pma', '/phpMyAdmin',
    '/phpmyadmin/index.php', '/myadmin', '/mysql', '/dbadmin',
    '/phpMyAdmin/', '/db/', '/sql', '/mysqlmanager', '/mysql-admin',
    // cPanel / Plesk / Webmin
    '/cpanel', '/cpanel/', '/whm', '/webmail',
    '/plesk', '/webmin',
    // CMS admin paths
    '/manager', '/manager/', '/manage', '/management',
    '/cms', '/cms/', '/cms/admin', '/cms/login',
    '/siteadmin', '/site-admin', '/site_admin',
    '/backend', '/backend/', '/backend/login',
    '/controlpanel', '/control-panel', '/control_panel',
    '/panel', '/panel/', '/panel/login',
    // API / Dev tools
    '/api', '/api/', '/api/admin', '/api/v1', '/api/v2',
    '/swagger', '/swagger/', '/swagger-ui', '/swagger-ui/', '/swagger-ui.html',
    '/api-docs', '/api-docs/', '/redoc',
    '/graphql', '/graphiql', '/playground',
    '/.env', '/.git', '/.git/config', '/.git/HEAD',
    '/.svn', '/.svn/entries', '/.hg',
    '/.htaccess', '/.htpasswd',
    '/server-status', '/server-info',
    '/debug', '/debug/', '/test', '/test/',
    '/console', '/console/', '/terminal',
    '/trace', '/actuator', '/actuator/health', '/actuator/env',
    '/health', '/healthcheck', '/status',
    // Monitoring
    '/grafana', '/kibana', '/prometheus', '/nagios',
    '/munin', '/cacti', '/zabbix',
    // Database tools
    '/adminer', '/adminer.php', '/adminer/', '/Adminer',
    '/pgadmin', '/pgadmin/', '/mongo-express',
    '/redis-commander', '/elasticsearch', '/_plugin/head',
    // Common app paths
    '/user', '/users', '/account', '/accounts',
    '/profile', '/settings', '/preferences',
    '/upload', '/uploads', '/files', '/documents',
    '/install', '/install/', '/setup', '/setup/',
    '/config', '/configuration', '/config.php',
    // Frameworks
    '/laravel', '/telescope', '/horizon',
    '/rails/info', '/rails/mailers',
    '/django-admin', '/django-admin/',
    '/flask-admin', '/flask-admin/',
    '/strapi', '/strapi/', '/keystone',
    // E-commerce
    '/shop/admin', '/store/admin', '/magento/admin',
    '/woocommerce', '/prestashop/admin',
    // DevOps
    '/jenkins', '/jenkins/', '/ci', '/cd',
    '/sonarqube', '/nexus', '/artifactory',
    '/portainer', '/rancher', '/kubernetes-dashboard',
    // Common file paths
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/security.txt', '/.well-known/security.txt',
    '/humans.txt', '/favicon.ico', '/manifest.json',
    // Backup/config exposure
    '/web.config', '/web.config.bak', '/web.config.old',
    '/wp-config.php', '/wp-config.php.bak',
    '/config.yml', '/config.json', '/config.xml',
    '/.env.example', '/.env.local', '/.env.production',
    '/.env.backup', '/.env.bak', '/.env.old',
    '/database.yml', '/database.json',
    '/application.yml', '/application.properties',
    // Info disclosure
    '/info.php', '/phpinfo.php', '/php_info.php', '/test.php',
    '/readme', '/README', '/readme.md', '/README.md',
    '/CHANGELOG', '/CHANGELOG.md', '/changelog.txt',
    '/LICENSE', '/version', '/version.txt',
    '/package.json', '/composer.json', '/Gemfile',
    '/requirements.txt', '/Pipfile', '/go.mod',
    // Error pages
    '/error', '/errors', '/404', '/500',
    // Misc
    '/cgi-bin/', '/cgi-bin/admin', '/cgi-bin/login',
    '/webdav', '/dav',
    '/temp', '/tmp', '/log', '/logs',
    '/backup', '/backups', '/bak',
    '/old', '/archive', '/archives',
    '/private', '/internal', '/restricted',
    '/secret', '/hidden', '/staging', '/dev',
];

// ============================================================
// BACKUP FILE PATTERNS
// ============================================================

function generateBackupPaths(baseUrl: string): string[] {
    const hostname = new URL(baseUrl).hostname.replace(/\./g, '_');
    const domain = new URL(baseUrl).hostname.split('.')[0];
    const paths: string[] = [];

    // Database dumps
    const dbFiles = [
        'dump.sql', 'backup.sql', 'database.sql', 'db.sql', 'data.sql',
        `${hostname}.sql`, `${domain}.sql`, 'mysql.sql', 'export.sql',
        'dump.sql.gz', 'backup.sql.gz', `${domain}.sql.gz`,
        'dump.sql.bz2', 'backup.sql.bz2',
        'db_backup.sql', 'site_backup.sql', 'full_backup.sql',
    ];

    // Archive files
    const archives = [
        'backup.zip', 'backup.tar.gz', 'backup.tar', 'backup.rar',
        `${hostname}.zip`, `${domain}.zip`, `${hostname}.tar.gz`,
        'site.zip', 'www.zip', 'html.zip', 'htdocs.zip',
        'public_html.zip', 'web.zip', 'files.zip',
        'archive.zip', 'archive.tar.gz', 'old.zip',
        `${domain}.tar.gz`, `${domain}.tar`, `${domain}.rar`,
        'source.zip', 'src.zip', 'code.zip',
    ];

    // Config backups
    const configs = [
        '.env.bak', '.env.old', '.env.backup', '.env.save',
        '.env.swp', '.env~', '.env.orig',
        'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php~',
        'wp-config.php.save', 'wp-config.php.orig', 'wp-config.php.swp',
        'config.php.bak', 'config.php.old', 'config.php~',
        'settings.php.bak', 'settings.php.old',
        'web.config.bak', 'web.config.old',
        'application.yml.bak', 'appsettings.json.bak',
        '.htaccess.bak', '.htaccess.old',
        'php.ini.bak', 'httpd.conf.bak',
    ];

    // Temp/editor files
    const temps = [
        'index.php~', 'index.php.bak', 'index.php.old',
        'index.html.bak', 'index.html.old',
        '.DS_Store', 'Thumbs.db',
        '.swp', '.swo',
    ];

    for (const f of [...dbFiles, ...archives, ...configs, ...temps]) {
        paths.push(`/${f}`);
        paths.push(`/backup/${f}`);
        paths.push(`/backups/${f}`);
    }

    return paths;
}

// ============================================================
// TECHNOLOGY FINGERPRINTING SIGNATURES
// ============================================================

interface TechSignature {
    name: string;
    category: TechFingerprint['category'];
    checks: Array<{
        type: 'header' | 'body' | 'cookie' | 'url';
        key?: string; // header name or cookie name
        pattern: RegExp;
        versionGroup?: number; // regex group index for version
    }>;
}

const TECH_SIGNATURES: TechSignature[] = [
    // Servers
    {
        name: 'Apache', category: 'server', checks: [
            { type: 'header', key: 'server', pattern: /Apache\/?(\S*)/i, versionGroup: 1 },
        ]
    },
    {
        name: 'Nginx', category: 'server', checks: [
            { type: 'header', key: 'server', pattern: /nginx\/?(\S*)/i, versionGroup: 1 },
        ]
    },
    {
        name: 'IIS', category: 'server', checks: [
            { type: 'header', key: 'server', pattern: /Microsoft-IIS\/?(\S*)/i, versionGroup: 1 },
        ]
    },
    {
        name: 'LiteSpeed', category: 'server', checks: [
            { type: 'header', key: 'server', pattern: /LiteSpeed/i },
        ]
    },
    {
        name: 'OpenResty', category: 'server', checks: [
            { type: 'header', key: 'server', pattern: /openresty\/?(\S*)/i, versionGroup: 1 },
        ]
    },
    // Languages / Frameworks
    {
        name: 'PHP', category: 'language', checks: [
            { type: 'header', key: 'x-powered-by', pattern: /PHP\/?(\S*)/i, versionGroup: 1 },
            { type: 'cookie', key: 'PHPSESSID', pattern: /.*/ },
        ]
    },
    {
        name: 'ASP.NET', category: 'framework', checks: [
            { type: 'header', key: 'x-powered-by', pattern: /ASP\.NET/i },
            { type: 'header', key: 'x-aspnet-version', pattern: /(\S+)/i, versionGroup: 1 },
            { type: 'cookie', key: 'ASP.NET_SessionId', pattern: /.*/ },
        ]
    },
    {
        name: 'Express.js', category: 'framework', checks: [
            { type: 'header', key: 'x-powered-by', pattern: /Express/i },
        ]
    },
    {
        name: 'Django', category: 'framework', checks: [
            { type: 'cookie', key: 'csrftoken', pattern: /.*/ },
            { type: 'header', key: 'x-frame-options', pattern: /DENY/i }, // Django default
            { type: 'body', pattern: /csrfmiddlewaretoken/i },
        ]
    },
    {
        name: 'Ruby on Rails', category: 'framework', checks: [
            { type: 'header', key: 'x-powered-by', pattern: /Phusion Passenger/i },
            { type: 'cookie', key: '_session_id', pattern: /.*/ },
            { type: 'header', key: 'x-runtime', pattern: /(\S+)/i },
        ]
    },
    {
        name: 'Laravel', category: 'framework', checks: [
            { type: 'cookie', key: 'laravel_session', pattern: /.*/ },
            { type: 'cookie', key: 'XSRF-TOKEN', pattern: /.*/ },
            { type: 'body', pattern: /laravel/i },
        ]
    },
    {
        name: 'Spring Boot', category: 'framework', checks: [
            { type: 'header', key: 'x-application-context', pattern: /(\S+)/i },
            { type: 'body', pattern: /Whitelabel Error Page/i },
        ]
    },
    // CMS
    {
        name: 'WordPress', category: 'cms', checks: [
            { type: 'body', pattern: /wp-content|wp-includes/i },
            { type: 'body', pattern: /<meta name="generator" content="WordPress (\S+)"/i, versionGroup: 1 },
            { type: 'url', pattern: /\/wp-login\.php/ },
        ]
    },
    {
        name: 'Joomla', category: 'cms', checks: [
            { type: 'body', pattern: /\/media\/jui\/|com_content/i },
            { type: 'body', pattern: /<meta name="generator" content="Joomla/i },
        ]
    },
    {
        name: 'Drupal', category: 'cms', checks: [
            { type: 'body', pattern: /\/sites\/default\/|Drupal\.settings/i },
            { type: 'header', key: 'x-generator', pattern: /Drupal (\S+)/i, versionGroup: 1 },
            { type: 'body', pattern: /<meta name="Generator" content="Drupal/i },
        ]
    },
    {
        name: 'Magento', category: 'cms', checks: [
            { type: 'body', pattern: /\/skin\/frontend\/|Mage\.Cookies/i },
            { type: 'cookie', key: 'frontend', pattern: /.*/ },
        ]
    },
    {
        name: 'Shopify', category: 'cms', checks: [
            { type: 'body', pattern: /cdn\.shopify\.com/i },
            { type: 'header', key: 'x-shopid', pattern: /(\S+)/i },
        ]
    },
    // CDN / WAF
    {
        name: 'Cloudflare', category: 'cdn', checks: [
            { type: 'header', key: 'cf-ray', pattern: /(\S+)/i },
            { type: 'header', key: 'server', pattern: /cloudflare/i },
        ]
    },
    {
        name: 'Akamai', category: 'cdn', checks: [
            { type: 'header', key: 'x-akamai-transformed', pattern: /(\S+)/i },
        ]
    },
    {
        name: 'AWS CloudFront', category: 'cdn', checks: [
            { type: 'header', key: 'x-amz-cf-id', pattern: /(\S+)/i },
            { type: 'header', key: 'via', pattern: /CloudFront/i },
        ]
    },
    // JS Frameworks (from HTML body)
    {
        name: 'React', category: 'js-framework', checks: [
            { type: 'body', pattern: /react\.production\.min\.js|__NEXT_DATA__|data-reactroot/i },
        ]
    },
    {
        name: 'Vue.js', category: 'js-framework', checks: [
            { type: 'body', pattern: /vue\.min\.js|__vue__|data-v-[a-f0-9]/i },
        ]
    },
    {
        name: 'Angular', category: 'js-framework', checks: [
            { type: 'body', pattern: /ng-version|angular\.min\.js|ng-app/i },
        ]
    },
    {
        name: 'jQuery', category: 'js-framework', checks: [
            { type: 'body', pattern: /jquery[\.\-](\d+\.\d+[\.\d]*)(\.min)?\.js/i, versionGroup: 1 },
        ]
    },
    // Analytics
    {
        name: 'Google Analytics', category: 'analytics', checks: [
            { type: 'body', pattern: /google-analytics\.com\/analytics\.js|gtag\(|UA-\d+/i },
        ]
    },
    {
        name: 'Google Tag Manager', category: 'analytics', checks: [
            { type: 'body', pattern: /googletagmanager\.com\/gtm\.js/i },
        ]
    },
];

// ============================================================
// MAIN: runReconScan
// ============================================================

/**
 * Run reconnaissance against a target URL.
 * Discovers admin panels, backup files, and fingerprints technology.
 */
export async function runReconScan(config: ReconConfig): Promise<ReconResult> {
    const concurrency = config.concurrency ?? 10;
    const findings: DetectorResult[] = [];
    const adminPanels: AdminPanel[] = [];
    const backupFiles: BackupFile[] = [];
    const technologies: TechFingerprint[] = [];

    // ── Step 1: Fetch base page for fingerprinting ──────────────
    const basePage = await probeUrl(config.baseUrl, config);

    if (basePage) {
        // Technology fingerprinting from base page
        const detected = fingerprintResponse(basePage.headers, basePage.body, basePage.cookies, config.baseUrl);
        technologies.push(...detected);

        for (const tech of detected) {
            findings.push({
                found: true,
                title: `Technology Detected: ${tech.name}${tech.version ? ` v${tech.version}` : ''}`,
                description: `The target is running ${tech.name}${tech.version ? ` version ${tech.version}` : ''}. Detected via ${tech.evidence}.`,
                category: 'info_disclosure',
                severity: 'info',
                confidence: tech.confidence,
                cweId: 'CWE-200',
                cweTitle: getCweEntry('CWE-200')?.title,
                affectedUrl: config.baseUrl,
                httpMethod: 'GET',
                parameter: '',
                payload: '',
                impact: `Technology fingerprinting reveals ${tech.category} technology. This information can help attackers craft targeted exploits.`,
                technicalDetail: `${tech.name} (${tech.category}) — ${tech.evidence}`,
                remediation: 'Remove version information from response headers. Configure the web server to suppress technology disclosure.',
                references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'],
            });
        }
    }

    // ── Step 2: Admin Panel Discovery (batched) ─────────────────
    const adminResults = await batchProbe(ADMIN_PATHS, config, concurrency);

    for (const result of adminResults) {
        if (!result.response) continue;
        const { status, body, headers } = result.response;

        // Skip clear 404s, 500s or WAF block pages
        if (status === 404 || status === 410 || status >= 500) continue;
        if (isSoft404OrWaf(status, body, headers)) continue;

        // Determine if this looks like an admin panel
        const hasLoginForm = /<form[^>]*>[\s\S]*?(password|passwd|login|signin|username|user)/i.test(body);
        const hasLoginKeywords = /(admin|login|sign.?in|authenticate|dashboard|control.?panel)/i.test(body);
        const titleMatch = body.match(/<title>([^<]+)<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : undefined;

        // Strict verification to avoid false positives
        let confidence: AdminPanel['confidence'] = 'possible';
        if (status === 200 && hasLoginForm && hasLoginKeywords && !body.toLowerCase().includes('just a moment')) {
            confidence = 'confirmed';
        } else if (status === 200 && hasLoginForm) {
            confidence = 'likely';
        } else if (status === 401) {
            confidence = 'likely';
        } else if (status === 200 && hasLoginKeywords && title && /(admin|login)/i.test(title)) {
            confidence = 'possible';
        } else {
            continue; // Skip ambiguous or empty pages
        }

        const panel: AdminPanel = {
            url: result.url,
            status,
            hasLoginForm,
            title,
            confidence,
        };
        adminPanels.push(panel);

        // Only report confirmed/likely as findings
        if (confidence === 'confirmed' || confidence === 'likely') {
            const severity = confidence === 'confirmed' ? 'medium' : 'low';
            findings.push({
                found: true,
                title: `Admin Panel Found: ${result.path}`,
                description: `An administrative interface was discovered at ${result.url}. ${hasLoginForm ? 'The page contains a login form.' : ''} ${title ? `Page title: "${title}".` : ''} HTTP status: ${status}.`,
                category: 'info_disclosure',
                severity,
                confidence: confidence === 'confirmed' ? 'high' : 'medium',
                cweId: 'CWE-200',
                cweTitle: getCweEntry('CWE-200')?.title,
                affectedUrl: result.url,
                httpMethod: 'GET',
                parameter: '',
                payload: '',
                responseCode: status,
                impact: 'Exposed admin panels provide attack surface for brute-force, credential stuffing, and targeted exploitation. Attackers can use this to gain unauthorized administrative access.',
                technicalDetail: `Path: ${result.path} | Status: ${status} | Login form: ${hasLoginForm} | Title: ${title || 'N/A'}`,
                remediation: 'Restrict admin panel access to whitelisted IPs. Implement rate limiting and 2FA. Move admin interfaces to non-standard paths. Use a VPN or bastion host.',
                reproductionSteps: [
                    `Navigate to: ${result.url}`,
                    `Observe the admin panel / login page`,
                ],
                references: [
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                ],
            });
        }

        // Also fingerprint technologies from admin pages
        if (basePage) {
            const adminTech = fingerprintResponse(headers, body, '', result.url);
            for (const tech of adminTech) {
                if (!technologies.some(t => t.name === tech.name)) {
                    technologies.push(tech);
                }
            }
        }
    }

    // ── Step 3: Backup File Scanner (batched) ───────────────────
    const backupPaths = generateBackupPaths(config.baseUrl);
    const backupResults = await batchProbe(backupPaths, config, concurrency);

    for (const result of backupResults) {
        if (!result.response) continue;
        const { status, body, headers } = result.response;

        // Only interested in 200 OK with actual content, and not a WAF block
        if (status !== 200 || body.length < 20) continue;
        if (isSoft404OrWaf(status, body, headers)) continue;

        const contentType = headers['content-type'] || 'text/plain';
        const contentLength = parseInt(headers['content-length'] || '0') || body.length;
        const lowerBody = body.toLowerCase();
        const ext = result.path.split('.').pop()?.toLowerCase();

        // 1. Skip obvious HTML pages that aren't backups
        if (lowerBody.includes('<html') || lowerBody.includes('<!doctype html>')) {
             if (ext !== 'bak' && ext !== 'old' && !result.path.includes('.env')) continue;
        }

        // 2. Strict Content Verification (Regex & Signatures)
        let isValidBackup = false;

        // .env files
        if (result.path.includes('.env') || ext === 'bak' || ext === 'old') {
            const hasEnvVars = /^[A-Z0-9_]+\s*=\s*.+/m.test(body);
            const hasSecrets = /(DB_|DATABASE_|SECRET|PASSWORD|KEY|TOKEN|API)/i.test(body);
            if (hasEnvVars || hasSecrets) isValidBackup = true;
        }
        
        // SQL dumps
        else if (ext === 'sql' || result.path.includes('dump.sql')) {
            const hasSql = /(CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|ALTER\s+TABLE|--\s+MySQL|--\s+PostgreSQL)/i.test(body);
            if (hasSql) isValidBackup = true;
        }
        
        // Binary archives (zip, tar, gz, rar)
        else if (ext && ['zip', 'gz', 'tar', 'rar', 'bz2', '7z'].includes(ext)) {
            // Must not be a typical text error page
            if (!lowerBody.includes('not found') && !lowerBody.includes('blocked')) {
                if (contentType.includes('application/') || contentType.includes('octet-stream')) {
                    isValidBackup = true;
                }
            }
        }
        
        // Config files (php, json, yml, config)
        else if (ext && ['php', 'json', 'yml', 'yaml', 'config', 'ini'].includes(ext)) {
            if (ext === 'php' && /<\?php/i.test(body)) isValidBackup = true;
            if (ext === 'json' && body.trim().startsWith('{')) isValidBackup = true;
            if ((ext === 'yml' || ext === 'yaml') && body.includes(':')) isValidBackup = true;
            if (ext === 'config' && /<configuration>/i.test(body)) isValidBackup = true;
            if (ext === 'ini' && /^\[.*\]/m.test(body)) isValidBackup = true;
        }

        if (isValidBackup) {
            const backup: BackupFile = {
                url: result.url,
                status,
                contentLength,
                contentType,
            };
            backupFiles.push(backup);

            findings.push({
                found: true,
                title: `Exposed Backup File: ${result.path}`,
                description: `A backup or sensitive file was found at ${result.url}. Content-Type: ${contentType || 'N/A'}, Size: ${formatBytes(contentLength)}. This file may contain database dumps, configuration secrets, or source code.`,
                category: 'info_disclosure',
                severity: 'high',
                confidence: 'high',
                cweId: 'CWE-530',
                cweTitle: 'Exposure of Backup File to an Unauthorized Control Sphere',
                affectedUrl: result.url,
                httpMethod: 'GET',
                parameter: '',
                payload: '',
                responseCode: status,
                response: body.slice(0, 1000),
                impact: 'Exposed backup files can reveal database credentials, API keys, source code, and other sensitive information. Attackers can use this data to compromise the entire application.',
                technicalDetail: `Path: ${result.path} | Content-Type: ${contentType} | Size: ${formatBytes(contentLength)}`,
                remediation: 'Remove all backup files from web-accessible directories. Configure the web server to deny access to backup file extensions (.bak, .sql, .zip, .old, ~, .swp). Use .htaccess or server config to block these patterns.',
                reproductionSteps: [
                    `Access: ${result.url}`,
                    `Observe the backup file content is accessible`,
                ],
                references: [
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                ],
            });
        }
    }

    return { adminPanels, backupFiles, technologies, findings };
}

// ============================================================
// HELPERS
// ============================================================

interface ProbeResponse {
    status: number;
    body: string;
    headers: Record<string, string>;
    cookies: string;
    time: number;
}

async function probeUrl(url: string, config: ReconConfig): Promise<ProbeResponse | null> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.requestTimeout);

        const headers: Record<string, string> = {
            'User-Agent': config.userAgent,
            ...config.customHeaders,
            ...config.authHeaders,
        };

        const response = await fetch(url, {
            method: 'GET',
            headers,
            signal: controller.signal,
            redirect: 'follow',
        });
        clearTimeout(timeoutId);

        const body = await response.text();
        const respHeaders: Record<string, string> = {};
        response.headers.forEach((v, k) => { respHeaders[k.toLowerCase()] = v; });

        return {
            status: response.status,
            body,
            headers: respHeaders,
            cookies: respHeaders['set-cookie'] || '',
            time: 0,
        };
    } catch {
        return null;
    }
}

interface BatchResult {
    path: string;
    url: string;
    response: ProbeResponse | null;
}

async function batchProbe(paths: string[], config: ReconConfig, concurrency: number): Promise<BatchResult[]> {
    const results: BatchResult[] = [];
    const origin = new URL(config.baseUrl).origin;

    // Process in chunks
    for (let i = 0; i < paths.length; i += concurrency) {
        const chunk = paths.slice(i, i + concurrency);
        const promises = chunk.map(async (path): Promise<BatchResult> => {
            const url = `${origin}${path}`;
            const response = await probeUrl(url, config);
            return { path, url, response };
        });
        const chunkResults = await Promise.all(promises);
        results.push(...chunkResults);
    }

    return results;
}

function fingerprintResponse(
    headers: Record<string, string>,
    body: string,
    cookies: string,
    url: string,
): TechFingerprint[] {
    const results: TechFingerprint[] = [];

    for (const sig of TECH_SIGNATURES) {
        for (const check of sig.checks) {
            let source = '';
            switch (check.type) {
                case 'header':
                    source = headers[check.key!] || '';
                    break;
                case 'body':
                    source = body;
                    break;
                case 'cookie':
                    source = cookies.includes(check.key!) || headers['set-cookie']?.includes(check.key!)
                        ? check.key!
                        : '';
                    break;
                case 'url':
                    source = url;
                    break;
            }

            if (!source) continue;
            const match = check.pattern.exec(source);
            if (match) {
                const version = check.versionGroup ? match[check.versionGroup] : undefined;
                const evidence = check.type === 'header'
                    ? `${check.key}: ${headers[check.key!]}`
                    : check.type === 'cookie'
                        ? `Cookie: ${check.key}`
                        : check.type === 'body'
                            ? `HTML content pattern`
                            : `URL pattern`;

                // Avoid duplicates
                if (!results.some(r => r.name === sig.name)) {
                    results.push({
                        name: sig.name,
                        version: version || undefined,
                        category: sig.category,
                        evidence,
                        confidence: check.type === 'header' ? 'high' : 'medium',
                    });
                }
                break; // One match per signature is enough
            }
        }
    }

    return results;
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function isSoft404OrWaf(status: number, body: string, headers: Record<string, string>): boolean {
    if (status === 403 || status === 406 || status === 429) return true;
    
    const bodyStr = body.toLowerCase();
    
    // Cloudflare / WAF block pages returning 200 or 400s
    if (headers['server']?.toLowerCase().includes('cloudflare') || headers['cf-ray']) {
        if (bodyStr.includes('just a moment...') || bodyStr.includes('cf-browser-verification') || bodyStr.includes('attention required!')) {
            return true;
        }
        if (bodyStr.includes('cloudflare') && (bodyStr.includes('blocked') || bodyStr.includes('access denied') || bodyStr.includes('security check'))) {
            return true;
        }
    }
    
    // Akamai
    if (bodyStr.includes('access denied') && bodyStr.includes('reference #')) return true;
    // CloudFront
    if (bodyStr.includes('request blocked.') || bodyStr.includes('could not be satisfied.')) return true;
    
    // Soft 404s (returns 200 but is actually a 404 page)
    if (status === 200) {
        if (/<title>[^<]*(404|not found|page not found)[^<]*<\/title>/i.test(bodyStr)) return true;
        if (/<h[1-3]>[^<]*(404|not found|page not found)[^<]*<\/h[1-3]>/i.test(bodyStr)) return true;
    }
    
    return false;
}
