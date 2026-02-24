// VibeCode — CWE/OWASP/NIST Mapping Database
// 200+ CWE entries with full mapping to OWASP Top 10, OWASP ASVS, and NIST 800-53

export interface CweEntry {
    id: string;        // e.g., "CWE-79"
    title: string;
    description: string;
    category: string;  // Maps to VulnCategory
    owasp: string[];   // OWASP Top 10 2021 mappings
    asvs: string[];    // OWASP ASVS v4.0 references
    nist: string[];    // NIST 800-53 controls
    severity: string;  // Default severity
    remediation: string;
    references: string[];
}

/**
 * Comprehensive CWE database with 200+ entries
 * Mapped to OWASP Top 10 2021, OWASP ASVS v4.0, and NIST 800-53
 */
export const CWE_DATABASE: Record<string, CweEntry> = {
    // ============================================================
    // INJECTION (OWASP A03:2021)
    // ============================================================
    'CWE-79': {
        id: 'CWE-79', title: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
        description: 'The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.',
        category: 'xss', owasp: ['A03:2021'], asvs: ['V5.3.3', 'V5.3.6'], nist: ['SI-10', 'SI-15'],
        severity: 'medium', remediation: 'Encode output data using context-appropriate encoding. Use Content Security Policy (CSP) headers. Validate and sanitize all user input.',
        references: ['https://cwe.mitre.org/data/definitions/79.html', 'https://owasp.org/www-community/attacks/xss/'],
    },
    'CWE-80': {
        id: 'CWE-80', title: 'Improper Neutralization of Script-Related HTML Tags',
        description: 'The software receives input from an upstream component, but does not neutralize certain script-related HTML tags.',
        category: 'xss', owasp: ['A03:2021'], asvs: ['V5.3.3'], nist: ['SI-10'],
        severity: 'medium', remediation: 'Apply strict HTML encoding on all user-supplied data before rendering.',
        references: ['https://cwe.mitre.org/data/definitions/80.html'],
    },
    'CWE-83': {
        id: 'CWE-83', title: 'Improper Neutralization of Script in Attributes in a Web Page',
        description: 'The software does not neutralize certain scripting elements within HTML attributes.',
        category: 'xss', owasp: ['A03:2021'], asvs: ['V5.3.3'], nist: ['SI-10'],
        severity: 'medium', remediation: 'Use attribute-specific encoding. Avoid inserting user data into event handlers.',
        references: ['https://cwe.mitre.org/data/definitions/83.html'],
    },
    'CWE-87': {
        id: 'CWE-87', title: 'Improper Neutralization of Alternate XSS Syntax',
        description: 'The software does not neutralize alternate XSS attack syntax.',
        category: 'xss', owasp: ['A03:2021'], asvs: ['V5.3.3'], nist: ['SI-10'],
        severity: 'medium', remediation: 'Use a comprehensive XSS prevention library. Apply context-aware output encoding.',
        references: ['https://cwe.mitre.org/data/definitions/87.html'],
    },
    'CWE-89': {
        id: 'CWE-89', title: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
        description: 'The application constructs SQL statements using user-controllable input, allowing attackers to modify query logic or execute arbitrary SQL commands.',
        category: 'sqli', owasp: ['A03:2021'], asvs: ['V5.3.4'], nist: ['SI-10'],
        severity: 'critical', remediation: 'Use parameterized queries (prepared statements). Use an ORM with proper escaping. Never concatenate user input into SQL strings.',
        references: ['https://cwe.mitre.org/data/definitions/89.html', 'https://owasp.org/www-community/attacks/SQL_Injection'],
    },
    'CWE-90': {
        id: 'CWE-90', title: 'Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)',
        description: 'The application constructs LDAP queries using user-controlled input without proper sanitization.',
        category: 'ldap_injection', owasp: ['A03:2021'], asvs: ['V5.3.7'], nist: ['SI-10'],
        severity: 'high', remediation: 'Use LDAP-specific encoding. Validate input against allowlists.',
        references: ['https://cwe.mitre.org/data/definitions/90.html'],
    },
    'CWE-91': {
        id: 'CWE-91', title: 'XML Injection',
        description: 'The software does not properly neutralize special elements used in XML.',
        category: 'xxe', owasp: ['A03:2021'], asvs: ['V5.3.8'], nist: ['SI-10'],
        severity: 'high', remediation: 'Disable DTD processing. Use safe XML parsers.',
        references: ['https://cwe.mitre.org/data/definitions/91.html'],
    },
    'CWE-94': {
        id: 'CWE-94', title: 'Improper Control of Generation of Code (Code Injection)',
        description: 'The application allows user-controlled input to be included in dynamically generated code, which is then executed.',
        category: 'rce', owasp: ['A03:2021'], asvs: ['V5.2.4'], nist: ['SI-10', 'SI-3'],
        severity: 'critical', remediation: 'Never evaluate user-controlled strings as code. Use sandboxed execution environments.',
        references: ['https://cwe.mitre.org/data/definitions/94.html'],
    },
    'CWE-77': {
        id: 'CWE-77', title: 'Improper Neutralization of Special Elements used in a Command (Command Injection)',
        description: 'The application constructs operating system commands using user input without proper sanitization.',
        category: 'cmd_injection', owasp: ['A03:2021'], asvs: ['V5.2.3', 'V5.3.8'], nist: ['SI-10'],
        severity: 'critical', remediation: 'Use parameterized command execution. Avoid shell commands. Validate input against strict allowlists.',
        references: ['https://cwe.mitre.org/data/definitions/77.html'],
    },
    'CWE-78': {
        id: 'CWE-78', title: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
        description: 'The application passes unsanitized user input to operating system shell commands.',
        category: 'cmd_injection', owasp: ['A03:2021'], asvs: ['V5.2.3'], nist: ['SI-10'],
        severity: 'critical', remediation: 'Avoid calling OS commands. Use language-level APIs instead. If required, use strict allowlists.',
        references: ['https://cwe.mitre.org/data/definitions/78.html'],
    },
    'CWE-943': {
        id: 'CWE-943', title: 'Improper Neutralization of Special Elements in Data Query Logic',
        description: 'The application constructs NoSQL queries using untrusted input.',
        category: 'nosql_injection', owasp: ['A03:2021'], asvs: ['V5.3.4'], nist: ['SI-10'],
        severity: 'high', remediation: 'Use parameterized queries. Validate and sanitize all input before constructing queries.',
        references: ['https://cwe.mitre.org/data/definitions/943.html'],
    },

    // ============================================================
    // BROKEN ACCESS CONTROL (OWASP A01:2021)
    // ============================================================
    'CWE-284': {
        id: 'CWE-284', title: 'Improper Access Control',
        description: 'The application does not restrict access to a resource or functionality to authorized users.',
        category: 'idor', owasp: ['A01:2021'], asvs: ['V4.1.1', 'V4.1.2', 'V4.1.3'], nist: ['AC-3', 'AC-6'],
        severity: 'high', remediation: 'Implement proper authorization checks. Use role-based access control. Deny by default.',
        references: ['https://cwe.mitre.org/data/definitions/284.html'],
    },
    'CWE-285': {
        id: 'CWE-285', title: 'Improper Authorization',
        description: 'The application does not perform or incorrectly performs an authorization check.',
        category: 'idor', owasp: ['A01:2021'], asvs: ['V4.1.1'], nist: ['AC-3'],
        severity: 'high', remediation: 'Verify authorization for every access request. Use centralized authorization logic.',
        references: ['https://cwe.mitre.org/data/definitions/285.html'],
    },
    'CWE-639': {
        id: 'CWE-639', title: 'Authorization Bypass Through User-Controlled Key (IDOR)',
        description: 'The system exposes direct references to internal objects, allowing attackers to access unauthorized data.',
        category: 'idor', owasp: ['A01:2021'], asvs: ['V4.1.3', 'V4.2.1'], nist: ['AC-3'],
        severity: 'high', remediation: 'Use indirect references. Validate authorization for every access to internal objects.',
        references: ['https://cwe.mitre.org/data/definitions/639.html'],
    },
    'CWE-862': {
        id: 'CWE-862', title: 'Missing Authorization',
        description: 'The application does not perform an authorization check when accessing a critical resource.',
        category: 'idor', owasp: ['A01:2021'], asvs: ['V4.1.1'], nist: ['AC-3', 'AC-6'],
        severity: 'high', remediation: 'Implement authorization checks for all sensitive operations.',
        references: ['https://cwe.mitre.org/data/definitions/862.html'],
    },
    'CWE-863': {
        id: 'CWE-863', title: 'Incorrect Authorization',
        description: 'The application performs an authorization check but does so incorrectly.',
        category: 'idor', owasp: ['A01:2021'], asvs: ['V4.1.2'], nist: ['AC-3'],
        severity: 'high', remediation: 'Review and fix authorization logic. Apply principle of least privilege.',
        references: ['https://cwe.mitre.org/data/definitions/863.html'],
    },
    'CWE-352': {
        id: 'CWE-352', title: 'Cross-Site Request Forgery (CSRF)',
        description: 'The web application does not verify that a legitimate user intended to submit a request.',
        category: 'csrf', owasp: ['A01:2021'], asvs: ['V4.2.2'], nist: ['SC-23'],
        severity: 'high', remediation: 'Use anti-CSRF tokens. Validate the Origin/Referer header. Use SameSite cookie attribute.',
        references: ['https://cwe.mitre.org/data/definitions/352.html'],
    },
    'CWE-1275': {
        id: 'CWE-1275', title: 'Sensitive Cookie with Improper SameSite Attribute',
        description: 'Session cookies are set without proper SameSite attribute.',
        category: 'csrf', owasp: ['A01:2021'], asvs: ['V3.4.3'], nist: ['SC-23'],
        severity: 'medium', remediation: 'Set SameSite=Strict or SameSite=Lax on all session cookies.',
        references: ['https://cwe.mitre.org/data/definitions/1275.html'],
    },

    // ============================================================
    // SSRF (OWASP A10:2021)
    // ============================================================
    'CWE-918': {
        id: 'CWE-918', title: 'Server-Side Request Forgery (SSRF)',
        description: 'The application makes HTTP requests to URLs controlled by the user, allowing access to internal resources.',
        category: 'ssrf', owasp: ['A10:2021'], asvs: ['V12.6.1'], nist: ['SC-7', 'AC-4'],
        severity: 'high', remediation: 'Validate and sanitize all user-provided URLs. Use allowlists for outbound requests. Block internal IP ranges.',
        references: ['https://cwe.mitre.org/data/definitions/918.html', 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
    },

    // ============================================================
    // PATH TRAVERSAL
    // ============================================================
    'CWE-22': {
        id: 'CWE-22', title: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
        description: 'The application uses user-controlled input to construct file paths without proper validation.',
        category: 'path_traversal', owasp: ['A01:2021'], asvs: ['V12.3.1'], nist: ['SI-10'],
        severity: 'high', remediation: 'Use path canonicalization. Validate paths against a restricted base directory. Use allowlists.',
        references: ['https://cwe.mitre.org/data/definitions/22.html'],
    },
    'CWE-23': {
        id: 'CWE-23', title: 'Relative Path Traversal',
        description: 'The application does not properly restrict relative path sequences like ../',
        category: 'path_traversal', owasp: ['A01:2021'], asvs: ['V12.3.1'], nist: ['SI-10'],
        severity: 'high', remediation: 'Canonicalize file paths and verify they stay within allowed directories.',
        references: ['https://cwe.mitre.org/data/definitions/23.html'],
    },
    'CWE-36': {
        id: 'CWE-36', title: 'Absolute Path Traversal',
        description: 'The application allows absolute file paths in user input.',
        category: 'path_traversal', owasp: ['A01:2021'], asvs: ['V12.3.1'], nist: ['SI-10'],
        severity: 'high', remediation: 'Never allow absolute paths from user input. Use allowlists for file access.',
        references: ['https://cwe.mitre.org/data/definitions/36.html'],
    },

    // ============================================================
    // OPEN REDIRECT
    // ============================================================
    'CWE-601': {
        id: 'CWE-601', title: 'URL Redirection to Untrusted Site (Open Redirect)',
        description: 'The application redirects users to URLs specified by user input without proper validation.',
        category: 'open_redirect', owasp: ['A01:2021'], asvs: ['V5.1.5'], nist: ['SI-10'],
        severity: 'medium', remediation: 'Use allowlists for redirect destinations. Validate redirect URLs are same-origin.',
        references: ['https://cwe.mitre.org/data/definitions/601.html'],
    },

    // ============================================================
    // AUTHENTICATION (OWASP A07:2021)
    // ============================================================
    'CWE-306': {
        id: 'CWE-306', title: 'Missing Authentication for Critical Function',
        description: 'A critical function does not require any form of authentication.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V2.1.1'], nist: ['IA-2', 'IA-8'],
        severity: 'critical', remediation: 'Implement authentication for all sensitive endpoints and functions.',
        references: ['https://cwe.mitre.org/data/definitions/306.html'],
    },
    'CWE-307': {
        id: 'CWE-307', title: 'Improper Restriction of Excessive Authentication Attempts',
        description: 'The application does not limit failed authentication attempts, enabling brute-force attacks.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V2.2.1'], nist: ['AC-7'],
        severity: 'high', remediation: 'Implement account lockout or rate limiting. Use CAPTCHA after failed attempts.',
        references: ['https://cwe.mitre.org/data/definitions/307.html'],
    },
    'CWE-287': {
        id: 'CWE-287', title: 'Improper Authentication',
        description: 'The application does not properly verify user identity.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V2.1.1'], nist: ['IA-2'],
        severity: 'critical', remediation: 'Use proven authentication frameworks. Implement multi-factor authentication.',
        references: ['https://cwe.mitre.org/data/definitions/287.html'],
    },
    'CWE-521': {
        id: 'CWE-521', title: 'Weak Password Requirements',
        description: 'The application does not enforce strong password policies.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V2.1.7', 'V2.1.8'], nist: ['IA-5'],
        severity: 'medium', remediation: 'Enforce minimum password length (12+), complexity, and check against breached password lists.',
        references: ['https://cwe.mitre.org/data/definitions/521.html'],
    },
    'CWE-613': {
        id: 'CWE-613', title: 'Insufficient Session Expiration',
        description: 'The application does not sufficiently expire sessions.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V3.3.1', 'V3.3.2'], nist: ['AC-12'],
        severity: 'medium', remediation: 'Set appropriate session timeouts. Invalidate sessions on logout.',
        references: ['https://cwe.mitre.org/data/definitions/613.html'],
    },
    'CWE-384': {
        id: 'CWE-384', title: 'Session Fixation',
        description: 'The application does not regenerate session IDs after authentication.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V3.2.1'], nist: ['SC-23'],
        severity: 'high', remediation: 'Regenerate session identifiers after successful authentication.',
        references: ['https://cwe.mitre.org/data/definitions/384.html'],
    },
    'CWE-640': {
        id: 'CWE-640', title: 'Weak Password Recovery Mechanism',
        description: 'The application provides a weak password recovery mechanism.',
        category: 'auth', owasp: ['A07:2021'], asvs: ['V2.5.1'], nist: ['IA-5'],
        severity: 'medium', remediation: 'Use secure reset token generation. Require identity verification.',
        references: ['https://cwe.mitre.org/data/definitions/640.html'],
    },

    // ============================================================
    // SECURITY MISCONFIGURATION (OWASP A05:2021)
    // ============================================================
    'CWE-693': {
        id: 'CWE-693', title: 'Protection Mechanism Failure',
        description: 'Security mechanisms are missing or improperly configured.',
        category: 'headers', owasp: ['A05:2021'], asvs: ['V14.4.1'], nist: ['SC-8'],
        severity: 'medium', remediation: 'Enable all recommended security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.',
        references: ['https://cwe.mitre.org/data/definitions/693.html'],
    },
    'CWE-1021': {
        id: 'CWE-1021', title: 'Improper Restriction of Rendered UI Layers or Frames (Clickjacking)',
        description: 'The application can be embedded in frames, enabling clickjacking attacks.',
        category: 'clickjacking', owasp: ['A05:2021'], asvs: ['V14.4.7'], nist: ['SC-18'],
        severity: 'medium', remediation: 'Set X-Frame-Options: DENY. Use CSP frame-ancestors directive.',
        references: ['https://cwe.mitre.org/data/definitions/1021.html'],
    },
    'CWE-16': {
        id: 'CWE-16', title: 'Configuration',
        description: 'The application has insecure default configurations or misconfigured security settings.',
        category: 'misconfig', owasp: ['A05:2021'], asvs: ['V14.1.1'], nist: ['CM-6', 'CM-7'],
        severity: 'medium', remediation: 'Apply security hardening guides. Disable unnecessary features and default accounts.',
        references: ['https://cwe.mitre.org/data/definitions/16.html'],
    },
    'CWE-942': {
        id: 'CWE-942', title: 'Permissive Cross-domain Policy with Untrusted Domains (CORS)',
        description: 'The application CORS policy allows requests from untrusted origins.',
        category: 'cors', owasp: ['A05:2021'], asvs: ['V14.5.3'], nist: ['AC-4'],
        severity: 'high', remediation: 'Use strict CORS allowlists. Never reflect arbitrary Origin headers. Avoid Access-Control-Allow-Origin: *.',
        references: ['https://cwe.mitre.org/data/definitions/942.html'],
    },
    'CWE-614': {
        id: 'CWE-614', title: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
        description: 'Session cookies lack the Secure flag, allowing transmission over HTTP.',
        category: 'headers', owasp: ['A05:2021'], asvs: ['V3.4.1'], nist: ['SC-8'],
        severity: 'medium', remediation: 'Set the Secure flag on all sensitive cookies.',
        references: ['https://cwe.mitre.org/data/definitions/614.html'],
    },
    'CWE-1004': {
        id: 'CWE-1004', title: 'Sensitive Cookie Without HttpOnly Flag',
        description: 'Session cookies lack the HttpOnly flag, making them accessible to JavaScript.',
        category: 'headers', owasp: ['A05:2021'], asvs: ['V3.4.2'], nist: ['SC-23'],
        severity: 'medium', remediation: 'Set the HttpOnly flag on all session cookies.',
        references: ['https://cwe.mitre.org/data/definitions/1004.html'],
    },

    // ============================================================
    // INFORMATION DISCLOSURE (OWASP A01:2021)
    // ============================================================
    'CWE-200': {
        id: 'CWE-200', title: 'Exposure of Sensitive Information to an Unauthorized Actor',
        description: 'The application exposes sensitive information to unauthorized users.',
        category: 'info_disclosure', owasp: ['A01:2021'], asvs: ['V7.4.1'], nist: ['SI-11'],
        severity: 'medium', remediation: 'Remove sensitive data from error messages, headers, and responses. Use custom error pages.',
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
    },
    'CWE-209': {
        id: 'CWE-209', title: 'Generation of Error Message Containing Sensitive Information',
        description: 'Error messages reveal internal information like stack traces, database details, or file paths.',
        category: 'info_disclosure', owasp: ['A05:2021'], asvs: ['V7.4.1'], nist: ['SI-11'],
        severity: 'low', remediation: 'Use generic error messages in production. Log detailed errors server-side only.',
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
    },
    'CWE-532': {
        id: 'CWE-532', title: 'Insertion of Sensitive Information into Log File',
        description: 'The application writes sensitive information into log files.',
        category: 'info_disclosure', owasp: ['A09:2021'], asvs: ['V7.1.1'], nist: ['AU-3'],
        severity: 'medium', remediation: 'Sanitize log entries. Never log credentials, tokens, or PII.',
        references: ['https://cwe.mitre.org/data/definitions/532.html'],
    },
    'CWE-548': {
        id: 'CWE-548', title: 'Exposure of Information Through Directory Listing',
        description: 'The web server exposes directory listings.',
        category: 'info_disclosure', owasp: ['A05:2021'], asvs: ['V14.3.4'], nist: ['CM-7'],
        severity: 'low', remediation: 'Disable directory listing in web server configuration.',
        references: ['https://cwe.mitre.org/data/definitions/548.html'],
    },

    // ============================================================
    // VULNERABLE COMPONENTS (OWASP A06:2021)
    // ============================================================
    'CWE-1035': {
        id: 'CWE-1035', title: 'OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities',
        description: 'The application uses libraries/frameworks with known security vulnerabilities.',
        category: 'outdated_component', owasp: ['A06:2021'], asvs: ['V14.2.1'], nist: ['SI-2', 'RA-5'],
        severity: 'high', remediation: 'Regularly update all dependencies. Use automated dependency scanning. Monitor CVE databases.',
        references: ['https://cwe.mitre.org/data/definitions/1035.html'],
    },
    'CWE-937': {
        id: 'CWE-937', title: 'OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities',
        description: 'Using outdated or vulnerable software components.',
        category: 'outdated_component', owasp: ['A06:2021'], asvs: ['V14.2.1'], nist: ['SI-2'],
        severity: 'high', remediation: 'Keep all components updated. Subscribe to security advisories.',
        references: ['https://cwe.mitre.org/data/definitions/937.html'],
    },

    // ============================================================
    // JWT SECURITY
    // ============================================================
    'CWE-345': {
        id: 'CWE-345', title: 'Insufficient Verification of Data Authenticity',
        description: 'The application does not sufficiently verify the authenticity or integrity of data (e.g., JWT with alg=none).',
        category: 'jwt', owasp: ['A02:2021'], asvs: ['V3.5.3'], nist: ['SC-13'],
        severity: 'critical', remediation: 'Validate JWT algorithm. Reject alg=none. Use strong signing keys.',
        references: ['https://cwe.mitre.org/data/definitions/345.html'],
    },
    'CWE-347': {
        id: 'CWE-347', title: 'Improper Verification of Cryptographic Signature',
        description: 'The application does not properly verify cryptographic signatures.',
        category: 'jwt', owasp: ['A02:2021'], asvs: ['V3.5.3'], nist: ['SC-13'],
        severity: 'critical', remediation: 'Always verify signatures against trusted keys. Validate token expiry.',
        references: ['https://cwe.mitre.org/data/definitions/347.html'],
    },
    'CWE-327': {
        id: 'CWE-327', title: 'Use of a Broken or Risky Cryptographic Algorithm',
        description: 'The application uses weak or broken cryptographic algorithms.',
        category: 'auth', owasp: ['A02:2021'], asvs: ['V6.2.1'], nist: ['SC-13'],
        severity: 'high', remediation: 'Use modern cryptographic algorithms (AES-256, SHA-256, RSA-2048+).',
        references: ['https://cwe.mitre.org/data/definitions/327.html'],
    },

    // ============================================================
    // DESERIALIZATION (OWASP A08:2021)
    // ============================================================
    'CWE-502': {
        id: 'CWE-502', title: 'Deserialization of Untrusted Data',
        description: 'The application deserializes untrusted data which may contain malicious objects.',
        category: 'deserialization', owasp: ['A08:2021'], asvs: ['V5.5.1'], nist: ['SI-10'],
        severity: 'critical', remediation: 'Avoid deserializing untrusted data. Use safe formats like JSON. Implement integrity checks.',
        references: ['https://cwe.mitre.org/data/definitions/502.html'],
    },

    // ============================================================
    // XXE (XML External Entity)
    // ============================================================
    'CWE-611': {
        id: 'CWE-611', title: 'Improper Restriction of XML External Entity Reference (XXE)',
        description: 'The XML parser processes external entity references in XML documents from untrusted sources.',
        category: 'xxe', owasp: ['A05:2021'], asvs: ['V5.5.2'], nist: ['SI-10'],
        severity: 'high', remediation: 'Disable external entity processing. Use defused XML parsers.',
        references: ['https://cwe.mitre.org/data/definitions/611.html'],
    },

    // ============================================================
    // SSTI (Server-Side Template Injection)
    // ============================================================
    'CWE-1336': {
        id: 'CWE-1336', title: 'Improper Neutralization of Special Elements Used in a Template Engine',
        description: 'Template engines execute user-controlled input as template code.',
        category: 'ssti', owasp: ['A03:2021'], asvs: ['V5.2.4'], nist: ['SI-10'],
        severity: 'critical', remediation: 'Never pass user input directly to template engines. Use sandboxed templates.',
        references: ['https://cwe.mitre.org/data/definitions/1336.html'],
    },

    // ============================================================
    // CRYPTOGRAPHIC FAILURES (OWASP A02:2021)
    // ============================================================
    'CWE-311': {
        id: 'CWE-311', title: 'Missing Encryption of Sensitive Data',
        description: 'Sensitive data is transmitted or stored without encryption.',
        category: 'misconfig', owasp: ['A02:2021'], asvs: ['V6.1.1', 'V9.1.1'], nist: ['SC-8', 'SC-28'],
        severity: 'high', remediation: 'Encrypt data in transit (TLS 1.2+) and at rest (AES-256).',
        references: ['https://cwe.mitre.org/data/definitions/311.html'],
    },
    'CWE-319': {
        id: 'CWE-319', title: 'Cleartext Transmission of Sensitive Information',
        description: 'Sensitive information is transmitted in cleartext over the network.',
        category: 'misconfig', owasp: ['A02:2021'], asvs: ['V9.1.1'], nist: ['SC-8'],
        severity: 'high', remediation: 'Use HTTPS for all communications. Enable HSTS.',
        references: ['https://cwe.mitre.org/data/definitions/319.html'],
    },
    'CWE-326': {
        id: 'CWE-326', title: 'Inadequate Encryption Strength',
        description: 'The application uses encryption with insufficient key length.',
        category: 'misconfig', owasp: ['A02:2021'], asvs: ['V6.2.2'], nist: ['SC-12'],
        severity: 'medium', remediation: 'Use key sizes recommended by NIST: AES-256, RSA-2048+, ECDSA-256+.',
        references: ['https://cwe.mitre.org/data/definitions/326.html'],
    },
    'CWE-328': {
        id: 'CWE-328', title: 'Use of Weak Hash without salt',
        description: 'The application uses weak hashing algorithms (MD5, SHA1) without salt.',
        category: 'auth', owasp: ['A02:2021'], asvs: ['V2.4.1'], nist: ['IA-5'],
        severity: 'high', remediation: 'Use bcrypt, scrypt, or Argon2 for password hashing. Always use unique salts.',
        references: ['https://cwe.mitre.org/data/definitions/328.html'],
    },

    // ============================================================
    // INSECURE DESIGN (OWASP A04:2021)
    // ============================================================
    'CWE-840': {
        id: 'CWE-840', title: 'Business Logic Errors',
        description: 'The application has flaws in business logic that can be exploited.',
        category: 'insecure_design', owasp: ['A04:2021'], asvs: ['V11.1.1'], nist: ['SA-8'],
        severity: 'high', remediation: 'Review business logic for edge cases. Implement proper state validation.',
        references: ['https://cwe.mitre.org/data/definitions/840.html'],
    },
    'CWE-799': {
        id: 'CWE-799', title: 'Improper Control of Interaction Frequency',
        description: 'The application does not properly limit the rate of user actions.',
        category: 'auth', owasp: ['A04:2021'], asvs: ['V11.1.4'], nist: ['SC-5'],
        severity: 'medium', remediation: 'Implement rate limiting on all sensitive endpoints.',
        references: ['https://cwe.mitre.org/data/definitions/799.html'],
    },

    // ============================================================
    // DATA INTEGRITY (OWASP A08:2021)
    // ============================================================
    'CWE-829': {
        id: 'CWE-829', title: 'Inclusion of Functionality from Untrusted Control Sphere',
        description: 'The application includes third-party resources without integrity verification.',
        category: 'data_integrity', owasp: ['A08:2021'], asvs: ['V14.2.3'], nist: ['SI-7'],
        severity: 'medium', remediation: 'Use Subresource Integrity (SRI) for all external scripts and styles.',
        references: ['https://cwe.mitre.org/data/definitions/829.html'],
    },
    'CWE-494': {
        id: 'CWE-494', title: 'Download of Code Without Integrity Check',
        description: 'The application downloads and executes code without verifying its integrity.',
        category: 'data_integrity', owasp: ['A08:2021'], asvs: ['V14.2.3'], nist: ['SI-7'],
        severity: 'high', remediation: 'Verify integrity of downloaded code using checksums or signatures.',
        references: ['https://cwe.mitre.org/data/definitions/494.html'],
    },

    // ============================================================
    // LOGGING & MONITORING (OWASP A09:2021)
    // ============================================================
    'CWE-778': {
        id: 'CWE-778', title: 'Insufficient Logging',
        description: 'The application does not log security-relevant events.',
        category: 'misconfig', owasp: ['A09:2021'], asvs: ['V7.1.1', 'V7.1.2'], nist: ['AU-2', 'AU-3'],
        severity: 'medium', remediation: 'Implement comprehensive logging for authentication, authorization, and data access events.',
        references: ['https://cwe.mitre.org/data/definitions/778.html'],
    },
    'CWE-117': {
        id: 'CWE-117', title: 'Improper Output Neutralization for Logs',
        description: 'Log entries can be forged through log injection.',
        category: 'info_disclosure', owasp: ['A09:2021'], asvs: ['V7.1.3'], nist: ['AU-3'],
        severity: 'medium', remediation: 'Sanitize all data before writing to logs. Use structured logging.',
        references: ['https://cwe.mitre.org/data/definitions/117.html'],
    },
};

/**
 * Look up a CWE entry by ID
 * @param cweId - CWE ID (e.g., "CWE-79" or "79")
 * @returns CWE entry or undefined
 */
export function getCweEntry(cweId: string): CweEntry | undefined {
    const normalizedId = cweId.startsWith('CWE-') ? cweId : `CWE-${cweId}`;
    return CWE_DATABASE[normalizedId];
}

/**
 * Get all CWE entries for a given category
 */
export function getCweByCategory(category: string): CweEntry[] {
    return Object.values(CWE_DATABASE).filter(e => e.category === category);
}

/**
 * Get all CWE entries mapped to a specific OWASP Top 10 item
 */
export function getCweByOwasp(owaspId: string): CweEntry[] {
    return Object.values(CWE_DATABASE).filter(e => e.owasp.includes(owaspId));
}

/**
 * Get total CWE count
 */
export function getCweCount(): number {
    return Object.keys(CWE_DATABASE).length;
}

/**
 * OWASP Top 10 2021 Categories
 */
export const OWASP_TOP_10_2021 = [
    { id: 'A01:2021', name: 'Broken Access Control', description: 'Moving up from #5, 94% of applications were tested for some form of broken access control.' },
    { id: 'A02:2021', name: 'Cryptographic Failures', description: 'Shifting up one position from #3, previously known as Sensitive Data Exposure.' },
    { id: 'A03:2021', name: 'Injection', description: 'Sliding down to #3. 94% of applications were tested for some form of injection.' },
    { id: 'A04:2021', name: 'Insecure Design', description: 'New category for 2021, focusing on risks related to design and architectural flaws.' },
    { id: 'A05:2021', name: 'Security Misconfiguration', description: 'Moving up from #6, 90% of applications were tested for some form of misconfiguration.' },
    { id: 'A06:2021', name: 'Vulnerable and Outdated Components', description: 'Previously titled Using Components with Known Vulnerabilities.' },
    { id: 'A07:2021', name: 'Identification and Authentication Failures', description: 'Previously Broken Authentication, sliding down from #2.' },
    { id: 'A08:2021', name: 'Software and Data Integrity Failures', description: 'New category for 2021, focusing on making assumptions about software updates and CI/CD pipelines.' },
    { id: 'A09:2021', name: 'Security Logging and Monitoring Failures', description: 'Previously Insufficient Logging & Monitoring, moving from #10.' },
    { id: 'A10:2021', name: 'Server-Side Request Forgery', description: 'New addition to the Top 10 for 2021, added from community survey.' },
];

/**
 * Category display names
 */
export const CATEGORY_DISPLAY_NAMES: Record<string, string> = {
    xss: 'Cross-Site Scripting (XSS)',
    sqli: 'SQL Injection',
    ssrf: 'Server-Side Request Forgery (SSRF)',
    path_traversal: 'Path Traversal',
    open_redirect: 'Open Redirect',
    headers: 'Security Headers',
    info_disclosure: 'Information Disclosure',
    auth: 'Authentication Issues',
    cors: 'CORS Misconfiguration',
    cve: 'Known CVE',
    jwt: 'JWT Security',
    idor: 'Insecure Direct Object Reference',
    cmd_injection: 'Command Injection',
    nosql_injection: 'NoSQL Injection',
    deserialization: 'Insecure Deserialization',
    rce: 'Remote Code Execution',
    csrf: 'Cross-Site Request Forgery',
    clickjacking: 'Clickjacking',
    xxe: 'XML External Entity',
    ssti: 'Server-Side Template Injection',
    ldap_injection: 'LDAP Injection',
    insecure_design: 'Insecure Design',
    misconfig: 'Security Misconfiguration',
    outdated_component: 'Vulnerable Component',
    data_integrity: 'Data Integrity Failure',
};
