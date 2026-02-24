# InjectProof

> Automated SQL injection scanner that finds what others miss.

**InjectProof** is a self-hosted web vulnerability scanner built for penetration testers who need more than basic SQLi detection. It crawls your target, discovers forms (including JavaScript-rendered ones), fingerprints the tech stack, finds exposed admin panels and backup files, then runs a full exploitation chain — from detection through database dumping — without touching sqlmap or any external tool.

Built on Next.js 15, runs in your browser, stores everything locally.

![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)
![License](https://img.shields.io/badge/License-Private-red)

---

## Why InjectProof?

Most SQL injection tools fall into two camps: automated scanners that produce false positives and miss anything behind a login form, or manual exploitation tools that require you to configure every parameter by hand.

InjectProof sits in between. It uses a headless browser (Puppeteer with stealth plugins) to interact with your target like a real user — filling forms, clicking buttons, handling CSRF tokens — while running an exploitation engine that automatically escalates from detection to full database extraction.

### What it does that Havij / sqlmap don't

| Feature | Havij | sqlmap | InjectProof |
|---------|-------|--------|-------------|
| Browser-based form interaction | ❌ | ❌ | ✅ |
| Automatic CSRF token handling | ❌ | ❌ | ✅ |
| JavaScript-rendered page crawling | ❌ | ❌ | ✅ |
| Auth bypass + recursive post-auth scan | ❌ | ❌ | ✅ |
| Admin panel discovery (300+ paths) | ✅ | ❌ | ✅ |
| Backup file scanner | ❌ | ❌ | ✅ |
| Technology fingerprinting | ❌ | ❌ | ✅ |
| WAF detection + adaptive evasion | Partial | ✅ | ✅ |
| Multi-technique exploitation (UNION/Error/Blind/Time) | Partial | ✅ | ✅ |
| Password hash extraction + cracking | ✅ | ✅ | ✅ |
| File read / OS command execution | ✅ | ✅ | ✅ |
| Professional HTML reports | ❌ | ❌ | ✅ |
| Modern web UI with real-time progress | ❌ | ❌ | ✅ |
| Self-hosted, no cloud dependency | ✅ | ✅ | ✅ |

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/YOUR_USERNAME/injectproof.git
cd injectproof
npm run setup

# Start the scanner
npm run dev
```

Open **http://localhost:3000** — login with `admin@injectproof.local` / `admin123`.

Add a target, start a scan, and watch InjectProof work through each phase in real time.

---

## How It Works

InjectProof runs scans in five phases:

**1. Crawling** — Discovers pages and endpoints using both static HTTP requests and a stealth headless browser. Captures forms, query parameters, AJAX endpoints, and JavaScript-rendered content.

**2. Vulnerability Detection** — Runs 11 detector modules against every discovered endpoint. Each detector sends targeted payloads and analyzes responses for evidence of exploitable vulnerabilities.

**3. Reconnaissance** — Probes for admin panels across 300+ common paths, scans for exposed backup files and database dumps, and fingerprints the target's technology stack (server, framework, CMS, CDN, WAF).

**4. Smart Form SQLi** — Opens a headless browser, navigates to pages with forms, fills them with SQLi payloads (handling CSRF tokens automatically), submits them, and analyzes responses. If a login form is vulnerable, it bypasses auth and scans post-login pages recursively.

**5. Deep Exploitation** — When SQLi is confirmed, the exploitation engine kicks in. It fingerprints the DBMS, detects the column count, finds injectable columns, and extracts:
- Database names, table structures, column types
- Full row data from every discovered table
- User accounts and password hashes (with dictionary cracking)
- Server files (`/etc/passwd`, config files)
- OS command execution (when running as DBA)

All extraction uses four techniques in priority order: UNION → Error-based → Boolean-blind → Time-blind. If a WAF is detected, payloads are automatically encoded with WAF-specific evasion strategies.

---

## Scanner Modules

### Vulnerability Detectors

| Module | CWE | What it finds |
|--------|-----|---------------|
| SQL Injection | CWE-89 | Error-based, boolean-blind, time-based detection across MySQL, PostgreSQL, MSSQL, SQLite |
| Cross-Site Scripting | CWE-79 | Reflected, stored, and DOM-based XSS with context-aware payloads |
| Server-Side Request Forgery | CWE-918 | Internal IP access, redirect chains, cloud metadata endpoints |
| Path Traversal | CWE-22 | Directory traversal with encoding bypass variants |
| Open Redirect | CWE-601 | URL parameter redirect validation bypass |
| CORS Misconfiguration | CWE-942 | Origin reflection, null origin, wildcard with credentials |
| Security Headers | — | Missing CSP, HSTS, X-Frame-Options, referrer policy |

### Advanced Detectors

| Module | What it finds |
|--------|---------------|
| Race Condition | HTTP/2 single-packet TOCTOU vulnerabilities |
| HTTP Request Smuggling | CL.TE and TE.CL desync attacks |
| Prototype Pollution | `__proto__` and `constructor.prototype` injection |
| Cloud Metadata SSRF | AWS IMDSv1/v2, GCP, Azure, DigitalOcean metadata endpoints |

### Reconnaissance

| Module | What it finds |
|--------|---------------|
| Admin Panel Finder | 300+ common admin paths with smart login form detection |
| Backup File Scanner | Exposed `.sql`, `.zip`, `.bak`, `.env`, config files |
| Technology Fingerprinter | Server, framework, CMS, CDN, WAF, JS libraries |

### Deep Exploitation

| Capability | Details |
|-----------|---------|
| DBMS Fingerprinting | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| Database Enumeration | Lists all databases, tables, columns with types |
| Data Extraction | Dumps rows from any table using 4 extraction techniques |
| User Enumeration | Extracts DB users, hostnames, privileges |
| Hash Extraction | Pulls password hashes with built-in dictionary cracking |
| File Read | Reads server files via LOAD_FILE / pg_read_file |
| OS Commands | Executes commands via xp_cmdshell / UDF (DBA only) |
| WAF Evasion | Adaptive encoding for Cloudflare, ModSecurity, AWS WAF, Akamai |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 (App Router), React 19, Tailwind CSS |
| API | tRPC v11 with type-safe end-to-end contracts |
| Database | SQLite via Prisma ORM (zero config) |
| Auth | JWT with bcrypt password hashing |
| Scanner | Custom TypeScript engine (no external dependencies) |
| Browser | Puppeteer with stealth anti-detection |
| Reports | HTML, Markdown, and JSON export |

---

## Configuration

Create a `.env` file:

```env
DATABASE_URL="file:./injectproof.db"
JWT_SECRET=change-this-to-a-random-64-char-string
NEXT_PUBLIC_APP_NAME=InjectProof
NEXT_PUBLIC_APP_URL=http://localhost:3000
SCANNER_USER_AGENT=InjectProof-Scanner/1.0
```

### Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@injectproof.local` | `admin123` |
| Pentester | `pentester@injectproof.local` | `pentester123` |

> Change these before exposing the instance to any network.

---

## Reports

InjectProof generates four report types:

- **Executive** — one-page summary with risk score and severity breakdown. For management.
- **Technical** — full payload details, request/response artifacts, reproduction steps. For developers.
- **Compliance** — findings mapped to OWASP Top 10, NIST 800-53, ASVS. For auditors.
- **Full** — everything above in a single document.

Each report includes CVSS v3.1 scores, CWE classifications, and actionable remediation guidance.

---

## Project Structure

```
src/
├── app/                    # Next.js pages
│   ├── login/              # Authentication
│   ├── api/trpc/           # API handler
│   └── (platform)/         # Dashboard, targets, scans, vulns, reports, settings
├── scanner/                # Core engine
│   ├── index.ts            # Scan orchestrator
│   ├── crawler.ts          # HTTP crawler
│   ├── headless-browser.ts # Stealth Chromium manager
│   ├── headless-crawler.ts # JS-aware SPA crawler
│   ├── detectors.ts        # 7 standard vuln detectors
│   ├── advanced-detectors.ts # 4 advanced detectors
│   ├── recon-scanner.ts    # Admin finder + backup scanner + fingerprinting
│   ├── smart-form-sqlmap.ts # Browser-based form SQLi engine
│   ├── sqli-exploiter.ts   # Deep exploitation engine
│   ├── post-exploit.ts     # Post-exploitation evidence gathering
│   ├── easm.ts             # External attack surface management
│   ├── cloud-exploit.ts    # Cloud infrastructure testing
│   └── cognitive-exploit.ts # Context-aware fuzzing
├── lib/                    # Utilities (auth, CVSS calc, CWE database)
├── server/                 # tRPC routers
└── types/                  # Shared TypeScript types
```

---

## Recommended Test Targets

> Only scan systems you own or have written authorization to test.

| Target | URL | Notes |
|--------|-----|-------|
| OWASP Juice Shop | `https://juice-shop.herokuapp.com` | Modern vulnerable web app |
| DVWA | `http://localhost/dvwa` | Classic PHP vulnerable app |
| WebGoat | `http://localhost:8080/WebGoat` | Java-based learning platform |
| bWAPP | `http://localhost/bWAPP` | 100+ vulnerabilities |
| SQLi-labs | `http://localhost/sqli-labs` | Dedicated SQLi practice |

---

## Scripts

| Command | What it does |
|---------|-------------|
| `npm run setup` | Full install → generate → push → seed |
| `npm run dev` | Start dev server at localhost:3000 |
| `npm run build` | Production build |
| `npm run db:reset` | Wipe and re-seed the database |
| `npm run db:studio` | Open Prisma visual DB browser |

---

## Security

InjectProof enforces security on its own platform:

- JWT authentication with HttpOnly cookies
- bcrypt (12 rounds) password hashing
- Five-tier RBAC (viewer → developer → pentester → security_lead → admin)
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers
- tRPC middleware-level authorization on every route

---

## Legal

This software is designed for authorized penetration testing only. Running it against targets without explicit written permission is illegal in most jurisdictions. The authors are not responsible for misuse.

---

## License

Private — All rights reserved.
