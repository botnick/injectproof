# InjectProof

> The SQL injection scanner that finds what sqlmap, Havij, and every other tool miss.

**InjectProof** is a self-hosted web vulnerability scanner built for penetration testers who refuse to settle for basic detection. It crawls your target with a stealth headless browser, discovers forms (including JavaScript-rendered ones), fingerprints the tech stack, finds exposed admin panels and backup files, then runs a **full adaptive exploitation chain** — from context-aware detection through database dumping — with a smart mutation engine that auto-bypasses WAFs. No sqlmap, no external tools, no manual configuration.

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
| **SQL context detection (32 contexts)** | ❌ | Partial | ✅ |
| **Stacked queries detection** | ❌ | ✅ | ✅ |
| **Second-order SQLi** | ❌ | ❌ | ✅ |
| **Cookie/Header injection (12+ headers)** | ❌ | Partial | ✅ |
| **Smart payload mutation (30+ tampers)** | ❌ | ✅ | ✅ |
| **PHP addslashes/GBK bypass** | ❌ | ✅ | ✅ |
| Admin panel discovery (300+ paths) | ✅ | ❌ | ✅ |
| Technology fingerprinting | ❌ | ❌ | ✅ |
| WAF detection + adaptive evasion (7+ WAFs) | Partial | ✅ | ✅ |
| Multi-technique exploitation (UNION/Error/Blind/Time) | Partial | ✅ | ✅ |
| Password hash extraction + cracking | ✅ | ✅ | ✅ |
| File read / OS command execution | ✅ | ✅ | ✅ |
| Out-of-Band DNS exfiltration payloads | ❌ | ✅ | ✅ |
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

InjectProof runs scans in seven phases:

**1. Crawling** — Discovers pages and endpoints using both static HTTP requests and a stealth headless browser. Captures forms, query parameters, AJAX endpoints, and JavaScript-rendered content.

**2. Intelligent Analysis** — The scanner brain analyzes every page: classifies forms (15 types: login, search, upload, comment, etc.), scores each field's attack priority, discovers hidden AJAX endpoints from inline JavaScript, maps interactive elements (buttons, tabs, pagination, sort controls, modals), classifies page types, extracts HTML comments for info leaks, and generates a prioritized attack plan. Discovered AJAX endpoints are automatically merged into the scan queue.

**3. Vulnerability Detection** — Runs 11 detector modules against every discovered endpoint (including AJAX endpoints found by the intelligence phase). Each detector sends targeted payloads and analyzes responses for evidence of exploitable vulnerabilities.

**4. Reconnaissance** — Probes for admin panels across 300+ common paths, scans for exposed backup files and database dumps, and fingerprints the target's technology stack (server, framework, CMS, CDN, WAF).

**5. Smart Form SQLi** — Opens a headless browser, navigates to pages with forms, fills them with SQLi payloads (handling CSRF tokens automatically), submits them, and analyzes responses. If a login form is vulnerable, it bypasses auth and scans post-login pages recursively.

**6. Adaptive Context Detection** — The V2 engine analyzes how each parameter is embedded in SQL: detects 32 injection contexts, identifies the exact closing characters and comment style needed, fingerprints the DBMS, and detects PHP backends. It also probes 12+ HTTP headers and tests for stacked query support and second-order SQLi.

**7. Deep Exploitation** — When SQLi is confirmed, the exploitation engine kicks in with context-aware payloads. It fingerprints the DBMS, detects the column count, finds injectable columns, and extracts:
- Database names, table structures, column types
- Full row data from every discovered table
- User accounts and password hashes (with dictionary cracking)
- Server files (`/etc/passwd`, config files)
- OS command execution (when running as DBA)

All extraction uses four techniques in priority order: UNION → Error-based → Boolean-blind → Time-blind. If a WAF blocks a payload, the **smart mutation engine** auto-applies 30+ tamper functions (space→comment, hex encoding, case alternation, inline MySQL comments, keyword splitting, etc.) and chains them in 2-deep combinations until the WAF is bypassed. Supports WAF-specific bypasses for Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, Sucuri, and F5 BigIP.

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

### Intelligent Scanner Brain

| Capability | Details |
|-----------|---------|
| Form Classification | 15 form types: login, registration, search, upload, comment, contact, profile-edit, password-change, password-reset, admin-action, filter, settings, payment, newsletter, delete-confirm |
| Field Analysis | Per-field SQLi/XSS priority scoring (0-10). Detects: injectable params, credentials, tokens, identifiers, content fields, file inputs |
| AJAX Discovery | Extracts hidden endpoints from inline JS: `fetch()`, `$.ajax()`, `axios`, `XMLHttpRequest`, `/api/*`, `.php` paths (10+ regex patterns) |
| Interactive Element Mapping | Discovers buttons, tabs, pagination, sort controls, dropdowns, modal triggers, and `data-*` URL attributes |
| Page Classification | 12 page types: login, dashboard, listing, detail, search-results, admin-panel, settings, profile, registration, error, api-docs, file-manager |
| Attack Plan Generator | Auto-generates prioritized attack steps based on form types, field analysis, and page context |
| HTML Comment Extraction | Finds developer comments that may leak paths, credentials, TODO items, or debug info |
| Risk Scoring | Per-page risk score (0-100) based on form types, interactive elements, AJAX count, auth/admin status |

### Adaptive SQLi Engine V2

| Capability | Details |
|-----------|---------|
| Context Detection | 32 SQL contexts: WHERE (string/numeric/paren/double-quote/backtick), ORDER BY, INSERT, UPDATE, LIKE, IN, HAVING, GROUP BY, LIMIT, BETWEEN, CASE WHEN, CONCAT, subquery, JSON, REST path |
| PHP-Specific | GBK/Big5 multibyte `addslashes()` bypass, numeric type juggling, PHP backend auto-detection (10 signatures) |
| MSSQL-Specific | Bracket notation `[col]`, EXEC stored procedure injection, xp_cmdshell probes |
| Stacked Queries | Auto-detects multi-statement support on MySQL, MSSQL, PostgreSQL, SQLite |
| Second-Order SQLi | Injects in one endpoint, triggers in another — supports auth-bypass, error-trigger, time-trigger markers |
| Header/Cookie Injection | Probes 12+ headers: Cookie, Referer, X-Forwarded-For, X-Client-IP, X-Real-IP, User-Agent, Accept-Language, X-Original-URL, X-Rewrite-URL, and more |
| Smart Mutation Engine | 30+ tamper functions with auto-chaining (2-deep combos). Space→comment, hex encoding, case swap, keyword split, scientific notation, null-byte, unicode fullwidth |
| WAF Bypass | Specific bypasses for Cloudflare, ModSecurity, AWS WAF, Akamai, Imperva, Sucuri, F5 BigIP + double URL encode + mixed encoding chains |
| Response Diff Engine | Statistical response comparison: length, word count, status code, title hash, content hash — not just length diff |
| Out-of-Band | DNS exfiltration payloads: MySQL `LOAD_FILE`, MSSQL `xp_dirtree`/`xp_subdirs`, PostgreSQL `COPY TO PROGRAM`, Oracle `UTL_HTTP` |

### Deep Exploitation

| Capability | Details |
|-----------|---------|
| DBMS Fingerprinting | MySQL, PostgreSQL, MSSQL, Oracle, SQLite (22 MySQL + 18 MSSQL error patterns) |
| Database Enumeration | Lists all databases, tables, columns with types |
| Data Extraction | Dumps rows from any table using 4 extraction techniques |
| User Enumeration | Extracts DB users, hostnames, privileges |
| Hash Extraction | Pulls password hashes with built-in dictionary cracking |
| File Read | Reads server files via LOAD_FILE / pg_read_file |
| OS Commands | Executes commands via xp_cmdshell / UDF (DBA only) |

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
│   ├── index.ts            # Scan orchestrator (7-phase pipeline)
│   ├── crawler.ts          # HTTP crawler
│   ├── headless-browser.ts # Stealth Chromium manager
│   ├── headless-crawler.ts # JS-aware SPA crawler
│   ├── intelligent-scanner.ts # 🧠 Scanner brain (form classification, AJAX discovery, attack planning)
│   ├── detectors.ts        # 11 standard vuln detectors + V2 integration
│   ├── advanced-detectors.ts # 4 advanced detectors
│   ├── recon-scanner.ts    # Admin finder + backup scanner + fingerprinting
│   ├── smart-form-sqlmap.ts # Browser-based form SQLi engine
│   ├── sqli-adaptive.ts    # 🔥 V2 Adaptive engine (context detection, mutation, stacked queries, header injection)
│   ├── sqli-exploiter.ts   # Deep exploitation engine (UNION/Error/Blind/Time)
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
