# 🛡️ VibeCode-InjectProof

> **Deep SQLi verification engine for authorized security testing with differential analysis and reproducible evidence.**

![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)
![Prisma](https://img.shields.io/badge/Prisma-6-2D3748?logo=prisma)
![tRPC](https://img.shields.io/badge/tRPC-11-398CCB?logo=trpc)

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Scanner Modules](#-scanner-modules)
- [Project Structure](#-project-structure)
- [API Reference](#-api-reference)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **🕷️ Smart Crawling** | HTTP + headless browser (Puppeteer stealth), SPA/JS-rendered pages, form/parameter discovery |
| **🔍 Vulnerability Detection** | 11 detector modules — XSS, SQLi, SSRF, CORS, Path Traversal, Open Redirect, Security Headers, Race Condition, HTTP Desync, Prototype Pollution, Cloud Metadata SSRF |
| **💉 Deep SQLi Exploitation** | Havij-style automated exploitation — DB enumeration, table extraction, data dumping |
| **🌐 EASM Recon** | Subdomain enumeration, cloud bucket hunting, leaked secret scanning, shadow API discovery |
| **☁️ Cloud & Infra** | Container escape detection, CI/CD poisoning, internal VPC pivoting |
| **🧠 Cognitive Fuzzing** | Context-aware payload generation, business logic flaw testing |
| **🔓 Post-Exploitation** | RCE evidence, schema extraction, internal port scanning |
| **📊 Reporting** | Executive, Technical, Compliance, Full reports in HTML/Markdown/JSON |
| **🎨 Premium UI** | Dark glassmorphism theme, real-time scan progress, interactive dashboards |
| **🔐 RBAC** | 5 user roles with JWT authentication |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 (App Router), React 19, Tailwind CSS 3 |
| API | tRPC v11 + SuperJSON |
| Database | SQLite via Prisma ORM v6 |
| Auth | JWT (jose) + bcryptjs |
| Scanner | Custom Node.js engine (11 detectors) |
| Browser | Puppeteer + puppeteer-extra-plugin-stealth |
| HTML Parser | Cheerio |
| UI | Lucide icons, Recharts, date-fns |

---

## 📦 Prerequisites

- **Node.js** 18+ ([download](https://nodejs.org/))
- **npm** (bundled with Node.js) or **pnpm**
- **Chrome / Edge** browser installed (for headless SPA crawling)
- **Git** (optional, for cloning)

---

## 🚀 Installation

### Option 1: One-Command Setup

```bash
npm run setup
```

This runs the full chain: `npm install` → `prisma generate` → `prisma db push` → `seed`

### Option 2: Step-by-Step

```bash
# 1. Install dependencies
npm install

# 2. Generate Prisma client
npx prisma generate

# 3. Create database and push schema
npx prisma db push

# 4. Seed default data (admin user + sample target)
npx tsx prisma/seed.ts

# 5. Start development server
npm run dev
```

The app will be available at **http://localhost:3000**

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root (or copy from `.env.example`):

```env
# ───── Database ─────
# SQLite database (auto-created)
DATABASE_URL="file:./vibecode.db"

# ───── Authentication ─────
# ⚠️ CHANGE THIS in production!
JWT_SECRET=vibecode-local-secret-key-change-in-production-2024

# ───── Application ─────
NEXT_PUBLIC_APP_NAME=VibeCode
NEXT_PUBLIC_APP_URL=http://localhost:3000

# ───── Scanner Settings ─────
SCANNER_MAX_CONCURRENT=5          # Max concurrent scan threads
SCANNER_REQUEST_TIMEOUT=30000     # Request timeout (ms)
SCANNER_MAX_CRAWL_DEPTH=10        # Max crawl depth
SCANNER_MAX_URLS=500              # Max URLs to discover
SCANNER_USER_AGENT=VibeCode-Scanner/1.0

# ───── Evidence Storage ─────
EVIDENCE_DIR=./evidence
```

### Default Login Credentials

| Role | Email | Password |
|------|-------|----------|
| **Admin** | `admin@vibecode.local` | `admin123` |
| **Pentester** | `pentester@vibecode.local` | `pentester123` |

> ⚠️ **Change these immediately in production!**

---

## 📖 Usage

### 1. Start the Server

```bash
# Development (with hot-reload)
npm run dev

# Production
npm run build
npm start
```

### 2. Login

Open **http://localhost:3000** → Login with credentials above.

### 3. Add a Target

1. Navigate to **Targets** → **New Target**
2. Enter the target URL (e.g., `https://juice-shop.herokuapp.com`)
3. Configure scan settings:
   - **Crawl Depth** — How deep to follow links (default: 10)
   - **Max URLs** — Maximum pages to discover (default: 500)
   - **Rate Limit** — Requests per second (default: 10)
   - **Authentication** — Optional (token, cookie, session, scripted login)

### 4. Run a Scan

1. Navigate to **Scans** → **New Scan**
2. Select your target from the dropdown
3. Choose scan profile:
   - **Quick** — Standard detectors only (fastest)
   - **Standard** — Standard + advanced detectors
   - **Deep** — All modules including EASM, cognitive fuzzing, post-exploitation
4. Click **Start Scan**
5. Monitor progress in real-time on the scan detail page

### 5. Review Vulnerabilities

- **Scans** → Click a completed scan → View all findings
- **Vulnerabilities** → Browse/filter all vulnerabilities across scans
- Each vulnerability includes:
  - CVSS score + vector
  - CWE classification
  - OWASP mapping
  - Request/response artifacts
  - Remediation steps

### 6. Generate Reports

1. Navigate to **Reports** → **Generate Report**
2. Select a scan
3. Choose report type:
   - **Executive** — High-level summary for management
   - **Technical** — Full technical details for developers
   - **Compliance** — Mapped to OWASP/NIST/ASVS frameworks
   - **Full** — Everything combined
4. Choose format: **HTML** / **Markdown** / **JSON**
5. Download the generated report

---

## 🔬 Scanner Modules

### Standard Detectors (7)

| Module | CWE | Description |
|--------|-----|-------------|
| XSS | CWE-79 | Reflected, Stored, DOM-based with context-aware payloads |
| SQLi | CWE-89 | Error-based, boolean-blind, time-based (MySQL/PostgreSQL/MSSQL/SQLite) |
| SSRF | CWE-918 | Internal IP probing, redirect chains, cloud metadata |
| Security Headers | — | CSP, HSTS, X-Frame-Options, referrer policy |
| CORS | CWE-942 | Origin reflection, null origin, wildcard + credentials |
| Path Traversal | CWE-22 | Directory traversal with encoding bypass |
| Open Redirect | CWE-601 | URL parameter redirect detection |

### Advanced Detectors (4)

| Module | Description |
|--------|-------------|
| Race Condition | HTTP/2 single-packet TOCTOU fuzzing |
| HTTP Desync | CL.TE / TE.CL request smuggling |
| Prototype Pollution | `__proto__` / `constructor.prototype` injection |
| Cloud Metadata SSRF | AWS IMDSv1/v2, GCP, Azure, DigitalOcean, K8s |

### Elite Modules

| Module | Description |
|--------|-------------|
| **EASM** (`easm.ts`) | CT log enumeration, DNS brute-force, bucket hunting, leaked secrets |
| **Cloud Exploit** (`cloud-exploit.ts`) | Container escape, SSRF pivoting, CI/CD poisoning |
| **Cognitive** (`cognitive-exploit.ts`) | AI-driven fuzzing, business logic, rate limit bypass |
| **Post-Exploit** (`post-exploit.ts`) | RCE evidence, schema extraction, port scanning |
| **SQLi Exploiter** (`sqli-exploiter.ts`) | Deep SQLi exploitation — DB/table/column enumeration + data dump |

---

## 📂 Project Structure

```
pentest/
├── prisma/
│   ├── schema.prisma          # Database schema (10 models)
│   ├── seed.ts                # Default data seeder
│   └── vibecode.db            # SQLite database (auto-generated)
├── src/
│   ├── app/                   # Next.js App Router pages
│   │   ├── globals.css        # Design system
│   │   ├── layout.tsx         # Root layout
│   │   ├── login/             # Login page
│   │   ├── api/trpc/          # tRPC HTTP handler
│   │   └── (platform)/        # Authenticated routes
│   │       ├── dashboard/     # Stats + charts
│   │       ├── targets/       # Target CRUD
│   │       ├── scans/         # Scan management
│   │       ├── vulnerabilities/ # Vulnerability browser
│   │       ├── reports/       # Report generation
│   │       └── settings/      # Platform settings
│   ├── components/            # Shared React components
│   ├── lib/                   # Utilities
│   │   ├── auth.ts            # JWT + RBAC
│   │   ├── cvss.ts            # CVSS v3.1 calculator
│   │   ├── cwe-database.ts    # 200+ CWE entries
│   │   ├── prisma.ts          # Prisma client
│   │   └── utils.ts           # Shared helpers
│   ├── scanner/               # Scanner engine
│   │   ├── index.ts           # Orchestrator (entry point)
│   │   ├── crawler.ts         # HTTP crawler
│   │   ├── headless-browser.ts # Stealth Chromium
│   │   ├── headless-crawler.ts # SPA-aware crawler
│   │   ├── payloads.ts        # Payload engine (52KB)
│   │   ├── detectors.ts       # 7 standard detectors
│   │   ├── advanced-detectors.ts # 4 advanced detectors
│   │   ├── sqli-exploiter.ts  # Deep SQLi exploitation
│   │   ├── easm.ts            # Attack surface management
│   │   ├── cloud-exploit.ts   # Cloud/infra exploitation
│   │   ├── cognitive-exploit.ts # AI fuzzing
│   │   ├── post-exploit.ts    # Post-exploitation
│   │   └── data/              # External payload databases
│   ├── server/                # tRPC routers + context
│   ├── trpc/                  # tRPC client config
│   └── types/                 # Shared TypeScript types
├── .env                       # Environment variables
├── .gitignore                 # Git ignore rules
├── package.json               # Dependencies + scripts
├── tailwind.config.ts         # Tailwind configuration
└── tsconfig.json              # TypeScript configuration
```

---

## 📡 API Reference

VibeCode uses **tRPC** for type-safe API calls. All routes are under `/api/trpc/`.

### Auth Router
| Procedure | Type | Auth | Description |
|-----------|------|------|-------------|
| `auth.login` | mutation | public | Email/password → JWT cookie |
| `auth.logout` | mutation | protected | Clear auth cookie |
| `auth.register` | mutation | admin | Create new user |
| `auth.me` | query | protected | Current user profile |

### Target Router
| Procedure | Type | Auth | Description |
|-----------|------|------|-------------|
| `target.list` | query | protected | Paginated target list |
| `target.getById` | query | protected | Single target detail |
| `target.create` | mutation | pentester+ | Create target |
| `target.update` | mutation | pentester+ | Update target config |
| `target.delete` | mutation | admin | Delete target |

### Scan Router
| Procedure | Type | Auth | Description |
|-----------|------|------|-------------|
| `scan.list` | query | protected | Paginated scan list |
| `scan.getById` | query | protected | Scan detail + logs |
| `scan.create` | mutation | pentester+ | Launch new scan |
| `scan.cancel` | mutation | pentester+ | Cancel running scan |
| `scan.getLogs` | query | protected | Scan execution logs |

### Vulnerability Router
| Procedure | Type | Auth | Description |
|-----------|------|------|-------------|
| `vulnerability.list` | query | protected | Filtered vulnerability list |
| `vulnerability.getById` | query | protected | Full detail + evidence |
| `vulnerability.updateStatus` | mutation | pentester+ | Change status |

### Report Router
| Procedure | Type | Auth | Description |
|-----------|------|------|-------------|
| `report.generate` | mutation | pentester+ | Generate report |
| `report.list` | query | protected | List reports |
| `report.getById` | query | protected | Report content |
| `report.download` | query | protected | Download report |

---

## 🔧 NPM Scripts

| Script | Command | Description |
|--------|---------|-------------|
| `npm run dev` | `next dev` | Development server (http://localhost:3000) |
| `npm run build` | `next build` | Production build |
| `npm start` | `next start` | Production server |
| `npm run lint` | `next lint` | ESLint check |
| `npm run db:generate` | `prisma generate` | Regenerate Prisma client |
| `npm run db:push` | `prisma db push` | Push schema to database |
| `npm run db:seed` | `tsx prisma/seed.ts` | Seed default data |
| `npm run db:reset` | Full reset | Drop + re-push + re-seed |
| `npm run db:studio` | `prisma studio` | Visual database browser |
| `npm run setup` | Full setup | install + generate + push + seed |

---

## 🎯 Recommended Test Targets

> ⚠️ **Only scan targets you own or have explicit permission to test!**

| Target | URL | Notes |
|--------|-----|-------|
| OWASP Juice Shop | `https://juice-shop.herokuapp.com` | Pre-seeded in database |
| DVWA | `http://localhost/dvwa` | Self-hosted |
| WebGoat | `http://localhost:8080/WebGoat` | Self-hosted |
| bWAPP | `http://localhost/bWAPP` | Self-hosted |
| HackTheBox | Various | CTF-style targets |

---

## 🔐 Security

### Platform Security
- **CSP Headers** — Strict Content-Security-Policy
- **HSTS** — HTTP Strict Transport Security with `includeSubDomains`
- **Frame Protection** — `X-Frame-Options: DENY`
- **XSS Filter** — `X-XSS-Protection: 1; mode=block`
- **Content Sniffing** — `X-Content-Type-Options: nosniff`
- **JWT** — HttpOnly cookies, HMAC-SHA256 signed
- **Passwords** — bcrypt with 12 salt rounds
- **RBAC** — Enforced at tRPC middleware level

### Role Hierarchy

| Role | Level | Capabilities |
|------|-------|-------------|
| `viewer` | 0 | Read-only dashboards |
| `developer` | 1 | View assigned vulnerabilities |
| `pentester` | 2 | Create targets, run scans, generate reports |
| `security_lead` | 3 | Full management + team oversight |
| `admin` | 4 | All operations + user management |

---

## ❓ Troubleshooting

### Common Issues

**Port 3000 already in use**
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Linux/macOS
lsof -i :3000
kill -9 <PID>
```

**Prisma client not generated**
```bash
npx prisma generate
```

**Database is empty after setup**
```bash
npx tsx prisma/seed.ts
```

**Headless browser not launching**
- Ensure Chrome or Edge is installed
- Puppeteer will download Chromium automatically on `npm install`
- On Linux, install dependencies: `sudo apt install -y libnss3 libatk-bridge2.0-0 libdrm2 libxcomposite1`

**TypeScript build errors**
```bash
npx tsc --noEmit
```

**Reset everything**
```bash
npm run db:reset
```

---

## ⚖️ Legal Disclaimer

> **This tool is intended for authorized security testing only.**
> Unauthorized access to computer systems is illegal. Always obtain written permission before testing any target.
> The developers assume no liability for misuse of this software.

---

## 📄 License

Private — All rights reserved.
