# InjectProof

> Adaptive oracle-driven web security scanner — authorized penetration testing, self-hosted, production-grade.

**InjectProof** is a self-hosted security scanner for authorized penetration testers and security teams. It combines a stealth headless browser crawler, a probabilistic oracle detection engine, and a full exploitation chain in a single Next.js application that runs natively on Windows and Linux with zero external tool dependencies.

Detection is statistical, not rule-based. Every finding is confirmed by replaying the anomaly and verifying the counter-factual returns to baseline before a vulnerability is recorded. No regex matching. No static thresholds. No false-positive floods.

![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)
![Prisma](https://img.shields.io/badge/Prisma-7-2D3748?logo=prisma)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/License-Private-red)

---

## Why InjectProof?

Traditional scanners make decisions with regex and thresholds — "response contains `You have an error in your SQL`" or "response length changed by more than 50 bytes." Both produce false positives on dynamic pages and false negatives on any target that suppresses error output.

InjectProof uses a compound oracle for every detection decision:

1. **Learn the baseline** — send 5–7 benign variants of each parameter, build a statistical cluster (mean/variance per feature axis via Welford online statistics, simhash centroid, vocabulary set). The anomaly threshold is calibrated from the actual within-cluster spread, not a hardcoded constant.
2. **Synthesize payloads** — a context-free grammar generates DBMS-specific, context-specific SQL payloads. XSS payloads are generated from the observed reflection context (script block vs attribute vs href vs text node). No static lists.
3. **Measure distance** — compute the Mahalanobis-diagonal distance of the attack response from the baseline cluster across 8 axes: status class, body length, word count, response time, simhash, header set, DOM structure, unseen tokens.
4. **Confirm** — replay the anomaly twice and send a benign counter-factual. Only confirmed (`replay passes` + `counter-factual returns`) findings reach the database.

### Feature comparison

| Feature | Havij | sqlmap | InjectProof |
|---------|-------|--------|-------------|
| Oracle-based detection (no regex/threshold) | ❌ | ❌ | ✅ |
| Reflection-context-aware XSS payloads | ❌ | Partial | ✅ |
| Bayesian DBMS fingerprinting | ❌ | ❌ | ✅ |
| Thompson-sampling technique bandit | ❌ | ❌ | ✅ |
| Browser-based form interaction + CSRF | ❌ | ❌ | ✅ |
| JavaScript-rendered page crawling (SPA) | ❌ | ❌ | ✅ |
| SQL context detection (32 contexts) | ❌ | Partial | ✅ |
| Stacked queries + second-order SQLi | ❌ | ✅ | ✅ |
| Header/Cookie injection (12+ headers) | ❌ | Partial | ✅ |
| WAF recovery (7 vendors, circuit breaker) | Partial | ✅ | ✅ |
| Multi-tenant org + RBAC (5 roles) | ❌ | ❌ | ✅ |
| Scope approval workflow | ❌ | ❌ | ✅ |
| Kill switch + request budget | ❌ | ❌ | ✅ |
| Encrypted evidence store (AES-256-GCM) | ❌ | ❌ | ✅ |
| Scan diff (new/fixed/regression tracking) | ❌ | ❌ | ✅ |
| Cross-scan learning (bandit persistence) | ❌ | ❌ | ✅ |
| SSE live scan events | ❌ | ❌ | ✅ |
| Slack / Discord / Teams / webhook alerts | ❌ | ❌ | ✅ |
| Light + Dark theme, EN/TH i18n | ❌ | ❌ | ✅ |
| Native Windows (no Docker required) | ❌ | ❌ | ✅ |
| Self-hosted, no cloud dependency | ✅ | ✅ | ✅ |

---

## Quick Start

### Windows (PowerShell / Git Bash)

```powershell
# 1. Clone + install
git clone <repo>
cd injectproof
npm ci

# 2. Create .env from example
copy .env.example .env
# Generate secrets and append them:
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(48).toString('base64'))" >> .env
node -e "console.log('EVIDENCE_KEY=' + require('crypto').randomBytes(32).toString('base64'))" >> .env

# 3. Bootstrap database + seed
npm run setup       # install → db:generate → db:push → seed → seed:tenant

# 4. Run
npm run dev         # http://localhost:3000
```

### Linux / macOS

```bash
git clone <repo>
cd injectproof
npm ci

cp .env.example .env
echo "JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(48).toString('base64'))")" >> .env
echo "EVIDENCE_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")" >> .env

npm run setup
npm run dev
```

Open **http://localhost:3000** — login with `admin@injectproof.local` / `admin123`.

> Change default credentials before exposing the instance to any network.

---

## Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@injectproof.local` | `admin123` |
| Pentester | `pentester@injectproof.local` | `pentester123` |

---

## Architecture

InjectProof is a single Next.js 15 App Router monolith. Three concerns run in one process: the React UI, the tRPC API, and the scanner engine (which drives Puppeteer in-process).

### Request path

```
Browser → Next.js App Router
         → /api/trpc/[trpc]
         → src/server/root.ts
         → src/server/routers/*
         → Prisma → SQLite
         → ScanWorkerPool → runScan()
```

### Oracle engine layers (`src/scanner/engine/`)

```
oracle/
  baseline.ts      Welford online statistics per axis; adaptive anomaly threshold
  features.ts      tokenize, simhash64, DOM structure hash, header set hash
  distance.ts      Mahalanobis-diagonal distance across 8 axes (σ-units)
  verdict.ts       Bayesian confidence posterior; replay + counter-factual gate

synth/
  context-infer.ts Bayesian context inference via marker triangulation (Dirichlet posterior)
                   Weighted probabilistic DBMS fingerprinting (log-sum-exp normalised)
  grammar.ts       CFG-driven SQL payload generator, DBMS-parameterized (5 families × 16 contexts)
  bandit.ts        Thompson-sampling TechniqueBandit (Beta distribution, Marsaglia-Tsang gamma)
  blind-extract.ts Expected-information-gain-optimal probe selection; K-of-M consensus gate
  waf-encoder.ts   12 encoding operators; hill-climber WAF bypass search

explore/
  markov.ts        MarkovUrlModel — URL n-gram + char trigram; generates novel candidate paths
  frontier.ts      FrontierQueue — info-gain priority (novelty + risk + coverage − cost)

detect/
  oracle-detector.ts  Shared oracle pipeline: baseline → payload loop → validate → provenance
  oracle-sqli.ts      Context inference + grammar synthesis + bandit-ordered payloads
  oracle-xss.ts       Reflection context inference → context-specific payload synthesis
                      SSRF semantic param scoring; PathTraversal depth-adaptive payloads

validate/
  pipeline.ts      replay(×2) + counter-factual + time-persistence + isolation

policy/
  policy.ts        Zod-schema policy; 9 built-in profiles; mergePolicies; pathAllowed; budgetRemaining

safety/
  kill-switch.ts   DB-backed KillSwitch singleton; hard-stops any running scan
  budget.ts        RequestBudget — requests + bytes + wall-clock caps
  action.ts        classifyAction — method + path verbs + CSRF marker → read-only / state-changing / dangerous

recovery/
  challenge-detect.ts  Classifies 403/WAF/Cloudflare/CAPTCHA/429/503/401 responses
  recover-403.ts       7-step recovery: realistic-headers → strip-automation → jitter → ua-rotate → tls-hint → browser-handoff → abandon
  circuit-breaker.ts   Per-host: 5 failures → open; 60s cooldown; half-open probe

fsm/
  index.ts         21-state typed scan state machine; per-state timeout + retry + checkpoint

orchestrate/
  reactive-rules.ts  Data-driven rule table (Map lookup, no if/else): admin-panel → sqli focus;
                     waf-detected → bypass mode; sqli-confirmed → deep-exploit; etc.

bus/
  agent-bus.ts     EventEmitter-based typed inter-agent bus (13 event types, 200-listener cap)

learning/
  cross-scan-store.ts  Persists bandit state + effective payloads + DBMS + WAF per domain
                       to .injectproof-learning.json; warm prior blending (α=EMA 0.1)
```

### Authorization hierarchy

`publicProcedure` → `protectedProcedure` → `pentesterProcedure` → `adminProcedure`

Roles: `viewer(0) < developer(1) < pentester(2) < security_lead(3) < admin(4)`

---

## Scan Pipeline

`runScan()` in `src/scanner/index.ts` runs 7 phases:

**1. Crawling** — static HTTP + Cheerio OR stealth headless browser (SPA). 4-tier fallback: Lightpanda binary → remote CDP → bundled Chromium → OS browser.

**2. Phase 1.5 Intelligence** — form classification (15 types), field attack-priority scoring, AJAX endpoint extraction from inline JS (10+ patterns), interactive element mapping, risk scoring. AJAX endpoints with confidence > 0.7 merge into the endpoint queue for downstream phases.

**3. Vulnerability Detection** — oracle detectors run on every discovered endpoint:
- `sqli_oracle` — context inference + grammar synthesis + bandit-ordered techniques
- `xss_oracle` — canary probe → reflection context → context-specific payloads
- `ssrf_oracle` — semantic param scoring → timing/content anomaly oracle
- `path_traversal_oracle` — depth-adaptive traversal sequences
- `headers` — missing/weak security headers
- `cors` — origin reflection, null origin, wildcard + credentials
- `open_redirect` — URL parameter redirect bypass

**4. Reconnaissance** — admin panel finder (300+ paths), backup file scanner, technology fingerprinter (server / framework / CMS / CDN / WAF).

**5. Smart Form SQLi** — headless browser fills forms with SQLi payloads, handles CSRF automatically, recurses post-auth.

**6. Adaptive SQLi V2** — 32 SQL contexts, header/cookie injection, stacked queries, second-order SQLi, mutation engine (30+ tampers, WAF-specific chains).

**7. Deep Exploitation** — UNION → error → boolean-blind → time-blind extraction chain; password hash cracking; OS command execution.

---

## Scanner Modules

### Oracle Detectors (primary — production use)

| ID | CWE | Method |
|----|-----|--------|
| `sqli_oracle` | CWE-89 | Bayesian context inference + CFG synthesis + Thompson bandit |
| `xss_oracle` | CWE-79 | Canary reflection context → context-specific payloads |
| `ssrf_oracle` | CWE-918 | Semantic param scoring → timing + content oracle |
| `path_traversal_oracle` | CWE-22 | Depth-adaptive traversal + oracle validation |
| `headers` | — | CSP, HSTS, X-Frame-Options, referrer policy, permissions policy |
| `cors` | CWE-942 | Origin reflection, null origin, wildcard + credentials |
| `open_redirect` | CWE-601 | URL parameter redirect bypass |

### Advanced Detectors

| ID | What it finds |
|----|---------------|
| `race_condition` | HTTP/2 single-packet TOCTOU via concurrent requests |
| `request_smuggling` | CL.TE and TE.CL HTTP/1.1 desync |
| `prototype_pollution` | `__proto__`, `constructor.prototype` parameter injection |
| `cloud_metadata` | AWS IMDSv1/v2, GCP, Azure, DigitalOcean metadata SSRF |

### Adaptive SQLi V2 Capabilities

| Capability | Details |
|-----------|---------|
| Context detection | 32 SQL contexts (WHERE string/numeric/paren, ORDER BY, INSERT, UPDATE, LIKE, IN, HAVING, LIMIT, JSON, REST path, stacked…) |
| Grammar synthesis | CFG generates context-aware, DBMS-specific payloads — not a static list |
| Technique bandit | Thompson sampling (Beta distribution) learns which technique works per target |
| DBMS fingerprinting | Weighted Bayesian posterior across MySQL / PostgreSQL / MSSQL / Oracle / SQLite |
| Header injection | Cookie, Referer, X-Forwarded-For, X-Client-IP, X-Real-IP, User-Agent, Accept-Language, X-Original-URL + more |
| Stacked queries | Auto-detects multi-statement support per DBMS |
| Second-order SQLi | Inject at one endpoint, trigger at another |
| WAF evasion | 12 encoding operators, hill-climber bypass search; per-vendor chains for Cloudflare / ModSecurity / AWS WAF / Akamai / Imperva / Sucuri / F5 |
| Mutation engine | 30+ tamper functions, auto-chained (2-deep combos) |
| Blind extraction | Expected-information-gain-optimal probe selection; K-of-M consensus |

### Deep Exploitation

| Capability | Details |
|-----------|---------|
| DBMS fingerprinting | 22 MySQL + 18 MSSQL error patterns; Bayesian Welford posterior |
| Schema enumeration | Databases → tables → columns with types |
| Data extraction | UNION / Error / Boolean-blind / Time-blind, automatic fallback chain |
| User enumeration | DB users, hosts, privileges |
| Hash extraction | Password hashes + dictionary cracking |
| File read | `LOAD_FILE`, `pg_read_file`, `UTL_FILE` |
| OS execution | `xp_cmdshell`, UDF injection (DBA required) |

---

## Enterprise Features

### Multi-tenancy

- `Organization` model with `Membership`; every User/Target/Scan scoped by `tenantId`
- Nullable + default-org fallback for full back-compat with legacy rows
- `resolveTenantForCtx`, `withTenant`, `tenantWhere(tenantId)` helpers

### Authentication & Access

- JWT via `jose` (HttpOnly cookie `vc_token`) — refuses to boot without `JWT_SECRET ≥ 32 bytes`
- bcrypt (12 rounds) password hashing
- Per-account exponential-backoff login lockout (`loginFailureState` on User)
- `mustChangePassword` flag — locked users land on the change-password page before the dashboard
- `assertTargetOwnership()` and `assertScopeApproval()` middleware on every scan/target route

### Scope Approval

Security leads sign off on scope before pentesters can scan a target. Approval history is kept; revocation is instant. Wired to `scope.create` / `scope.revoke` tRPC procedures.

### Kill Switch & Safety

- `KillSwitch` — DB-backed singleton; flipping it mid-scan aborts within the next probe cycle
- `RequestBudget` — per-scan caps: max requests, max bytes transferred, max wall-clock time
- `classifyAction` — multi-signal classifier (method + path verbs + CSRF marker) → read-only / state-changing / dangerous; blocks dangerous actions in `high_safety` mode

### Worker Pool & Scheduler

- `ScanWorkerPool` — `SCANNER_MAX_CONCURRENT` cap (default 2), AbortController per scan, 5 s heartbeat, `recoverOrphans()` for post-restart cleanup
- `ScanScheduler` — 5-field cron parser (no external deps), drives `ScheduledScan` rows

### Evidence Store

- `storeArtifact()` writes to `EVIDENCE_DIR/<scanId>/<vulnId>/…` with SHA-256 hash
- AES-256-GCM encryption under `EVIDENCE_KEY` when `sensitive: true`

### Scan Diff

`computeScanDiff(currentScanId)` compares against the previous completed scan of the same target. Returns new / fixed / stillOpen / regressions with a markdown renderer. Critical for "did the developer's fix actually land?" reviews.

### Notifications

Slack / Discord / Teams / generic-webhook dispatchers for `NotificationConfig`. Triggered on scan completion, new critical findings, and kill-switch events.

### Live Scan Events

`/api/scan/[id]/events` SSE stream pushes progress + `ScanLog` entries in real time. The scan detail page switches to 10 s tRPC polling when SSE is connected, reverts to 2 s on disconnect.

### Secret Redaction

`src/lib/redaction.ts` — every log, evidence artifact, and report passes through the redactor before writing. Covers Authorization / Cookie / Bearer tokens / API keys / JWT / AWS keys / PAT / PEM / Thai national ID / SSN / credit cards. Header + URL + JSON body + form body helpers.

### SSRF Guard

`checkTargetUrl(url)` rejects private/loopback/link-local/metadata IPs including DNS-rebinding attempts. Lab-mode override requires `security_lead+` role.

### Policy Engine

9 built-in scan profiles: `passive_only`, `ci_fast`, `api_only`, `spa_deep`, `authenticated_standard`, `enterprise_full`, `high_safety`, `staging_deep`, `compliance_mapping`. Policies are Zod-validated, merge-able, and can be stored in the database. `LEGACY_PASSTHROUGH` for back-compat.

### Cross-Scan Learning

`CrossScanLearningStore` persists per-domain: bandit arm statistics, effective payloads by context, WAF vendor, tech stack, confirmed DBMS, scan count. Warm-prior blending (`targetWeight = min(scanCount/5, 0.7)`). Global bandit updated via EMA (α = 0.1). Survives process restarts via `.injectproof-learning.json`.

### Reactive Orchestration

`reactive-rules.ts` — data-driven rule table (`Map` lookup, zero `if/else` dispatch). 7 rules fire on bus events: admin panel found → escalate auth-bypass + SQLi focus; WAF detected → activate encoding bypass mode; SQLi confirmed → deep-exploit chain; subdomain found → scope expand; backup found → enumerate; auth bypass → crawl elevated.

---

## UI

- **Light mode default**, dark mode under `[data-theme='dark']` toggle
- **EN / TH bilingual** — full translation bundle (60+ keys), `useT()` hook, `LanguageProvider`
- IBM Plex Sans + IBM Plex Sans Thai + IBM Plex Mono (Thai subset loaded)
- Design system: `glass-card`, `stat-card`, `badge-{severity}`, `btn-primary`, `input-field`, `data-table`, `sidebar-link`
- Live scan detail page with SSE progress, collapsible log stream, finding cards
- Scope approval manager (security_lead+ signs; pentesters see state + history)
- Change-password page (≥ 12 char, current-password re-verification)
- Target edit page with pre-filled auth config (Bearer token / Cookie / Session headers)

---

## Configuration

Copy `.env.example` to `.env` and fill in the required keys:

```env
# Required
DATABASE_URL="file:./injectproof.db"
JWT_SECRET=<48 random bytes, base64>
EVIDENCE_KEY=<32 random bytes, base64>

# Optional — scanner tuning
SCANNER_MAX_CONCURRENT=2
SCANNER_USER_AGENT=InjectProof-Scanner/2.0
SCANNER_REQUEST_TIMEOUT=15000
SCANNER_MAX_CRAWL_DEPTH=10
SCANNER_MAX_URLS=500

# Optional — evidence storage
EVIDENCE_DIR=./evidence

# Optional — scheduler
SCHEDULER_ENABLED=true

# Optional — outbound notifications
NOTIFY_SLACK_WEBHOOK=https://hooks.slack.com/...
NOTIFY_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
NOTIFY_TEAMS_WEBHOOK=https://outlook.office.com/webhook/...

# Optional — feature flags
SCANNER_FSM=true     # typed state machine (21 states)
```

The app refuses to boot if `JWT_SECRET` is missing or shorter than 32 bytes.

---

## Scripts

| Command | What it does |
|---------|-------------|
| `npm run setup` | install + db:generate + db:push + db:seed + db:seed:tenant |
| `npm run dev` | Next.js dev server at http://localhost:3000 |
| `npm run build` | Production build |
| `npm run start` | Serve production build |
| `npm run lint` | ESLint 10 via `eslint-config-next` |
| `npm test` | Vitest unit tests (`src/**/*.test.ts`) |
| `npm run test:watch` | Vitest watch mode |
| `npm run test:coverage` | v8 coverage report |
| `npm run test:bench` | Scanner benchmark driver (writes report to `bench/reports/`) |
| `npm run db:generate` | Regenerate Prisma client |
| `npm run db:push` | Push schema (additive, no data loss) |
| `npm run db:seed` | Create default admin/pentester users |
| `npm run db:reset` | **Destructive** — force reset + reseed |
| `npm run db:studio` | Prisma Studio visual DB browser |

---

## Project Structure

```
src/
├── app/
│   ├── login/                        # Public auth page
│   ├── api/
│   │   ├── trpc/[trpc]/              # tRPC handler
│   │   ├── healthz/                  # Liveness probe
│   │   ├── readyz/                   # Readiness probe (pings Prisma)
│   │   └── scan/[id]/events/         # SSE live scan stream
│   └── (platform)/                   # Authenticated shell
│       ├── dashboard/
│       ├── targets/
│       │   ├── new/                  # Create target (with auth config)
│       │   └── [id]/
│       │       ├── edit/             # Edit target + pre-filled auth config
│       │       └── scope/            # Scope approval manager
│       ├── scans/
│       │   ├── new/                  # Start scan, select oracle modules
│       │   └── [id]/                 # Live scan detail + SSE events
│       ├── vulnerabilities/
│       ├── reports/
│       └── settings/
│           └── password/             # Change-password page
├── scanner/
│   ├── index.ts                      # 7-phase orchestrator
│   ├── detectors.ts                  # ALL_DETECTORS + DEFAULT_DETECTORS (oracle-first)
│   ├── engine/
│   │   ├── oracle/                   # baseline, features, distance, verdict
│   │   ├── synth/                    # context-infer, grammar, bandit, blind-extract, waf-encoder
│   │   ├── explore/                  # markov, frontier
│   │   ├── detect/                   # oracle-detector, oracle-sqli, oracle-xss
│   │   ├── validate/                 # pipeline (replay + counter-factual)
│   │   ├── policy/                   # policy engine, 9 built-in profiles
│   │   ├── safety/                   # kill-switch, budget, action classifier
│   │   ├── recovery/                 # challenge-detect, recover-403, circuit-breaker, ua-pool
│   │   ├── fsm/                      # 21-state scan state machine
│   │   ├── bus/                      # typed EventEmitter agent bus
│   │   ├── learning/                 # cross-scan persistence store
│   │   └── orchestrate/              # reactive rules engine (data-driven, Map-based)
│   ├── crawler.ts                    # Static HTTP + Cheerio
│   ├── headless-browser.ts           # Stealth Chromium manager (4-tier fallback)
│   ├── headless-crawler.ts           # SPA crawler
│   ├── intelligent-scanner.ts        # Form classification, AJAX discovery, attack planning
│   ├── sqli-adaptive.ts              # V2 adaptive engine (32 contexts, header injection)
│   ├── sqli-exploiter.ts             # UNION/Error/Blind/Time exploitation
│   ├── smart-form-sqlmap.ts          # Browser form SQLi + CSRF handling
│   ├── recon-scanner.ts              # Admin finder, backup scanner, fingerprinter
│   ├── post-exploit.ts               # Post-exploitation evidence gathering
│   ├── easm.ts                       # External attack surface management
│   └── cloud-exploit.ts              # Cloud metadata + infrastructure testing
├── lib/
│   ├── auth.ts                       # JWT sign/verify; refuses to boot without JWT_SECRET
│   ├── config.ts                     # Zod-validated env reader (single source of truth)
│   ├── platform.ts                   # Cross-platform FS/process/env bedrock
│   ├── prisma.ts                     # Prisma singleton
│   ├── cvss.ts                       # CVSS v3.1 calculator + common vectors
│   ├── cwe-database.ts               # 200+ CWE entries with remediation guidance
│   ├── redaction.ts                  # Secret redactor (headers, URL, JSON, form body)
│   ├── ssrf-guard.ts                 # Private IP + DNS-rebinding guard
│   ├── tenant.ts                     # Multi-tenant helpers
│   ├── evidence-store.ts             # AES-256-GCM encrypted artifact storage
│   ├── scan-diff.ts                  # New/fixed/regression diff across scans
│   ├── notifiers.ts                  # Slack/Discord/Teams/webhook dispatchers
│   ├── rate-limit-login.ts           # Exponential-backoff login lockout
│   └── i18n/                         # EN/TH translation bundles + useT() hook
├── server/
│   ├── root.ts                       # tRPC app router
│   ├── trpc.ts                       # Middleware: public/protected/pentester/admin
│   ├── auth-middleware.ts            # assertTargetOwnership, assertScopeApproval
│   └── routers/                      # auth, target, scan, vulnerability, report, scope
├── worker/
│   ├── pool.ts                       # ScanWorkerPool (AbortController, heartbeat, orphan recovery)
│   └── scheduler.ts                  # 5-field cron scheduler (no external deps)
├── components/ui/                    # ThemeToggle, LanguageToggle, shared components
├── generated/prisma/                 # Auto-generated Prisma client (do not edit)
└── types/index.ts                    # Shared TypeScript types
```

---

## Data Model

10 Prisma models in `prisma/schema.prisma`:

```
Organization  ─┬─ Membership → User
               └─ Policy

Target ────────┬─ Scan ──────── ScanLog
               │              └─ Vulnerability ── Evidence
               ├─ ScopeApproval
               ├─ SurfaceNode ── SurfaceEdge
               └─ ScheduledScan

KillSwitch     (singleton, DB-backed)
ApiKey         (per-organization)
Checkpoint     (FSM state persistence)
```

Key fields added in the enterprise phase (all nullable / defaulted — `db:push` is additive):

- `User.mustChangePassword`, `loginFailureState`, `passwordChangedAt`, `tenantId`
- `Scan.heartbeatAt`, `safetyMode`, `tenantId`
- `Vulnerability.provenance` (JSON), `validationLevel` (`confirmed` | `candidate`)
- `Evidence.hash` (SHA-256), `encryption` (AES-256-GCM metadata)
- `Target.scopeApprovalId`, `tenantId`

`validationLevel = 'confirmed'` requires replay + counter-factual. Automation and alerting should filter on this — `'candidate'` is for human triage.

---

## Benchmark Lab

`bench/` contains a reproducible scanner measurement harness:

- `bench/compose.yml` — Docker fleet: DVWA, Juice Shop, sqli-labs, bWAPP, XVWA, WAF-fronted DVWA (ModSecurity CRS), clean nginx (false-positive audit)
- `bench/fixtures/*.json` — ground truth per target
- `bench/runner.ts` — isolates `bench/.bench.db`, seeds users + targets, runs `runScan()` programmatically, scores findings vs. ground truth
- Output: `bench/reports/<timestamp>.md` with precision / recall / FP-rate per target
- Unreachable targets are skipped gracefully (no Docker fleet required for partial runs)

Run: `npm run test:bench`

---

## CI / CD

`.github/workflows/ci.yml` — matrix `[ubuntu-latest, windows-latest]` × Node 20:

- `npm ci` → `next lint` → `tsc --noEmit` → `vitest run`
- Informational jobs: bench smoke + CycloneDX SBOM generation
- Pre-build env sanity check via `scripts/cross/envcheck.mjs` (bilingual EN/TH error messages)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 App Router, React 19, Tailwind CSS v4 (CSS-first) |
| API | tRPC v11, SuperJSON, Zod validation |
| Database | SQLite via Prisma 7 (client emitted to `src/generated/prisma`) |
| Auth | `jose` JWT, bcrypt (12 rounds), HttpOnly cookie |
| Browser | Puppeteer + stealth (4-tier fallback, Lightpanda / CDP / Chromium / OS) |
| Testing | Vitest + v8 coverage (243 unit tests) |
| i18n | Custom `useT()` hook + EN/TH bundles; IBM Plex Sans Thai |
| Platform | Cross-platform: Windows (Git Bash / PowerShell) + Linux; Docker optional |

---

## Security

InjectProof enforces security on its own platform:

- JWT authentication with HttpOnly cookies; `JWT_SECRET ≥ 32 bytes` enforced at boot
- bcrypt (12 rounds) password hashing
- Per-account exponential-backoff login lockout
- Five-tier RBAC enforced at tRPC middleware layer (not in handlers)
- `mustChangePassword` gate before dashboard access
- SSRF guard on all target URLs (private IP + DNS-rebinding rejection)
- Secret redaction on all logs, evidence, and reports
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy in `next.config.mjs`
- Scope approval workflow — pentesters cannot scan without security_lead sign-off
- Kill switch — any admin can halt all scans instantly
- AES-256-GCM evidence encryption for sensitive artifacts

---

## Recommended Test Targets

> Only scan systems you own or have written authorization to test.

| Target | Docker image | Notes |
|--------|-------------|-------|
| DVWA | `vulnerables/web-dvwa` | Classic PHP vulnerable app |
| OWASP Juice Shop | `bkimminich/juice-shop` | Modern Node.js SPA |
| sqli-labs | `acgpiano/sqli-labs` | Dedicated SQLi practice (MySQL) |
| bWAPP | `raesene/bwapp` | 100+ vulnerabilities |
| WebGoat | `webgoat/goat-and-wolf` | Java-based learning platform |

All targets are included in `bench/compose.yml` for automated scoring.

---

## Legal

This software is designed for authorized penetration testing only. Running it against targets without explicit written permission is illegal in most jurisdictions. The authors are not responsible for misuse.

---

## Recent Changes

### Scanner depth — sqlmap-parity deep exploitation
- **Parallel breakout discovery + UNION sweep + error-wrapper detection** (concurrency 8 with short-circuit on first hit). Reduces first-expression extraction from ~160 s worst case to ~20 s.
- **Time-blind last-resort in force-try** — previously absent; now closes the "fully blind endpoint" gap by probing every breakout alternate with a DBMS-native `SLEEP` and extracting via expected-information-gain optimal probes.
- **28 sqlmap-style tampers** (`between`, `charencode`, `charunicodeencode`, `chardoubleencode`, `space2comment`, `space2dash`, `space2hash`, `space2mysqlblank`, `space2plus`, `randomcase`, `equaltolike`, `greatest`, `percentage`, `appendnullbyte`, `modsecurityversioned`, `modsecurityzeroversioned`, `halfversionedmorekeywords`, `versionedkeywords`, `symboliclogical`, `apostrophemask`, `apostrophenullencode`, `base64encode`, `concat2concatws`, `plus2concat`, `bluecoat`, `hex-keywords`, `inline-comment`, `plain`) with 7 WAF-specific chains (cloudflare, modsecurity, aws_waf, imperva, akamai, f5_bigip, bluecoat).
- **Trigram-Jaccard response similarity** replaces the old `Math.abs(len - baseline) < 50` boolean-blind heuristic — tolerant of CSRF tokens, dynamic timestamps, ad slots.
- **sqlmap `--level` 1–5** expands UNION column-count sweep from 1–5 (default) to 1–40 (exhaustive).
- **sqlmap `--risk` 1–3** unlocks OR-based boolean and stacked-query probes (explicit opt-in because they can return extra rows on UPDATE queries).
- **Oracle DBMS full support** — `all_users`, `all_tables`, `all_tab_columns`, `user_role_privs`, `sys.user$` enumeration with `LISTAGG` aggregator.
- **7 injection points** — query, body, JSON, header, cookie, path, multipart.
- **HEX-encoded string literals** bypass quote-stripping WAFs and resolve outer-breakout quote conflicts.
- **Row-by-row fallback** when `GROUP_CONCAT` hits `group_concat_max_len` (MySQL default 1024 bytes).

### Authentication & access-control testing (new modules)
- **BAC/IDOR scanner** (`src/scanner/bac-scanner.ts`) — four classes of OWASP #1 Broken Access Control: unauthenticated access to protected endpoints, vertical BAC (low-priv user hits admin paths), IDOR (numeric / UUID / short-hex ID enumeration on path + query slots), horizontal BAC (two-session replay). Uses the same trigram-Jaccard similarity oracle as the SQLi engine.
- **Auth scanner** (`src/scanner/auth-scanner.ts`) — JWT `alg:none`, HS256 weak-secret brute force (100-entry dictionary), HS/RS algorithm confusion advisory (JWKS exposure), missing-auth endpoint probes, password-reset token entropy + numerical-drift analysis.

### Form-level injection (new modules)
- **SmartFormFiller** (`src/scanner/smart-form-filler.ts`) — semantic inference across 40+ field types (email, phone, name, address, credit card, IBAN, SSN, Thai national ID, …) with EN + TH keyword matching. Realistic value generator produces values that pass backend validation (Luhn-valid Visa, RFC email, E.164 phone, ISO dates, RFC5737 IP). Multi-input-type support covers radio, checkbox, select, file (in-memory tiny PNG), range, color, date/time — including SPA-safe event dispatch so React/Vue reactivity fires.
- **SmartFormXssScanner** (`src/scanner/smart-form-xss.ts`) — 11 payload templates across 7 contexts (html-body, attribute, href, script-string, script-block, polyglot, reflect-only). Execution verified via `window.__IPF_XSS_<token>` sentinel — not just reflection matching. Uses SmartFormFiller so payloads reach the backend past validation.

### Reporting
- **Corporate PDF report** at `/api/scan/[id]/report.pdf` — Puppeteer renders an A4 document with cover page, exec summary (EN + TH), severity breakdown table, category bar chart, per-finding cards (CVSS + CWE + payload + request/response + remediation + OWASP/ASVS/NIST mapping), and appendix. Bilingual throughout.
- **Report PDF button** on every scan detail page.

### Live scanner events (SSE)
- `src/scanner/exploit-events.ts` — EventEmitter-backed session registry keyed by vulnerability ID; 60-second grace period after completion so late-joining SSE clients still replay the full log.
- `/api/vulnerability/[id]/exploit-events` SSE endpoint + `useExploitEvents` React hook.
- `LiveExploitPanel` UI — phase stepper (11 phases EN + TH), animated live-log terminal, elapsed counter, result summary grid.

### Stealth browser
- `headless: 'new'` mode (Chrome 112+ new headless ≈ real Chrome).
- 22 DOM-level stealth patches including UA Client Hints (Sec-CH-UA), Worker-scoped `navigator.webdriver`, Battery API, timezone-locale consistency, outer window dimensions, media-devices enumeration.
- Anti-detection launch args: `--disable-blink-features=AutomationControlled`, `--use-fake-ui-for-media-stream`, TLS-fingerprint-adjacent networking flags.
- `headful` mode + `timezone` + `acceptLanguage` config fields.

### `realMode` humane behaviour
- `src/scanner/humanize.ts` — seeded PRNG, `humanType` (Gaussian-jittered per-key delay + 1% typo/backspace + punctuation beats), `humanClick` (quadratic-bezier mouse path + hover pause + variable click offset), `humanScroll` (wheel chunks with ease-out), `humanPause`, `simulateVisibilityFlicker`.
- Viewport ladder (`1280×720`, `1366×768`, `1440×900`, `1536×864`, `1920×1080`) and UA pool (Chrome 131 Win/Mac/Linux + Edge 131 + Chrome 130 Win) randomised per `newPage` when `realMode` is enabled.
- Opt-in via **Stealth mode** checkbox on the New Scan page — 3–10× slower, for targets behind Cloudflare Turnstile / PerimeterX / Datadome.

### Internal target support
- `SCANNER_ALLOW_INTERNAL_TARGETS=true` env flag unlocks scanning of `localhost`, `127.0.0.1`, RFC1918 (`10.x`, `172.16–31.x`, `192.168.x`), and `169.254.x`. Required for internal pentest use cases.
- Development mode (`NODE_ENV=development`) always allows `localhost` by default — reachable only from the scanner host itself.
- Strict boolean env parsing (`envBool`) — `SCANNER_X=false` / `=0` / `=no` now correctly parses to `false` (previously any non-empty string coerced to `true`).

### UI: every page works, no dead-ends
- **Settings page** is now a real controlled form — `settings.updateProfile` and `settings.updateNotificationPrefs` tRPC procedures persist changes, with audit-log trail. Previously every input was a `defaultValue` stub with no save handler.
- **User menu dropdown** (Profile / Change Password / Logout) replaces the lone logout icon in the sidebar.
- **Signup page** at `/signup` — bootstraps the first admin when the DB is empty, disables itself afterwards (admin-gated). `auth.isFirstRun` query controls the login-page "create first admin" link.
- **Scope-approval auto-redirect** — creating a production / staging target drops the user on the scope-approval page with a pre-filled rationale template.
- **Scope-required banner** on target detail when no active `ScopeApproval` exists.
- **Inline ⚡ Exploit button** on scan detail SQLi rows → deep-links to `/vulnerabilities/:id?tab=sqli_exploit`.
- **Dashboard heatmap widget** — target × category grid wires the previously-orphaned `dashboard.heatmapData` procedure.
- **RBAC UI gating** — sidebar filtered via `canSeeRoute(role, route)` so viewers/developers don't see routes their role can't use.
- **Pagination** on Targets, Scans, Vulnerabilities, and Reports list pages (20/page with auto-reset on filter change).
- **i18n cleanup** — hardcoded Thai on Reports page replaced with `useT()` keys; both EN and TH bundles extended.

### Runtime / operational
- `SCANNER_ALLOW_INTERNAL_TARGETS`, tightened `envBool` parser, actionable error messages with step-by-step fix instructions (EN + TH).
- `.injectproof-learning.json` added to `.gitignore` (regenerates on demand).

---

## License

Private — All rights reserved.
