// InjectProof — Scan Orchestrator
// Main entry point for running vulnerability scans
// Coordinates crawling, detection, evidence collection, and result storage

import type { ScanConfig, DetectorResult, ScanProgress } from '@/types';
import { crawlTarget, type CrawlConfig, type CrawlResult } from '@/scanner/crawler';
import { crawlTargetHeadless } from '@/scanner/headless-crawler';
import { isCdpAvailable } from '@/scanner/headless-browser';
import { ALL_DETECTORS } from '@/scanner/detectors';
import { ADVANCED_DETECTORS } from '@/scanner/advanced-detectors';
import { runSmartFormSqliScan, type SmartFormScanConfig } from '@/scanner/smart-form-sqlmap';
import { runReconScan, type ReconConfig } from '@/scanner/recon-scanner';
import { analyzePageIntelligence, type PageIntelligence } from '@/scanner/intelligent-scanner';
import * as cheerio from 'cheerio';
import prisma from '@/lib/prisma';
import { addScanLog } from '@/scanner/engine/log';
import { safeRun } from '@/scanner/engine/safe-run';
import { ScanAgentBus } from '@/scanner/engine/bus/agent-bus';
import { getLearningStore } from '@/scanner/engine/learning/cross-scan-store';
import { evaluateRules, rulesSummary, type ReactiveContext } from '@/scanner/engine/orchestrate/reactive-rules';
import { shouldProceed, KillSwitchEngagedError } from '@/scanner/engine/safety/kill-switch';
import { budgetTrackerFor, releaseBudgetTracker, BudgetExceededError } from '@/scanner/engine/safety/request-budget';
import { enumerateSubdomains, huntCloudBuckets, scanForLeakedSecrets, discoverShadowApis } from '@/scanner/easm';
import { detectContainerExposure } from '@/scanner/cloud-exploit';
import { runContextAwareFuzzing, detectBusinessLogicFlaws } from '@/scanner/cognitive-exploit';
import { extractDatabaseSchema } from '@/scanner/post-exploit';
import { computeScanDiff } from '@/lib/scan-diff';
import { dispatch } from '@/lib/notifiers';
import type { NotificationTarget } from '@/lib/notifiers';

export type ProgressCallback = (progress: ScanProgress) => void;

/** Persist live progress status to DB for real-time UI updates */
async function persistProgress(scanId: string, progress: ScanProgress): Promise<void> {
    await safeRun(
        { scanId, phase: progress.phase, module: 'orchestrator', operation: 'persistProgress' },
        async () => {
            await prisma.scan.update({
                where: { id: scanId },
                data: {
                    progress: progress.progress,
                    currentPhase: progress.phase,
                    currentModule: progress.currentModule || null,
                    currentUrl: progress.currentUrl || null,
                    statusMessage: progress.message || null,
                },
            });
        },
    );
}

/**
 * Run a complete vulnerability scan against a target
 * This is the main entry point for the scan engine
 */
export async function runScan(
    config: ScanConfig,
    onProgress?: ProgressCallback,
): Promise<{ vulnCount: number; errors: string[] }> {
    const errors: string[] = [];
    let totalVulns = 0;

    try {
        // Update scan status to running
        await prisma.scan.update({
            where: { id: config.scanId },
            data: {
                status: 'running',
                startedAt: new Date(),
                progress: 0,
            },
        });

        await addScanLog(config.scanId, 'info', 'orchestrator', `Scan started for target: ${config.baseUrl}`);

        // Initialize per-scan request budget (requests × bytes × wall-clock)
        const budget = budgetTrackerFor(config.scanId, {
            maxRequests: Math.max(config.maxUrls, 100) * 80,
            maxBytes: 512 * 1024 * 1024,   // 512 MB
            maxWallMs: 6 * 60 * 60 * 1000, // 6 hours
        });

        // Enterprise: initialize bus + learning store + reactive context
        const bus = new ScanAgentBus(config.scanId);
        const learning = getLearningStore();
        const reactiveCtx: ReactiveContext = {
            baseUrl: config.baseUrl,
            scanId: config.scanId,
            wafMode: false,
            techStack: learning.getTechStack(config.baseUrl),
            confirmedDbms: learning.getDbms(config.baseUrl),
            confirmedAdminPanels: [],
            pendingTasks: [],
        };

        // Wire bus → reactive rules: findings auto-trigger follow-up tasks
        const _unsubBus = bus.onAny(event => {
            const newTasks = evaluateRules(event, reactiveCtx);
            reactiveCtx.pendingTasks.push(...newTasks);
            // Persist learning side-effects
            if (event.type === 'waf:detected') learning.recordWaf(config.baseUrl, (event as any).vendor);
            if (event.type === 'sqli:confirmed') learning.recordDbms(config.baseUrl, (event as any).dbms);
            if (event.type === 'tech:detected') learning.recordTech(config.baseUrl, (event as any).tech);
        });

        await addScanLog(config.scanId, 'info', 'orchestrator',
            `[ENTERPRISE] Prior learning: ${learning.summary(config.baseUrl)} | Rules: ${rulesSummary()}`);

        // ========================================
        // PHASE 1: CRAWLING
        // ========================================
        const progressUpdate: ScanProgress = {
            scanId: config.scanId,
            phase: 'crawling',
            progress: 5,
            urlsDiscovered: 0,
            urlsScanned: 0,
            vulnsFound: 0,
            message: 'Starting crawl...',
        };
        onProgress?.(progressUpdate);
        await persistProgress(config.scanId, progressUpdate);

        await addScanLog(config.scanId, 'info', 'crawler', 'Starting web crawl');

        const crawlConfig: CrawlConfig = {
            baseUrl: config.baseUrl,
            maxDepth: config.maxCrawlDepth,
            maxUrls: config.maxUrls,
            requestTimeout: config.requestTimeout,
            rateLimit: config.rateLimit,
            userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
            customHeaders: config.customHeaders,
            excludePaths: config.excludePaths,
            includePaths: config.includePaths,
            authHeaders: buildAuthHeaders(config),
            enableHeadless: config.enableHeadless,
            cdpEndpoint: config.cdpEndpoint,
        };

        // Smart mode selection (4-tier auto-detection):
        //   1. Lightpanda binary (Linux)
        //   2. Remote CDP endpoint (Lightpanda Docker / Browserless)
        //   3. Bundled Chromium (puppeteer.launch — works everywhere)
        //   4. OS browser (Edge/Chrome — last resort)
        //   Default (no headless): static fetch + cheerio
        let crawlResult: CrawlResult;
        let crawlMode = 'static';

        if (crawlConfig.enableHeadless) {
            if (crawlConfig.cdpEndpoint) {
                // Remote CDP mode (Lightpanda / Docker / Browserless)
                const cdpReady = await isCdpAvailable(crawlConfig.cdpEndpoint);
                if (cdpReady) {
                    crawlMode = 'headless:remote';
                    await addScanLog(config.scanId, 'info', 'crawler', `Headless mode: remote CDP at ${crawlConfig.cdpEndpoint}`);
                    crawlResult = await crawlTargetHeadless({
                        ...crawlConfig,
                        cdpEndpoint: crawlConfig.cdpEndpoint,
                    });
                } else {
                    await addScanLog(config.scanId, 'warn', 'crawler', `CDP endpoint ${crawlConfig.cdpEndpoint} unavailable — falling back to local browser`);
                    // Try bundled Chromium / local browser fallback
                    crawlMode = 'headless:bundled';
                    await addScanLog(config.scanId, 'info', 'crawler', 'Headless mode: auto-detect (bundled Chromium → OS browser)');
                    crawlResult = await crawlTargetHeadless(crawlConfig);
                }
            } else {
                // No remote endpoint — auto-detect (Lightpanda → bundled Chromium → OS browser)
                crawlMode = 'headless:auto';
                await addScanLog(config.scanId, 'info', 'crawler', 'Headless mode: auto-detect (Lightpanda → bundled Chromium → OS browser)');
                crawlResult = await crawlTargetHeadless(crawlConfig);
            }
        } else {
            crawlResult = await crawlTarget(crawlConfig);
        }

        await addScanLog(
            config.scanId,
            'info',
            'crawler',
            `Crawl complete [${crawlMode}]: ${crawlResult.endpoints.length} endpoints, ${crawlResult.discoveredUrls.length} URLs` +
            (crawlResult.jsRenderedPages ? `, ${crawlResult.jsRenderedPages} JS-rendered pages` : '') +
            (crawlResult.interceptedRequests?.length ? `, ${crawlResult.interceptedRequests.length} AJAX requests intercepted` : ''),
        );

        if (crawlResult.errors.length > 0) {
            for (const err of crawlResult.errors.slice(0, 10)) {
                await addScanLog(config.scanId, 'warn', 'crawler', err);
            }
            errors.push(...crawlResult.errors);
        }

        // Update scan with crawl stats
        const totalParams = crawlResult.endpoints.reduce((sum, ep) => sum + ep.params.length, 0);
        await prisma.scan.update({
            where: { id: config.scanId },
            data: {
                totalUrls: crawlResult.endpoints.length,
                totalParams: totalParams,
                progress: 20,
            },
        });

        const crawlDone: ScanProgress = {
            scanId: config.scanId,
            phase: 'crawling',
            progress: 15,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned: 0,
            vulnsFound: 0,
            message: `Found ${crawlResult.endpoints.length} endpoints with ${totalParams} parameters`,
        };
        onProgress?.(crawlDone);
        await persistProgress(config.scanId, crawlDone);

        // ========================================
        // PHASE 1.5: INTELLIGENT PAGE ANALYSIS
        // Classify forms, discover AJAX endpoints, map interactive elements,
        // generate attack plans, and calculate risk scores
        // ========================================
        const intelligenceProgress: ScanProgress = {
            scanId: config.scanId,
            phase: 'crawling',
            progress: 16,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned: 0,
            vulnsFound: 0,
            message: '[INTEL] Intelligent Analysis — classifying forms, discovering AJAX endpoints, mapping attack surface...',
            currentModule: 'Intelligent Scanner',
        };
        onProgress?.(intelligenceProgress);
        await persistProgress(config.scanId, intelligenceProgress);

        const pageIntelligence: PageIntelligence[] = [];
        let totalFormsClassified = 0;
        let totalAjaxDiscovered = 0;
        let totalInteractiveElements = 0;

        // Deduplicate endpoints for intelligence analysis
        const seenUrlsIntel = new Set<string>();
        const intelEndpoints = crawlResult.endpoints.filter(ep => {
            const key = `${ep.method}:${ep.url}`;
            if (seenUrlsIntel.has(key)) return false;
            seenUrlsIntel.add(key);
            return true;
        });

        for (const ep of intelEndpoints) {
            try {
                // Fetch page HTML for intelligent analysis
                const res = await fetch(ep.url, {
                    headers: {
                        'User-Agent': config.userAgent || 'InjectProof-Scanner/1.0',
                        ...config.customHeaders,
                        ...buildAuthHeaders(config),
                    },
                    signal: AbortSignal.timeout(config.requestTimeout),
                    redirect: 'follow',
                });

                const contentType = res.headers.get('content-type') || '';
                if (!contentType.includes('text/html')) continue;

                const html = await res.text();
                const $ = cheerio.load(html);
                const intel = analyzePageIntelligence(ep.url, html, $);

                pageIntelligence.push(intel);
                totalFormsClassified += intel.forms.length;
                totalAjaxDiscovered += intel.ajaxEndpoints.length;
                totalInteractiveElements += intel.interactiveElements.length;

                // Merge discovered AJAX endpoints back into crawl results
                for (const ajax of intel.ajaxEndpoints) {
                    const exists = crawlResult.endpoints.some(e => e.url === ajax.url && e.method === ajax.method);
                    if (!exists && ajax.confidence > 0.7) {
                        crawlResult.endpoints.push({
                            url: ajax.url,
                            method: ajax.method,
                            params: ajax.params.map(p => ({ name: p, type: 'query' as const, value: '' })),
                            forms: [],
                            headers: {},
                            depth: ep.depth + 1,
                            source: `intelligent-scanner:${ep.url}`,
                        });
                    }
                }

                // Log high-risk pages and attack plans
                if (intel.riskScore >= 30) {
                    await addScanLog(config.scanId, 'warn', 'intelligent-scanner',
                        `[HIGH-RISK] page [${intel.riskScore}/100]: ${ep.url} | Type: ${intel.pageType} | Forms: ${intel.forms.map(f => `${f.classification}(${f.attackPriority})`).join(', ')}`);
                }

                if (intel.attackPlan.length > 0) {
                    await addScanLog(config.scanId, 'info', 'intelligent-scanner',
                        `[PLAN] Attack plan for ${ep.url}: ${intel.attackPlan.slice(0, 3).map(s => `[P${s.priority}] ${s.technique} -> ${s.params.join(',')}`).join(' | ')}`);
                }

                // Log form classifications
                for (const form of intel.forms) {
                    if (form.attackPriority === 'critical' || form.attackPriority === 'high') {
                        await addScanLog(config.scanId, 'warn', 'intelligent-scanner',
                            `[FORM] ${form.classification.toUpperCase()} at ${form.action} [${form.attackPriority}] — ${form.estimatedPurpose}`);
                    }
                }

                // Log comments (potential info leaks)
                if (intel.comments.length > 0) {
                    await addScanLog(config.scanId, 'info', 'intelligent-scanner',
                        `[COMMENT] HTML comments found on ${ep.url}: ${intel.comments.slice(0, 3).join(' | ')}`);
                }
            } catch {
                // Best-effort analysis
            }
        }

        await addScanLog(config.scanId, 'info', 'intelligent-scanner',
            `[INTEL] complete: ${totalFormsClassified} forms classified, ${totalAjaxDiscovered} AJAX endpoints discovered, ${totalInteractiveElements} interactive elements mapped`);

        // Re-deduplicate after AJAX endpoint injection
        const seenUrlsV2 = new Set<string>();
        const uniqueEndpointsV2 = crawlResult.endpoints.filter(ep => {
            const key = `${ep.method}:${ep.url}`;
            if (seenUrlsV2.has(key)) return false;
            seenUrlsV2.add(key);
            return true;
        });

        const intelProgress: ScanProgress = {
            scanId: config.scanId,
            phase: 'crawling',
            progress: 20,
            urlsDiscovered: crawlResult.discoveredUrls.length + totalAjaxDiscovered,
            urlsScanned: 0,
            vulnsFound: 0,
            message: `Intelligence done: ${uniqueEndpointsV2.length} total endpoints (${totalAjaxDiscovered} from AJAX), ${totalFormsClassified} forms classified`,
        };
        onProgress?.(intelProgress);
        await persistProgress(config.scanId, intelProgress);

        // ========================================
        // PHASE 2: VULNERABILITY SCANNING
        // ========================================
        const scanStart: ScanProgress = {
            scanId: config.scanId,
            phase: 'scanning',
            progress: 25,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned: 0,
            vulnsFound: 0,
            message: 'Starting vulnerability detection...',
        };
        onProgress?.(scanStart);
        await persistProgress(config.scanId, scanStart);

        // Determine which detectors to run
        const activeDetectors = config.modules.length > 0
            ? ALL_DETECTORS.filter(d => config.modules.includes(d.id))
            : ALL_DETECTORS;

        await addScanLog(
            config.scanId,
            'info',
            'orchestrator',
            `Running ${activeDetectors.length} detector modules: ${activeDetectors.map(d => d.id).join(', ')}`,
        );

        const detectorConfig = {
            baseUrl: config.baseUrl,
            requestTimeout: config.requestTimeout,
            userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
            customHeaders: config.customHeaders,
            authHeaders: buildAuthHeaders(config),
            scanId: config.scanId,
        };

        let urlsScanned = 0;
        const totalEndpoints = crawlResult.endpoints.length;
        let payloadCount = 0;

        // Run detectors on each endpoint (using expanded list after intelligence phase)
        const seenUrlsFinal = new Set<string>();
        const finalEndpoints = crawlResult.endpoints.filter(ep => {
            const key = `${ep.method}:${ep.url}`;
            if (seenUrlsFinal.has(key)) return false;
            seenUrlsFinal.add(key);
            return true;
        });
        for (const endpoint of finalEndpoints) {
            // Check if scan was cancelled
            const scanRecord = await prisma.scan.findUnique({ where: { id: config.scanId } });
            if (scanRecord?.status === 'cancelled') {
                await addScanLog(config.scanId, 'info', 'orchestrator', 'Scan cancelled by user');
                break;
            }

            // Kill switch — admin can halt all scans within 1s from DB
            try {
                await shouldProceed();
            } catch (e) {
                if (e instanceof KillSwitchEngagedError) {
                    await addScanLog(config.scanId, 'warn', 'orchestrator', `[KILL-SWITCH] scan halted: ${e.message}`);
                    break;
                }
                throw e;
            }

            // Budget guard — stops detection when request/byte/wall limits hit
            const budgetState = budget.exhausted();
            if (budgetState.exhausted) {
                await addScanLog(config.scanId, 'warn', 'orchestrator',
                    `[BUDGET] scan budget exhausted (${budgetState.limiting}) — stopping detection early`);
                break;
            }

            urlsScanned++;
            const scanProgress = 25 + Math.floor((urlsScanned / totalEndpoints) * 60);

            for (const detector of activeDetectors) {
                try {
                    const detectorProgress: ScanProgress = {
                        scanId: config.scanId,
                        phase: 'scanning',
                        progress: scanProgress,
                        currentModule: detector.name,
                        currentUrl: endpoint.url,
                        urlsDiscovered: crawlResult.discoveredUrls.length,
                        urlsScanned,
                        vulnsFound: totalVulns,
                        message: `[${detector.name}] Scanning ${endpoint.url}`,
                    };
                    onProgress?.(detectorProgress);
                    await persistProgress(config.scanId, detectorProgress);

                    const detectionResults = await detector.detect(endpoint, detectorConfig);

                    for (const result of detectionResults) {
                        if (result.found) {
                            await saveVulnerability(config, result, detector.id);
                            totalVulns++;
                            payloadCount++;

                            // Emit confirmed findings to bus for reactive escalation
                            if ((result as any).type === 'sqli' && result.confidence === 'high') {
                                bus.emit({ type: 'sqli:confirmed', url: endpoint.url, param: (result as any).param ?? '', dbms: (result as any).dbms ?? 'unknown', technique: (result as any).technique ?? 'unknown', severity: 'high' });
                                if ((result as any).payload) learning.recordEffectivePayload(config.baseUrl, (result as any).context ?? 'generic', (result as any).payload);
                            } else if ((result as any).type === 'sqli') {
                                bus.emit({ type: 'sqli:candidate', url: endpoint.url, param: (result as any).param ?? '', technique: (result as any).technique ?? 'unknown', confidence: result.confidence === 'medium' ? 0.6 : 0.4 });
                            }

                            // Post-exploitation: extract DB schema on confirmed high-confidence SQLi (deep scans only)
                            const isDeep = config.scanType === 'deep';
                            if (isDeep && result.category === 'sqli' && result.confidence === 'high' && result.parameter) {
                                const dbmsMap: Record<string, 'mysql' | 'postgres' | 'sqlite' | 'mssql'> = {
                                    mysql: 'mysql', mariadb: 'mysql', postgresql: 'postgres', mssql: 'mssql', sqlite: 'sqlite',
                                };
                                const dbmsHint = dbmsMap[reactiveCtx.confirmedDbms ?? ''] ?? 'mysql';
                                const postExploitConfig = {
                                    baseUrl: config.baseUrl,
                                    requestTimeout: config.requestTimeout,
                                    userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                                    authHeaders: buildAuthHeaders(config),
                                };
                                const schemaFindings = await extractDatabaseSchema(
                                    endpoint, result.parameter, dbmsHint, postExploitConfig,
                                ).catch(() => []);
                                for (const sf of schemaFindings) {
                                    if (sf.found) {
                                        await saveVulnerability(config, sf, 'post_exploit_schema');
                                        totalVulns++;
                                    }
                                }
                            }
                        }
                    }
                } catch (error) {
                    const errMsg = error instanceof Error ? error.message : String(error);
                    await addScanLog(config.scanId, 'error', detector.id, `Error on ${endpoint.url}: ${errMsg}`);
                    errors.push(`[${detector.id}] ${errMsg}`);
                }
            }

            // Update payload count every URL
            await prisma.scan.update({
                where: { id: config.scanId },
                data: { progress: scanProgress, totalPayloads: payloadCount },
            });
        }

        // ========================================
        // PHASE 2.5: ADVANCED DETECTORS (deep scans only)
        // Race conditions, HTTP desync, prototype pollution, cloud metadata SSRF,
        // context-aware fuzzing, business logic flaws, container exposure
        // ========================================
        if (config.scanType === 'deep') {
            const advancedProgress: ScanProgress = {
                scanId: config.scanId,
                phase: 'scanning',
                progress: 82,
                urlsDiscovered: crawlResult.discoveredUrls.length,
                urlsScanned,
                vulnsFound: totalVulns,
                message: '[ADVANCED] Running advanced red-team detectors...',
                currentModule: 'Advanced Detectors',
            };
            onProgress?.(advancedProgress);
            await persistProgress(config.scanId, advancedProgress);
            await addScanLog(config.scanId, 'info', 'advanced', 'Starting advanced detectors: race condition, HTTP desync, prototype pollution, cloud metadata SSRF');

            const cloudConfig = {
                baseUrl: config.baseUrl,
                requestTimeout: config.requestTimeout,
                userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                authHeaders: buildAuthHeaders(config),
            };
            const cogConfig = {
                baseUrl: config.baseUrl,
                requestTimeout: config.requestTimeout,
                userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                authHeaders: buildAuthHeaders(config),
            };

            for (const ep of finalEndpoints.slice(0, 20)) {
                for (const advDet of ADVANCED_DETECTORS) {
                    const advFindings = await advDet.detect(ep, detectorConfig).catch(() => []);
                    for (const f of advFindings) {
                        if (f.found) { await saveVulnerability(config, f, advDet.id); totalVulns++; }
                    }
                }
                const [ctxFindings, bizFindings] = await Promise.all([
                    runContextAwareFuzzing(ep, cogConfig).catch(() => []),
                    detectBusinessLogicFlaws(ep, cogConfig).catch(() => []),
                ]);
                for (const f of [...ctxFindings, ...bizFindings]) {
                    if (f.found) { await saveVulnerability(config, f, 'cognitive'); totalVulns++; }
                }
            }

            const containerFindings = await detectContainerExposure(cloudConfig).catch(() => []);
            for (const f of containerFindings) {
                if (f.found) { await saveVulnerability(config, f, 'cloud_exploit'); totalVulns++; }
            }

            await addScanLog(config.scanId, 'info', 'advanced', 'Advanced detectors completed');
        }

        // ========================================
        // PHASE 2.75: RECONNAISSANCE (Admin Panels + Backup Files + Tech Fingerprinting)
        // ========================================
        const reconProgress: ScanProgress = {
            scanId: config.scanId,
            phase: 'scanning',
            progress: 83,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned,
            vulnsFound: totalVulns,
            message: '[RECON] Reconnaissance — discovering admin panels, backup files, fingerprinting technology...',
            currentModule: 'Recon Scanner',
        };
        onProgress?.(reconProgress);
        await persistProgress(config.scanId, reconProgress);

        await addScanLog(config.scanId, 'info', 'recon', 'Starting reconnaissance: admin panels, backup files, technology fingerprinting');

        try {
            const reconConfig: ReconConfig = {
                baseUrl: config.baseUrl,
                requestTimeout: config.requestTimeout,
                userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                customHeaders: config.customHeaders,
                authHeaders: buildAuthHeaders(config),
                concurrency: 10,
            };

            const reconResult = await runReconScan(reconConfig);

            // Log summary
            await addScanLog(config.scanId, 'info', 'recon',
                `Recon complete: ${reconResult.adminPanels.length} admin panels, ${reconResult.backupFiles.length} backup files, ${reconResult.technologies.length} technologies detected`);

            // Save findings
            for (const finding of reconResult.findings) {
                if (finding.found) {
                    await saveVulnerability(config, finding, 'recon_scanner');
                    totalVulns++;
                    payloadCount++;
                }
            }

            if (reconResult.adminPanels.length > 0) {
                await addScanLog(config.scanId, 'warn', 'recon',
                    `[ADMIN-PANEL] found: ${reconResult.adminPanels.filter(p => p.confidence === 'confirmed').map(p => p.url).join(', ')}`);
            }

            if (reconResult.backupFiles.length > 0) {
                await addScanLog(config.scanId, 'warn', 'recon',
                    `[BACKUP] Exposed backup files: ${reconResult.backupFiles.map(f => f.url).join(', ')}`);
            }

            if (reconResult.technologies.length > 0) {
                await addScanLog(config.scanId, 'info', 'recon',
                    `[TECH] Technologies: ${reconResult.technologies.map(t => `${t.name}${t.version ? ` v${t.version}` : ''}`).join(', ')}`);
            }

            // Emit admin panel findings to bus for reactive processing
            for (const panel of ((reconResult as any).adminPanels ?? [])) {
                bus.emit({ type: 'admin:panel', url: panel.url, confidence: panel.confidence ?? 0.8, statusCode: panel.statusCode ?? 200 });
            }
            for (const tech of ((reconResult as any).technologies ?? [])) {
                bus.emit({ type: 'tech:detected', tech: tech.name ?? tech, version: tech.version, category: tech.category ?? 'web' });
            }
            if ((reconResult as any).wafVendor) {
                bus.emit({ type: 'waf:detected', vendor: (reconResult as any).wafVendor, confidence: 0.9, url: config.baseUrl });
            }
        } catch (err) {
            const errMsg = err instanceof Error ? err.message : String(err);
            await addScanLog(config.scanId, 'error', 'recon', `Recon error: ${errMsg}`);
        }

        // ========================================
        // PHASE 2.8: EASM — External Attack Surface
        // Subdomain enum, cloud bucket hunting, leaked secrets, shadow API discovery
        // ========================================
        await addScanLog(config.scanId, 'info', 'easm', 'Starting EASM: subdomains, cloud buckets, leaked secrets, shadow APIs');
        try {
            const easmDomain = new URL(config.baseUrl).hostname;
            const easmConfig = {
                baseUrl: config.baseUrl,
                domain: easmDomain,
                requestTimeout: config.requestTimeout,
                userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                scanId: config.scanId,
            };

            const [subdomains, cloudBucketFindings, shadowApiFindings] = await Promise.all([
                enumerateSubdomains(easmConfig).catch(() => []),
                huntCloudBuckets(easmConfig).catch(() => []),
                discoverShadowApis(easmConfig).catch(() => []),
            ]);

            if (subdomains.length > 0) {
                await addScanLog(config.scanId, 'info', 'easm',
                    `[EASM] Subdomains discovered: ${subdomains.slice(0, 15).join(', ')}${subdomains.length > 15 ? ` (+${subdomains.length - 15} more)` : ''}`);
            }

            for (const f of [...cloudBucketFindings, ...shadowApiFindings]) {
                if (f.found) {
                    await saveVulnerability(config, f, 'easm');
                    totalVulns++;
                }
            }

            // Scan JS files for leaked secrets
            const jsUrls = crawlResult.endpoints.filter(ep => /\.js(\?|$)/.test(ep.url)).map(ep => ep.url);
            if (jsUrls.length > 0) {
                const secretFindings = await scanForLeakedSecrets(jsUrls, easmConfig).catch(() => []);
                for (const f of secretFindings) {
                    if (f.found) {
                        await saveVulnerability(config, f, 'easm_secrets');
                        totalVulns++;
                    }
                }
            }

            await addScanLog(config.scanId, 'info', 'easm',
                `[EASM] complete: ${subdomains.length} subdomains, ` +
                `${cloudBucketFindings.filter(f => f.found).length} cloud buckets, ` +
                `${shadowApiFindings.filter(f => f.found).length} shadow APIs, ` +
                `${jsUrls.length} JS files scanned for secrets`);
        } catch (err) {
            const errMsg = err instanceof Error ? err.message : String(err);
            await addScanLog(config.scanId, 'error', 'easm', `EASM error: ${errMsg}`);
        }

        // ========================================
        // PHASE 2.5: SMART FORM SQLi (InjectProof Deep Engine)
        // ========================================
        if (crawlConfig.enableHeadless) {
            const smartFormProgress: ScanProgress = {
                scanId: config.scanId,
                phase: 'scanning',
                progress: 86,
                urlsDiscovered: crawlResult.discoveredUrls.length,
                urlsScanned,
                vulnsFound: totalVulns,
                message: '[SMART-FORM] Smart Form SQLi Engine — auto-discovering and attacking forms...',
                currentModule: 'Smart Form SQLmap',
            };
            onProgress?.(smartFormProgress);
            await persistProgress(config.scanId, smartFormProgress);

            await addScanLog(config.scanId, 'info', 'smart-form-sqli', 'Starting InjectProof Smart Form SQLi Engine');

            const smartConfig: SmartFormScanConfig = {
                baseUrl: config.baseUrl,
                requestTimeout: config.requestTimeout,
                userAgent: config.userAgent || 'InjectProof-Scanner/1.0',
                customHeaders: config.customHeaders,
                authHeaders: buildAuthHeaders(config),
                cdpEndpoint: config.cdpEndpoint,
                maxFormsPerPage: 20,
                maxPayloadsPerField: 15,
                enableDeepExploit: true,
            };

            // Scan each unique URL for forms
            const smartUrls = new Set<string>();
            for (const ep of finalEndpoints) {
                if (ep.forms.length > 0 || ep.url === config.baseUrl) {
                    smartUrls.add(ep.url);
                }
            }
            // Always include base URL
            smartUrls.add(config.baseUrl);

            for (const smartUrl of smartUrls) {
                try {
                    await addScanLog(config.scanId, 'info', 'smart-form-sqli', `Scanning forms at: ${smartUrl}`);

                    const smartResult = await runSmartFormSqliScan(smartUrl, smartConfig);

                    // Log results
                    for (const entry of smartResult.log) {
                        await addScanLog(config.scanId, 'info', 'smart-form-sqli', `[${entry.phase}] ${entry.msg}`, entry.detail ? { detail: entry.detail } : undefined);
                    }

                    // Save vulnerabilities
                    for (const result of smartResult.results) {
                        if (result.found) {
                            await saveVulnerability(config, result, 'smart_form_sqli');
                            totalVulns++;
                            payloadCount++;
                        }
                    }

                    if (smartResult.authBypassed) {
                        await addScanLog(config.scanId, 'warn', 'smart-form-sqli', '[AUTH-BYPASS] login form is vulnerable to SQLi authentication bypass');
                    }

                    if (smartResult.exploitData) {
                        await addScanLog(
                            config.scanId,
                            'warn',
                            'smart-form-sqli',
                            `[DB-DUMP] ${smartResult.exploitData.dbms} | DB: ${smartResult.exploitData.currentDatabase} | ${smartResult.exploitData.databases.length} databases extracted`,
                        );
                    }
                } catch (err) {
                    const errMsg = err instanceof Error ? err.message : String(err);
                    await addScanLog(config.scanId, 'error', 'smart-form-sqli', `Error on ${smartUrl}: ${errMsg}`);
                }
            }

            await addScanLog(config.scanId, 'info', 'smart-form-sqli', 'Smart Form SQLi Engine completed');
        }

        // ========================================
        // PHASE 3: FINALIZATION
        // ========================================
        const analyzing: ScanProgress = {
            scanId: config.scanId,
            phase: 'analyzing',
            progress: 90,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned,
            vulnsFound: totalVulns,
            message: 'Analyzing results...',
        };
        onProgress?.(analyzing);
        await persistProgress(config.scanId, analyzing);

        // Count vulnerabilities by severity
        const vulnCounts = await prisma.vulnerability.groupBy({
            by: ['severity'],
            where: { scanId: config.scanId },
            _count: { id: true },
        });

        const severityCounts: Record<string, number> = {};
        for (const vc of vulnCounts) {
            severityCounts[vc.severity] = vc._count.id;
        }

        // Update scan with final results
        const scanRecord = await prisma.scan.findUnique({ where: { id: config.scanId } });
        const duration = Math.floor((Date.now() - (scanRecord?.startedAt?.getTime() ?? Date.now())) / 1000);

        await prisma.scan.update({
            where: { id: config.scanId },
            data: {
                status: 'completed',
                completedAt: new Date(),
                progress: 100,
                duration,
                totalUrls: urlsScanned,
                totalPayloads: payloadCount,
                criticalCount: severityCounts.critical || 0,
                highCount: severityCounts.high || 0,
                mediumCount: severityCounts.medium || 0,
                lowCount: severityCounts.low || 0,
                infoCount: severityCounts.info || 0,
                // Clear live status fields
                currentPhase: 'completed',
                currentModule: null,
                currentUrl: null,
                statusMessage: `Scan completed. Found ${totalVulns} vulnerabilities in ${duration}s.`,
            },
        });

        // Update target last scan time
        await prisma.target.update({
            where: { id: config.targetId },
            data: { lastScanAt: new Date() },
        });

        await addScanLog(
            config.scanId,
            'info',
            'orchestrator',
            `Scan completed. ${totalVulns} vulnerabilities found. Duration: ${duration}s`,
        );

        onProgress?.({
            scanId: config.scanId,
            phase: 'completed',
            progress: 100,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned,
            vulnsFound: totalVulns,
            message: `Scan completed. Found ${totalVulns} vulnerabilities.`,
        });

        // Enterprise bus cleanup + stats
        const busStats = bus.snapshot();
        if (busStats.totalEmitted > 0) {
            await addScanLog(config.scanId, 'info', 'orchestrator',
                `[ENTERPRISE] Bus: ${busStats.totalEmitted} events | Reactive tasks: ${reactiveCtx.pendingTasks.length}`);
        }
        _unsubBus();

        // Scan diff — compare this scan's findings against the previous scan of the same target
        try {
            const diff = await computeScanDiff(config.scanId);
            if (diff.previousScanId) {
                await addScanLog(config.scanId, 'info', 'scan-diff',
                    `[DIFF] vs ${diff.previousScanId.slice(0, 8)}: +${diff.newFindings.length} new, -${diff.fixedFindings.length} fixed, ` +
                    `${diff.stillOpen.length} still open, ${diff.regressions.length} regressions | delta=${diff.summary.delta > 0 ? '+' : ''}${diff.summary.delta}`);
            }
        } catch {
            // Non-critical — no previous scan or query failure
        }

        // Outbound notifications — fan out to all active notification configs
        try {
            const notifRows = await prisma.notificationConfig.findMany({ where: { isActive: true } });
            const topSeverity = (severityCounts.critical || 0) > 0 ? 'critical'
                : (severityCounts.high || 0) > 0 ? 'high'
                : (severityCounts.medium || 0) > 0 ? 'medium' : 'info';
            for (const nc of notifRows) {
                const events: string[] = JSON.parse(nc.events ?? '[]');
                if (!events.includes('scan_completed') && !events.includes('all')) continue;
                const channelCfg: Record<string, string> = JSON.parse(nc.config ?? '{}');
                const webhookEndpoint = channelCfg.webhook_url ?? channelCfg.webhook ?? '';
                if (!webhookEndpoint) continue;
                const target: NotificationTarget = {
                    channel: nc.channel as NotificationTarget['channel'],
                    endpoint: webhookEndpoint,
                    signingSecret: channelCfg.signing_secret,
                };
                await dispatch(target, {
                    title: `InjectProof scan completed: ${config.baseUrl}`,
                    body: `Found ${totalVulns} vulnerabilities in ${duration}s.`,
                    severity: topSeverity as any,
                    context: {
                        url: config.baseUrl,
                        scanId: config.scanId,
                        total: totalVulns,
                        critical: severityCounts.critical || 0,
                        high: severityCounts.high || 0,
                        medium: severityCounts.medium || 0,
                        duration: `${duration}s`,
                    },
                }).catch(() => {}); // non-critical
            }
        } catch {
            // Notification failure is non-critical
        }

    } catch (error) {
        const errMsg = error instanceof Error ? error.message : String(error);
        errors.push(`Fatal error: ${errMsg}`);

        await prisma.scan.update({
            where: { id: config.scanId },
            data: {
                status: 'failed',
                errorMessage: errMsg,
                completedAt: new Date(),
                currentPhase: 'failed',
                currentModule: null,
                currentUrl: null,
                statusMessage: `Scan failed: ${errMsg}`,
            },
        });

        await addScanLog(config.scanId, 'error', 'orchestrator', `Scan failed: ${errMsg}`);

        onProgress?.({
            scanId: config.scanId,
            phase: 'failed',
            progress: 0,
            urlsDiscovered: 0,
            urlsScanned: 0,
            vulnsFound: totalVulns,
            message: `Scan failed: ${errMsg}`,
        });
    } finally {
        releaseBudgetTracker(config.scanId);
    }

    return { vulnCount: totalVulns, errors };
}

// ============================================================
// HELPERS
// ============================================================

/** Build auth headers from scan config */
function buildAuthHeaders(config: ScanConfig): Record<string, string> | undefined {
    if (!config.authType || !config.authConfig) return undefined;

    switch (config.authType) {
        case 'token':
            return { Authorization: `Bearer ${config.authConfig.token}` };
        case 'cookie':
            return { Cookie: config.authConfig.cookie as string };
        case 'session':
            return config.authConfig.headers as Record<string, string>;
        default:
            return undefined;
    }
}

/** Save a detected vulnerability to the database */
async function saveVulnerability(
    config: ScanConfig,
    result: DetectorResult,
    detectorModule: string,
): Promise<void> {
    await prisma.vulnerability.create({
        data: {
            targetId: config.targetId,
            scanId: config.scanId,
            title: result.title,
            description: result.description,
            category: result.category,
            severity: result.severity,
            confidence: result.confidence,
            cvssScore: result.cvssScore,
            cvssVector: result.cvssVector,
            cweId: result.cweId,
            cweTitle: result.cweTitle,
            mappedCveIds: result.mappedCveIds ? JSON.stringify(result.mappedCveIds) : null,
            mappedOwasp: result.mappedOwasp ? JSON.stringify(result.mappedOwasp) : null,
            mappedOwaspAsvs: result.mappedOwaspAsvs ? JSON.stringify(result.mappedOwaspAsvs) : null,
            mappedNist: result.mappedNist ? JSON.stringify(result.mappedNist) : null,
            affectedUrl: result.affectedUrl,
            httpMethod: result.httpMethod,
            parameter: result.parameter,
            parameterType: result.parameterType,
            injectionPoint: result.injectionPoint,
            payload: result.payload,
            requestArtifact: result.request,
            responseArtifact: result.response,
            responseCode: result.responseCode,
            responseTime: result.responseTime,
            timingEvidence: result.timingEvidence ? JSON.stringify(result.timingEvidence) : null,
            domSnapshot: result.domSnapshot,
            screenshotPath: result.screenshotPath,
            impact: result.impact,
            technicalDetail: result.technicalDetail,
            remediation: result.remediation,
            reproductionSteps: result.reproductionSteps ? JSON.stringify(result.reproductionSteps) : null,
            references: result.references ? JSON.stringify(result.references) : null,
            detectorModule,
            sqliExploitData: result.sqliExploitData || null,
            // Adaptive-engine provenance + validation level. Findings from
            // legacy detectors that have no provenance land as 'candidate';
            // oracle-driven ones that passed full validation land as
            // 'confirmed'. Automation (alerting, SLA counts) should filter on
            // validationLevel='confirmed' only.
            provenance: result.provenance ? JSON.stringify(result.provenance) : null,
            validationLevel:
                result.provenance && result.confidence === 'high' ? 'confirmed' : 'candidate',
            status: 'open',
        },
    });
}

