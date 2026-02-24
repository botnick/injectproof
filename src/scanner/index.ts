// InjectProof — Scan Orchestrator
// Main entry point for running vulnerability scans
// Coordinates crawling, detection, evidence collection, and result storage

import type { ScanConfig, DetectorResult, ScanProgress } from '@/types';
import { crawlTarget, type CrawlConfig, type CrawlResult } from '@/scanner/crawler';
import { crawlTargetHeadless } from '@/scanner/headless-crawler';
import { isCdpAvailable } from '@/scanner/headless-browser';
import { ALL_DETECTORS } from '@/scanner/detectors';
import { runSmartFormSqliScan, type SmartFormScanConfig } from '@/scanner/smart-form-sqlmap';
import { runReconScan, type ReconConfig } from '@/scanner/recon-scanner';
import prisma from '@/lib/prisma';

export type ProgressCallback = (progress: ScanProgress) => void;

/** Persist live progress status to DB for real-time UI updates */
async function persistProgress(scanId: string, progress: ScanProgress): Promise<void> {
    try {
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
    } catch {
        // Silently fail — don't interrupt scan for progress tracking
    }
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
            progress: 20,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned: 0,
            vulnsFound: 0,
            message: `Found ${crawlResult.endpoints.length} endpoints with ${totalParams} parameters`,
        };
        onProgress?.(crawlDone);
        await persistProgress(config.scanId, crawlDone);

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
        };

        let urlsScanned = 0;
        const totalEndpoints = crawlResult.endpoints.length;
        let payloadCount = 0;

        // Run detectors on each endpoint
        // Only scan unique endpoints (first occurrence)
        const seenUrls = new Set<string>();
        const uniqueEndpoints = crawlResult.endpoints.filter(ep => {
            const key = `${ep.method}:${ep.url}`;
            if (seenUrls.has(key)) return false;
            seenUrls.add(key);
            return true;
        });

        for (const endpoint of uniqueEndpoints) {
            // Check if scan was cancelled
            const scanRecord = await prisma.scan.findUnique({ where: { id: config.scanId } });
            if (scanRecord?.status === 'cancelled') {
                await addScanLog(config.scanId, 'info', 'orchestrator', 'Scan cancelled by user');
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
        // PHASE 2.75: RECONNAISSANCE (Admin Panels + Backup Files + Tech Fingerprinting)
        // ========================================
        const reconProgress: ScanProgress = {
            scanId: config.scanId,
            phase: 'scanning',
            progress: 83,
            urlsDiscovered: crawlResult.discoveredUrls.length,
            urlsScanned,
            vulnsFound: totalVulns,
            message: '🔍 Reconnaissance — discovering admin panels, backup files, fingerprinting technology...',
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
                    `🚪 Admin panels found: ${reconResult.adminPanels.filter(p => p.confidence === 'confirmed').map(p => p.url).join(', ')}`);
            }

            if (reconResult.backupFiles.length > 0) {
                await addScanLog(config.scanId, 'warn', 'recon',
                    `📦 Exposed backup files: ${reconResult.backupFiles.map(f => f.url).join(', ')}`);
            }

            if (reconResult.technologies.length > 0) {
                await addScanLog(config.scanId, 'info', 'recon',
                    `🔧 Technologies: ${reconResult.technologies.map(t => `${t.name}${t.version ? ` v${t.version}` : ''}`).join(', ')}`);
            }
        } catch (err) {
            const errMsg = err instanceof Error ? err.message : String(err);
            await addScanLog(config.scanId, 'error', 'recon', `Recon error: ${errMsg}`);
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
                message: '🧠 Smart Form SQLi Engine — auto-discovering and attacking forms...',
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
            for (const ep of uniqueEndpoints) {
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
                        await addScanLog(config.scanId, 'warn', 'smart-form-sqli', '🔓 AUTH BYPASS DETECTED — login form is vulnerable to SQLi authentication bypass');
                    }

                    if (smartResult.exploitData) {
                        await addScanLog(
                            config.scanId,
                            'warn',
                            'smart-form-sqli',
                            `🗄️ Database dumped: ${smartResult.exploitData.dbms} | DB: ${smartResult.exploitData.currentDatabase} | ${smartResult.exploitData.databases.length} databases extracted`,
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
            status: 'open',
        },
    });
}

/** Add a log entry for a scan */
async function addScanLog(
    scanId: string,
    level: string,
    module: string,
    message: string,
    details?: Record<string, unknown>,
): Promise<void> {
    try {
        await prisma.scanLog.create({
            data: {
                scanId,
                level,
                module,
                message,
                details: details ? JSON.stringify(details) : null,
            },
        });
    } catch {
        // Silently fail on log errors to not interrupt the scan
        console.error(`[ScanLog] Failed to write log: ${message}`);
    }
}
