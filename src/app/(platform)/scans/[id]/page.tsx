// VibeCode — Scan Detail Page (CWE-Grouped Glassmorphism)
'use client';

import { use, useEffect, useRef, useState, useMemo } from 'react';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import {
    ArrowLeft, Bug, Activity, Terminal,
    Crosshair, Layers, Globe, Shield,
    CheckCircle2, XCircle, Radio, Gauge,
    ChevronDown, ChevronRight, ExternalLink,
} from 'lucide-react';
import { getCweEntry, OWASP_TOP_10_2021, CATEGORY_DISPLAY_NAMES } from '@/lib/cwe-database';

/* ── OWASP category colors ────────────────────────────── */
const OWASP_COLORS: Record<string, { dot: string; text: string; border: string; bg: string }> = {
    'A01:2021': { dot: 'bg-red-500', text: 'text-red-400', border: 'border-red-500/15', bg: 'bg-red-500/5' },
    'A02:2021': { dot: 'bg-purple-500', text: 'text-purple-400', border: 'border-purple-500/15', bg: 'bg-purple-500/5' },
    'A03:2021': { dot: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/15', bg: 'bg-orange-500/5' },
    'A04:2021': { dot: 'bg-pink-500', text: 'text-pink-400', border: 'border-pink-500/15', bg: 'bg-pink-500/5' },
    'A05:2021': { dot: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500/15', bg: 'bg-amber-500/5' },
    'A06:2021': { dot: 'bg-teal-500', text: 'text-teal-400', border: 'border-teal-500/15', bg: 'bg-teal-500/5' },
    'A07:2021': { dot: 'bg-indigo-500', text: 'text-indigo-400', border: 'border-indigo-500/15', bg: 'bg-indigo-500/5' },
    'A08:2021': { dot: 'bg-cyan-500', text: 'text-cyan-400', border: 'border-cyan-500/15', bg: 'bg-cyan-500/5' },
    'A09:2021': { dot: 'bg-emerald-500', text: 'text-emerald-400', border: 'border-emerald-500/15', bg: 'bg-emerald-500/5' },
    'A10:2021': { dot: 'bg-violet-500', text: 'text-violet-400', border: 'border-violet-500/15', bg: 'bg-violet-500/5' },
};

const DEFAULT_OWASP_COLOR = { dot: 'bg-gray-500', text: 'text-gray-400', border: 'border-gray-500/15', bg: 'bg-gray-500/5' };

/* ── Phase visual config ────────────────────────────────── */
const PHASES: Record<string, {
    label: string; Icon: typeof Activity;
    gradient: string; glow: string; ring: string;
}> = {
    crawling: { label: 'Crawling', Icon: Globe, gradient: 'from-cyan-500 to-blue-500', glow: 'shadow-cyan-500/20', ring: 'ring-cyan-500/25' },
    scanning: { label: 'Scanning', Icon: Crosshair, gradient: 'from-violet-500 to-indigo-500', glow: 'shadow-violet-500/20', ring: 'ring-violet-500/25' },
    analyzing: { label: 'Analyzing', Icon: Layers, gradient: 'from-amber-500 to-orange-500', glow: 'shadow-amber-500/20', ring: 'ring-amber-500/25' },
    evidence: { label: 'Evidence', Icon: Shield, gradient: 'from-emerald-500 to-teal-500', glow: 'shadow-emerald-500/20', ring: 'ring-emerald-500/25' },
    completed: { label: 'Completed', Icon: CheckCircle2, gradient: 'from-emerald-500 to-teal-500', glow: 'shadow-emerald-500/20', ring: 'ring-emerald-500/25' },
    failed: { label: 'Failed', Icon: XCircle, gradient: 'from-red-500 to-rose-500', glow: 'shadow-red-500/20', ring: 'ring-red-500/25' },
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/* ── Group vulnerabilities by OWASP category ──────────── */
interface VulnGroup {
    owaspId: string;
    owaspName: string;
    vulns: any[];
    highestSeverity: string;
    uniqueCwes: string[];
    uniqueUrls: string[];
}

function groupVulnsByOwasp(vulns: any[]): VulnGroup[] {
    const groups: Record<string, VulnGroup> = {};

    for (const vuln of vulns) {
        const cweEntry = vuln.cweId ? getCweEntry(vuln.cweId) : null;
        const owaspIds = cweEntry?.owasp || [];
        const owaspId = owaspIds[0] || 'Other';
        const owaspInfo = OWASP_TOP_10_2021.find(o => o.id === owaspId);

        if (!groups[owaspId]) {
            groups[owaspId] = {
                owaspId,
                owaspName: owaspInfo?.name || 'Uncategorized',
                vulns: [],
                highestSeverity: 'info',
                uniqueCwes: [],
                uniqueUrls: [],
            };
        }

        groups[owaspId].vulns.push(vuln);

        // Track highest severity
        const currentIdx = SEV_ORDER.indexOf(groups[owaspId].highestSeverity);
        const vulnIdx = SEV_ORDER.indexOf(vuln.severity);
        if (vulnIdx >= 0 && vulnIdx < currentIdx) {
            groups[owaspId].highestSeverity = vuln.severity;
        }

        // Track unique CWEs
        if (vuln.cweId && !groups[owaspId].uniqueCwes.includes(vuln.cweId)) {
            groups[owaspId].uniqueCwes.push(vuln.cweId);
        }

        // Track unique URLs
        if (vuln.affectedUrl && !groups[owaspId].uniqueUrls.includes(vuln.affectedUrl)) {
            groups[owaspId].uniqueUrls.push(vuln.affectedUrl);
        }
    }

    // Sort by severity priority, then by OWASP ID
    return Object.values(groups).sort((a, b) => {
        const sevDiff = SEV_ORDER.indexOf(a.highestSeverity) - SEV_ORDER.indexOf(b.highestSeverity);
        if (sevDiff !== 0) return sevDiff;
        return a.owaspId.localeCompare(b.owaspId);
    });
}

/* ── Deduplicate vulns by CWE within a group ──────────── */
interface DeduplicatedVuln {
    cweId: string;
    cweTitle: string;
    title: string;
    severity: string;
    cvssScore: number | null;
    category: string;
    parameter: string;
    urls: string[];
    count: number;
    firstVulnId: string;
    nist: string[];
    owasp: string[];
}

function deduplicateVulns(vulns: any[]): DeduplicatedVuln[] {
    const map: Record<string, DeduplicatedVuln> = {};

    for (const vuln of vulns) {
        // Group by CWE + parameter + category so same vuln on same param merges
        const cweKey = vuln.cweId || vuln.title;
        const param = vuln.parameter || '';
        const cat = vuln.category || '';
        const key = `${cweKey}::${param}::${cat}`;
        const cweEntry = vuln.cweId ? getCweEntry(vuln.cweId) : null;

        if (!map[key]) {
            map[key] = {
                cweId: vuln.cweId || '',
                cweTitle: cweEntry?.title || vuln.cweTitle || '',
                title: vuln.title,
                severity: vuln.severity,
                cvssScore: vuln.cvssScore,
                category: cat,
                parameter: param,
                urls: [],
                count: 0,
                firstVulnId: vuln.id,
                nist: cweEntry?.nist || [],
                owasp: cweEntry?.owasp || [],
            };
        }

        map[key].count++;
        if (vuln.affectedUrl && !map[key].urls.includes(vuln.affectedUrl)) {
            map[key].urls.push(vuln.affectedUrl);
        }

        // Keep highest severity
        const currentIdx = SEV_ORDER.indexOf(map[key].severity);
        const vulnIdx = SEV_ORDER.indexOf(vuln.severity);
        if (vulnIdx >= 0 && vulnIdx < currentIdx) {
            map[key].severity = vuln.severity;
        }
    }

    return Object.values(map).sort(
        (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    );
}

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { data: scan, isLoading } = trpc.scan.getById.useQuery(id, {
        refetchInterval: (q) => q.state.data?.status === 'running' ? 2000 : false,
    });
    const { data: logs } = trpc.scan.getLogs.useQuery(
        { scanId: id, limit: 100 },
        { refetchInterval: scan?.status === 'running' ? 2000 : false },
    );

    const logsRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        if (scan?.status === 'running') logsRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs, scan?.status]);

    const vulnGroups = useMemo(() => {
        if (!scan?.vulnerabilities) return [];
        return groupVulnsByOwasp(scan.vulnerabilities);
    }, [scan?.vulnerabilities]);

    if (isLoading) return <Skeleton />;
    if (!scan) return (
        <div className="flex flex-col items-center justify-center py-24 gap-4 animate-fade-in">
            <XCircle className="w-10 h-10 text-gray-700" />
            <p className="text-sm text-gray-500">Scan not found</p>
        </div>
    );

    const isRunning = scan.status === 'running';
    const phase = PHASES[(scan as any).currentPhase || scan.status] || PHASES.scanning;
    const elapsed = scan.startedAt ? Math.floor((Date.now() - new Date(scan.startedAt).getTime()) / 1000) : 0;

    return (
        <div className="space-y-6 animate-fade-in">
            {/* ── Header ────────────────────────────── */}
            <div className="flex items-center gap-3">
                <Link href="/scans" className="group p-2.5 rounded-xl border border-transparent hover:border-white/[0.06] hover:bg-white/[0.03] transition-all duration-300">
                    <ArrowLeft className="w-4 h-4 text-gray-500 group-hover:text-white transition-colors" />
                </Link>
                <div className="flex-1 min-w-0">
                    <h1 className="text-xl font-semibold text-white tracking-tight truncate">
                        {scan.target?.name || 'Scan Results'}
                    </h1>
                    <p className="text-xs text-gray-500 mt-0.5 tracking-wide">
                        {scan.scanType} scan
                        {scan.duration ? ` · ${scan.duration}s` : isRunning && elapsed > 0 ? ` · ${elapsed}s elapsed` : ''}
                    </p>
                </div>
                <Pill status={scan.status} />
            </div>

            {/* ── Live Progress Panel ────────────────── */}
            {isRunning && (
                <div className="relative overflow-hidden rounded-2xl">
                    <div className="absolute inset-0 rounded-2xl p-px bg-gradient-to-br from-white/[0.12] via-white/[0.04] to-white/[0.08]">
                        <div className="rounded-2xl w-full h-full bg-[#0a0f1e]" />
                    </div>
                    <div className="relative rounded-2xl bg-white/[0.02] backdrop-blur-2xl p-6 space-y-5">
                        <div className="absolute inset-x-0 top-0 h-px overflow-hidden">
                            <div className={`h-full w-1/3 bg-gradient-to-r ${phase.gradient} opacity-60 animate-scan-sweep`} />
                        </div>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3.5">
                                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${phase.gradient} p-[1px] ${phase.glow} shadow-lg`}>
                                    <div className="w-full h-full rounded-[11px] bg-[#0a0f1e] flex items-center justify-center">
                                        <phase.Icon className="w-4 h-4 text-white animate-pulse" />
                                    </div>
                                </div>
                                <div>
                                    <p className="text-sm font-semibold text-white">{phase.label}</p>
                                    {(scan as any).currentModule && (
                                        <p className="text-xs text-gray-500 font-mono mt-0.5">{(scan as any).currentModule}</p>
                                    )}
                                </div>
                            </div>
                            <div className="flex items-center gap-6">
                                <MiniStat label="URLs" value={scan.totalUrls} />
                                <MiniStat label="Found" value={scan._count?.vulnerabilities || 0} accent />
                                <div className="flex items-center gap-2">
                                    <Gauge className="w-3.5 h-3.5 text-gray-600" />
                                    <span className="text-sm font-bold text-white tabular-nums">{scan.progress}%</span>
                                </div>
                            </div>
                        </div>
                        {(scan as any).currentUrl && (
                            <div className="flex items-center gap-2.5 rounded-xl bg-white/[0.03] border border-white/[0.06] px-4 py-2.5">
                                <Radio className="w-3 h-3 text-violet-400 animate-pulse flex-shrink-0" />
                                <code className="text-xs text-gray-400 truncate font-mono flex-1">{(scan as any).currentUrl}</code>
                            </div>
                        )}
                        {(scan as any).statusMessage && (
                            <p className="text-xs text-gray-600 truncate pl-1">{(scan as any).statusMessage}</p>
                        )}
                        <div className="h-1.5 rounded-full bg-white/[0.04] overflow-hidden">
                            <div
                                className={`h-full rounded-full bg-gradient-to-r ${phase.gradient} transition-all duration-700 ease-out relative`}
                                style={{ width: `${scan.progress}%` }}
                            >
                                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/25 to-transparent animate-shimmer" />
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Severity Stats ────────────────────── */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-2.5">
                <GlassCell label="URLs" value={scan.totalUrls} />
                <GlassCell label="Critical" value={scan.criticalCount} color="text-red-400" dot="bg-red-500" />
                <GlassCell label="High" value={scan.highCount} color="text-orange-400" dot="bg-orange-500" />
                <GlassCell label="Medium" value={scan.mediumCount} color="text-amber-400" dot="bg-amber-500" />
                <GlassCell label="Low" value={scan.lowCount} color="text-blue-400" dot="bg-blue-500" />
                <GlassCell label="Info" value={scan.infoCount} color="text-gray-500" dot="bg-gray-500" />
            </div>

            {/* ── Grouped Vulnerabilities ──────────────── */}
            <div className="space-y-3">
                <div className="flex items-center gap-2.5 px-1">
                    <Bug className="w-3.5 h-3.5 text-gray-500" />
                    <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                        Vulnerabilities
                    </h2>
                    <span className="ml-auto text-xs text-gray-700 font-mono tabular-nums">
                        {scan.vulnerabilities?.length || 0}
                    </span>
                </div>

                {vulnGroups.length > 0 ? (
                    <div className="space-y-2.5">
                        {vulnGroups.map(group => (
                            <OwaspGroup key={group.owaspId} group={group} />
                        ))}
                    </div>
                ) : (
                    <div className="vuln-group">
                        <div className="px-5 py-12 text-center">
                            <p className="text-sm text-gray-600">
                                {isRunning ? 'Scanning in progress...' : 'No vulnerabilities found'}
                            </p>
                        </div>
                    </div>
                )}
            </div>

            {/* ── Execution Log ──────────────────────── */}
            <GlassSection
                icon={<Terminal className="w-3.5 h-3.5" />}
                title="Execution Log"
                count={logs?.length || 0}
                live={isRunning}
            >
                <div className="max-h-72 overflow-y-auto">
                    {logs && logs.length > 0 ? (
                        <div className="p-4 space-y-px font-mono text-[11px] leading-5">
                            {[...logs].reverse().map((log: any) => (
                                <div key={log.id} className="flex gap-2.5 py-px hover:bg-white/[0.01] rounded px-1 -mx-1 transition-colors">
                                    <span className="text-gray-700 flex-shrink-0 tabular-nums w-[68px]">
                                        {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                                    </span>
                                    <span className={`flex-shrink-0 w-10 text-right ${log.level === 'error' ? 'text-red-400/70' : log.level === 'warn' ? 'text-amber-400/70' : 'text-gray-600'
                                        }`}>{log.level}</span>
                                    <span className="text-violet-400/40 flex-shrink-0 w-[72px] truncate">{log.module}</span>
                                    <span className={`flex-1 truncate ${log.level === 'error' ? 'text-red-300/70' : log.level === 'warn' ? 'text-amber-300/60' : 'text-gray-500'
                                        }`}>{log.message}</span>
                                </div>
                            ))}
                            <div ref={logsRef} />
                        </div>
                    ) : (
                        <div className="p-5 text-gray-700 font-mono text-xs">No logs yet</div>
                    )}
                </div>
            </GlassSection>
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   OWASP Group — Collapsible category section
   ══════════════════════════════════════════════════════════ */

function OwaspGroup({ group }: { group: VulnGroup }) {
    const [expanded, setExpanded] = useState(true);
    const colors = OWASP_COLORS[group.owaspId] || DEFAULT_OWASP_COLOR;
    const deduplicated = useMemo(() => deduplicateVulns(group.vulns), [group.vulns]);

    return (
        <div className="vuln-group">
            {/* Group Header */}
            <button
                onClick={() => setExpanded(!expanded)}
                className="vuln-group-header w-full"
            >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${colors.dot}`} />

                <div className="flex items-center gap-2 flex-1 min-w-0">
                    <span className={`text-[11px] font-mono font-semibold ${colors.text} px-1.5 py-0.5 rounded ${colors.bg} ${colors.border} border`}>
                        {group.owaspId === 'Other' ? 'N/A' : group.owaspId.replace(':2021', '')}
                    </span>
                    <span className="text-sm font-medium text-gray-300 truncate">
                        {group.owaspName}
                    </span>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                    {/* Unique CWE count */}
                    <span className="text-[10px] text-gray-600 uppercase tracking-wider">
                        {group.uniqueCwes.length} CWE
                    </span>
                    {/* Vuln count */}
                    <span className="text-xs font-mono text-gray-600 tabular-nums min-w-[28px] text-right">
                        {group.vulns.length}
                    </span>
                    {/* Highest severity */}
                    <SevBadge severity={group.highestSeverity} />
                    {/* Chevron */}
                    {expanded
                        ? <ChevronDown className="w-3.5 h-3.5 text-gray-600" />
                        : <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
                    }
                </div>
            </button>

            {/* Group Body — Deduplicated Vulns */}
            {expanded && (
                <div className="vuln-group-body">
                    {deduplicated.map((item, idx) => (
                        <div key={`${item.cweId}-${item.parameter}-${item.category}-${idx}`} className="border-b border-white/[0.02] last:border-0">
                            {/* CWE Row */}
                            <Link
                                href={`/vulnerabilities/${item.firstVulnId}`}
                                className="flex items-center gap-3 px-5 py-3 hover:bg-white/[0.02] transition-all duration-200 group"
                            >
                                <SevDot severity={item.severity} />

                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        {item.cweId && (
                                            <span className="text-[11px] font-mono text-violet-400/70 flex-shrink-0">
                                                {item.cweId}
                                            </span>
                                        )}
                                        <p className="text-sm text-gray-300 group-hover:text-white truncate transition-colors">
                                            {item.title}
                                        </p>
                                        {item.parameter && (
                                            <span className="text-[10px] font-mono text-cyan-400/60 bg-cyan-500/5 border border-cyan-500/10 rounded px-1.5 py-0.5 flex-shrink-0">
                                                {item.parameter}
                                            </span>
                                        )}
                                    </div>
                                    {/* NIST controls */}
                                    {item.nist.length > 0 && (
                                        <div className="flex items-center gap-1.5 mt-1">
                                            <span className="text-[10px] text-gray-700">NIST:</span>
                                            {item.nist.slice(0, 3).map(n => (
                                                <span key={n} className="text-[10px] text-blue-400/50 font-mono">{n}</span>
                                            ))}
                                            {item.nist.length > 3 && (
                                                <span className="text-[10px] text-gray-700">+{item.nist.length - 3}</span>
                                            )}
                                        </div>
                                    )}
                                </div>

                                <div className="flex items-center gap-2.5 flex-shrink-0">
                                    {item.count > 1 && (
                                        <span className="text-[10px] font-mono text-gray-600 bg-white/[0.03] border border-white/[0.06] rounded-full px-2 py-0.5">
                                            ×{item.count}
                                        </span>
                                    )}
                                    <SevBadge severity={item.severity} />
                                    {item.cvssScore != null && (
                                        <span className="text-xs font-mono text-gray-600 tabular-nums">{item.cvssScore}</span>
                                    )}
                                </div>
                            </Link>

                            {/* Affected URLs (compact, shown under the CWE row) */}
                            {item.urls.length > 0 && (
                                <div className="px-5 pb-2.5 -mt-1">
                                    <div className="flex flex-wrap gap-1.5 pl-5">
                                        {item.urls.slice(0, 5).map(url => (
                                            <span
                                                key={url}
                                                className="inline-flex items-center gap-1 text-[10px] font-mono text-gray-600 bg-white/[0.02] border border-white/[0.04] rounded-lg px-2 py-0.5 max-w-[280px] truncate"
                                            >
                                                <Globe className="w-2.5 h-2.5 flex-shrink-0 text-gray-700" />
                                                {url.replace(/^https?:\/\//, '').replace(/\/$/, '')}
                                            </span>
                                        ))}
                                        {item.urls.length > 5 && (
                                            <span className="text-[10px] text-gray-700 self-center">
                                                +{item.urls.length - 5} more
                                            </span>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   Sub-components
   ══════════════════════════════════════════════════════════ */

function Skeleton() {
    return (
        <div className="space-y-6 animate-fade-in">
            <div className="h-8 w-48 rounded-xl bg-white/[0.03] animate-pulse" />
            <div className="h-40 rounded-2xl bg-white/[0.02] animate-pulse" />
            <div className="grid grid-cols-6 gap-2.5">
                {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="h-16 rounded-xl bg-white/[0.02] animate-pulse" />
                ))}
            </div>
        </div>
    );
}

function Pill({ status }: { status: string }) {
    const styles: Record<string, string> = {
        running: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/15 shadow-emerald-500/5',
        completed: 'bg-blue-500/10 text-blue-400 border-blue-500/15',
        failed: 'bg-red-500/10 text-red-400 border-red-500/15',
        cancelled: 'bg-gray-500/8 text-gray-400 border-gray-500/15',
        queued: 'bg-amber-500/10 text-amber-400 border-amber-500/15',
    };
    return (
        <span className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium border shadow-sm backdrop-blur-sm ${styles[status] || styles.queued}`}>
            {status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
            {status}
        </span>
    );
}

function MiniStat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
    return (
        <div className="text-right">
            <p className={`text-sm font-semibold tabular-nums ${accent ? 'text-red-400' : 'text-white'}`}>{value}</p>
            <p className="text-[10px] text-gray-600 uppercase tracking-wider">{label}</p>
        </div>
    );
}

function GlassCell({ label, value, color, dot }: { label: string; value: number; color?: string; dot?: string }) {
    return (
        <div className="group rounded-xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-md p-3 text-center hover:bg-white/[0.04] hover:border-white/[0.1] transition-all duration-300">
            <div className="flex items-center justify-center gap-1.5">
                {dot && <span className={`w-1.5 h-1.5 rounded-full ${dot} opacity-60`} />}
                <p className={`text-base font-semibold tabular-nums ${color || 'text-white'}`}>{value}</p>
            </div>
            <p className="text-[10px] text-gray-600 mt-1 uppercase tracking-wider">{label}</p>
        </div>
    );
}

function GlassSection({ icon, title, count, live, children }: {
    icon: React.ReactNode; title: string; count: number; live?: boolean; children: React.ReactNode;
}) {
    return (
        <section className="rounded-2xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-white/[0.04] flex items-center gap-2.5">
                <span className="text-gray-500">{icon}</span>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{title}</h3>
                {live && (
                    <span className="ml-1.5 flex items-center gap-1.5 text-[10px] text-emerald-500/60 font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-sm shadow-emerald-500/30" />
                        LIVE
                    </span>
                )}
                <span className="ml-auto text-xs text-gray-700 font-mono tabular-nums">{count}</span>
            </div>
            {children}
        </section>
    );
}

function SevDot({ severity }: { severity: string }) {
    const c: Record<string, string> = {
        critical: 'bg-red-500 shadow-red-500/40', high: 'bg-orange-500 shadow-orange-500/40',
        medium: 'bg-amber-500 shadow-amber-500/40', low: 'bg-blue-500 shadow-blue-500/40', info: 'bg-gray-600',
    };
    return <span className={`w-2 h-2 rounded-full flex-shrink-0 shadow-sm ${c[severity] || c.info}`} />;
}

function SevBadge({ severity }: { severity: string }) {
    const c: Record<string, string> = {
        critical: 'bg-red-500/8 text-red-400 border-red-500/15',
        high: 'bg-orange-500/8 text-orange-400 border-orange-500/15',
        medium: 'bg-amber-500/8 text-amber-400 border-amber-500/15',
        low: 'bg-blue-500/8 text-blue-400 border-blue-500/15',
        info: 'bg-gray-500/8 text-gray-400 border-gray-500/15',
    };
    return (
        <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium border flex-shrink-0 ${c[severity] || c.info}`}>
            {severity}
        </span>
    );
}
