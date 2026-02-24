// VibeCode — Vulnerabilities List Page (OWASP-Grouped Glassmorphism)
'use client';

import { useState, useMemo } from 'react';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import {
    Bug, Search, ChevronDown, ChevronRight,
    Globe, Shield, ExternalLink, Fingerprint,
} from 'lucide-react';
import { getCweEntry, OWASP_TOP_10_2021, CATEGORY_DISPLAY_NAMES } from '@/lib/cwe-database';

/* ── OWASP category colors ─────────────────────────────── */
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
const DEFAULT_COLOR = { dot: 'bg-gray-500', text: 'text-gray-400', border: 'border-gray-500/15', bg: 'bg-gray-500/5' };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/* ── Grouping types ────────────────────────────────────── */
interface GroupedItem {
    cweId: string;
    cweTitle: string;
    title: string;
    severity: string;
    cvssScore: number | null;
    category: string;
    parameter: string;
    status: string;
    urls: string[];
    count: number;
    firstVulnId: string;
    nist: string[];
    targetNames: string[];
}

interface OwaspGroup {
    owaspId: string;
    owaspName: string;
    items: GroupedItem[];
    highestSeverity: string;
    totalCount: number;
    uniqueCwes: number;
}

function groupByOwasp(vulns: any[]): OwaspGroup[] {
    // Step 1: Group by OWASP → CWE+param+category
    const owaspMap: Record<string, { owaspName: string; dedup: Record<string, GroupedItem> }> = {};

    for (const vuln of vulns) {
        const cweEntry = vuln.cweId ? getCweEntry(vuln.cweId) : null;
        const owaspId = cweEntry?.owasp?.[0] || 'Other';
        const owaspInfo = OWASP_TOP_10_2021.find(o => o.id === owaspId);

        if (!owaspMap[owaspId]) {
            owaspMap[owaspId] = {
                owaspName: owaspInfo?.name || 'Uncategorized',
                dedup: {},
            };
        }

        const cweKey = vuln.cweId || vuln.title;
        const param = vuln.parameter || '';
        const cat = vuln.category || '';
        const key = `${cweKey}::${param}::${cat}`;

        if (!owaspMap[owaspId].dedup[key]) {
            owaspMap[owaspId].dedup[key] = {
                cweId: vuln.cweId || '',
                cweTitle: cweEntry?.title || vuln.cweTitle || '',
                title: vuln.title,
                severity: vuln.severity,
                cvssScore: vuln.cvssScore,
                category: cat,
                parameter: param,
                status: vuln.status || 'open',
                urls: [],
                count: 0,
                firstVulnId: vuln.id,
                nist: cweEntry?.nist || [],
                targetNames: [],
            };
        }

        const item = owaspMap[owaspId].dedup[key];
        item.count++;
        if (vuln.affectedUrl && !item.urls.includes(vuln.affectedUrl)) {
            item.urls.push(vuln.affectedUrl);
        }
        const tName = vuln.target?.name || '';
        if (tName && !item.targetNames.includes(tName)) {
            item.targetNames.push(tName);
        }

        // Keep highest severity
        const ci = SEV_ORDER.indexOf(item.severity);
        const vi = SEV_ORDER.indexOf(vuln.severity);
        if (vi >= 0 && vi < ci) item.severity = vuln.severity;

        // Track most severe status
        if (vuln.status === 'open' || vuln.status === 'confirmed') item.status = vuln.status;
    }

    // Step 2: Build groups sorted by severity
    return Object.entries(owaspMap)
        .map(([owaspId, { owaspName, dedup }]) => {
            const items = Object.values(dedup).sort(
                (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
            );
            const uniqueCwes = new Set(items.map(i => i.cweId).filter(Boolean)).size;
            const totalCount = items.reduce((s, i) => s + i.count, 0);
            const highestSeverity = items[0]?.severity || 'info';

            return { owaspId, owaspName, items, highestSeverity, totalCount, uniqueCwes };
        })
        .sort((a, b) => {
            const s = SEV_ORDER.indexOf(a.highestSeverity) - SEV_ORDER.indexOf(b.highestSeverity);
            return s !== 0 ? s : a.owaspId.localeCompare(b.owaspId);
        });
}

export default function VulnerabilitiesPage() {
    const [search, setSearch] = useState('');
    const [severity, setSeverity] = useState('');
    const [category, setCategory] = useState('');
    const [status, setStatus] = useState('');

    // Fetch larger page to allow proper grouping
    const { data, isLoading } = trpc.vulnerability.list.useQuery({
        pageSize: 100,
        search: search || undefined,
        severity: severity || undefined,
        category: category || undefined,
        status: status || undefined,
    });
    const { data: stats } = trpc.vulnerability.stats.useQuery();

    const groups = useMemo(() => {
        if (!data?.items) return [];
        return groupByOwasp(data.items);
    }, [data?.items]);

    const totalGrouped = useMemo(
        () => groups.reduce((s, g) => s + g.items.length, 0), [groups]
    );

    return (
        <div className="space-y-6 animate-fade-in">
            {/* ── Header ──────────────────────────────── */}
            <div className="page-header">
                <h1 className="page-title flex items-center gap-3">
                    <div className="w-8 h-8 rounded-xl flex items-center justify-center bg-red-500/10 border border-red-500/20">
                        <Bug className="w-4 h-4 text-red-400" />
                    </div>
                    Vulnerabilities
                </h1>
                <p className="page-subtitle">
                    {data?.total || 0} vulnerabilities · {totalGrouped} unique findings across all targets
                </p>
            </div>

            {/* ── Severity Filter Chips ────────────────── */}
            {stats && (
                <div className="flex gap-2 flex-wrap">
                    {stats.bySeverity
                        .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
                        .map(s => (
                            <button
                                key={s.severity}
                                onClick={() => setSeverity(severity === s.severity ? '' : s.severity)}
                                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl border text-xs font-medium transition-all cursor-pointer backdrop-blur-sm ${severity === s.severity
                                    ? 'border-white/[0.15] bg-white/[0.06] text-white'
                                    : 'border-white/[0.06] bg-white/[0.02] text-gray-400 hover:bg-white/[0.04] hover:border-white/[0.1]'
                                    }`}
                            >
                                <span className={`w-2 h-2 rounded-full ${s.severity === 'critical' ? 'bg-red-500' :
                                    s.severity === 'high' ? 'bg-orange-500' :
                                        s.severity === 'medium' ? 'bg-amber-500' :
                                            s.severity === 'low' ? 'bg-blue-500' : 'bg-gray-500'
                                    }`} />
                                <span className="capitalize">{s.severity}</span>
                                <span className="text-gray-600 font-mono tabular-nums">{s.count}</span>
                            </button>
                        ))}
                </div>
            )}

            {/* ── Search & Filters ────────────────────── */}
            <div className="flex gap-3 flex-wrap">
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600" />
                    <input
                        type="text"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search by title, URL, parameter..."
                        className="input-field pl-10"
                    />
                </div>
                <select value={category} onChange={e => setCategory(e.target.value)} className="input-field w-auto">
                    <option value="">All Categories</option>
                    <option value="xss">XSS</option>
                    <option value="sqli">SQL Injection</option>
                    <option value="ssrf">SSRF</option>
                    <option value="headers">Headers</option>
                    <option value="cors">CORS</option>
                    <option value="path_traversal">Path Traversal</option>
                    <option value="open_redirect">Open Redirect</option>
                    <option value="info_disclosure">Info Disclosure</option>
                    <option value="csrf">CSRF</option>
                    <option value="auth">Authentication</option>
                    <option value="jwt">JWT</option>
                    <option value="cmd_injection">Command Injection</option>
                    <option value="rce">RCE</option>
                </select>
                <select value={status} onChange={e => setStatus(e.target.value)} className="input-field w-auto">
                    <option value="">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="fixed">Fixed</option>
                    <option value="false_positive">False Positive</option>
                    <option value="accepted">Accepted</option>
                </select>
            </div>

            {/* ── Grouped Vulnerability List ──────────── */}
            {isLoading ? (
                <div className="space-y-3">
                    {Array.from({ length: 3 }).map((_, i) => (
                        <div key={i} className="h-20 rounded-2xl bg-white/[0.02] animate-pulse" />
                    ))}
                </div>
            ) : groups.length > 0 ? (
                <div className="space-y-2.5">
                    {groups.map(group => (
                        <VulnOwaspGroup key={group.owaspId} group={group} />
                    ))}
                </div>
            ) : (
                <div className="empty-state">
                    <Bug className="empty-state-icon" />
                    <h3 className="text-lg font-semibold text-gray-400">No vulnerabilities found</h3>
                    <p className="text-sm text-gray-600 mt-1">Run a scan to discover vulnerabilities</p>
                </div>
            )}
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   OWASP Group Component
   ══════════════════════════════════════════════════════════ */

function VulnOwaspGroup({ group }: { group: OwaspGroup }) {
    const [expanded, setExpanded] = useState(true);
    const colors = OWASP_COLORS[group.owaspId] || DEFAULT_COLOR;

    return (
        <div className="vuln-group">
            {/* Header */}
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
                    <span className="text-[10px] text-gray-600 uppercase tracking-wider">
                        {group.uniqueCwes} CWE
                    </span>
                    <span className="text-xs font-mono text-gray-600 tabular-nums">
                        {group.totalCount}
                    </span>
                    <SevBadge severity={group.highestSeverity} />
                    {expanded
                        ? <ChevronDown className="w-3.5 h-3.5 text-gray-600" />
                        : <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
                    }
                </div>
            </button>

            {/* Body */}
            {expanded && (
                <div className="vuln-group-body">
                    {group.items.map((item, idx) => (
                        <div key={`${item.cweId}-${item.parameter}-${idx}`} className="border-b border-white/[0.02] last:border-0">
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

                                    {/* Meta: NIST + Target */}
                                    <div className="flex items-center gap-3 mt-1">
                                        {item.nist.length > 0 && (
                                            <div className="flex items-center gap-1">
                                                <span className="text-[10px] text-gray-700">NIST:</span>
                                                {item.nist.slice(0, 3).map(n => (
                                                    <span key={n} className="text-[10px] text-blue-400/50 font-mono">{n}</span>
                                                ))}
                                            </div>
                                        )}
                                        {item.targetNames.length > 0 && (
                                            <span className="text-[10px] text-gray-700 truncate max-w-[150px]">
                                                {item.targetNames[0]}
                                            </span>
                                        )}
                                    </div>
                                </div>

                                <div className="flex items-center gap-2.5 flex-shrink-0">
                                    {item.count > 1 && (
                                        <span className="text-[10px] font-mono text-gray-600 bg-white/[0.03] border border-white/[0.06] rounded-full px-2 py-0.5">
                                            ×{item.count}
                                        </span>
                                    )}
                                    <StatusBadge status={item.status} />
                                    <SevBadge severity={item.severity} />
                                    {item.cvssScore != null && (
                                        <span className="text-xs font-mono text-gray-600 tabular-nums">{item.cvssScore}</span>
                                    )}
                                </div>
                            </Link>

                            {/* Affected URLs */}
                            {item.urls.length > 0 && (
                                <div className="px-5 pb-2.5 -mt-1">
                                    <div className="flex flex-wrap gap-1.5 pl-5">
                                        {item.urls.slice(0, 4).map(url => (
                                            <span
                                                key={url}
                                                className="inline-flex items-center gap-1 text-[10px] font-mono text-gray-600 bg-white/[0.02] border border-white/[0.04] rounded-lg px-2 py-0.5 max-w-[260px] truncate"
                                            >
                                                <Globe className="w-2.5 h-2.5 flex-shrink-0 text-gray-700" />
                                                {url.replace(/^https?:\/\//, '').replace(/\/$/, '')}
                                            </span>
                                        ))}
                                        {item.urls.length > 4 && (
                                            <span className="text-[10px] text-gray-700 self-center">
                                                +{item.urls.length - 4} more
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
   Micro Components
   ══════════════════════════════════════════════════════════ */

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

function StatusBadge({ status }: { status: string }) {
    const c: Record<string, string> = {
        open: 'bg-yellow-600/10 text-yellow-400 border-yellow-600/15',
        confirmed: 'bg-red-600/10 text-red-400 border-red-600/15',
        fixed: 'bg-green-600/10 text-green-400 border-green-600/15',
        false_positive: 'bg-gray-600/10 text-gray-400 border-gray-600/15',
        accepted: 'bg-blue-600/10 text-blue-400 border-blue-600/15',
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border flex-shrink-0 ${c[status] || c.open}`}>
            {status.replace('_', ' ')}
        </span>
    );
}
