// InjectProof — Vulnerability Detail Page (Premium Design)
'use client';

import { use, useState, useMemo, useEffect, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import { trpc } from '@/trpc/client';
import type { SqliExploitResult } from '@/types';
import Link from 'next/link';
import {
    ArrowLeft, Bug, Shield, ExternalLink, Code, FileText,
    AlertTriangle, CheckCircle, Copy, Link2, Skull,
    Database, Lock, Globe, Fingerprint, ChevronDown,
    ChevronRight, Server, Table, Columns3, User, HardDrive,
    Terminal, Zap, Hash, Eye, Activity, Loader2,
} from 'lucide-react';
import { getCweEntry, OWASP_TOP_10_2021 } from '@/lib/cwe-database';
import { useExploitEvents } from './use-exploit-events';

export default function VulnDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { data: vuln, isLoading, refetch } = trpc.vulnerability.getById.useQuery(id);
    const updateStatus = trpc.vulnerability.updateStatus.useMutation({ onSuccess: () => refetch() });
    const runDeepExploit = trpc.vulnerability.runDeepExploit.useMutation({
        onSuccess: () => { refetch(); setActiveTab('sqli_exploit'); },
    });
    // Read ?tab= from the URL so deep-links like
    // /vulnerabilities/:id?tab=sqli_exploit open directly to the exploit tab.
    // Used by the inline Exploit button on the scan detail page.
    const searchParams = useSearchParams();
    const tabFromUrl = searchParams.get('tab');
    const VALID_TABS = ['overview', 'evidence', 'remediation', 'chain', 'sqli_exploit'] as const;
    const initialTab = (tabFromUrl && (VALID_TABS as readonly string[]).includes(tabFromUrl))
        ? (tabFromUrl as typeof VALID_TABS[number])
        : 'overview';
    const [activeTab, setActiveTab] = useState<typeof VALID_TABS[number]>(initialTab);

    // Live exploit stream — enabled while the mutation is in-flight. The SSE
    // endpoint tolerates late connection via its buffered replay, so the race
    // between mutation kickoff and stream subscribe is safe either way.
    const liveExploit = useExploitEvents(id, runDeepExploit.isPending);

    // NOTE: All hooks MUST be called before any early return (Rules of Hooks)
    const sqliExploit = useMemo<SqliExploitResult | null>(() => {
        try { return vuln?.sqliExploitData ? JSON.parse(vuln.sqliExploitData) : null; } catch { return null; }
    }, [vuln?.sqliExploitData]);

    if (isLoading) return <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" /></div>;
    if (!vuln) return <div className="text-gray-500 text-center py-12">Vulnerability not found</div>;

    const cweEntry = vuln.cweId ? getCweEntry(vuln.cweId) : null;
    const mappedOwasp: string[] = cweEntry?.owasp || (vuln.mappedOwasp ? JSON.parse(vuln.mappedOwasp) : []);
    const mappedNist: string[] = cweEntry?.nist || (vuln.mappedNist ? JSON.parse(vuln.mappedNist) : []);
    const mappedAsvs: string[] = cweEntry?.asvs || [];
    const reproSteps = vuln.reproductionSteps ? JSON.parse(vuln.reproductionSteps) : [];
    const references = vuln.references ? JSON.parse(vuln.references) : [];
    const chainGraph = vuln.attackChainGraph ? JSON.parse(vuln.attackChainGraph) : null;

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header */}
            <div className="flex items-start gap-3">
                <Link href="/vulnerabilities" className="p-2 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all mt-1"><ArrowLeft className="w-5 h-5" /></Link>
                <div className="flex-1">
                    <div className="flex items-center gap-3 mb-1 flex-wrap">
                        <span className={vuln.severity === 'critical' ? 'badge-critical' : vuln.severity === 'high' ? 'badge-high' : vuln.severity === 'medium' ? 'badge-medium' : vuln.severity === 'low' ? 'badge-low' : 'badge-info'}>{vuln.severity}</span>
                        {vuln.cvssScore && <span className="text-xs font-mono text-gray-400">CVSS {vuln.cvssScore}</span>}
                        {vuln.raceConditionConfirmed && <span className="badge-critical">⚡ Race Condition</span>}
                        {vuln.cloudMetadataExtracted && <span className="badge-critical">☁️ Cloud Metadata</span>}
                    </div>
                    <h1 className="text-xl font-bold text-[var(--text-primary)]">{vuln.title}</h1>
                    <p className="text-sm text-gray-400 font-mono mt-1">{vuln.affectedUrl}</p>
                </div>
            </div>

            {/* Status Actions */}
            <div className="flex gap-2 flex-wrap">
                {['open', 'confirmed', 'fixed', 'false_positive', 'accepted'].map(s => (
                    <button key={s} onClick={() => updateStatus.mutate({ id: vuln.id, status: s as any })}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${vuln.status === s ? 'border-brand-500 bg-brand-600/10 text-[var(--accent)]' : 'border-[var(--border-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--bg-hover)]'}`}>
                        {s.replace('_', ' ')}
                    </button>
                ))}
            </div>

            {/* Run Deep Exploit — always available on SQLi findings so the
                operator can re-run with manual breakout/dbms overrides when
                the auto-discovery picked the wrong pattern. */}
            {vuln.category === 'sqli' && vuln.parameter && (
                <DeepExploitLauncher
                    hasResult={!!sqliExploit}
                    isPartial={!!sqliExploit && (sqliExploit.databases.length === 0 || !sqliExploit.currentDatabase)}
                    isPending={runDeepExploit.isPending}
                    error={runDeepExploit.error?.message}
                    onRun={(opts) => runDeepExploit.mutate({ id: vuln.id, ...opts })}
                />
            )}

            {/* Tabs */}
            <div className="tab-list">
                {(['overview', 'evidence', ...(sqliExploit ? ['sqli_exploit'] : []), 'remediation', 'chain'] as const).map(tab => (
                    <button key={tab} onClick={() => setActiveTab(tab as any)} className={`tab-item ${activeTab === tab ? 'active' : ''}`}>
                        {tab === 'overview' ? 'Overview' : tab === 'evidence' ? 'Evidence' : tab === 'remediation' ? 'Remediation' : tab === 'sqli_exploit' ? '🔓 SQLi Exploit' : 'Attack Chain'}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            {activeTab === 'overview' && (
                <div className="space-y-4">
                    <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">Description</h3><p className="text-sm text-gray-400 leading-relaxed">{vuln.description}</p></div>
                    {vuln.technicalDetail && <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">Technical Details</h3><p className="text-sm text-gray-400 leading-relaxed">{vuln.technicalDetail}</p></div>}
                    {vuln.impact && <div className="glass-card border-red-600/15"><h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> Impact</h3><p className="text-sm text-gray-400">{vuln.impact}</p></div>}

                    {/* Quick Info Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Category</p><p className="text-sm text-[var(--text-primary)] capitalize">{vuln.category}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">HTTP Method</p><p className="text-sm text-[var(--text-primary)]">{vuln.httpMethod}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Parameter</p><p className="text-sm text-[var(--text-primary)] font-mono">{vuln.parameter || '—'}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Confidence</p><p className="text-sm text-[var(--text-primary)] capitalize">{vuln.confidence}</p></div>
                    </div>

                    {/* ── Security Framework Mapping (Premium Cards) ── */}
                    <div className="space-y-3">
                        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2 px-1">
                            <Shield className="w-3.5 h-3.5" />
                            Security Framework Mapping
                        </h3>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            {/* CWE Card */}
                            {vuln.cweId && (
                                <div className="framework-card accent-purple">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Fingerprint className="w-4 h-4 text-violet-400" />
                                        <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">CWE</span>
                                    </div>
                                    <p className="text-sm font-mono font-semibold text-violet-300">{vuln.cweId}</p>
                                    <p className="text-xs text-gray-500 mt-1.5 leading-relaxed line-clamp-2">
                                        {cweEntry?.title || vuln.cweTitle || 'Unknown weakness'}
                                    </p>
                                    {cweEntry && (
                                        <a
                                            href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html`}
                                            target="_blank"
                                            rel="noopener"
                                            className="inline-flex items-center gap-1 text-[10px] text-violet-400/60 hover:text-violet-400 mt-2 transition-colors"
                                        >
                                            <ExternalLink className="w-2.5 h-2.5" />
                                            MITRE Reference
                                        </a>
                                    )}
                                </div>
                            )}

                            {/* OWASP Card */}
                            {mappedOwasp.length > 0 && (
                                <div className="framework-card accent-amber">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Globe className="w-4 h-4 text-amber-400" />
                                        <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">OWASP Top 10</span>
                                    </div>
                                    <div className="space-y-2">
                                        {mappedOwasp.map(owaspId => {
                                            const info = OWASP_TOP_10_2021.find(o => o.id === owaspId);
                                            return (
                                                <div key={owaspId}>
                                                    <span className="text-sm font-mono font-semibold text-amber-300">{owaspId.replace(':2021', '')}</span>
                                                    {info && (
                                                        <p className="text-xs text-gray-500 mt-0.5">{info.name}</p>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                    {mappedAsvs.length > 0 && (
                                        <div className="mt-3 pt-2.5 border-t border-white/[0.04]">
                                            <p className="text-[10px] text-gray-600 uppercase tracking-wider mb-1">ASVS</p>
                                            <div className="flex flex-wrap gap-1">
                                                {mappedAsvs.map(a => (
                                                    <span key={a} className="text-[10px] font-mono text-amber-400/50 bg-amber-500/5 border border-amber-500/10 rounded px-1.5 py-0.5">{a}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* NIST Card */}
                            {mappedNist.length > 0 && (
                                <div className="framework-card accent-blue">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Lock className="w-4 h-4 text-blue-400" />
                                        <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">NIST 800-53</span>
                                    </div>
                                    <div className="flex flex-wrap gap-1.5">
                                        {mappedNist.map(n => (
                                            <span key={n} className="text-xs font-mono font-semibold text-blue-300 bg-blue-500/8 border border-blue-500/15 rounded-lg px-2.5 py-1">
                                                {n}
                                            </span>
                                        ))}
                                    </div>
                                    <a
                                        href="https://csf.tools/reference/nist-sp-800-53/r5/"
                                        target="_blank"
                                        rel="noopener"
                                        className="inline-flex items-center gap-1 text-[10px] text-blue-400/60 hover:text-blue-400 mt-3 transition-colors"
                                    >
                                        <ExternalLink className="w-2.5 h-2.5" />
                                        NIST Reference
                                    </a>
                                </div>
                            )}
                        </div>

                        {/* CVSS Vector (if available) */}
                        {vuln.cvssVector && (
                            <div className="framework-card accent-red">
                                <div className="flex items-center gap-2 mb-2">
                                    <Database className="w-4 h-4 text-red-400" />
                                    <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">CVSS v3.1 Vector</span>
                                    {vuln.cvssScore && (
                                        <span className={`ml-auto text-sm font-bold tabular-nums ${vuln.cvssScore >= 9 ? 'text-red-400' :
                                            vuln.cvssScore >= 7 ? 'text-orange-400' :
                                                vuln.cvssScore >= 4 ? 'text-amber-400' :
                                                    'text-blue-400'
                                            }`}>
                                            {vuln.cvssScore}
                                        </span>
                                    )}
                                </div>
                                <code className="text-xs text-gray-500 font-mono break-all leading-relaxed">{vuln.cvssVector}</code>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {activeTab === 'evidence' && (
                <div className="space-y-4">
                    {vuln.payload && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2 flex items-center gap-2"><Code className="w-4 h-4 text-brand-400" /> Payload</h3><div className="code-block">{vuln.payload}</div></div>
                    )}
                    {vuln.requestArtifact && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">HTTP Request</h3><div className="code-block text-xs max-h-64 overflow-y-auto whitespace-pre-wrap">{vuln.requestArtifact}</div></div>
                    )}
                    {vuln.responseArtifact && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">HTTP Response</h3><div className="code-block text-xs max-h-64 overflow-y-auto whitespace-pre-wrap">{vuln.responseArtifact.substring(0, 5000)}{vuln.responseArtifact.length > 5000 ? '\n... (truncated)' : ''}</div></div>
                    )}
                    {reproSteps.length > 0 && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Reproduction Steps</h3>
                            <ol className="space-y-2">{reproSteps.map((step: string, i: number) => (
                                <li key={i} className="flex gap-3 text-sm text-gray-400"><span className="w-6 h-6 rounded-full bg-[var(--bg-hover)] flex items-center justify-center text-xs text-gray-500 flex-shrink-0">{i + 1}</span><span>{step}</span></li>
                            ))}</ol>
                        </div>
                    )}
                </div>
            )}

            {activeTab === 'remediation' && (
                <div className="space-y-4">
                    {(vuln.remediation || cweEntry?.remediation) && (
                        <div className="glass-card border-green-600/15">
                            <h3 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2"><CheckCircle className="w-4 h-4" /> Remediation</h3>
                            <p className="text-sm text-gray-400 leading-relaxed whitespace-pre-wrap">{vuln.remediation || cweEntry?.remediation}</p>
                        </div>
                    )}
                    {references.length > 0 && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2"><Link2 className="w-4 h-4 text-brand-400" /> References</h3>
                            <ul className="space-y-1">{references.map((ref: string, i: number) => (
                                <li key={i}><a href={ref} target="_blank" rel="noopener" className="text-sm text-brand-400 hover:underline flex items-center gap-1"><ExternalLink className="w-3 h-3" />{ref}</a></li>
                            ))}</ul>
                        </div>
                    )}
                </div>
            )}

            {activeTab === 'chain' && (
                <div className="space-y-4">
                    {chainGraph ? (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2"><Skull className="w-4 h-4 text-red-400" /> Attack Chain Graph</h3>
                            <div className="code-block text-xs">{JSON.stringify(chainGraph, null, 2)}</div>
                        </div>
                    ) : (
                        <div className="glass-card text-center py-8"><p className="text-sm text-gray-600">No attack chain data for this vulnerability</p></div>
                    )}
                    {vuln.cachePoisoningImpact && <div className="glass-card"><h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">Cache Poisoning Impact</h3><p className="text-sm text-gray-400">{vuln.cachePoisoningImpact}</p></div>}
                </div>
            )}
            {activeTab === 'sqli_exploit' && (
                <>
                    {(runDeepExploit.isPending || liveExploit.logs.length > 0 || liveExploit.phaseHistory.length > 0) && (
                        <LiveExploitPanel state={liveExploit} />
                    )}
                    {sqliExploit && !runDeepExploit.isPending && <SqliExploitPanel data={sqliExploit} />}
                </>
            )}
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   SQLi EXPLOITATION PANEL — InjectProof DB Tree View
   ══════════════════════════════════════════════════════════ */

function SqliExploitPanel({ data }: { data: SqliExploitResult }) {
    const [expandedDbs, setExpandedDbs] = useState<Set<string>>(new Set([data.currentDatabase, data.databases[0]?.name].filter(Boolean)));
    const [expandedTables, setExpandedTables] = useState<Set<string>>(new Set());
    const [showLog, setShowLog] = useState(false);
    const [showDataFor, setShowDataFor] = useState<string | null>(null);

    const toggleDb = (name: string) => {
        setExpandedDbs(prev => { const n = new Set(prev); n.has(name) ? n.delete(name) : n.add(name); return n; });
    };
    const toggleTable = (key: string) => {
        setExpandedTables(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
    };

    const totalTables = data.databases.reduce((s, d) => s + d.tables.length, 0);
    const totalCols = data.databases.reduce((s, d) => s + d.tables.reduce((s2, t) => s2 + t.columns.length, 0), 0);
    const totalRows = data.databases.reduce((s, d) => s + d.tables.reduce((s2, t) => s2 + t.sampleRows.length, 0), 0);
    const successSteps = data.exploitLog.filter(s => s.success).length;
    // Three tiers of extraction outcome, each with distinct UI treatment:
    //   full       = currentDatabase + at least one enumerated table → red banner, full tree
    //   partial    = SOME data extracted (DB name OR stub DB from confirmed injection) → amber banner, partial tree + guidance
    //   diagnostic = nothing extracted at all → amber banner, no tree, manual override guidance
    const isFullSuccess = !!data.currentDatabase && data.databases.some(d => d.tables.length > 0);
    const isPartial = !isFullSuccess && (!!data.currentDatabase || data.databases.length > 0);
    const isDiagnosticOnly = !isFullSuccess && !isPartial;
    const successfulTechniques = data.testedTechniques.filter(t => t.success).map(t => t.technique);
    const failedTechniques = data.testedTechniques.filter(t => !t.success).map(t => t.technique);

    return (
        <div className="space-y-4 animate-fade-in">
            {/* ── Server Info Banner ── */}
            <div className={`relative overflow-hidden rounded-2xl border ${isDiagnosticOnly ? 'border-amber-500/20 from-amber-950/20' : isPartial ? 'border-amber-500/25 from-amber-950/20' : 'border-red-500/20 from-red-950/30'} bg-gradient-to-br via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-5`}>
                <div className={`absolute -top-20 -right-20 w-40 h-40 ${isDiagnosticOnly || isPartial ? 'bg-amber-500/5' : 'bg-red-500/5'} rounded-full blur-3xl`} />
                <div className="absolute -bottom-10 -left-10 w-32 h-32 bg-violet-500/5 rounded-full blur-3xl" />
                <div className="relative">
                    <div className="flex items-center gap-2 mb-4">
                        <div className={`w-8 h-8 rounded-lg ${isDiagnosticOnly || isPartial ? 'bg-amber-500/10 border-amber-500/20' : 'bg-red-500/10 border-red-500/20'} border flex items-center justify-center`}>
                            <Skull className={`w-4 h-4 ${isDiagnosticOnly || isPartial ? 'text-amber-400' : 'text-red-400'}`} />
                        </div>
                        <div>
                            <h3 className={`text-sm font-semibold ${isDiagnosticOnly || isPartial ? 'text-amber-300' : 'text-red-300'}`}>
                                {isFullSuccess ? 'Deep SQLi Exploitation Successful'
                                 : isPartial ? 'Injection Confirmed — Enumeration Partially Blocked'
                                 : 'Deep Exploitation — Diagnostic Mode'}
                            </h3>
                            <p className="text-[10px] text-gray-500 uppercase tracking-wider">
                                {isFullSuccess ? 'InjectProof Multi-Technique Extraction'
                                 : isPartial ? 'Technique worked but schema access blocked — try manual overrides below'
                                 : 'No technique extracted — review log + try manual breakoutPrefix'}
                            </p>
                        </div>
                        <span className={`ml-auto px-2.5 py-1 rounded-full ${isDiagnosticOnly || isPartial ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' : 'bg-red-500/10 border-red-500/20 text-red-400'} border text-[10px] font-bold uppercase tracking-wider`}>
                            {data.technique}
                        </span>
                    </div>

                    {(isDiagnosticOnly || isPartial) && data.testedTechniques.length > 0 && (
                        <div className="mb-4 rounded-xl border border-amber-500/15 bg-amber-500/5 p-3 space-y-2.5">
                            {successfulTechniques.length > 0 && (
                                <div>
                                    <p className="text-[10px] uppercase tracking-wider text-emerald-400 font-semibold mb-1.5">✓ Confirmed working</p>
                                    <div className="flex flex-wrap gap-1.5">
                                        {successfulTechniques.map((t, i) => (
                                            <span key={i} className="px-2 py-1 rounded text-[10px] font-mono border bg-emerald-500/10 text-emerald-300 border-emerald-500/20">
                                                ✓ {t}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            {failedTechniques.length > 0 && (
                                <div>
                                    <p className="text-[10px] uppercase tracking-wider text-amber-400 font-semibold mb-1.5">
                                        ✗ Did not succeed {successfulTechniques.length > 0 && '(tried as alternates)'}
                                    </p>
                                    <div className="flex flex-wrap gap-1.5">
                                        {failedTechniques.map((t, i) => (
                                            <span key={i} className="px-2 py-1 rounded text-[10px] font-mono border bg-red-500/10 text-red-300 border-red-500/20">
                                                ✗ {t}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            <div className="pt-2 border-t border-amber-500/10">
                                <p className="text-xs text-amber-300/80 leading-relaxed">
                                    {isPartial
                                        ? <><strong className="text-amber-200">Injection is real.</strong> We extracted {data.currentDatabase ? `the current database name (${data.currentDatabase})` : 'partial metadata'} but couldn&apos;t enumerate the full schema — usually because the DB user lacks <code className="text-amber-100">information_schema</code> access or the WAF blocks the <code className="text-amber-100">FROM information_schema.*</code> signature. Try the Deep Exploit launcher above with a different <code className="text-amber-100">breakoutPrefix</code> or <code className="text-amber-100">dbmsHint</code>.</>
                                        : <><strong className="text-amber-200">No extraction succeeded.</strong> The parameter may be behind a WAF, or the breakout auto-discovery picked the wrong pattern. Open the Deep Exploit launcher above and provide a manual <code className="text-amber-100">breakoutPrefix</code> (try <code className="text-amber-100">&apos;</code>, <code className="text-amber-100">&quot;</code>, <code className="text-amber-100">)</code>, <code className="text-amber-100">&apos;)</code>, or <code className="text-amber-100">&quot;)</code>), and if you know the backend DB, set <code className="text-amber-100">dbmsHint</code>.</>}
                                </p>
                            </div>
                        </div>
                    )}
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                        <InfoChip icon={<Server className="w-3.5 h-3.5" />} label="DBMS" value={data.dbms || data.dbmsFamily} color="red" />
                        <InfoChip icon={<Database className="w-3.5 h-3.5" />} label="Current DB" value={data.currentDatabase} color="violet" />
                        <InfoChip icon={<User className="w-3.5 h-3.5" />} label="User" value={data.currentUser} color="cyan" />
                        <InfoChip icon={<Globe className="w-3.5 h-3.5" />} label="Host" value={data.hostname} color="amber" />
                        <InfoChip icon={<Hash className="w-3.5 h-3.5" />} label="Columns" value={`${data.columnCount} (inj: #${data.injectableColumn})`} color="green" />
                        <InfoChip icon={<HardDrive className="w-3.5 h-3.5" />} label="Data Dir" value={data.dataDir} color="blue" />
                    </div>
                </div>
            </div>

            {/* ── Stats Row ── */}
            <div className="grid grid-cols-4 gap-3">
                <StatCard label="Databases" value={data.databases.length} icon={<Database className="w-4 h-4" />} color="violet" />
                <StatCard label="Tables" value={totalTables} icon={<Table className="w-4 h-4" />} color="cyan" />
                <StatCard label="Columns" value={totalCols} icon={<Columns3 className="w-4 h-4" />} color="green" />
                <StatCard label="Rows Extracted" value={totalRows} icon={<Eye className="w-4 h-4" />} color="amber" />
            </div>

            {/* ── Database Tree View ── */}
            <div className="relative overflow-hidden rounded-2xl border border-violet-500/15 bg-gradient-to-br from-violet-950/20 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl">
                <div className="absolute -top-16 -right-16 w-32 h-32 bg-violet-500/5 rounded-full blur-3xl" />
                <div className="px-5 py-3.5 border-b border-white/[0.04] flex items-center gap-2">
                    <Database className="w-4 h-4 text-violet-400" />
                    <h3 className="text-sm font-semibold text-[var(--text-primary)]">Database Structure</h3>
                    <span className="text-[10px] text-gray-600 ml-auto font-mono">{data.databases.length} db · {totalTables} tables · {totalCols} columns</span>
                </div>
                <div className="p-4 space-y-1 relative">
                    {data.databases.map(db => {
                        const isExpanded = expandedDbs.has(db.name);
                        const isCurrent = db.name === data.currentDatabase;
                        return (
                            <div key={db.name}>
                                {/* Database Node */}
                                <button
                                    onClick={() => toggleDb(db.name)}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-xl text-left transition-all group hover:bg-violet-500/5 ${isExpanded ? 'bg-violet-500/5' : ''
                                        }`}
                                >
                                    {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-violet-400" /> : <ChevronRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-violet-400" />}
                                    <Database className="w-4 h-4 text-violet-400" />
                                    <span className="text-sm font-mono font-semibold text-violet-300">{db.name}</span>
                                    {isCurrent && <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-violet-500/15 text-violet-400 border border-violet-500/20">CURRENT</span>}
                                    <span className="ml-auto text-[10px] text-gray-600 font-mono">{db.tables.length} tables</span>
                                </button>

                                {/* Tables */}
                                {isExpanded && (
                                    <div className="ml-5 pl-4 border-l border-violet-500/10 space-y-0.5 mt-0.5 animate-fade-in">
                                        {db.tables.map(tbl => {
                                            const tblKey = `${db.name}.${tbl.name}`;
                                            const isTblExpanded = expandedTables.has(tblKey);
                                            const isInteresting = /user|admin|password|pass|login|secret|token|cred|auth/i.test(tbl.name);
                                            return (
                                                <div key={tblKey}>
                                                    <button
                                                        onClick={() => toggleTable(tblKey)}
                                                        className={`w-full flex items-center gap-2 px-3 py-1.5 rounded-lg text-left transition-all group hover:bg-cyan-500/5 ${isTblExpanded ? 'bg-cyan-500/5' : ''
                                                            }`}
                                                    >
                                                        {isTblExpanded ? <ChevronDown className="w-3 h-3 text-cyan-400" /> : <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-cyan-400" />}
                                                        <Table className="w-3.5 h-3.5 text-cyan-400" />
                                                        <span className={`text-sm font-mono ${isInteresting ? 'text-red-300 font-semibold' : 'text-cyan-300'}`}>{tbl.name}</span>
                                                        {isInteresting && <span className="px-1 py-0.5 rounded text-[8px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">⚠ SENSITIVE</span>}
                                                        <span className="ml-auto text-[10px] text-gray-600 font-mono">{tbl.columns.length} cols{tbl.rowCount ? ` · ${tbl.rowCount} rows` : ''}</span>
                                                    </button>

                                                    {/* Columns */}
                                                    {isTblExpanded && (
                                                        <div className="ml-5 pl-4 border-l border-cyan-500/10 mt-0.5 animate-fade-in">
                                                            <div className="space-y-0.5">
                                                                {tbl.columns.map(col => {
                                                                    const isSensCol = /password|pass|pwd|secret|token|hash|salt|key|credit|ssn|phone/i.test(col.name);
                                                                    return (
                                                                        <div key={col.name} className="flex items-center gap-2 px-3 py-1 rounded-lg hover:bg-green-500/5 transition-all">
                                                                            <Columns3 className="w-3 h-3 text-green-400/60" />
                                                                            <span className={`text-xs font-mono ${isSensCol ? 'text-red-300 font-semibold' : 'text-green-300'}`}>{col.name}</span>
                                                                            <span className="text-[10px] text-gray-600 font-mono ml-1">{col.type}</span>
                                                                            {isSensCol && <span className="text-[8px] text-red-400">🔑</span>}
                                                                        </div>
                                                                    );
                                                                })}
                                                            </div>

                                                            {/* Sample Data Rows */}
                                                            {tbl.sampleRows.length > 0 && (
                                                                <div className="mt-2 mb-1">
                                                                    <button
                                                                        onClick={() => setShowDataFor(showDataFor === tblKey ? null : tblKey)}
                                                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-semibold text-amber-400 bg-amber-500/5 border border-amber-500/10 hover:bg-amber-500/10 transition-all uppercase tracking-wider"
                                                                    >
                                                                        <Eye className="w-3 h-3" />
                                                                        {showDataFor === tblKey ? 'Hide' : 'Show'} Extracted Data ({tbl.sampleRows.length} rows)
                                                                    </button>
                                                                    {showDataFor === tblKey && (
                                                                        <div className="mt-2 rounded-xl overflow-hidden border border-amber-500/10 animate-fade-in">
                                                                            <div className="overflow-x-auto">
                                                                                <table className="w-full text-xs font-mono">
                                                                                    <thead>
                                                                                        <tr className="bg-amber-500/5 border-b border-amber-500/10">
                                                                                            {Object.keys(tbl.sampleRows[0]).map(h => (
                                                                                                <th key={h} className="px-3 py-2 text-left text-amber-400/70 font-semibold uppercase tracking-wider text-[10px]">{h}</th>
                                                                                            ))}
                                                                                        </tr>
                                                                                    </thead>
                                                                                    <tbody>
                                                                                        {tbl.sampleRows.map((row, ri) => (
                                                                                            <tr key={ri} className={`border-b border-white/[0.02] ${ri % 2 === 0 ? 'bg-[var(--bg-subtle)]' : 'bg-[var(--bg-hover)]/30'} hover:bg-amber-500/5 transition-colors`}>
                                                                                                {Object.values(row).map((v, ci) => (
                                                                                                    <td key={ci} className="px-3 py-1.5 text-[var(--text-primary)] max-w-[200px] truncate">{String(v)}</td>
                                                                                                ))}
                                                                                            </tr>
                                                                                        ))}
                                                                                    </tbody>
                                                                                </table>
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* ── Evidence Summary (citation-ready packet) ── */}
            {data.evidenceSummary && (
                <div className="rounded-2xl border border-blue-500/15 bg-gradient-to-br from-blue-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-5 space-y-3">
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                            <Hash className="w-4 h-4 text-blue-400" />
                        </div>
                        <div>
                            <h3 className="text-sm font-semibold text-blue-300">Evidence Summary</h3>
                            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Citation-ready packet · hand to dev team</p>
                        </div>
                        <span className="ml-auto px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[10px] font-bold uppercase tracking-wider">
                            Confidence {Math.round(data.evidenceSummary.confidence * 100)}%
                        </span>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div><div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Injection point</div><div className="font-mono text-blue-200">{data.evidenceSummary.injectionPoint}</div></div>
                        <div><div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Parameter</div><div className="font-mono text-blue-200">{data.evidenceSummary.parameterName}</div></div>
                        <div><div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Breakout</div><div className="font-mono text-blue-200">{data.evidenceSummary.breakoutPattern || '<empty>'}</div></div>
                        <div><div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Requests · Extracted · Duration</div><div className="font-mono text-blue-200">{data.evidenceSummary.totalRequests} · {data.evidenceSummary.successfulExtractions} · {Math.round(data.evidenceSummary.durationMs / 100) / 10}s</div></div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Target URL</div>
                        <div className="font-mono text-xs text-blue-100 break-all px-3 py-2 rounded-lg bg-[var(--bg-subtle)] border border-white/[0.04]">{data.evidenceSummary.targetUrl}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Proving payload (drop into any HTTP client)</div>
                        <div className="font-mono text-xs text-amber-200 break-all px-3 py-2 rounded-lg bg-amber-500/5 border border-amber-500/15">{data.evidenceSummary.primaryPoc || '<no payload captured>'}</div>
                    </div>
                </div>
            )}

            {/* ── Remediation Guidance ── */}
            {data.remediation && (
                <div className="rounded-2xl border border-emerald-500/15 bg-gradient-to-br from-emerald-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-5 space-y-4">
                    <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                            <Zap className="w-4 h-4 text-emerald-400" />
                        </div>
                        <div>
                            <h3 className="text-sm font-semibold text-emerald-300">Remediation Guidance</h3>
                            <p className="text-[10px] text-gray-500 uppercase tracking-wider">สำหรับนำไปให้พนักงานแก้ / Hand to the developer who owns this code</p>
                        </div>
                        <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/10 border border-red-500/20 text-red-400 font-mono">
                            {data.remediation.cwe.split('—')[0].trim()}
                        </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-[var(--bg-subtle)] border border-white/[0.04]">
                            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">What&apos;s wrong (EN)</div>
                            <p className="text-xs text-gray-300 leading-relaxed">{data.remediation.summary}</p>
                        </div>
                        <div className="p-3 rounded-lg bg-[var(--bg-subtle)] border border-white/[0.04]">
                            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">สรุปช่องโหว่ (TH)</div>
                            <p className="text-xs text-gray-300 leading-relaxed">{data.remediation.summaryTh}</p>
                        </div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Fix — parameterized query example</div>
                        <pre className="font-mono text-xs text-emerald-100 px-3 py-3 rounded-lg bg-emerald-500/5 border border-emerald-500/15 overflow-x-auto whitespace-pre-wrap">{data.remediation.fixExample}</pre>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">คำแนะนำเพิ่มเติม</div>
                        <p className="font-mono text-xs text-emerald-100/80 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/15 whitespace-pre-wrap">{data.remediation.fixExampleTh}</p>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Systemic controls (beyond this single fix)</div>
                        <ul className="space-y-1.5">
                            {data.remediation.systemicControls.map((c, i) => (
                                <li key={i} className="text-xs text-gray-300 leading-relaxed pl-4 relative">
                                    <span className="absolute left-0 top-1.5 w-1.5 h-1.5 rounded-full bg-emerald-400/60" />
                                    {c}
                                </li>
                            ))}
                        </ul>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider">References:</span>
                        {data.remediation.references.map((r, i) => (
                            <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                               className="text-[10px] font-mono text-blue-400 hover:text-blue-300 underline underline-offset-2 truncate max-w-[320px]">
                                {r.replace(/^https?:\/\//, '')}
                            </a>
                        ))}
                    </div>
                    <div className="flex items-center gap-2 pt-2 border-t border-white/[0.04]">
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider">OWASP:</span>
                        <span className="text-[10px] text-gray-400 font-mono">{data.remediation.owasp}</span>
                    </div>
                </div>
            )}

            {/* ── Exploit Step Log (Terminal Style) ── */}
            <div className="rounded-2xl border border-green-500/15 bg-gradient-to-br from-green-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl overflow-hidden">
                <button
                    onClick={() => setShowLog(!showLog)}
                    className="w-full px-5 py-3.5 flex items-center gap-2 hover:bg-green-500/5 transition-all"
                >
                    <Terminal className="w-4 h-4 text-green-400" />
                    <h3 className="text-sm font-semibold text-[var(--text-primary)]">Exploitation Log</h3>
                    <span className="text-[10px] text-gray-600 font-mono">{successSteps}/{data.exploitLog.length} steps successful</span>
                    <div className="ml-auto flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-[var(--bg-hover)] overflow-hidden">
                            <div className="h-full rounded-full bg-gradient-to-r from-green-500 to-emerald-400" style={{ width: `${(successSteps / Math.max(data.exploitLog.length, 1)) * 100}%` }} />
                        </div>
                        {showLog ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                    </div>
                </button>
                {showLog && (
                    <div className="border-t border-white/[0.04] max-h-96 overflow-y-auto animate-fade-in">
                        <div className="p-3 space-y-0.5 font-mono text-xs">
                            {data.exploitLog.map((step, i) => (
                                <div key={i} className={`flex items-start gap-2 px-3 py-1.5 rounded-lg transition-all ${step.success ? 'hover:bg-green-500/5' : 'hover:bg-red-500/5 opacity-60'
                                    }`}>
                                    <span className="flex-shrink-0 w-4 text-center">
                                        {step.success ? <Zap className="w-3 h-3 text-green-400 inline" /> : <span className="text-red-400">✗</span>}
                                    </span>
                                    <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${step.phase === 'fingerprint' ? 'bg-violet-500/10 text-violet-400 border border-violet-500/20' :
                                        step.phase === 'column-count' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                                            step.phase === 'find-injectable' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                                                step.phase === 'server-info' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                                    step.phase.includes('enum') ? 'bg-green-500/10 text-green-400 border border-green-500/20' :
                                                        step.phase === 'sample-rows' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                                            'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                                        }`}>{step.phase}</span>
                                    <span className="text-gray-500 truncate flex-1" title={step.payload}>{step.payload.length > 80 ? step.payload.slice(0, 80) + '…' : step.payload}</span>
                                    {step.extracted && (
                                        <span className="flex-shrink-0 text-green-300 max-w-[200px] truncate" title={step.extracted}>→ {step.extracted}</span>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   LIVE EXPLOIT PANEL — realtime streaming view
   ══════════════════════════════════════════════════════════
   Opens while deepExploitSqli is running. Three-pane layout:
   1) Phase stepper (vertical) with pulse indicator on active phase
   2) Current activity card (big, animated)
   3) Scrolling log terminal (auto-scrolls, newest at bottom)
   User explicitly said: "ไม่สนเรื่อง requests user รอได้ ขอแค่มี animate
   บอก user ทั้งหมด … ไม่มีคำว่ารอไม่ไหว" — so we visualise every
   heartbeat, not just phase transitions. */

const PHASE_ORDER = [
    'init', 'breakout-discovery', 'fingerprint', 'column-count',
    'union-sweep', 'server-info', 'enum-databases', 'enum-tables',
    'enum-cols', 'enum-users', 'done',
] as const;

const PHASE_LABELS: Record<string, { label: string; labelTh: string }> = {
    'init':                { label: 'Initialising',          labelTh: 'เริ่มต้น' },
    'breakout-discovery':  { label: 'Discovering breakout',  labelTh: 'ค้นหา breakout' },
    'fingerprint':         { label: 'Fingerprinting DBMS',   labelTh: 'ระบุชนิด database' },
    'column-count':        { label: 'Counting columns',      labelTh: 'นับจำนวน column' },
    'union-sweep':         { label: 'Sweeping UNION',        labelTh: 'ทดสอบ UNION injection' },
    'server-info':         { label: 'Server information',    labelTh: 'อ่านข้อมูล server' },
    'enum-databases':      { label: 'Enumerating databases', labelTh: 'รายการ database' },
    'enum-tables':         { label: 'Walking tables',        labelTh: 'รายการ table' },
    'enum-cols':           { label: 'Columns + sample rows', labelTh: 'columns + ข้อมูลตัวอย่าง' },
    'enum-users':          { label: 'DB users + hashes',     labelTh: 'users + password hash' },
    'done':                { label: 'Complete',              labelTh: 'เสร็จสิ้น' },
};

function LiveExploitPanel({ state }: { state: ReturnType<typeof useExploitEvents> }) {
    const logContainerRef = useRef<HTMLDivElement>(null);
    const [elapsed, setElapsed] = useState(0);

    // Elapsed counter — tick every 250ms while streaming.
    useEffect(() => {
        if (!state.startedAt || !state.streaming) return;
        const id = setInterval(() => setElapsed(Date.now() - state.startedAt!), 250);
        return () => clearInterval(id);
    }, [state.startedAt, state.streaming]);

    // Auto-scroll log to bottom as new entries arrive (terminal-style).
    useEffect(() => {
        const el = logContainerRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [state.logs.length]);

    const activeIdx = state.currentPhase ? PHASE_ORDER.indexOf(state.currentPhase as typeof PHASE_ORDER[number]) : -1;
    const statusAccent =
        state.status === 'success' ? { ring: 'bg-emerald-500/10 border-emerald-500/30', text: 'text-emerald-300', bar: 'bg-emerald-400' } :
        state.status === 'partial' ? { ring: 'bg-amber-500/10 border-amber-500/30',     text: 'text-amber-300',    bar: 'bg-amber-400' } :
        state.status === 'failed'  ? { ring: 'bg-red-500/10 border-red-500/30',         text: 'text-red-300',      bar: 'bg-red-400'    } :
        state.status === 'error'   ? { ring: 'bg-red-500/10 border-red-500/30',         text: 'text-red-300',      bar: 'bg-red-400'    } :
        state.status === 'waiting' ? { ring: 'bg-gray-500/10 border-gray-500/30',       text: 'text-gray-300',     bar: 'bg-gray-400'   } :
                                     { ring: 'bg-violet-500/10 border-violet-500/30',   text: 'text-violet-300',   bar: 'bg-violet-400' };

    const secondsElapsed = Math.floor(elapsed / 1000);
    const formattedElapsed = `${Math.floor(secondsElapsed / 60)}:${String(secondsElapsed % 60).padStart(2, '0')}`;

    return (
        <div className="space-y-4 animate-fade-in">
            {/* ── Header / status bar ── */}
            <div className={`relative overflow-hidden rounded-2xl border ${statusAccent.ring} bg-gradient-to-br from-violet-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-5`}>
                <div className="absolute -top-20 -right-20 w-40 h-40 bg-violet-500/5 rounded-full blur-3xl" />
                <div className="relative">
                    <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-xl ${statusAccent.ring} border flex items-center justify-center`}>
                            {state.streaming
                                ? <Loader2 className={`w-5 h-5 ${statusAccent.text} animate-spin`} />
                                : <Activity className={`w-5 h-5 ${statusAccent.text}`} />}
                        </div>
                        <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                                <h3 className={`text-sm font-semibold ${statusAccent.text}`}>
                                    {state.status === 'success'  ? 'Deep Exploit — Extraction Complete' :
                                     state.status === 'partial'  ? 'Deep Exploit — Partial Extraction' :
                                     state.status === 'failed'   ? 'Deep Exploit — Failed' :
                                     state.status === 'error'    ? 'Deep Exploit — Stream Error' :
                                     state.status === 'waiting'  ? 'Deep Exploit — Connecting…' :
                                                                   'Deep Exploit — In Progress'}
                                </h3>
                                {state.streaming && <span className="inline-flex w-2 h-2 rounded-full bg-red-500 animate-pulse" aria-label="live" />}
                            </div>
                            <p className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                                {state.currentPhase
                                    ? (PHASE_LABELS[state.currentPhase]?.label ?? state.currentPhase)
                                    : (state.status === 'waiting' ? 'Subscribing to stream…' : 'Preparing…')}
                                {state.currentPhaseDetail ? ` · ${state.currentPhaseDetail}` : ''}
                            </p>
                        </div>
                        <div className="text-right shrink-0">
                            <div className={`font-mono text-lg font-semibold ${statusAccent.text}`}>{formattedElapsed}</div>
                            <div className="text-[10px] text-gray-500 uppercase tracking-wider">elapsed</div>
                        </div>
                    </div>
                    {state.errorMessage && (
                        <div className="mt-3 p-2.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-300 font-mono">
                            {state.errorMessage}
                        </div>
                    )}
                </div>
            </div>

            {/* ── Main two-pane: phase stepper + live log ── */}
            <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,280px)_1fr] gap-4">
                {/* Phase stepper */}
                <div className="rounded-2xl border border-violet-500/15 bg-gradient-to-br from-violet-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-4">
                    <div className="flex items-center gap-2 mb-3">
                        <Fingerprint className="w-3.5 h-3.5 text-violet-400" />
                        <h4 className="text-xs font-semibold text-violet-300 uppercase tracking-wider">Phases</h4>
                    </div>
                    <ol className="space-y-1">
                        {PHASE_ORDER.map((p, i) => {
                            const labels = PHASE_LABELS[p];
                            const isActive = state.currentPhase === p && state.streaming;
                            const isDone = activeIdx >= 0 && i < activeIdx;
                            const isFinal = state.status !== 'running' && state.status !== 'waiting' && state.status !== 'idle' && p === 'done';
                            return (
                                <li key={p} className="flex items-center gap-2.5 py-1">
                                    <span
                                        className={`relative w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${
                                            isActive ? 'bg-violet-500/20 border border-violet-400' :
                                            isDone   ? 'bg-emerald-500/20 border border-emerald-400/40' :
                                            isFinal  ? `${statusAccent.ring} border` :
                                                       'bg-[var(--bg-subtle)] border border-white/[0.06]'
                                        }`}
                                    >
                                        {isActive && <span className="absolute inset-0 rounded-full bg-violet-400/40 animate-ping" />}
                                        {isDone && <CheckCircle className="w-3 h-3 text-emerald-300" />}
                                        {isActive && <span className="w-1.5 h-1.5 rounded-full bg-violet-300" />}
                                        {!isActive && !isDone && !isFinal && <span className="text-[9px] font-mono text-gray-600">{i + 1}</span>}
                                    </span>
                                    <div className="flex-1 min-w-0">
                                        <div className={`text-xs font-medium truncate ${
                                            isActive ? 'text-violet-200' :
                                            isDone   ? 'text-emerald-300/80' :
                                                       'text-gray-500'
                                        }`}>
                                            {labels?.label ?? p}
                                        </div>
                                        <div className="text-[10px] text-gray-600 truncate">{labels?.labelTh}</div>
                                    </div>
                                </li>
                            );
                        })}
                    </ol>
                </div>

                {/* Live log terminal */}
                <div className="rounded-2xl border border-green-500/15 bg-gradient-to-br from-green-950/10 via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-white/[0.04] flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-green-400" />
                        <h4 className="text-xs font-semibold text-green-300 uppercase tracking-wider">Live log</h4>
                        <span className="text-[10px] text-gray-600 font-mono ml-auto">{state.logs.length} entries</span>
                        {state.streaming && <span className="inline-flex w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />}
                    </div>
                    <div ref={logContainerRef} className="h-[520px] overflow-y-auto p-3 space-y-0.5 font-mono text-[11px] scroll-smooth">
                        {state.logs.length === 0 && !state.streaming && (
                            <div className="text-gray-600 text-center py-8">No log entries yet</div>
                        )}
                        {state.logs.length === 0 && state.streaming && (
                            <div className="text-violet-400/80 text-center py-8 animate-pulse">Waiting for first probe…</div>
                        )}
                        {state.logs.map((step, i) => (
                            <div
                                key={i}
                                className={`flex items-start gap-2 px-2.5 py-1 rounded-md transition-all animate-fade-in ${
                                    step.success ? 'hover:bg-green-500/5' : 'hover:bg-red-500/5 opacity-70'
                                }`}
                                style={{ animation: `fadeInSlide 180ms ease-out` }}
                            >
                                <span className="shrink-0 w-4 text-center">
                                    {step.success
                                        ? <Zap className="w-3 h-3 text-green-400 inline" />
                                        : <span className="text-red-400">✗</span>}
                                </span>
                                <span className={`shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${phaseBadgeClass(step.phase)}`}>
                                    {step.phase}
                                </span>
                                <span className="text-gray-400 truncate flex-1" title={step.payload}>
                                    {step.payload.length > 110 ? step.payload.slice(0, 110) + '…' : step.payload}
                                </span>
                                {step.extracted && (
                                    <span className="shrink-0 text-green-300 max-w-[260px] truncate" title={step.extracted}>
                                        → {step.extracted}
                                    </span>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* ── Result summary (post-completion) ── */}
            {state.result && (
                <div className={`rounded-2xl border ${statusAccent.ring} bg-gradient-to-br from-[var(--bg-card)] to-[var(--bg-subtle)] p-4 grid grid-cols-2 md:grid-cols-6 gap-3`}>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">DBMS</div>
                        <div className={`text-sm font-mono ${statusAccent.text}`}>{state.result.dbms}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Current DB</div>
                        <div className="text-sm font-mono text-[var(--text-primary)]">{state.result.currentDatabase || '—'}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">User</div>
                        <div className="text-sm font-mono text-[var(--text-primary)]">{state.result.currentUser || '—'}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Databases</div>
                        <div className="text-sm font-mono text-violet-300">{state.result.databases}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Tables / Cols</div>
                        <div className="text-sm font-mono text-cyan-300">{state.result.tables} / {state.result.columns}</div>
                    </div>
                    <div>
                        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Rows / Duration</div>
                        <div className="text-sm font-mono text-amber-300">{state.result.rows} / {(state.result.durationMs / 1000).toFixed(1)}s</div>
                    </div>
                </div>
            )}
        </div>
    );
}

function phaseBadgeClass(phase: string): string {
    if (phase === 'init' || phase === 'breakout' || phase === 'breakout-discovery') return 'bg-violet-500/10 text-violet-400 border border-violet-500/20';
    if (phase === 'fingerprint') return 'bg-violet-500/10 text-violet-400 border border-violet-500/20';
    if (phase === 'column-count') return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
    if (phase === 'technique-test' || phase === 'technique' || phase === 'union-sweep') return 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20';
    if (phase.startsWith('server-') || phase === 'server-info') return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
    if (phase.startsWith('enum-') || phase.includes('enum')) return 'bg-green-500/10 text-green-400 border border-green-500/20';
    if (phase.startsWith('tables-') || phase.startsWith('cols-')) return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
    if (phase.startsWith('rows-') || phase.startsWith('row-')) return 'bg-red-500/10 text-red-400 border border-red-500/20';
    if (phase === 'admin-check') return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    if (phase === 'file-read' || phase.startsWith('os-cmd-')) return 'bg-pink-500/10 text-pink-400 border border-pink-500/20';
    if (phase === 'done') return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
    return 'bg-gray-500/10 text-gray-400 border border-gray-500/20';
}

/* ── Deep Exploit Launcher (manual run) ── */

function DeepExploitLauncher({
    hasResult,
    isPartial,
    isPending,
    error,
    onRun,
}: {
    hasResult: boolean;
    isPartial: boolean;
    isPending: boolean;
    error?: string;
    onRun: (opts: {
        dbmsHint?: 'mysql' | 'postgresql' | 'mssql' | 'oracle' | 'sqlite';
        breakoutPrefix?: string;
        originalParamValue?: string;
        level?: number;
        risk?: number;
        tampers?: string[];
    }) => void;
}) {
    const [dbmsHint, setDbmsHint] = useState<'auto' | 'mysql' | 'postgresql' | 'mssql' | 'oracle' | 'sqlite'>('auto');
    const [breakoutPrefix, setBreakoutPrefix] = useState<string>('');
    const [origValue, setOrigValue] = useState<string>('');
    const [level, setLevel] = useState<number>(1);
    const [risk, setRisk] = useState<number>(1);
    const [tampersCsv, setTampersCsv] = useState<string>('');
    const [showAdvanced, setShowAdvanced] = useState(false);

    const accent = isPartial ? 'amber' : hasResult ? 'green' : 'red';
    const colors = {
        red:   { border: 'border-red-500/20',   bg: 'from-red-950/20',   icon: 'text-red-400',   ring: 'bg-red-500/10 border-red-500/20',   title: 'text-red-300' },
        amber: { border: 'border-amber-500/20', bg: 'from-amber-950/20', icon: 'text-amber-400', ring: 'bg-amber-500/10 border-amber-500/20', title: 'text-amber-300' },
        green: { border: 'border-green-500/20', bg: 'from-green-950/20', icon: 'text-green-400', ring: 'bg-green-500/10 border-green-500/20', title: 'text-green-300' },
    }[accent];

    return (
        <div className={`rounded-xl border ${colors.border} bg-gradient-to-br ${colors.bg} via-[var(--bg-card)] to-[var(--bg-card)] p-4 space-y-3`}>
            <div className="flex items-start gap-3">
                <div className={`w-9 h-9 rounded-lg ${colors.ring} border flex items-center justify-center shrink-0`}>
                    <Skull className={`w-4 h-4 ${colors.icon}`} />
                </div>
                <div className="flex-1">
                    <h3 className={`text-sm font-semibold ${colors.title}`}>
                        {isPartial ? 'Re-run Deep Exploit (last attempt was diagnostic-only)'
                            : hasResult ? 'Re-run Deep Exploit'
                            : 'Run Deep Exploitation'}
                    </h3>
                    <p className="text-xs text-gray-400 mt-1">
                        {isPartial
                            ? <>The previous run found no working extraction technique. Try a manual breakout override below — common patterns are <code className="text-amber-200">'</code>, <code className="text-amber-200">"</code>, <code className="text-amber-200">)</code>, <code className="text-amber-200">')</code>, or <code className="text-amber-200">"%</code>.</>
                            : <>Drive the multi-technique exploit engine (auto-discover breakout → UNION → Error → Boolean → Time) against this finding to dump database structure, current user/host, and sample rows.</>}
                    </p>
                </div>
            </div>
            <div className="flex flex-wrap items-center gap-3 pl-12">
                <label className="text-xs text-gray-500">DBMS:</label>
                <select
                    value={dbmsHint}
                    onChange={(e) => setDbmsHint(e.target.value as typeof dbmsHint)}
                    disabled={isPending}
                    className="input-field !py-1 !text-xs !w-auto"
                >
                    <option value="auto">Auto-detect</option>
                    <option value="mysql">MySQL / MariaDB</option>
                    <option value="postgresql">PostgreSQL</option>
                    <option value="mssql">MSSQL</option>
                    <option value="sqlite">SQLite</option>
                    <option value="oracle">Oracle</option>
                </select>
                <button
                    type="button"
                    onClick={() => setShowAdvanced(v => !v)}
                    className="text-xs text-gray-500 hover:text-[var(--text-primary)] underline-offset-2 hover:underline"
                >
                    {showAdvanced ? 'Hide' : 'Show'} advanced overrides
                </button>
                <button
                    onClick={() => {
                        const tampers = tampersCsv.split(',').map(s => s.trim()).filter(Boolean);
                        onRun({
                            dbmsHint: dbmsHint === 'auto' ? undefined : dbmsHint,
                            breakoutPrefix: breakoutPrefix.trim() || undefined,
                            originalParamValue: origValue.trim() || undefined,
                            level: level !== 1 ? level : undefined,
                            risk: risk !== 1 ? risk : undefined,
                            tampers: tampers.length > 0 ? tampers : undefined,
                        });
                    }}
                    disabled={isPending}
                    className="btn-primary !text-xs flex items-center gap-2 disabled:opacity-50 ml-auto"
                >
                    {isPending
                        ? <><div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Exploiting…</>
                        : <><Zap className="w-3.5 h-3.5" /> {hasResult ? 'Re-run' : 'Run'} Deep Exploit</>}
                </button>
                {isPending && <span className="text-[10px] text-gray-500 w-full pl-0">~10–60s depending on technique + WAF</span>}
            </div>
            {showAdvanced && (
                <div className="pl-12 grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                        <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">Breakout closer (e.g. <code className="text-amber-300">'</code>, <code className="text-amber-300">")</code>)</label>
                        <input
                            type="text"
                            value={breakoutPrefix}
                            onChange={(e) => setBreakoutPrefix(e.target.value)}
                            placeholder="auto-discover (leave blank)"
                            disabled={isPending}
                            className="input-field !py-1 !text-xs font-mono w-full"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">Original param value (preserved as prefix)</label>
                        <input
                            type="text"
                            value={origValue}
                            onChange={(e) => setOrigValue(e.target.value)}
                            placeholder="e.g. 10 (auto from URL if blank)"
                            disabled={isPending}
                            className="input-field !py-1 !text-xs font-mono w-full"
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">Level (sqlmap --level, 1–5)</label>
                        <select
                            value={level}
                            onChange={(e) => setLevel(Number(e.target.value))}
                            disabled={isPending}
                            className="input-field !py-1 !text-xs !w-full"
                        >
                            <option value={1}>1 — Default (fast, 5-col UNION)</option>
                            <option value={2}>2 — Moderate (10-col UNION)</option>
                            <option value={3}>3 — Thorough (20-col UNION)</option>
                            <option value={4}>4 — Deep (30-col UNION)</option>
                            <option value={5}>5 — Exhaustive (40-col UNION + all variants)</option>
                        </select>
                    </div>
                    <div>
                        <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">Risk (sqlmap --risk, 1–3)</label>
                        <select
                            value={risk}
                            onChange={(e) => setRisk(Number(e.target.value))}
                            disabled={isPending}
                            className="input-field !py-1 !text-xs !w-full"
                        >
                            <option value={1}>1 — Safe (AND-based, read-only)</option>
                            <option value={2}>2 — OR-based (may return extra rows)</option>
                            <option value={3}>3 — Stacked queries (authorised testing only)</option>
                        </select>
                    </div>
                    <div className="md:col-span-2">
                        <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                            Tampers (comma-separated — e.g. <code className="text-amber-300">randomcase,space2comment,modsecurityversioned</code>)
                        </label>
                        <input
                            type="text"
                            value={tampersCsv}
                            onChange={(e) => setTampersCsv(e.target.value)}
                            placeholder="leave blank for auto-WAF chain"
                            disabled={isPending}
                            className="input-field !py-1 !text-xs font-mono w-full"
                        />
                        <p className="text-[10px] text-gray-600 mt-1">
                            28 tampers available: between, charencode, charunicodeencode, chardoubleencode, space2comment, space2dash, space2hash, space2mysqlblank, space2plus, randomcase, equaltolike, greatest, percentage, appendnullbyte, modsecurityversioned, modsecurityzeroversioned, halfversionedmorekeywords, versionedkeywords, symboliclogical, apostrophemask, apostrophenullencode, base64encode, concat2concatws, plus2concat, bluecoat, hex-keywords, inline-comment
                        </p>
                    </div>
                </div>
            )}
            {error && (
                <div className="ml-12 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">
                    {error}
                </div>
            )}
        </div>
    );
}

/* ── SQLi Micro Components ── */

function InfoChip({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string; color: string }) {
    const colorMap: Record<string, string> = {
        red: 'text-red-400 bg-red-500/5 border-red-500/15',
        violet: 'text-violet-400 bg-violet-500/5 border-violet-500/15',
        cyan: 'text-cyan-400 bg-cyan-500/5 border-cyan-500/15',
        amber: 'text-amber-400 bg-amber-500/5 border-amber-500/15',
        green: 'text-green-400 bg-green-500/5 border-green-500/15',
        blue: 'text-blue-400 bg-blue-500/5 border-blue-500/15',
    };
    return (
        <div className={`rounded-xl border ${colorMap[color] || colorMap.red} p-2.5`}>
            <div className={`flex items-center gap-1.5 mb-1 ${colorMap[color]?.split(' ')[0]}`}>{icon}<span className="text-[9px] font-bold uppercase tracking-wider text-gray-500">{label}</span></div>
            <p className="text-xs font-mono text-[var(--text-primary)] truncate" title={value}>{value || '—'}</p>
        </div>
    );
}

function StatCard({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color: string }) {
    const colorMap: Record<string, string> = {
        violet: 'text-violet-400 border-violet-500/15 from-violet-950/20',
        cyan: 'text-cyan-400 border-cyan-500/15 from-cyan-950/20',
        green: 'text-green-400 border-green-500/15 from-green-950/20',
        amber: 'text-amber-400 border-amber-500/15 from-amber-950/20',
    };
    const c = colorMap[color] || colorMap.violet;
    return (
        <div className={`rounded-xl border ${c} bg-gradient-to-br via-[var(--bg-card)] to-[var(--bg-card)] backdrop-blur-xl p-3 text-center`}>
            <div className={`flex items-center justify-center gap-1.5 mb-1 ${c.split(' ')[0]}`}>{icon}</div>
            <p className={`text-2xl font-bold tabular-nums ${c.split(' ')[0]}`}>{value}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mt-0.5">{label}</p>
        </div>
    );
}
