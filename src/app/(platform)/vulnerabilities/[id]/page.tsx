// InjectProof — Vulnerability Detail Page (Premium Design)
'use client';

import { use, useState, useMemo } from 'react';
import { trpc } from '@/trpc/client';
import type { SqliExploitResult } from '@/types';
import Link from 'next/link';
import {
    ArrowLeft, Bug, Shield, ExternalLink, Code, FileText,
    AlertTriangle, CheckCircle, Copy, Link2, Skull,
    Database, Lock, Globe, Fingerprint, ChevronDown,
    ChevronRight, Server, Table, Columns3, User, HardDrive,
    Terminal, Zap, Hash, Eye,
} from 'lucide-react';
import { getCweEntry, OWASP_TOP_10_2021 } from '@/lib/cwe-database';

export default function VulnDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { data: vuln, isLoading, refetch } = trpc.vulnerability.getById.useQuery(id);
    const updateStatus = trpc.vulnerability.updateStatus.useMutation({ onSuccess: () => refetch() });
    const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'remediation' | 'chain' | 'sqli_exploit'>('overview');

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
                <Link href="/vulnerabilities" className="p-2 rounded-lg hover:bg-surface-800/50 text-gray-400 hover:text-white transition-all mt-1"><ArrowLeft className="w-5 h-5" /></Link>
                <div className="flex-1">
                    <div className="flex items-center gap-3 mb-1 flex-wrap">
                        <span className={vuln.severity === 'critical' ? 'badge-critical' : vuln.severity === 'high' ? 'badge-high' : vuln.severity === 'medium' ? 'badge-medium' : vuln.severity === 'low' ? 'badge-low' : 'badge-info'}>{vuln.severity}</span>
                        {vuln.cvssScore && <span className="text-xs font-mono text-gray-400">CVSS {vuln.cvssScore}</span>}
                        {vuln.raceConditionConfirmed && <span className="badge-critical">⚡ Race Condition</span>}
                        {vuln.cloudMetadataExtracted && <span className="badge-critical">☁️ Cloud Metadata</span>}
                    </div>
                    <h1 className="text-xl font-bold text-white">{vuln.title}</h1>
                    <p className="text-sm text-gray-400 font-mono mt-1">{vuln.affectedUrl}</p>
                </div>
            </div>

            {/* Status Actions */}
            <div className="flex gap-2 flex-wrap">
                {['open', 'confirmed', 'fixed', 'false_positive', 'accepted'].map(s => (
                    <button key={s} onClick={() => updateStatus.mutate({ id: vuln.id, status: s as any })}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${vuln.status === s ? 'border-brand-500 bg-brand-600/10 text-brand-300' : 'border-surface-700 text-gray-500 hover:text-gray-300 hover:border-surface-600'}`}>
                        {s.replace('_', ' ')}
                    </button>
                ))}
            </div>

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
                    <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2">Description</h3><p className="text-sm text-gray-400 leading-relaxed">{vuln.description}</p></div>
                    {vuln.technicalDetail && <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2">Technical Details</h3><p className="text-sm text-gray-400 leading-relaxed">{vuln.technicalDetail}</p></div>}
                    {vuln.impact && <div className="glass-card border-red-600/15"><h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> Impact</h3><p className="text-sm text-gray-400">{vuln.impact}</p></div>}

                    {/* Quick Info Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Category</p><p className="text-sm text-gray-200 capitalize">{vuln.category}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">HTTP Method</p><p className="text-sm text-gray-200">{vuln.httpMethod}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Parameter</p><p className="text-sm text-gray-200 font-mono">{vuln.parameter || '—'}</p></div>
                        <div className="glass-card !p-3"><p className="text-xs text-gray-500 mb-1">Confidence</p><p className="text-sm text-gray-200 capitalize">{vuln.confidence}</p></div>
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
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-2"><Code className="w-4 h-4 text-brand-400" /> Payload</h3><div className="code-block">{vuln.payload}</div></div>
                    )}
                    {vuln.requestArtifact && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2">HTTP Request</h3><div className="code-block text-xs max-h-64 overflow-y-auto whitespace-pre-wrap">{vuln.requestArtifact}</div></div>
                    )}
                    {vuln.responseArtifact && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2">HTTP Response</h3><div className="code-block text-xs max-h-64 overflow-y-auto whitespace-pre-wrap">{vuln.responseArtifact.substring(0, 5000)}{vuln.responseArtifact.length > 5000 ? '\n... (truncated)' : ''}</div></div>
                    )}
                    {reproSteps.length > 0 && (
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-3">Reproduction Steps</h3>
                            <ol className="space-y-2">{reproSteps.map((step: string, i: number) => (
                                <li key={i} className="flex gap-3 text-sm text-gray-400"><span className="w-6 h-6 rounded-full bg-surface-800 flex items-center justify-center text-xs text-gray-500 flex-shrink-0">{i + 1}</span><span>{step}</span></li>
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
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2"><Link2 className="w-4 h-4 text-brand-400" /> References</h3>
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
                        <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2"><Skull className="w-4 h-4 text-red-400" /> Attack Chain Graph</h3>
                            <div className="code-block text-xs">{JSON.stringify(chainGraph, null, 2)}</div>
                        </div>
                    ) : (
                        <div className="glass-card text-center py-8"><p className="text-sm text-gray-600">No attack chain data for this vulnerability</p></div>
                    )}
                    {vuln.cachePoisoningImpact && <div className="glass-card"><h3 className="text-sm font-semibold text-gray-300 mb-2">Cache Poisoning Impact</h3><p className="text-sm text-gray-400">{vuln.cachePoisoningImpact}</p></div>}
                </div>
            )}
            {activeTab === 'sqli_exploit' && sqliExploit && (
                <SqliExploitPanel data={sqliExploit} />
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

    return (
        <div className="space-y-4 animate-fade-in">
            {/* ── Server Info Banner ── */}
            <div className="relative overflow-hidden rounded-2xl border border-red-500/20 bg-gradient-to-br from-red-950/30 via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-5">
                <div className="absolute -top-20 -right-20 w-40 h-40 bg-red-500/5 rounded-full blur-3xl" />
                <div className="absolute -bottom-10 -left-10 w-32 h-32 bg-violet-500/5 rounded-full blur-3xl" />
                <div className="relative">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                            <Skull className="w-4 h-4 text-red-400" />
                        </div>
                        <div>
                            <h3 className="text-sm font-semibold text-red-300">Deep SQLi Exploitation Successful</h3>
                            <p className="text-[10px] text-gray-500 uppercase tracking-wider">InjectProof Multi-Technique Extraction</p>
                        </div>
                        <span className="ml-auto px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-[10px] font-bold text-red-400 uppercase tracking-wider">
                            {data.technique}
                        </span>
                    </div>
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
            <div className="relative overflow-hidden rounded-2xl border border-violet-500/15 bg-gradient-to-br from-violet-950/20 via-surface-900/80 to-surface-900/80 backdrop-blur-xl">
                <div className="absolute -top-16 -right-16 w-32 h-32 bg-violet-500/5 rounded-full blur-3xl" />
                <div className="px-5 py-3.5 border-b border-white/[0.04] flex items-center gap-2">
                    <Database className="w-4 h-4 text-violet-400" />
                    <h3 className="text-sm font-semibold text-gray-200">Database Structure</h3>
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
                                                                                            <tr key={ri} className={`border-b border-white/[0.02] ${ri % 2 === 0 ? 'bg-surface-900/50' : 'bg-surface-800/30'} hover:bg-amber-500/5 transition-colors`}>
                                                                                                {Object.values(row).map((v, ci) => (
                                                                                                    <td key={ci} className="px-3 py-1.5 text-gray-300 max-w-[200px] truncate">{String(v)}</td>
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

            {/* ── Exploit Step Log (Terminal Style) ── */}
            <div className="rounded-2xl border border-green-500/15 bg-gradient-to-br from-green-950/10 via-surface-900/80 to-surface-900/80 backdrop-blur-xl overflow-hidden">
                <button
                    onClick={() => setShowLog(!showLog)}
                    className="w-full px-5 py-3.5 flex items-center gap-2 hover:bg-green-500/5 transition-all"
                >
                    <Terminal className="w-4 h-4 text-green-400" />
                    <h3 className="text-sm font-semibold text-gray-200">Exploitation Log</h3>
                    <span className="text-[10px] text-gray-600 font-mono">{successSteps}/{data.exploitLog.length} steps successful</span>
                    <div className="ml-auto flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-surface-700 overflow-hidden">
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
            <p className="text-xs font-mono text-gray-300 truncate" title={value}>{value || '—'}</p>
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
        <div className={`rounded-xl border ${c} bg-gradient-to-br via-surface-900/80 to-surface-900/80 backdrop-blur-xl p-3 text-center`}>
            <div className={`flex items-center justify-center gap-1.5 mb-1 ${c.split(' ')[0]}`}>{icon}</div>
            <p className={`text-2xl font-bold tabular-nums ${c.split(' ')[0]}`}>{value}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mt-0.5">{label}</p>
        </div>
    );
}
