// VibeCode — Target Detail Page
'use client';

import { use } from 'react';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import { ArrowLeft, Radar, Globe, Shield, Clock, Bug, Play, Pencil, ShieldAlert } from 'lucide-react';

export default function TargetDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { data: target, isLoading } = trpc.target.getById.useQuery(id);
    // Fetch scope approval state. For dev-env targets this is advisory; for
    // prod/staging the scan router hard-rejects without it. Either way we
    // surface the state so the user isn't surprised later.
    const { data: scope } = trpc.scope.listForTarget.useQuery({ targetId: id });

    if (isLoading) return <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" /></div>;
    if (!target) return <div className="text-gray-500 text-center py-12">Target not found</div>;

    const needsScope = target.environment === 'production' || target.environment === 'staging';
    const hasActiveScope = Boolean(scope?.current);

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex items-center gap-3">
                <Link href="/targets" className="p-2 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all"><ArrowLeft className="w-5 h-5" /></Link>
                <div className="flex-1">
                    <h1 className="page-title">{target.name}</h1>
                    <p className="text-sm text-gray-400 font-mono">{target.baseUrl}</p>
                </div>
                <div className="flex gap-2">
                    <Link href={`/targets/${target.id}/edit`} className="btn-secondary flex items-center gap-2"><Pencil className="w-4 h-4" /> Edit</Link>
                    <Link href={`/scans/new?targetId=${target.id}`} className="btn-primary flex items-center gap-2"><Play className="w-4 h-4" /> Start Scan</Link>
                </div>
            </div>

            {/* Scope-required banner — only for prod/staging targets without an
                approved scope. Dev targets don't show this since scans run without
                scope checks there. */}
            {needsScope && !hasActiveScope && (
                <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 px-4 py-3 flex items-start gap-3 text-sm">
                    <ShieldAlert className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                        <p className="font-medium text-amber-200">Scope approval required before scanning</p>
                        <p className="text-amber-300/80 text-xs mt-1">
                            This is a <strong className="capitalize">{target.environment}</strong> target.
                            A <code className="text-amber-100">security_lead</code> must sign an engagement scope
                            (allowed paths, allowed methods, exploit / OS-cmd / file-read flags) before any scan
                            can start. Without a signed approval, <code className="text-amber-100">scan.create</code> will reject.
                        </p>
                    </div>
                    <Link
                        href={`/targets/${target.id}/scope`}
                        className="btn-secondary !bg-amber-500/20 !border-amber-500/30 !text-amber-100 hover:!bg-amber-500/30 text-xs flex-shrink-0"
                    >
                        Request Scope Approval →
                    </Link>
                </div>
            )}

            {/* Info Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="glass-card">
                    <p className="text-xs text-gray-500 mb-1">Environment</p>
                    <p className="text-sm font-medium capitalize text-[var(--text-primary)]">{target.environment}</p>
                </div>
                <div className="glass-card">
                    <p className="text-xs text-gray-500 mb-1">Criticality</p>
                    <p className="text-sm font-medium capitalize text-[var(--text-primary)]">{target.criticality}</p>
                </div>
                <div className="glass-card">
                    <p className="text-xs text-gray-500 mb-1">Total Scans / Vulns</p>
                    <p className="text-sm font-medium text-[var(--text-primary)]">{target._count?.scans || 0} scans / {target._count?.vulnerabilities || 0} vulns</p>
                </div>
            </div>

            {target.description && (
                <div className="glass-card">
                    <p className="text-xs text-gray-500 mb-1">Description</p>
                    <p className="text-sm text-[var(--text-primary)]">{target.description}</p>
                </div>
            )}

            {/* Scan History */}
            <div className="glass-card">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2"><Clock className="w-4 h-4 text-brand-400" /> Scan History</h3>
                {target.scans && target.scans.length > 0 ? (
                    <table className="data-table">
                        <thead><tr><th>Type</th><th>Status</th><th>Started By</th><th>Date</th><th></th></tr></thead>
                        <tbody>
                            {target.scans.map((scan: any) => (
                                <tr key={scan.id}>
                                    <td className="capitalize">{scan.scanType}</td>
                                    <td><span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${scan.status === 'completed' ? 'bg-blue-600/15 text-blue-400 border-blue-600/25' : scan.status === 'running' ? 'bg-green-600/15 text-green-400 border-green-600/25' : 'bg-gray-600/15 text-gray-400 border-gray-600/25'}`}>{scan.status}</span></td>
                                    <td>{scan.startedBy?.name}</td>
                                    <td className="text-xs text-gray-500">{new Date(scan.createdAt).toLocaleString()}</td>
                                    <td><Link href={`/scans/${scan.id}`} className="text-brand-400 text-xs hover:underline">View →</Link></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <p className="text-sm text-gray-600 text-center py-4">No scans yet. <Link href={`/scans/new?targetId=${target.id}`} className="text-brand-400 hover:underline">Start one →</Link></p>
                )}
            </div>
        </div>
    );
}
