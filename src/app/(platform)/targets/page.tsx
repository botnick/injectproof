// VibeCode — Targets List Page
'use client';

import { useState } from 'react';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import { Target, Plus, Search, Globe, Shield, ExternalLink, Trash2 } from 'lucide-react';

export default function TargetsPage() {
    const [search, setSearch] = useState('');
    const [envFilter, setEnvFilter] = useState('');
    const { data, isLoading, refetch } = trpc.target.list.useQuery({ search, environment: envFilter || undefined });
    const deleteMutation = trpc.target.delete.useMutation({ onSuccess: () => refetch() });

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between">
                <div className="page-header !mb-0">
                    <h1 className="page-title flex items-center gap-3">
                        <div className="w-8 h-8 rounded-xl flex items-center justify-center bg-emerald-500/10 border border-emerald-500/20"><Target className="w-4 h-4 text-emerald-400" /></div>
                        Targets
                    </h1>
                    <p className="page-subtitle">{data?.total || 0} registered targets</p>
                </div>
                <Link href="/targets/new" className="btn-primary flex items-center gap-2">
                    <Plus className="w-4 h-4" /> New Target
                </Link>
            </div>

            {/* Filters */}
            <div className="flex gap-3 flex-wrap">
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search targets..." className="input-field pl-10" />
                </div>
                <select value={envFilter} onChange={e => setEnvFilter(e.target.value)} className="input-field w-auto">
                    <option value="">All Environments</option>
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="internal">Internal</option>
                </select>
            </div>

            {/* Table */}
            {isLoading ? (
                <div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" /></div>
            ) : data?.items && data.items.length > 0 ? (
                <div className="glass-card !p-0 overflow-hidden">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>URL</th>
                                <th>Environment</th>
                                <th>Criticality</th>
                                <th>Scans</th>
                                <th>Vulns</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.items.map((target: any) => (
                                <tr key={target.id}>
                                    <td>
                                        <Link href={`/targets/${target.id}`} className="font-medium text-gray-200 hover:text-brand-400 transition-colors">
                                            {target.name}
                                        </Link>
                                    </td>
                                    <td className="font-mono text-xs">{target.baseUrl}</td>
                                    <td><EnvBadge env={target.environment} /></td>
                                    <td><CritBadge crit={target.criticality} /></td>
                                    <td>{target._count?.scans || 0}</td>
                                    <td>{target._count?.vulnerabilities || 0}</td>
                                    <td>
                                        <div className="flex gap-2">
                                            <Link href={`/targets/${target.id}`} className="text-gray-500 hover:text-brand-400"><ExternalLink className="w-4 h-4" /></Link>
                                            <button onClick={() => { if (confirm('Delete this target?')) deleteMutation.mutate(target.id); }} className="text-gray-500 hover:text-red-400"><Trash2 className="w-4 h-4" /></button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : (
                <div className="empty-state">
                    <Globe className="empty-state-icon" />
                    <h3 className="text-lg font-semibold text-gray-400">No targets yet</h3>
                    <p className="text-sm text-gray-600 mt-1">Add your first target to start scanning</p>
                    <Link href="/targets/new" className="btn-primary mt-4">Add Target</Link>
                </div>
            )}
        </div>
    );
}

function EnvBadge({ env }: { env: string }) {
    const styles: Record<string, string> = {
        production: 'bg-red-600/15 text-red-400 border-red-600/25',
        staging: 'bg-yellow-600/15 text-yellow-400 border-yellow-600/25',
        development: 'bg-blue-600/15 text-blue-400 border-blue-600/25',
        internal: 'bg-gray-600/15 text-gray-400 border-gray-600/25',
    };
    return <span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${styles[env] || styles.internal}`}>{env}</span>;
}

function CritBadge({ crit }: { crit: string }) {
    const styles: Record<string, string> = {
        critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low',
    };
    return <span className={styles[crit] || 'badge-info'}>{crit}</span>;
}
