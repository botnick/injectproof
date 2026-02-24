// InjectProof — Scans List Page (Premium Glassmorphism + Delete)
'use client';

import { useState } from 'react';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import {
    Radar, Plus, Globe, Clock, Bug, Trash2,
    StopCircle, ExternalLink, Search, Filter,
    CheckCircle2, XCircle, Loader2, AlertTriangle,
} from 'lucide-react';

/* ── Status config ─────────────────────────────────────── */
const STATUS_CONFIG: Record<string, {
    label: string; color: string; dot: string; border: string;
    bg: string; icon: typeof CheckCircle2;
}> = {
    completed: { label: 'Completed', color: 'text-blue-400', dot: 'bg-blue-400', border: 'border-blue-500/20', bg: 'bg-blue-500/8', icon: CheckCircle2 },
    running: { label: 'Running', color: 'text-emerald-400', dot: 'bg-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/8', icon: Loader2 },
    failed: { label: 'Failed', color: 'text-red-400', dot: 'bg-red-400', border: 'border-red-500/20', bg: 'bg-red-500/8', icon: XCircle },
    cancelled: { label: 'Cancelled', color: 'text-gray-400', dot: 'bg-gray-400', border: 'border-gray-500/20', bg: 'bg-gray-500/8', icon: XCircle },
    queued: { label: 'Queued', color: 'text-amber-400', dot: 'bg-amber-400', border: 'border-amber-500/20', bg: 'bg-amber-500/8', icon: Clock },
};

const SCAN_TYPE_LABELS: Record<string, { label: string; accent: string }> = {
    quick: { label: 'Quick', accent: 'text-cyan-400 bg-cyan-500/8 border-cyan-500/15' },
    standard: { label: 'Standard', accent: 'text-violet-400 bg-violet-500/8 border-violet-500/15' },
    deep: { label: 'Deep', accent: 'text-amber-400 bg-amber-500/8 border-amber-500/15' },
    custom: { label: 'Custom', accent: 'text-pink-400 bg-pink-500/8 border-pink-500/15' },
};

export default function ScansPage() {
    const { data, isLoading, refetch } = trpc.scan.list.useQuery({}, {
        refetchInterval: (q) => {
            const hasRunning = q.state.data?.items?.some((s: any) => s.status === 'running');
            return hasRunning ? 3000 : false;
        },
    });
    const stopMutation = trpc.scan.stop.useMutation({ onSuccess: () => refetch() });
    const deleteMutation = trpc.scan.delete.useMutation({ onSuccess: () => refetch() });

    const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
    const [filterStatus, setFilterStatus] = useState<string>('all');

    const filteredItems = (data?.items || []).filter((scan: any) =>
        filterStatus === 'all' || scan.status === filterStatus
    );

    const handleDelete = (scanId: string) => {
        if (deleteConfirm === scanId) {
            deleteMutation.mutate(scanId);
            setDeleteConfirm(null);
        } else {
            setDeleteConfirm(scanId);
            // Auto-cancel confirmation after 3s
            setTimeout(() => setDeleteConfirm(prev => prev === scanId ? null : prev), 3000);
        }
    };

    // Stats
    const stats = {
        total: data?.total || 0,
        running: data?.items?.filter((s: any) => s.status === 'running').length || 0,
        completed: data?.items?.filter((s: any) => s.status === 'completed').length || 0,
        failed: data?.items?.filter((s: any) => s.status === 'failed').length || 0,
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* ── Header ─────────────────────────────── */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3.5">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-brand-500/10 border border-brand-500/20">
                        <Radar className="w-5 h-5 text-violet-400" />
                    </div>
                    <div>
                        <h1 className="text-xl font-semibold text-white tracking-tight">Scans</h1>
                        <p className="text-xs text-gray-600 mt-0.5">{stats.total} total · {stats.running} active</p>
                    </div>
                </div>
                <Link href="/scans/new" className="btn-primary flex items-center gap-2 text-sm">
                    <Plus className="w-3.5 h-3.5" /> New Scan
                </Link>
            </div>

            {/* ── Quick Stats ────────────────────────── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                <MiniStatCard label="Total" value={stats.total} icon={<Radar className="w-3.5 h-3.5" />} color="text-white" />
                <MiniStatCard label="Running" value={stats.running} icon={<Loader2 className="w-3.5 h-3.5 animate-spin" />} color="text-emerald-400" dot="bg-emerald-400" />
                <MiniStatCard label="Completed" value={stats.completed} icon={<CheckCircle2 className="w-3.5 h-3.5" />} color="text-blue-400" />
                <MiniStatCard label="Failed" value={stats.failed} icon={<XCircle className="w-3.5 h-3.5" />} color="text-red-400" />
            </div>

            {/* ── Filter Tabs ────────────────────────── */}
            <div className="flex items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-gray-600" />
                <div className="flex gap-1 p-1 rounded-xl bg-white/[0.02] border border-white/[0.06]">
                    {['all', 'running', 'completed', 'failed', 'cancelled'].map(status => (
                        <button
                            key={status}
                            onClick={() => setFilterStatus(status)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 capitalize ${filterStatus === status
                                ? 'bg-violet-500/15 text-violet-300 border border-violet-500/20'
                                : 'text-gray-500 hover:text-gray-300 border border-transparent'
                                }`}
                        >
                            {status}
                        </button>
                    ))}
                </div>
                <span className="ml-auto text-xs text-gray-700 font-mono tabular-nums">{filteredItems.length}</span>
            </div>

            {/* ── Scan Cards ─────────────────────────── */}
            {isLoading ? (
                <div className="space-y-3">
                    {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="h-24 rounded-2xl bg-white/[0.02] animate-pulse border border-white/[0.04]"
                            style={{ animationDelay: `${i * 100}ms` }} />
                    ))}
                </div>
            ) : filteredItems.length > 0 ? (
                <div className="space-y-2.5">
                    {filteredItems.map((scan: any) => {
                        const statusCfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.queued;
                        const typeCfg = SCAN_TYPE_LABELS[scan.scanType] || SCAN_TYPE_LABELS.standard;
                        const vulnCount = scan._count?.vulnerabilities || 0;
                        const isRunning = scan.status === 'running';
                        const isDeleting = deleteMutation.isPending && deleteConfirm === null;

                        return (
                            <div
                                key={scan.id}
                                className="group relative rounded-2xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-xl overflow-hidden hover:border-white/[0.1] hover:bg-white/[0.03] transition-all duration-300"
                            >
                                {/* Running indicator - animated top border */}
                                {isRunning && (
                                    <div className="absolute inset-x-0 top-0 h-px overflow-hidden">
                                        <div className="h-full w-1/3 bg-gradient-to-r from-violet-500 to-cyan-500 opacity-60 animate-scan-sweep" />
                                    </div>
                                )}

                                <div className="flex items-center gap-4 px-5 py-4">
                                    {/* Status Icon */}
                                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 border ${statusCfg.bg} ${statusCfg.border}`}>
                                        <statusCfg.icon className={`w-4 h-4 ${statusCfg.color} ${isRunning ? 'animate-spin' : ''}`} />
                                    </div>

                                    {/* Main Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2.5">
                                            <Link href={`/scans/${scan.id}`}
                                                className="text-sm font-semibold text-gray-200 hover:text-white transition-colors truncate">
                                                {scan.target?.name || 'Unknown Target'}
                                            </Link>
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${typeCfg.accent}`}>
                                                {typeCfg.label}
                                            </span>
                                            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border ${statusCfg.bg} ${statusCfg.color} ${statusCfg.border}`}>
                                                {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
                                                {statusCfg.label}
                                            </span>
                                        </div>

                                        <div className="flex items-center gap-4 mt-1.5">
                                            {/* URL */}
                                            <span className="flex items-center gap-1 text-[11px] text-gray-600 font-mono truncate max-w-[300px]">
                                                <Globe className="w-3 h-3 flex-shrink-0 text-gray-700" />
                                                {scan.target?.baseUrl?.replace(/^https?:\/\//, '') || '-'}
                                            </span>

                                            {/* Progress (running only) */}
                                            {isRunning && (
                                                <div className="flex items-center gap-2">
                                                    <div className="w-20 h-1.5 rounded-full bg-white/[0.04] overflow-hidden">
                                                        <div
                                                            className="h-full rounded-full bg-gradient-to-r from-violet-500 to-cyan-500 transition-all duration-700 relative"
                                                            style={{ width: `${scan.progress}%` }}
                                                        >
                                                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/25 to-transparent animate-shimmer" />
                                                        </div>
                                                    </div>
                                                    <span className="text-[10px] text-gray-500 tabular-nums font-mono">{scan.progress}%</span>
                                                </div>
                                            )}

                                            {/* Current module */}
                                            {isRunning && scan.currentModule && (
                                                <span className="text-[10px] text-violet-400/50 font-mono truncate max-w-[120px]">
                                                    {scan.currentModule}
                                                </span>
                                            )}

                                            {/* Duration */}
                                            {scan.duration && (
                                                <span className="flex items-center gap-1 text-[11px] text-gray-600 tabular-nums">
                                                    <Clock className="w-3 h-3 text-gray-700" />
                                                    {scan.duration}s
                                                </span>
                                            )}

                                            {/* Date */}
                                            <span className="text-[11px] text-gray-700">
                                                {new Date(scan.createdAt).toLocaleDateString('en-US', {
                                                    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
                                                })}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Right side — Stats + Actions */}
                                    <div className="flex items-center gap-3 flex-shrink-0">
                                        {/* Vuln count */}
                                        {vulnCount > 0 && (
                                            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-500/5 border border-red-500/10">
                                                <Bug className="w-3 h-3 text-red-400/70" />
                                                <span className="text-xs font-semibold text-red-400 tabular-nums">{vulnCount}</span>
                                            </div>
                                        )}
                                        {vulnCount === 0 && !isRunning && (
                                            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.02] border border-white/[0.06]">
                                                <Bug className="w-3 h-3 text-gray-700" />
                                                <span className="text-xs text-gray-600 tabular-nums">0</span>
                                            </div>
                                        )}

                                        {/* View button */}
                                        <Link href={`/scans/${scan.id}`}
                                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white bg-white/[0.03] border border-white/[0.06] hover:border-white/[0.12] hover:bg-white/[0.06] transition-all duration-200">
                                            <ExternalLink className="w-3 h-3" />
                                            View
                                        </Link>

                                        {/* Stop button */}
                                        {isRunning && (
                                            <button
                                                onClick={() => stopMutation.mutate(scan.id)}
                                                disabled={stopMutation.isPending}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-amber-400/70 hover:text-amber-400 bg-amber-500/5 border border-amber-500/10 hover:border-amber-500/20 hover:bg-amber-500/10 transition-all duration-200"
                                            >
                                                <StopCircle className="w-3 h-3" />
                                                Stop
                                            </button>
                                        )}

                                        {/* Delete button */}
                                        {!isRunning && (
                                            <button
                                                onClick={() => handleDelete(scan.id)}
                                                disabled={isDeleting}
                                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 ${deleteConfirm === scan.id
                                                    ? 'text-red-400 bg-red-500/15 border border-red-500/30 shadow-sm shadow-red-500/10'
                                                    : 'text-gray-600 hover:text-red-400/80 bg-white/[0.02] border border-white/[0.06] hover:border-red-500/15 hover:bg-red-500/5'
                                                    }`}
                                            >
                                                <Trash2 className="w-3 h-3" />
                                                {deleteConfirm === scan.id ? 'Confirm?' : 'Delete'}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            ) : (
                /* ── Empty State ─────────────────────── */
                <div className="flex flex-col items-center justify-center py-20 gap-4">
                    <div className="w-14 h-14 rounded-2xl flex items-center justify-center bg-brand-500/10 border border-brand-500/20">
                        <Radar className="w-6 h-6 text-gray-600" />
                    </div>
                    <div className="text-center">
                        <p className="text-sm text-gray-400 font-medium">No scans found</p>
                        <p className="text-xs text-gray-600 mt-1">
                            {filterStatus !== 'all' ? 'Try changing the filter' : 'Start your first vulnerability scan'}
                        </p>
                    </div>
                    {filterStatus === 'all' && (
                        <Link href="/scans/new" className="btn-primary mt-2 text-sm flex items-center gap-2">
                            <Plus className="w-3.5 h-3.5" /> Start First Scan
                        </Link>
                    )}
                </div>
            )}

            {/* ── Delete Error Toast ─────────────────── */}
            {deleteMutation.isError && (
                <div className="fixed bottom-6 right-6 z-50 animate-fade-in">
                    <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 backdrop-blur-xl shadow-xl shadow-red-500/5">
                        <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
                        <p className="text-sm text-red-300">{deleteMutation.error.message}</p>
                    </div>
                </div>
            )}
        </div>
    );
}

/* ══════════════════════════════════════════════════════════
   Sub-components
   ══════════════════════════════════════════════════════════ */

function MiniStatCard({ label, value, icon, color, dot }: {
    label: string; value: number; icon: React.ReactNode; color: string; dot?: string;
}) {
    return (
        <div className="group rounded-xl border border-white/[0.06] bg-white/[0.02] backdrop-blur-md p-3 hover:bg-white/[0.04] hover:border-white/[0.1] transition-all duration-300">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <span className={`${color} opacity-60`}>{icon}</span>
                    <p className="text-[10px] text-gray-600 uppercase tracking-wider font-medium">{label}</p>
                </div>
                {dot && <span className={`w-1.5 h-1.5 rounded-full ${dot} animate-pulse shadow-sm`} />}
            </div>
            <p className={`text-lg font-semibold tabular-nums mt-1 ${color}`}>{value}</p>
        </div>
    );
}
