// VibeCode — Dashboard Page (Deep Glassmorphism)
'use client';

import { trpc } from '@/trpc/client';
import {
    Target, Radar, Bug, AlertTriangle, CheckCircle,
    Activity, TrendingUp, Sparkles, Brain, Cpu,
} from 'lucide-react';
import {
    PieChart, Pie, Cell, Tooltip, ResponsiveContainer, AreaChart, Area,
    XAxis, YAxis, CartesianGrid,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#f87171',
    high: '#fb923c',
    medium: '#fbbf24',
    low: '#60a5fa',
    info: '#6b7280',
};

export default function DashboardPage() {
    const { data: stats, isLoading: statsLoading } = trpc.dashboard.stats.useQuery();
    const { data: severityData } = trpc.dashboard.severityDistribution.useQuery();
    const { data: trendData } = trpc.dashboard.trendData.useQuery();
    const { data: recentScans } = trpc.dashboard.recentScans.useQuery(5);

    if (statsLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="flex flex-col items-center gap-3">
                    <div className="w-10 h-10 rounded-2xl flex items-center justify-center bg-brand-500/10 border border-brand-500/20 neural-pulse">
                        <Cpu className="w-5 h-5 text-brand-400 animate-pulse" />
                    </div>
                    <span className="text-xs text-gray-500">Loading dashboard...</span>
                </div>
            </div>
        );
    }

    const tooltipStyle = {
        background: 'rgba(10, 15, 30, 0.9)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '14px',
        color: '#e2e8f0',
        fontSize: '12px',
        backdropFilter: 'blur(24px)',
        boxShadow: '0 8px 40px rgba(0,0,0,0.3)',
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Page Header */}
            <div className="page-header flex items-center justify-between">
                <div>
                    <h1 className="page-title flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl flex items-center justify-center bg-brand-500/10 border border-brand-500/20">
                            <Activity className="w-4 h-4 text-brand-400" />
                        </div>
                        Dashboard
                    </h1>
                    <p className="page-subtitle mt-1">Global security overview and AI-powered insights</p>
                </div>
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-brand-500/5 border border-brand-500/10 text-[11px] text-gray-500">
                    <Sparkles className="w-3.5 h-3.5 text-brand-400" />
                    <span>AI Analysis Active</span>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <StatCard icon={<Target className="w-5 h-5" />} label="Targets" value={stats?.totalTargets || 0} color="brand" />
                <StatCard icon={<Radar className="w-5 h-5" />} label="Total Scans" value={stats?.totalScans || 0} color="blue" />
                <StatCard icon={<Bug className="w-5 h-5" />} label="Vulnerabilities" value={stats?.totalVulnerabilities || 0} color="amber" />
                <StatCard icon={<AlertTriangle className="w-5 h-5" />} label="Critical + High" value={(stats?.criticalVulns || 0) + (stats?.highVulns || 0)} color="red" />
                <StatCard icon={<CheckCircle className="w-5 h-5" />} label="Fixed" value={stats?.fixedVulns || 0} color="green" />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Severity Distribution */}
                <div className="glass-card">
                    <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2 relative z-10">
                        <div className="w-1.5 h-1.5 rounded-full bg-brand-400" style={{ boxShadow: '0 0 6px rgba(129,140,248,0.4)' }} />
                        Severity Distribution
                    </h3>
                    {severityData && severityData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <PieChart>
                                <Pie dataKey="count" data={severityData} cx="50%" cy="50%" outerRadius={80} innerRadius={45} paddingAngle={4} strokeWidth={0}>
                                    {severityData.map((entry, i) => (
                                        <Cell key={i} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={tooltipStyle} />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="flex flex-col items-center justify-center h-[220px] text-gray-700 text-sm gap-2">
                            <Brain className="w-8 h-8 text-gray-800" />
                            <span>No data yet</span>
                        </div>
                    )}
                    <div className="flex flex-wrap gap-3 mt-2 justify-center relative z-10">
                        {Object.entries(SEVERITY_COLORS).map(([key, color]) => (
                            <div key={key} className="flex items-center gap-1.5">
                                <div className="w-2 h-2 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}40` }} />
                                <span className="text-[11px] text-gray-500 capitalize">{key}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Trend Chart */}
                <div className="glass-card lg:col-span-2">
                    <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2 relative z-10">
                        <TrendingUp className="w-4 h-4 text-brand-400" />
                        30-Day Vulnerability Trend
                    </h3>
                    {trendData && trendData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={250}>
                            <AreaChart data={trendData}>
                                <defs>
                                    <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f87171" stopOpacity={0.2} /><stop offset="95%" stopColor="#f87171" stopOpacity={0} /></linearGradient>
                                    <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#fb923c" stopOpacity={0.2} /><stop offset="95%" stopColor="#fb923c" stopOpacity={0} /></linearGradient>
                                    <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#fbbf24" stopOpacity={0.15} /><stop offset="95%" stopColor="#fbbf24" stopOpacity={0} /></linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
                                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#475569' }} tickFormatter={(v) => v.slice(5)} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fontSize: 10, fill: '#475569' }} axisLine={false} tickLine={false} />
                                <Tooltip contentStyle={tooltipStyle} />
                                <Area type="monotone" dataKey="critical" stroke="#f87171" fill="url(#critGrad)" strokeWidth={2} dot={false} />
                                <Area type="monotone" dataKey="high" stroke="#fb923c" fill="url(#highGrad)" strokeWidth={2} dot={false} />
                                <Area type="monotone" dataKey="medium" stroke="#fbbf24" fill="url(#medGrad)" strokeWidth={2} dot={false} />
                            </AreaChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="flex flex-col items-center justify-center h-[250px] text-gray-700 text-sm gap-2">
                            <Radar className="w-8 h-8 text-gray-800" />
                            <span>No data yet — run your first scan!</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Recent Scans */}
            <div className="glass-card">
                <div className="flex items-center justify-between mb-4 relative z-10">
                    <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ boxShadow: '0 0 6px rgba(52, 211, 153, 0.4)' }} />
                        Recent Scans
                    </h3>
                    <a href="/scans" className="text-[11px] text-brand-400/70 hover:text-brand-400 transition-colors">View all →</a>
                </div>
                {recentScans && recentScans.length > 0 ? (
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Target</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Vulns</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recentScans.map((scan: any) => (
                                <tr key={scan.id} className="cursor-pointer hover-lift" onClick={() => window.location.href = `/scans/${scan.id}`}>
                                    <td className="font-medium text-gray-200">{scan.target?.name}</td>
                                    <td><span className="capitalize text-xs text-gray-400">{scan.scanType}</span></td>
                                    <td><StatusBadge status={scan.status} /></td>
                                    <td className="font-mono text-xs">{scan._count?.vulnerabilities || 0}</td>
                                    <td className="text-xs text-gray-600">{new Date(scan.createdAt).toLocaleDateString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <div className="text-center py-10 text-gray-700 text-sm">
                        No scans yet. <a href="/scans/new" className="text-brand-400/70 hover:text-brand-400 transition-colors">Start your first scan →</a>
                    </div>
                )}
            </div>

            {/* Severity Summary */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <SeverityCard severity="Critical" count={stats?.criticalVulns || 0} color="#f87171" />
                <SeverityCard severity="High" count={stats?.highVulns || 0} color="#fb923c" />
                <SeverityCard severity="Medium" count={stats?.mediumVulns || 0} color="#fbbf24" />
                <SeverityCard severity="Low" count={stats?.lowVulns || 0} color="#60a5fa" />
                <SeverityCard severity="Info" count={stats?.infoVulns || 0} color="#6b7280" />
            </div>
        </div>
    );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
    const glowMap: Record<string, { border: string; glow: string; iconColor: string }> = {
        brand: { border: 'rgba(129,140,248,0.1)', glow: 'rgba(99,102,241,0.06)', iconColor: 'text-brand-400' },
        blue: { border: 'rgba(96,165,250,0.1)', glow: 'rgba(96,165,250,0.06)', iconColor: 'text-blue-400' },
        amber: { border: 'rgba(251,191,36,0.1)', glow: 'rgba(251,191,36,0.06)', iconColor: 'text-amber-400' },
        red: { border: 'rgba(248,113,113,0.1)', glow: 'rgba(248,113,113,0.06)', iconColor: 'text-red-400' },
        green: { border: 'rgba(52,211,153,0.1)', glow: 'rgba(52,211,153,0.06)', iconColor: 'text-emerald-400' },
    };
    const cfg = glowMap[color] || glowMap.brand;

    return (
        <div className="stat-card hover-lift"
            style={{ borderColor: cfg.border, boxShadow: `inset 0 1px 0 rgba(255,255,255,0.03)` }}>
            <div className="flex items-center justify-between mb-3 relative z-10">
                <span className={`${cfg.iconColor} opacity-70`}>{icon}</span>
            </div>
            <p className="text-2xl font-bold text-white tracking-tight relative z-10">{value.toLocaleString()}</p>
            <p className="text-[11px] text-gray-500 mt-1 font-medium relative z-10">{label}</p>
        </div>
    );
}

function SeverityCard({ severity, count, color }: { severity: string; count: number; color: string }) {
    return (
        <div className="glass-card !p-4 flex items-center gap-3 hover-lift">
            <div className="w-3 h-3 rounded-full flex-shrink-0 relative z-10" style={{ background: color, boxShadow: `0 0 12px ${color}30` }} />
            <div className="relative z-10">
                <p className="text-xl font-bold text-white tracking-tight">{count}</p>
                <p className="text-[11px] text-gray-600 font-medium">{severity}</p>
            </div>
        </div>
    );
}

function StatusBadge({ status }: { status: string }) {
    const styles: Record<string, { bg: string; text: string; border: string }> = {
        queued: { bg: 'rgba(251,191,36,0.06)', text: '#fbbf24', border: 'rgba(251,191,36,0.1)' },
        running: { bg: 'rgba(52,211,153,0.06)', text: '#34d399', border: 'rgba(52,211,153,0.1)' },
        completed: { bg: 'rgba(96,165,250,0.06)', text: '#60a5fa', border: 'rgba(96,165,250,0.1)' },
        failed: { bg: 'rgba(248,113,113,0.06)', text: '#f87171', border: 'rgba(248,113,113,0.1)' },
        cancelled: { bg: 'rgba(148,163,184,0.06)', text: '#94a3b8', border: 'rgba(148,163,184,0.1)' },
    };
    const s = styles[status] || styles.cancelled;
    return (
        <span
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-medium"
            style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}`, backdropFilter: 'blur(12px)' }}
        >
            {status === 'running' && <span className="status-live" />}
            {status}
        </span>
    );
}
