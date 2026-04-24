// InjectProof — Settings Page
// ============================
// Controlled form wired to settings.* tRPC procedures. Before this rewrite
// every input was a dead-end stub (defaultValue + no onChange, "Save Settings"
// with no handler). Now:
//  - Profile name actually persists (email/role stay read-only — email change
//    needs an audit trail we haven't built, role change is admin-only).
//  - Notification prefs round-trip through NotificationConfig.
//  - The old "Default Scan Settings" block has been removed — those are per-
//    Target and the Target form already captures them. We replaced it with a
//    small info card pointing users at /targets/new.

'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Settings, User, Bell, Database, Shield, Save, CheckCircle2, AlertCircle, ExternalLink, KeyRound } from 'lucide-react';
import { trpc } from '@/trpc/client';

type FeedbackState = { kind: 'idle' } | { kind: 'success'; message: string } | { kind: 'error'; message: string };

export default function SettingsPage() {
    const profileQuery = trpc.settings.getProfile.useQuery();
    const notifyQuery = trpc.settings.getNotificationPrefs.useQuery();
    const updateProfile = trpc.settings.updateProfile.useMutation();
    const updateNotifyPrefs = trpc.settings.updateNotificationPrefs.useMutation();

    const [name, setName] = useState('');
    const [prefs, setPrefs] = useState({
        criticalVuln: false,
        scanCompleted: false,
        slaOverdue: false,
        newTarget: false,
    });
    const [feedback, setFeedback] = useState<FeedbackState>({ kind: 'idle' });

    // Hydrate local state once each query returns. Using a secondary effect
    // rather than initialising useState to make reset-on-reload predictable.
    useEffect(() => {
        if (profileQuery.data?.name && name === '') setName(profileQuery.data.name);
    }, [profileQuery.data, name]);
    useEffect(() => {
        if (notifyQuery.data) setPrefs(notifyQuery.data);
    }, [notifyQuery.data]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setFeedback({ kind: 'idle' });
        try {
            // Fire both in parallel — they touch different tables so ordering
            // doesn't matter. Surface the first error if any fail.
            await Promise.all([
                updateProfile.mutateAsync({ name }),
                updateNotifyPrefs.mutateAsync(prefs),
            ]);
            await Promise.all([profileQuery.refetch(), notifyQuery.refetch()]);
            setFeedback({ kind: 'success', message: 'Settings saved. Changes are live across the platform.' });
        } catch (err) {
            setFeedback({
                kind: 'error',
                message: err instanceof Error ? err.message : 'Failed to save settings',
            });
        }
    };

    const user = profileQuery.data;
    const isBusy = updateProfile.isPending || updateNotifyPrefs.isPending;

    const NOTIFICATION_ROWS: Array<{ key: keyof typeof prefs; label: string; help: string }> = [
        { key: 'criticalVuln', label: 'New Critical Vulnerability', help: 'Fires when a scan discovers a finding scored critical.' },
        { key: 'scanCompleted', label: 'Scan Completed', help: 'Fires when any scan transitions to completed or failed.' },
        { key: 'slaOverdue', label: 'SLA Overdue', help: 'Fires when an open finding exceeds its severity-based remediation deadline.' },
        { key: 'newTarget', label: 'New Target Added', help: 'Fires when anyone on the team registers a new target.' },
    ];

    return (
        <form onSubmit={handleSubmit} className="space-y-6 animate-fade-in max-w-3xl">
            <div className="page-header">
                <h1 className="page-title flex items-center gap-3">
                    <div className="w-8 h-8 rounded-xl flex items-center justify-center bg-slate-500/10 border border-slate-500/20">
                        <Settings className="w-4 h-4 text-gray-400" />
                    </div>
                    Settings
                </h1>
                <p className="page-subtitle">Profile and notification preferences for your account</p>
            </div>

            {/* ── Profile ── */}
            <div className="glass-card space-y-4">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2 relative z-10">
                    <User className="w-4 h-4 text-brand-400" /> Profile
                </h3>
                <div className="grid grid-cols-2 gap-4 relative z-10">
                    <div>
                        <label className="input-label">Name</label>
                        <input
                            type="text"
                            value={name}
                            onChange={e => setName(e.target.value)}
                            disabled={profileQuery.isLoading || isBusy}
                            className="input-field"
                            placeholder={profileQuery.isLoading ? 'Loading…' : 'Your display name'}
                            maxLength={80}
                            required
                        />
                    </div>
                    <div>
                        <label className="input-label">
                            Email <span className="text-[10px] text-gray-500">(read-only)</span>
                        </label>
                        <input type="email" value={user?.email ?? ''} className="input-field" disabled />
                    </div>
                </div>
                <div className="grid grid-cols-2 gap-4 relative z-10">
                    <div>
                        <label className="input-label">
                            Role <span className="text-[10px] text-gray-500">(managed by admin)</span>
                        </label>
                        <input type="text" value={user?.role ?? ''} className="input-field capitalize" disabled />
                    </div>
                    <div>
                        <label className="input-label">Multi-factor Authentication</label>
                        <div className="input-field flex items-center" style={{ background: 'var(--bg-subtle)' }}>
                            {user?.mfaEnabled
                                ? <span className="text-sm text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" /> Enabled</span>
                                : <span className="text-sm text-gray-500 flex items-center gap-1.5"><AlertCircle className="w-3.5 h-3.5" /> Not configured</span>}
                        </div>
                    </div>
                </div>
                <div className="pt-2 relative z-10">
                    <Link
                        href="/settings/password"
                        className="inline-flex items-center gap-2 text-xs text-brand-400 hover:text-brand-300 transition-colors"
                    >
                        <KeyRound className="w-3.5 h-3.5" /> Change password
                    </Link>
                </div>
            </div>

            {/* ── Scanner defaults info card ── */}
            {/* The old "Default Scan Settings" block has been removed — those
                values (maxCrawlDepth, maxUrls, rateLimit, userAgent) belong on
                individual Target records and the Target form already captures
                them. Keeping a stub on Settings would suggest a global default
                that doesn't actually exist — worse UX than no block at all. */}
            <div className="glass-card relative z-10">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2 mb-3">
                    <Shield className="w-4 h-4 text-brand-400" /> Scanner Defaults
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                    Scanner settings (crawl depth, URL cap, rate limit, auth) are configured
                    <strong className="text-gray-200"> per target</strong> — each app you assess
                    has its own scan profile. Visit the Target form to set them.
                </p>
                <Link
                    href="/targets/new"
                    className="inline-flex items-center gap-2 mt-3 text-sm text-brand-400 hover:text-brand-300 transition-colors"
                >
                    Go to Target form <ExternalLink className="w-3.5 h-3.5" />
                </Link>
            </div>

            {/* ── Notifications ── */}
            <div className="glass-card space-y-4">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2 relative z-10">
                    <Bell className="w-4 h-4 text-brand-400" /> Notifications
                </h3>
                <div className="space-y-2 relative z-10">
                    {NOTIFICATION_ROWS.map(row => (
                        <label
                            key={row.key}
                            className="flex items-start justify-between gap-3 p-3 rounded-xl cursor-pointer transition-all hover:bg-white/[0.02]"
                            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)' }}
                        >
                            <div className="flex-1 min-w-0">
                                <span className="block text-sm text-[var(--text-primary)]">{row.label}</span>
                                <span className="block text-[11px] text-gray-500 mt-0.5">{row.help}</span>
                            </div>
                            <input
                                type="checkbox"
                                checked={prefs[row.key]}
                                onChange={e => setPrefs(prev => ({ ...prev, [row.key]: e.target.checked }))}
                                disabled={notifyQuery.isLoading || isBusy}
                                className="mt-0.5 rounded border-gray-600 bg-transparent text-brand-500 focus:ring-brand-500/20"
                            />
                        </label>
                    ))}
                </div>
            </div>

            {/* ── Database (info only) ── */}
            <div className="glass-card space-y-3">
                <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2 relative z-10">
                    <Database className="w-4 h-4 text-brand-400" /> Database
                </h3>
                <div className="flex items-center gap-3 relative z-10">
                    <span className="text-sm text-gray-400">Storage: SQLite (Local)</span>
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span className="text-xs text-green-400">Connected</span>
                </div>
            </div>

            {/* ── Feedback + Save ── */}
            {feedback.kind === 'success' && (
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 flex items-start gap-2 text-sm text-emerald-300">
                    <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <span>{feedback.message}</span>
                </div>
            )}
            {feedback.kind === 'error' && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 flex items-start gap-2 text-sm text-red-300">
                    <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <span>{feedback.message}</span>
                </div>
            )}
            <div className="flex items-center gap-3">
                <button type="submit" disabled={isBusy || profileQuery.isLoading} className="btn-primary inline-flex items-center gap-2 disabled:opacity-50">
                    {isBusy
                        ? <><div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Saving…</>
                        : <><Save className="w-4 h-4" /> Save Settings</>}
                </button>
                {profileQuery.isLoading && <span className="text-xs text-gray-500">Loading profile…</span>}
            </div>
        </form>
    );
}
