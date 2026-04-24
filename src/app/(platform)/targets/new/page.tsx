'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { Target, ArrowLeft, Globe, Shield, Save, Lock, Plus, Trash2, KeyRound, AlertTriangle } from 'lucide-react';
import Link from 'next/link';

function buildAuthConfig(
    authType: string,
    token: string,
    cookie: string,
    headers: { key: string; value: string }[],
): Record<string, unknown> | undefined {
    if (authType === 'token' && token)
        return { token };
    if (authType === 'cookie' && cookie)
        return { cookie };
    if (authType === 'session') {
        const h: Record<string, string> = {};
        for (const row of headers) {
            if (row.key.trim()) h[row.key.trim()] = row.value;
        }
        return Object.keys(h).length ? { headers: h } : undefined;
    }
    return undefined;
}

export default function NewTargetPage() {
    const router = useRouter();
    const [form, setForm] = useState({
        name: '',
        baseUrl: '',
        description: '',
        environment: 'development',
        criticality: 'medium',
        authType: 'none',
        maxCrawlDepth: 10,
        maxUrls: 500,
        rateLimit: 10,
    });
    const [authToken, setAuthToken] = useState('');
    const [authCookie, setAuthCookie] = useState('');
    const [authHeaders, setAuthHeaders] = useState([{ key: '', value: '' }]);

    const createMutation = trpc.target.create.useMutation({
        onSuccess: (data) => {
            // Production / staging targets require a signed scope approval
            // before scans can start. Auto-navigate the user to the scope
            // page with a pre-filled rationale so they don't have to hunt
            // for it. Development targets go straight to the detail view.
            const needsScope = form.environment === 'production' || form.environment === 'staging';
            if (needsScope) {
                router.push(`/targets/${data.id}/scope?rationale=auto-created`);
            } else {
                router.push(`/targets/${data.id}`);
            }
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        createMutation.mutate({
            name: form.name,
            baseUrl: form.baseUrl,
            description: form.description || undefined,
            environment: form.environment as any,
            criticality: form.criticality as any,
            authType: form.authType as any,
            authConfig: buildAuthConfig(form.authType, authToken, authCookie, authHeaders),
            maxCrawlDepth: form.maxCrawlDepth,
            maxUrls: form.maxUrls,
            rateLimit: form.rateLimit,
        });
    };

    const addHeaderRow = () => setAuthHeaders(h => [...h, { key: '', value: '' }]);
    const removeHeaderRow = (i: number) => setAuthHeaders(h => h.filter((_, idx) => idx !== i));
    const updateHeader = (i: number, field: 'key' | 'value', val: string) =>
        setAuthHeaders(h => h.map((row, idx) => idx === i ? { ...row, [field]: val } : row));

    return (
        <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
            <div className="flex items-center gap-3">
                <Link href="/targets" className="p-2 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all">
                    <ArrowLeft className="w-5 h-5" />
                </Link>
                <div className="page-header !mb-0">
                    <h1 className="page-title">New Target</h1>
                    <p className="page-subtitle">Register a new web application for scanning</p>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="glass-card space-y-5">
                {/* Basic Info */}
                <div className="space-y-4">
                    <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        <Globe className="w-4 h-4" style={{ color: 'var(--accent)' }} /> Basic Information
                    </h3>
                    <div>
                        <label className="input-label">Target Name *</label>
                        <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                            placeholder="e.g., Main Website" className="input-field" required />
                    </div>
                    <div>
                        <label className="input-label">Base URL *</label>
                        <input type="url" value={form.baseUrl} onChange={e => setForm({ ...form, baseUrl: e.target.value })}
                            placeholder="https://example.com" className="input-field font-mono" required />
                        <p className="mt-1.5 text-[10px] text-gray-500 leading-relaxed">
                            Accepts <code className="text-gray-400">http://</code> or <code className="text-gray-400">https://</code>.
                            Internal hosts (<code className="text-gray-400">localhost</code>, <code className="text-gray-400">192.168.x</code>, <code className="text-gray-400">10.x</code>, <code className="text-gray-400">172.16–31.x</code>)
                            require <code className="text-amber-400">SCANNER_ALLOW_INTERNAL_TARGETS=true</code> in the server .env file.
                        </p>
                    </div>
                    <div>
                        <label className="input-label">Description</label>
                        <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
                            placeholder="Brief description of the target..." className="input-field" rows={2} />
                    </div>
                </div>

                {/* Classification */}
                <div className="space-y-4 pt-4 border-t border-[var(--border-subtle)]">
                    <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        <Shield className="w-4 h-4" style={{ color: 'var(--accent)' }} /> Classification
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="input-label">Environment</label>
                            <select value={form.environment} onChange={e => setForm({ ...form, environment: e.target.value })} className="input-field">
                                <option value="development">Development</option>
                                <option value="internal">Internal</option>
                                <option value="staging">Staging</option>
                                <option value="production">Production</option>
                            </select>
                            {(form.environment === 'production' || form.environment === 'staging') && (
                                <div className="mt-2 flex items-start gap-2 text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
                                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                                    <span>
                                        Scans against <strong>{form.environment}</strong> targets require a scope approval signed by a security_lead before scanning.
                                        You can add one from the target's <strong>Scope</strong> page after creating it.
                                    </span>
                                </div>
                            )}
                        </div>
                        <div>
                            <label className="input-label">Business Criticality</label>
                            <select value={form.criticality} onChange={e => setForm({ ...form, criticality: e.target.value })} className="input-field">
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                    </div>
                </div>

                {/* Scan Config */}
                <div className="space-y-4 pt-4 border-t border-[var(--border-subtle)]">
                    <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        <Target className="w-4 h-4" style={{ color: 'var(--accent)' }} /> Scan Configuration
                    </h3>
                    <div className="grid grid-cols-3 gap-4">
                        <div>
                            <label className="input-label">Max Crawl Depth</label>
                            <input type="number" value={form.maxCrawlDepth}
                                onChange={e => setForm({ ...form, maxCrawlDepth: parseInt(e.target.value) })}
                                className="input-field" min="1" max="50" />
                        </div>
                        <div>
                            <label className="input-label">Max URLs</label>
                            <input type="number" value={form.maxUrls}
                                onChange={e => setForm({ ...form, maxUrls: parseInt(e.target.value) })}
                                className="input-field" min="1" max="5000" />
                        </div>
                        <div>
                            <label className="input-label">Rate Limit (req/s)</label>
                            <input type="number" value={form.rateLimit}
                                onChange={e => setForm({ ...form, rateLimit: parseInt(e.target.value) })}
                                className="input-field" min="1" max="100" />
                        </div>
                    </div>
                </div>

                {/* Authentication */}
                <div className="space-y-4 pt-4 border-t border-[var(--border-subtle)]">
                    <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        <Lock className="w-4 h-4" style={{ color: 'var(--accent)' }} /> Authentication
                    </h3>
                    <div>
                        <label className="input-label">Auth Type</label>
                        <select value={form.authType} onChange={e => setForm({ ...form, authType: e.target.value })} className="input-field">
                            <option value="none">None — scan without authentication</option>
                            <option value="token">Bearer Token — Authorization header</option>
                            <option value="cookie">Cookie — session cookie string</option>
                            <option value="session">Session Headers — custom header(s)</option>
                        </select>
                    </div>

                    {/* Bearer Token */}
                    {form.authType === 'token' && (
                        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-3">
                            <p className="text-xs text-[var(--text-muted)] flex items-center gap-1.5">
                                <KeyRound className="w-3.5 h-3.5" />
                                Sent as <code className="font-mono bg-[var(--bg-code)] px-1 rounded">Authorization: Bearer &lt;token&gt;</code>
                            </p>
                            <div>
                                <label className="input-label">Token Value</label>
                                <input type="password" value={authToken} onChange={e => setAuthToken(e.target.value)}
                                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                    className="input-field font-mono" autoComplete="off" />
                            </div>
                        </div>
                    )}

                    {/* Cookie */}
                    {form.authType === 'cookie' && (
                        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-3">
                            <p className="text-xs text-[var(--text-muted)] flex items-center gap-1.5">
                                <KeyRound className="w-3.5 h-3.5" />
                                Sent as <code className="font-mono bg-[var(--bg-code)] px-1 rounded">Cookie: &lt;value&gt;</code>
                            </p>
                            <div>
                                <label className="input-label">Cookie String</label>
                                <input type="text" value={authCookie} onChange={e => setAuthCookie(e.target.value)}
                                    placeholder="sessionid=abc123; csrftoken=xyz456"
                                    className="input-field font-mono" autoComplete="off" />
                                <p className="text-xs text-[var(--text-muted)] mt-1">Copy from browser DevTools → Application → Cookies</p>
                            </div>
                        </div>
                    )}

                    {/* Session Headers */}
                    {form.authType === 'session' && (
                        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-4 space-y-3">
                            <p className="text-xs text-[var(--text-muted)] flex items-center gap-1.5">
                                <KeyRound className="w-3.5 h-3.5" />
                                Custom headers added to every request
                            </p>
                            <div className="space-y-2">
                                {authHeaders.map((row, i) => (
                                    <div key={i} className="flex gap-2 items-center">
                                        <input type="text" value={row.key} onChange={e => updateHeader(i, 'key', e.target.value)}
                                            placeholder="Header name (e.g. X-Auth-Token)"
                                            className="input-field font-mono flex-1" />
                                        <span className="text-[var(--text-muted)] text-sm">:</span>
                                        <input type="text" value={row.value} onChange={e => updateHeader(i, 'value', e.target.value)}
                                            placeholder="Value"
                                            className="input-field font-mono flex-1" />
                                        {authHeaders.length > 1 && (
                                            <button type="button" onClick={() => removeHeaderRow(i)}
                                                className="p-1.5 rounded-md text-[var(--text-muted)] hover:text-red-500 hover:bg-red-50 transition-all flex-shrink-0">
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                ))}
                                <button type="button" onClick={addHeaderRow}
                                    className="flex items-center gap-1.5 text-xs text-[var(--accent)] hover:underline mt-1">
                                    <Plus className="w-3.5 h-3.5" /> Add header
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {/* Actions */}
                <div className="flex gap-3 pt-4 border-t border-[var(--border-subtle)]">
                    <button type="submit" disabled={createMutation.isPending} className="btn-primary flex items-center gap-2">
                        {createMutation.isPending
                            ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            : <Save className="w-4 h-4" />}
                        {createMutation.isPending ? 'Creating...' : 'Create Target'}
                    </button>
                    <Link href="/targets" className="btn-secondary">Cancel</Link>
                </div>

                {createMutation.isError && (
                    <div className="bg-red-600/10 border border-red-600/20 rounded-lg px-4 py-2.5 text-red-500 text-sm">
                        {createMutation.error.message}
                    </div>
                )}
            </form>
        </div>
    );
}
