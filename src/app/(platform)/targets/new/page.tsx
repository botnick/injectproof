// VibeCode — New Target Form
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { Target, ArrowLeft, Globe, Shield, Save } from 'lucide-react';
import Link from 'next/link';

export default function NewTargetPage() {
    const router = useRouter();
    const [form, setForm] = useState({
        name: '',
        baseUrl: '',
        description: '',
        environment: 'production',
        criticality: 'medium',
        authType: 'none',
        maxCrawlDepth: 10,
        maxUrls: 500,
        rateLimit: 10,
    });

    const createMutation = trpc.target.create.useMutation({
        onSuccess: (data) => {
            router.push(`/targets/${data.id}`);
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
            maxCrawlDepth: form.maxCrawlDepth,
            maxUrls: form.maxUrls,
            rateLimit: form.rateLimit,
        });
    };

    return (
        <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
            <div className="flex items-center gap-3">
                <Link href="/targets" className="p-2 rounded-lg hover:bg-surface-800/50 text-gray-400 hover:text-white transition-all">
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
                    <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2"><Globe className="w-4 h-4 text-brand-400" /> Basic Information</h3>
                    <div>
                        <label className="input-label">Target Name *</label>
                        <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g., Main Website" className="input-field" required />
                    </div>
                    <div>
                        <label className="input-label">Base URL *</label>
                        <input type="url" value={form.baseUrl} onChange={e => setForm({ ...form, baseUrl: e.target.value })} placeholder="https://example.com" className="input-field font-mono" required />
                    </div>
                    <div>
                        <label className="input-label">Description</label>
                        <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Brief description of the target..." className="input-field" rows={3} />
                    </div>
                </div>

                {/* Classification */}
                <div className="space-y-4 pt-4 border-t border-surface-700">
                    <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2"><Shield className="w-4 h-4 text-brand-400" /> Classification</h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="input-label">Environment</label>
                            <select value={form.environment} onChange={e => setForm({ ...form, environment: e.target.value })} className="input-field">
                                <option value="production">Production</option>
                                <option value="staging">Staging</option>
                                <option value="development">Development</option>
                                <option value="internal">Internal</option>
                            </select>
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
                <div className="space-y-4 pt-4 border-t border-surface-700">
                    <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2"><Target className="w-4 h-4 text-brand-400" /> Scan Configuration</h3>
                    <div className="grid grid-cols-3 gap-4">
                        <div>
                            <label className="input-label">Max Crawl Depth</label>
                            <input type="number" value={form.maxCrawlDepth} onChange={e => setForm({ ...form, maxCrawlDepth: parseInt(e.target.value) })} className="input-field" min="1" max="50" />
                        </div>
                        <div>
                            <label className="input-label">Max URLs</label>
                            <input type="number" value={form.maxUrls} onChange={e => setForm({ ...form, maxUrls: parseInt(e.target.value) })} className="input-field" min="1" max="5000" />
                        </div>
                        <div>
                            <label className="input-label">Rate Limit (req/s)</label>
                            <input type="number" value={form.rateLimit} onChange={e => setForm({ ...form, rateLimit: parseInt(e.target.value) })} className="input-field" min="1" max="100" />
                        </div>
                    </div>
                    <div>
                        <label className="input-label">Authentication</label>
                        <select value={form.authType} onChange={e => setForm({ ...form, authType: e.target.value })} className="input-field">
                            <option value="none">None</option>
                            <option value="token">Bearer Token</option>
                            <option value="cookie">Cookie</option>
                            <option value="session">Session Headers</option>
                        </select>
                    </div>
                </div>

                {/* Actions */}
                <div className="flex gap-3 pt-4 border-t border-surface-700">
                    <button type="submit" disabled={createMutation.isPending} className="btn-primary flex items-center gap-2">
                        {createMutation.isPending ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
                        {createMutation.isPending ? 'Creating...' : 'Create Target'}
                    </button>
                    <Link href="/targets" className="btn-secondary">Cancel</Link>
                </div>

                {createMutation.isError && (
                    <div className="bg-red-600/10 border border-red-600/20 rounded-lg px-4 py-2.5 text-red-400 text-sm">
                        {createMutation.error.message}
                    </div>
                )}
            </form>
        </div>
    );
}
