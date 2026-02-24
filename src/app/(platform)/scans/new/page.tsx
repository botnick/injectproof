// VibeCode — New Scan Page
'use client';

import { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { trpc } from '@/trpc/client';
import Link from 'next/link';
import { ArrowLeft, Radar, Play, Zap, Shield, Search as SearchIcon } from 'lucide-react';

const SCAN_MODULES = [
    { id: 'xss', name: 'XSS Detection', desc: 'Reflected, Stored, DOM-based XSS' },
    { id: 'sqli', name: 'SQL Injection', desc: 'Error, Boolean, Time-based SQLi' },
    { id: 'ssrf', name: 'SSRF', desc: 'Server-Side Request Forgery' },
    { id: 'headers', name: 'Security Headers', desc: 'Missing/misconfigured headers' },
    { id: 'cors', name: 'CORS', desc: 'Cross-Origin misconfiguration' },
    { id: 'path_traversal', name: 'Path Traversal', desc: 'Directory traversal attacks' },
    { id: 'open_redirect', name: 'Open Redirect', desc: 'Unvalidated redirects' },
];

export default function NewScanPage() {
    return (
        <Suspense fallback={<div className="flex justify-center py-12"><div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" /></div>}>
            <NewScanContent />
        </Suspense>
    );
}

function NewScanContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const preselectedTarget = searchParams.get('targetId') || '';

    const [targetId, setTargetId] = useState(preselectedTarget);
    const [scanType, setScanType] = useState('standard');
    const [selectedModules, setSelectedModules] = useState<string[]>([]);

    const { data: targets } = trpc.target.list.useQuery({ pageSize: 100 });
    const createScan = trpc.scan.create.useMutation({
        onSuccess: (data) => router.push(`/scans/${data.id}`),
    });

    const toggleModule = (id: string) => {
        setSelectedModules(prev => prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]);
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetId) return;
        createScan.mutate({
            targetId,
            scanType: scanType as any,
            modules: scanType === 'custom' ? selectedModules : undefined,
        });
    };

    return (
        <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
            <div className="flex items-center gap-3">
                <Link href="/scans" className="p-2 rounded-lg hover:bg-surface-800/50 text-gray-400 hover:text-white transition-all"><ArrowLeft className="w-5 h-5" /></Link>
                <div className="page-header !mb-0">
                    <h1 className="page-title">New Scan</h1>
                    <p className="page-subtitle">Configure and launch a vulnerability scan</p>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="glass-card space-y-6">
                {/* Target Selection */}
                <div>
                    <label className="input-label">Select Target *</label>
                    <select value={targetId} onChange={e => setTargetId(e.target.value)} className="input-field" required>
                        <option value="">Choose a target...</option>
                        {targets?.items?.map((t: any) => (
                            <option key={t.id} value={t.id}>{t.name} — {t.baseUrl}</option>
                        ))}
                    </select>
                </div>

                {/* Scan Type */}
                <div>
                    <label className="input-label">Scan Profile</label>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2">
                        {[
                            { id: 'quick', label: 'Quick', icon: <Zap className="w-4 h-4" />, desc: 'Headers & CORS' },
                            { id: 'standard', label: 'Standard', icon: <Shield className="w-4 h-4" />, desc: 'OWASP Top 10' },
                            { id: 'deep', label: 'Deep', icon: <SearchIcon className="w-4 h-4" />, desc: 'Full coverage' },
                            { id: 'custom', label: 'Custom', icon: <Radar className="w-4 h-4" />, desc: 'Pick modules' },
                        ].map(type => (
                            <button key={type.id} type="button" onClick={() => setScanType(type.id)}
                                className={`p-3 rounded-xl border text-left transition-all ${scanType === type.id ? 'border-brand-500 bg-brand-600/10' : 'border-surface-700 hover:border-surface-600 bg-surface-900/50'}`}>
                                <div className={`mb-2 ${scanType === type.id ? 'text-brand-400' : 'text-gray-500'}`}>{type.icon}</div>
                                <p className={`text-sm font-medium ${scanType === type.id ? 'text-white' : 'text-gray-300'}`}>{type.label}</p>
                                <p className="text-xs text-gray-500 mt-0.5">{type.desc}</p>
                            </button>
                        ))}
                    </div>
                </div>

                {/* Custom Modules */}
                {scanType === 'custom' && (
                    <div>
                        <label className="input-label">Select Modules</label>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                            {SCAN_MODULES.map(mod => (
                                <button key={mod.id} type="button" onClick={() => toggleModule(mod.id)}
                                    className={`p-3 rounded-lg border text-left transition-all ${selectedModules.includes(mod.id) ? 'border-brand-500 bg-brand-600/10' : 'border-surface-700 bg-surface-900/50 hover:border-surface-600'}`}>
                                    <p className={`text-sm font-medium ${selectedModules.includes(mod.id) ? 'text-white' : 'text-gray-400'}`}>{mod.name}</p>
                                    <p className="text-xs text-gray-500">{mod.desc}</p>
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {/* Submit */}
                <div className="flex gap-3 pt-4 border-t border-surface-700">
                    <button type="submit" disabled={!targetId || createScan.isPending} className="btn-primary flex items-center gap-2">
                        {createScan.isPending ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Play className="w-4 h-4" />}
                        {createScan.isPending ? 'Launching...' : 'Launch Scan'}
                    </button>
                    <Link href="/scans" className="btn-secondary">Cancel</Link>
                </div>

                {createScan.isError && (
                    <div className="bg-red-600/10 border border-red-600/20 rounded-lg px-4 py-2.5 text-red-400 text-sm">{createScan.error.message}</div>
                )}
            </form>
        </div>
    );
}
