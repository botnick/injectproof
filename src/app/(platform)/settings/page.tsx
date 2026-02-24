// VibeCode — Settings Page (Glassmorphism)
'use client';

import { Settings, User, Key, Bell, Shield, Database } from 'lucide-react';
import { trpc } from '@/trpc/client';

export default function SettingsPage() {
    const { data: user } = trpc.auth.me.useQuery();

    return (
        <div className="space-y-6 animate-fade-in max-w-3xl">
            <div className="page-header">
                <h1 className="page-title flex items-center gap-3">
                    <div className="w-8 h-8 rounded-xl flex items-center justify-center bg-slate-500/10 border border-slate-500/20">
                        <Settings className="w-4 h-4 text-gray-400" />
                    </div>
                    Settings
                </h1>
                <p className="page-subtitle">Platform configuration and user preferences</p>
            </div>

            {/* Profile */}
            <div className="glass-card space-y-4">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2 relative z-10">
                    <User className="w-4 h-4 text-brand-400" /> Profile
                </h3>
                <div className="grid grid-cols-2 gap-4 relative z-10">
                    <div><label className="input-label">Name</label><input type="text" defaultValue={user?.name || ''} className="input-field" /></div>
                    <div><label className="input-label">Email</label><input type="email" defaultValue={user?.email || ''} className="input-field" disabled /></div>
                </div>
                <div className="grid grid-cols-2 gap-4 relative z-10">
                    <div><label className="input-label">Role</label><input type="text" defaultValue={user?.role || ''} className="input-field" disabled /></div>
                    <div><label className="input-label">MFA</label><p className="text-sm text-gray-400 mt-2">{user?.mfaEnabled ? '✅ Enabled' : '❌ Disabled'}</p></div>
                </div>
            </div>

            {/* Scanner Config */}
            <div className="glass-card space-y-4">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2 relative z-10">
                    <Shield className="w-4 h-4 text-brand-400" /> Default Scan Settings
                </h3>
                <div className="grid grid-cols-3 gap-4 relative z-10">
                    <div><label className="input-label">Default Depth</label><input type="number" defaultValue={10} className="input-field" /></div>
                    <div><label className="input-label">Default Max URLs</label><input type="number" defaultValue={500} className="input-field" /></div>
                    <div><label className="input-label">Default Rate Limit</label><input type="number" defaultValue={10} className="input-field" /></div>
                </div>
                <div className="relative z-10"><label className="input-label">Default User Agent</label><input type="text" defaultValue="InjectProof-Scanner/1.0" className="input-field font-mono" /></div>
            </div>

            {/* Notifications */}
            <div className="glass-card space-y-4">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2 relative z-10">
                    <Bell className="w-4 h-4 text-brand-400" /> Notifications
                </h3>
                <div className="space-y-3 relative z-10">
                    {['New Critical Vulnerability', 'Scan Completed', 'SLA Overdue', 'New Target Added'].map(notif => (
                        <label key={notif} className="flex items-center justify-between p-3 rounded-xl cursor-pointer transition-all hover:bg-white/[0.02]"
                            style={{
                                background: 'rgba(255,255,255,0.02)',
                                border: '1px solid rgba(255,255,255,0.05)',
                            }}>
                            <span className="text-sm text-gray-300">{notif}</span>
                            <input type="checkbox" defaultChecked className="rounded border-gray-600 bg-transparent text-brand-500 focus:ring-brand-500/20" />
                        </label>
                    ))}
                </div>
            </div>

            {/* Database */}
            <div className="glass-card space-y-3">
                <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2 relative z-10">
                    <Database className="w-4 h-4 text-brand-400" /> Database
                </h3>
                <div className="flex items-center gap-3 relative z-10">
                    <span className="text-sm text-gray-400">Storage: SQLite (Local)</span>
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span className="text-xs text-green-400">Connected</span>
                </div>
            </div>

            <button className="btn-primary">Save Settings</button>
        </div>
    );
}
