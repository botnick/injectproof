// InjectProof — Platform Layout (Deep Glassmorphism Sidebar + Floating Header)
'use client';

import { useState, useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import {
    Shield, LayoutDashboard, Target, Radar, Bug, FileText,
    Settings, LogOut, ChevronLeft, ChevronRight, Bell,
    Activity, Skull, Sparkles, Cpu, Zap,
} from 'lucide-react';

const navItems = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/targets', label: 'Targets', icon: Target },
    { href: '/scans', label: 'Scans', icon: Radar },
    { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { href: '/reports', label: 'Reports', icon: FileText },
    { href: '/settings', label: 'Settings', icon: Settings },
];

export default function PlatformLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const pathname = usePathname();
    const [collapsed, setCollapsed] = useState(false);
    const [user, setUser] = useState<{ name: string; email: string; role: string } | null>(null);

    useEffect(() => {
        const token = localStorage.getItem('injectproof_token');
        if (!token) {
            router.push('/login');
            return;
        }
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            setUser({ name: payload.name, email: payload.email, role: payload.role });
        } catch {
            router.push('/login');
        }
    }, [router]);

    const handleLogout = () => {
        localStorage.removeItem('injectproof_token');
        document.cookie = 'injectproof_token=; path=/; max-age=0';
        router.push('/login');
    };

    if (!user) return null;

    return (
        <div className="flex min-h-screen bg-[#030712]">
            {/* Aurora Background */}
            <div className="aurora-bg" />

            {/* ── Sidebar — Clean Dark Panel ─────────── */}
            <aside
                className={`${collapsed ? 'w-[72px]' : 'w-[260px]'} fixed h-full z-30
                    border-r border-white/[0.08] transition-all duration-300 ease-out
                    flex flex-col bg-[#0a0a0a]`}
            >
                {/* Logo */}
                <div className="flex items-center gap-3 px-4 h-16 border-b border-white/[0.05]">
                    <div className="flex items-center justify-center w-9 h-9 rounded-xl neural-pulse flex-shrink-0"
                        style={{
                            background: 'linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.08))',
                            border: '1px solid rgba(129,140,248,0.2)',
                            boxShadow: '0 0 20px rgba(99,102,241,0.1)',
                        }}
                    >
                        <Skull className="w-5 h-5 text-brand-400" />
                    </div>
                    {!collapsed && (
                        <div className="overflow-hidden whitespace-nowrap">
                            <h1 className="text-lg font-bold leading-tight tracking-tight text-white flex items-center gap-1">
                                InjectProof
                            </h1>
                            <p className="text-[10px] text-gray-400 font-medium leading-tight flex items-center gap-1 mt-0.5">
                                <Sparkles className="w-2.5 h-2.5 text-brand-400" /> SQLi Verification Engine
                            </p>
                        </div>
                    )}
                </div>

                {/* Navigation */}
                <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
                    {navItems.map((item) => {
                        const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
                        return (
                            <Link
                                key={item.href}
                                href={item.href}
                                className={`sidebar-link ${isActive ? 'active' : ''}`}
                            >
                                <item.icon className={`w-[18px] h-[18px] flex-shrink-0 ${isActive ? 'text-brand-400' : ''}`} />
                                {!collapsed && <span>{item.label}</span>}
                            </Link>
                        );
                    })}
                </nav>

                {/* AI Status */}
                {!collapsed && (
                    <div className="mx-3 mb-2 p-3 rounded-xl"
                        style={{
                            background: 'rgba(99,102,241,0.04)',
                            border: '1px solid rgba(129,140,248,0.08)',
                            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.02)',
                        }}
                    >
                        <div className="flex items-center gap-2 mb-1">
                            <Cpu className="w-3.5 h-3.5 text-brand-400" />
                            <span className="text-xs font-medium text-gray-300">AI Engine</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="status-live" />
                            <span className="text-[11px] text-gray-500">Ready · Cognitive v2.0</span>
                        </div>
                    </div>
                )}

                {/* Collapse Toggle */}
                <button
                    onClick={() => setCollapsed(!collapsed)}
                    className="mx-3 mb-2 flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-gray-600 hover:text-gray-400 hover:bg-white/[0.03] transition-all text-sm"
                >
                    {collapsed ? <ChevronRight className="w-4 h-4" /> : <><ChevronLeft className="w-4 h-4" /><span className="text-xs">Collapse</span></>}
                </button>

                {/* User */}
                <div className="p-3 border-t border-white/[0.05]">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                            style={{
                                background: 'linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.1))',
                                border: '1px solid rgba(129,140,248,0.15)',
                            }}
                        >
                            <span className="text-xs font-bold text-brand-400">{user.name.charAt(0).toUpperCase()}</span>
                        </div>
                        {!collapsed && (
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-gray-200 truncate">{user.name}</p>
                                <p className="text-[11px] text-gray-600 truncate capitalize">{user.role.replace('_', ' ')}</p>
                            </div>
                        )}
                        {!collapsed && (
                            <button onClick={handleLogout} className="text-gray-600 hover:text-red-400 transition-colors duration-300" title="Logout">
                                <LogOut className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                </div>
            </aside>

            {/* ── Main Content ─────────────────────────── */}
            <main className={`${collapsed ? 'ml-[72px]' : 'ml-[260px]'} flex-1 transition-all duration-300 ease-out relative z-10`}>
                {/* Clean Header */}
                <header
                    className="h-14 flex items-center justify-between px-6 sticky top-0 z-20 border-bottom border-white/[0.08] bg-[#0a0a0a]/90 backdrop-blur-md"
                >
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
                            style={{
                                background: 'rgba(52,211,153,0.04)',
                                border: '1px solid rgba(52,211,153,0.1)',
                            }}
                        >
                            <div className="status-live" />
                            <span className="text-[11px] text-emerald-400 font-medium">System Active</span>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <button className="p-2 rounded-xl text-gray-600 hover:text-gray-400 hover:bg-white/[0.04] transition-all relative group">
                            <Zap className="w-4 h-4" />
                            <span className="absolute -top-1 -right-1 w-2 h-2 bg-brand-500 rounded-full opacity-0 group-hover:opacity-100 transition-opacity" />
                        </button>
                        <button className="p-2 rounded-xl text-gray-600 hover:text-gray-400 hover:bg-white/[0.04] transition-all relative">
                            <Bell className="w-4 h-4" />
                        </button>
                    </div>
                </header>

                {/* Page Content */}
                <div className="p-6">
                    {children}
                </div>
            </main>
        </div>
    );
}
