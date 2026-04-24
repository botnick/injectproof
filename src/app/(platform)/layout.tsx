// InjectProof — Platform Layout (Deep Glassmorphism Sidebar + Floating Header)
'use client';

import { useState, useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import {
    Shield, LayoutDashboard, Target, Radar, Bug, FileText,
    Settings, LogOut, ChevronLeft, ChevronRight, Sparkles,
} from 'lucide-react';
import { ThemeToggle } from '@/components/ui/theme-toggle';
import { LanguageToggle } from '@/components/ui/language-toggle';

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
        <div className="flex min-h-screen bg-[var(--bg-void)]">
            {/* Aurora Background */}
            <div className="aurora-bg" />

            {/* ── Sidebar ─────────────────────────────── */}
            <aside
                className={`${collapsed ? 'w-[72px]' : 'w-[260px]'} fixed h-full z-30
                    border-r border-[var(--border-subtle)] transition-all duration-300 ease-out
                    flex flex-col bg-[var(--bg-sidebar)]`}
                style={{ boxShadow: '1px 0 0 var(--border-subtle)' }}
            >
                {/* Logo */}
                <div className="flex items-center gap-3 px-4 h-16 border-b border-[var(--border-subtle)]">
                    <div className="flex items-center justify-center w-9 h-9 rounded-xl flex-shrink-0"
                        style={{
                            background: 'linear-gradient(135deg, rgba(79,70,229,0.12), rgba(139,92,246,0.08))',
                            border: '1px solid rgba(79,70,229,0.2)',
                        }}
                    >
                        <Shield className="w-5 h-5" style={{ color: 'var(--accent)' }} />
                    </div>
                    {!collapsed && (
                        <div className="overflow-hidden whitespace-nowrap">
                            <h1 className="text-lg font-bold leading-tight tracking-tight text-[var(--text-primary)] flex items-center gap-1">
                                InjectProof
                            </h1>
                            <p className="text-[10px] text-[var(--text-muted)] font-medium leading-tight flex items-center gap-1 mt-0.5">
                                <Sparkles className="w-2.5 h-2.5" style={{ color: 'var(--accent)' }} /> Security Scanner
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
                                <item.icon className="w-[18px] h-[18px] flex-shrink-0" />
                                {!collapsed && <span>{item.label}</span>}
                            </Link>
                        );
                    })}
                </nav>

                {/* Collapse Toggle */}
                <button
                    onClick={() => setCollapsed(!collapsed)}
                    className="mx-3 mb-2 flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-all text-sm"
                >
                    {collapsed ? <ChevronRight className="w-4 h-4" /> : <><ChevronLeft className="w-4 h-4" /><span className="text-xs">Collapse</span></>}
                </button>

                {/* User */}
                <div className="p-3 border-t border-[var(--border-subtle)]">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                            style={{
                                background: 'var(--accent-glow)',
                                border: '1px solid var(--border-accent)',
                            }}
                        >
                            <span className="text-xs font-bold" style={{ color: 'var(--accent)' }}>{user.name.charAt(0).toUpperCase()}</span>
                        </div>
                        {!collapsed && (
                            <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-[var(--text-primary)] truncate">{user.name}</p>
                                <p className="text-[11px] text-[var(--text-muted)] truncate capitalize">{user.role.replace('_', ' ')}</p>
                            </div>
                        )}
                        {!collapsed && (
                            <button onClick={handleLogout} className="text-[var(--text-muted)] hover:text-red-500 transition-colors duration-300" title="Logout">
                                <LogOut className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                </div>
            </aside>

            {/* ── Main Content ─────────────────────────── */}
            <main className={`${collapsed ? 'ml-[72px]' : 'ml-[260px]'} flex-1 transition-all duration-300 ease-out relative z-10`}>
                {/* Header */}
                <header
                    className="h-14 flex items-center justify-between px-6 sticky top-0 z-20 border-b border-[var(--border-subtle)] backdrop-blur-md"
                    style={{ background: 'var(--bg-header)' }}
                >
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                            style={{
                                background: 'rgba(22,163,74,0.08)',
                                border: '1px solid rgba(22,163,74,0.2)',
                            }}
                        >
                            <div className="status-live" />
                            <span className="text-[11px] font-medium" style={{ color: 'var(--status-active)' }}>System Active</span>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <LanguageToggle />
                        <ThemeToggle />
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
