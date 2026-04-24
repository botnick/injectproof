// InjectProof — UserMenu dropdown
// ================================
// Replaces the lone Logout icon in the sidebar. Gives the user a proper
// entrypoint to their profile, password change, and logout without having
// to click Settings in the main sidebar.
//
// Uses plain HTMLDetailsElement for the dropdown so we don't pull in
// @radix-ui or shadcn Popover just for one menu — keeps bundle small and
// it plays well with the collapsed/expanded sidebar state.

'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { LogOut, User, KeyRound, ChevronDown } from 'lucide-react';

export interface UserMenuProps {
    user: { name: string; role: string; email?: string };
    collapsed?: boolean;
    onLogout: () => void;
}

export function UserMenu({ user, collapsed = false, onLogout }: UserMenuProps) {
    const [open, setOpen] = useState(false);
    const containerRef = useRef<HTMLDivElement>(null);

    // Close on outside-click. Plain listener — no library.
    useEffect(() => {
        if (!open) return;
        const onDocClick = (e: MouseEvent) => {
            if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
                setOpen(false);
            }
        };
        const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
        document.addEventListener('mousedown', onDocClick);
        document.addEventListener('keydown', onEsc);
        return () => {
            document.removeEventListener('mousedown', onDocClick);
            document.removeEventListener('keydown', onEsc);
        };
    }, [open]);

    const initial = user.name.charAt(0).toUpperCase();

    return (
        <div ref={containerRef} className="relative">
            <button
                onClick={() => setOpen(v => !v)}
                aria-expanded={open}
                aria-haspopup="menu"
                className={`w-full flex items-center gap-3 px-2 py-1.5 rounded-xl hover:bg-[var(--bg-hover)] transition-all ${open ? 'bg-[var(--bg-hover)]' : ''}`}
            >
                <div
                    className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{
                        background: 'var(--accent-glow)',
                        border: '1px solid var(--border-accent)',
                    }}
                >
                    <span className="text-xs font-bold" style={{ color: 'var(--accent)' }}>{initial}</span>
                </div>
                {!collapsed && (
                    <>
                        <div className="flex-1 min-w-0 text-left">
                            <p className="text-sm font-medium text-[var(--text-primary)] truncate">{user.name}</p>
                            <p className="text-[11px] text-[var(--text-muted)] truncate capitalize">{user.role.replace('_', ' ')}</p>
                        </div>
                        <ChevronDown
                            className={`w-4 h-4 text-[var(--text-muted)] transition-transform ${open ? 'rotate-180' : ''}`}
                        />
                    </>
                )}
            </button>

            {open && (
                <div
                    role="menu"
                    className="absolute bottom-full left-0 right-0 mb-2 z-50 py-1 rounded-xl bg-[var(--bg-card)] border border-[var(--border-subtle)] shadow-2xl backdrop-blur-xl animate-fade-in"
                    style={{ minWidth: collapsed ? '220px' : undefined }}
                >
                    {/* Show full details even when collapsed sidebar — the menu is the only
                        place to confirm which account you're signed in as in that state. */}
                    {collapsed && (
                        <div className="px-3 py-2 border-b border-[var(--border-subtle)]">
                            <p className="text-sm font-medium text-[var(--text-primary)] truncate">{user.name}</p>
                            <p className="text-[11px] text-[var(--text-muted)] truncate capitalize">{user.role.replace('_', ' ')}</p>
                        </div>
                    )}
                    <Link
                        href="/settings"
                        onClick={() => setOpen(false)}
                        role="menuitem"
                        className="flex items-center gap-2 px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
                    >
                        <User className="w-4 h-4 text-[var(--text-muted)]" />
                        <span>Profile &amp; Settings</span>
                    </Link>
                    <Link
                        href="/settings/password"
                        onClick={() => setOpen(false)}
                        role="menuitem"
                        className="flex items-center gap-2 px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
                    >
                        <KeyRound className="w-4 h-4 text-[var(--text-muted)]" />
                        <span>Change Password</span>
                    </Link>
                    <div className="border-t border-[var(--border-subtle)] my-1" />
                    <button
                        onClick={() => { setOpen(false); onLogout(); }}
                        role="menuitem"
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                        <LogOut className="w-4 h-4" />
                        <span>Logout</span>
                    </button>
                </div>
            )}
        </div>
    );
}
