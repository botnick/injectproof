// InjectProof — Login Page
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { Shield, Eye, EyeOff, Lock, Mail, Fingerprint, Sparkles } from 'lucide-react';

export default function LoginPage() {
    const router = useRouter();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');

    // First-run check: if the DB has zero users, show a "Sign up" link so
    // the operator can bootstrap the first admin account. Hidden after the
    // first user exists because public signup is gated to admins after that.
    const { data: isFirstRun } = trpc.auth.isFirstRun.useQuery();

    const loginMutation = trpc.auth.login.useMutation({
        onSuccess: (data) => {
            localStorage.setItem('injectproof_token', data.token);
            document.cookie = `injectproof_token=${data.token}; path=/; max-age=86400; SameSite=Strict`;
            router.push('/dashboard');
        },
        onError: (err) => {
            setError(err.message || 'Invalid email or password');
        },
    });

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        loginMutation.mutate({ email, password });
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-[var(--bg-void)] relative overflow-hidden">
            {/* Aurora background */}
            <div className="aurora-bg" />

            {/* Dot grid */}
            <div className="absolute inset-0 grid-pattern opacity-30" />

            {/* Floating glass orbs */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute top-[10%] left-[15%] w-[600px] h-[600px] rounded-full blur-[150px] animate-float"
                    style={{ background: 'rgba(99,102,241,0.06)' }} />
                <div className="absolute bottom-[5%] right-[10%] w-[700px] h-[700px] rounded-full blur-[160px] animate-float"
                    style={{ background: 'rgba(139,92,246,0.05)', animationDelay: '3s' }} />
                <div className="absolute top-[40%] left-[40%] -translate-x-1/2 -translate-y-1/2 w-[900px] h-[900px] rounded-full blur-[180px]"
                    style={{ background: 'rgba(34,211,238,0.025)' }} />
            </div>

            <div className="relative z-10 w-full max-w-[420px] mx-4 animate-fade-in">
                {/* Logo */}
                <div className="text-center mb-10">
                    <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl mb-5 border border-brand-500/20 bg-brand-500/10 shadow-[0_0_40px_rgba(99,102,241,0.1)] neural-pulse animate-float">
                        <Shield className="w-10 h-10 text-brand-400" />
                    </div>
                    <h1 className="text-4xl font-bold tracking-tight" style={{ fontFamily: 'Outfit, sans-serif' }}>
                        <span className="gradient-text">Inject</span>
                        <span className="text-[var(--text-primary)]">Proof</span>
                    </h1>
                    <p className="text-[var(--text-secondary)] mt-2 text-sm flex items-center justify-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-brand-500/50" />
                        Deep SQLi Verification Engine
                    </p>
                </div>

                {/* Login Card — Clean Premium Panel */}
                <div className="glass-card relative overflow-hidden">
                    {/* Inner light reflection */}
                    <div className="absolute inset-0 rounded-2xl pointer-events-none"
                        style={{
                            background: 'linear-gradient(135deg, rgba(255,255,255,0.04) 0%, transparent 40%, transparent 60%, rgba(255,255,255,0.01) 100%)',
                        }}
                    />

                    <form onSubmit={handleSubmit} className="space-y-5 relative z-10">
                        <div>
                            <label className="input-label">Email</label>
                            <div className="relative">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="admin@injectproof.local"
                                    className="input-field pl-11"
                                    required
                                    autoFocus
                                />
                            </div>
                        </div>

                        <div>
                            <label className="input-label">Password</label>
                            <div className="relative">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                    className="input-field pl-11 pr-11"
                                    required
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-4 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                                >
                                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>

                        {error && (
                            <div className="rounded-xl px-4 py-3 text-red-400 text-sm flex items-center gap-2 bg-red-500/10 border border-red-500/20">
                                <div className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0" />
                                {error}
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loginMutation.isPending}
                            className="btn-primary w-full flex items-center justify-center gap-2 !py-3.5 text-sm"
                        >
                            {loginMutation.isPending ? (
                                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                            ) : (
                                <Fingerprint className="w-4 h-4" />
                            )}
                            {loginMutation.isPending ? 'Authenticating...' : 'Access Platform'}
                        </button>
                    </form>

                    <div className="mt-6 pt-5 border-t border-[var(--border-subtle)] relative z-10 space-y-2">
                        <p className="text-[11px] text-[var(--text-muted)] text-center">
                            Demo: <code className="text-brand-400/60 font-mono">admin@injectproof.local</code> / <code className="text-brand-400/60 font-mono">admin123</code>
                        </p>
                        {/* Bootstrap-only signup link — disappears after the first
                            admin is created. Post-bootstrap, new accounts must be
                            provisioned by an admin (no public self-serve). */}
                        {isFirstRun && (
                            <p className="text-[11px] text-center text-amber-400/80">
                                No users yet.{' '}
                                <a href="/signup" className="underline hover:text-amber-300 transition-colors">
                                    Create the first admin account →
                                </a>
                            </p>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <div className="text-center mt-8 space-y-2">
                    <p className="text-[11px] text-[var(--text-muted)]">
                        InjectProof v1.0 — Deep SQLi Verification Engine
                    </p>
                    <div className="flex items-center justify-center gap-3 text-[10px] text-[var(--text-secondary)]">
                        <span>OWASP</span>
                        <span className="w-0.5 h-0.5 rounded-full bg-[var(--text-muted)]" />
                        <span>CVE</span>
                        <span className="w-0.5 h-0.5 rounded-full bg-[var(--text-muted)]" />
                        <span>CWE</span>
                        <span className="w-0.5 h-0.5 rounded-full bg-[var(--text-muted)]" />
                        <span>CVSS v3.1</span>
                        <span className="w-0.5 h-0.5 rounded-full bg-[var(--text-muted)]" />
                        <span>NIST</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
