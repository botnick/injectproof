// InjectProof — Signup page
// ==========================
// Mirror of the login page, calls auth.register. Two modes:
//  - First-run bootstrap: no users exist → form works, creates the first
//    admin account.
//  - Post-bootstrap: users exist → form posts and server returns 403. We
//    show that clearly so the user understands signup is admin-gated.
//
// No role selector — the server forces the first-run user to admin, and
// post-bootstrap non-admins can only be created by an admin via a different
// flow (user-management, future work).

'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { Shield, Eye, EyeOff, Lock, Mail, User, Sparkles, UserPlus, AlertCircle } from 'lucide-react';

export default function SignupPage() {
    const router = useRouter();
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState('');

    const { data: isFirstRun, isLoading: firstRunLoading } = trpc.auth.isFirstRun.useQuery();

    const registerMutation = trpc.auth.register.useMutation({
        onSuccess: (data) => {
            // Auto-sign-in the newly-created user — same token storage as login.
            localStorage.setItem('injectproof_token', data.token);
            document.cookie = `injectproof_token=${data.token}; path=/; max-age=86400; SameSite=Strict`;
            router.push('/dashboard');
        },
        onError: (err) => {
            setError(err.message || 'Registration failed');
        },
    });

    // After bootstrap, this page is effectively closed to the public. Redirect
    // to login with an explanatory banner instead of showing a dead form that
    // will always 403.
    useEffect(() => {
        if (!firstRunLoading && isFirstRun === false) {
            // Stay on the page but surface a clear message. Some operators
            // may want to view this intentionally.
        }
    }, [firstRunLoading, isFirstRun]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        if (password.length < 12) {
            setError('Password must be at least 12 characters');
            return;
        }
        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        registerMutation.mutate({
            name,
            email,
            password,
            // Role is ignored on first-run (server forces admin) and rejected
            // post-bootstrap (server requires admin caller). We send `viewer`
            // as a safe sentinel in case someone ever opens the admin-gated path.
            role: 'viewer',
        });
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-[var(--bg-void)] relative overflow-hidden">
            <div className="aurora-bg" />
            <div className="absolute inset-0 grid-pattern opacity-30" />
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute top-[10%] left-[15%] w-[600px] h-[600px] rounded-full blur-[150px] animate-float"
                    style={{ background: 'rgba(99,102,241,0.06)' }} />
                <div className="absolute bottom-[5%] right-[10%] w-[700px] h-[700px] rounded-full blur-[160px] animate-float"
                    style={{ background: 'rgba(139,92,246,0.05)', animationDelay: '3s' }} />
            </div>

            <div className="relative z-10 w-full max-w-[420px] mx-4 animate-fade-in">
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 border border-brand-500/20 bg-brand-500/10">
                        <Shield className="w-8 h-8 text-brand-400" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight" style={{ fontFamily: 'Outfit, sans-serif' }}>
                        <span className="gradient-text">Inject</span>
                        <span className="text-[var(--text-primary)]">Proof</span>
                    </h1>
                    <p className="text-[var(--text-secondary)] mt-2 text-sm flex items-center justify-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-brand-500/50" />
                        {isFirstRun ? 'Bootstrap the first admin' : 'Create Account'}
                    </p>
                </div>

                <div className="glass-card relative overflow-hidden">
                    {/* Clear explanation of what this page does right now. */}
                    {!firstRunLoading && isFirstRun === false && (
                        <div className="relative z-10 mb-5 rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200 flex items-start gap-2">
                            <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                            <div>
                                <p className="font-medium">Public signup is disabled</p>
                                <p className="text-xs text-amber-300/80 mt-1">
                                    An admin user already exists. Ask an existing admin to create an account for you,
                                    or <a href="/login" className="underline hover:text-amber-200">sign in here</a>.
                                </p>
                            </div>
                        </div>
                    )}

                    {isFirstRun && (
                        <div className="relative z-10 mb-5 rounded-xl border border-brand-500/20 bg-brand-500/10 px-4 py-3 text-sm text-brand-200">
                            <p className="font-medium flex items-center gap-2"><UserPlus className="w-4 h-4" /> First-run bootstrap</p>
                            <p className="text-xs text-brand-300/80 mt-1">
                                You&apos;re creating the <strong>first admin account</strong> for this installation.
                                This form is only available until the first user is registered — afterwards, new
                                accounts must be provisioned by an admin.
                            </p>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-5 relative z-10">
                        <div>
                            <label className="input-label">Name</label>
                            <div className="relative">
                                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type="text"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    placeholder="Your full name"
                                    className="input-field pl-11"
                                    required
                                    autoFocus
                                    disabled={isFirstRun === false}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="input-label">Email</label>
                            <div className="relative">
                                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="you@example.com"
                                    className="input-field pl-11"
                                    required
                                    disabled={isFirstRun === false}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="input-label">Password <span className="text-[10px] text-gray-500">(≥ 12 characters)</span></label>
                            <div className="relative">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••••••"
                                    className="input-field pl-11 pr-11"
                                    required
                                    minLength={12}
                                    disabled={isFirstRun === false}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-4 top-1/2 -translate-y-1/2 text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                                >
                                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>

                        <div>
                            <label className="input-label">Confirm Password</label>
                            <div className="relative">
                                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Repeat password"
                                    className="input-field pl-11"
                                    required
                                    minLength={12}
                                    disabled={isFirstRun === false}
                                />
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
                            disabled={registerMutation.isPending || isFirstRun === false || firstRunLoading}
                            className="btn-primary w-full flex items-center justify-center gap-2 !py-3.5 text-sm disabled:opacity-50"
                        >
                            {registerMutation.isPending ? (
                                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                            ) : (
                                <UserPlus className="w-4 h-4" />
                            )}
                            {registerMutation.isPending ? 'Creating account…' : 'Create Account'}
                        </button>
                    </form>

                    <div className="mt-6 pt-5 border-t border-[var(--border-subtle)] relative z-10 text-center">
                        <p className="text-[11px] text-[var(--text-muted)]">
                            Already have an account? <a href="/login" className="text-brand-400 hover:text-brand-300 underline">Sign in</a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
