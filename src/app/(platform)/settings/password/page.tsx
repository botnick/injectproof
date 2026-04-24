// InjectProof — Change-password page
// Seeded users (admin/pentester) land on `mustChangePassword=true` so the
// first login flow routes here. Enforced from the trpc `auth.changePassword`
// mutation which re-verifies the current password and clears the flag.

'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { KeyRound, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function ChangePasswordPage() {
    const router = useRouter();
    const [current, setCurrent] = useState('');
    const [next, setNext] = useState('');
    const [confirm, setConfirm] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState(false);

    const mut = trpc.auth.changePassword.useMutation({
        onSuccess: () => {
            setSuccess(true);
            setError(null);
            setTimeout(() => router.push('/dashboard'), 1200);
        },
        onError: (err) => {
            setError(err.message);
            setSuccess(false);
        },
    });

    const strength = passwordStrength(next);
    const canSubmit = current.length > 0 && next.length >= 12 && next === confirm && !mut.isPending;

    function submit(e: React.FormEvent) {
        e.preventDefault();
        if (next !== confirm) {
            setError('Passwords do not match');
            return;
        }
        mut.mutate({ currentPassword: current, newPassword: next });
    }

    return (
        <div className="max-w-xl mx-auto animate-fade-in">
            <div className="glass-card p-8 space-y-6">
                <header className="space-y-1">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-indigo-500/15 flex items-center justify-center ring-1 ring-indigo-500/25">
                            <KeyRound className="w-5 h-5 text-indigo-400" />
                        </div>
                        <h1 className="text-2xl font-semibold">Change password</h1>
                    </div>
                    <p className="text-sm text-gray-400">
                        Required on first login for seeded accounts. Minimum 12 characters. Use a passphrase
                        you don&rsquo;t reuse anywhere else.
                    </p>
                </header>

                <form onSubmit={submit} className="space-y-4">
                    <Field label="Current password" value={current} onChange={setCurrent} type="password" autoComplete="current-password" />
                    <Field label="New password" value={next} onChange={setNext} type="password" autoComplete="new-password" />
                    <StrengthMeter value={strength} />
                    <Field label="Confirm new password" value={confirm} onChange={setConfirm} type="password" autoComplete="new-password" />

                    {error && (
                        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-sm">
                            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                            <span>{error}</span>
                        </div>
                    )}
                    {success && (
                        <div className="flex items-start gap-2 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm">
                            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                            <span>Password updated. Redirecting to dashboard&hellip;</span>
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={!canSubmit}
                        className="btn-primary w-full flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        <ShieldCheck className="w-4 h-4" />
                        {mut.isPending ? 'Updating…' : 'Update password'}
                    </button>
                </form>
            </div>
        </div>
    );
}

function Field({
    label,
    value,
    onChange,
    type = 'text',
    autoComplete,
}: {
    label: string;
    value: string;
    onChange: (v: string) => void;
    type?: string;
    autoComplete?: string;
}) {
    return (
        <label className="block space-y-1">
            <span className="text-xs uppercase tracking-wider text-gray-400">{label}</span>
            <input
                type={type}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                autoComplete={autoComplete}
                className="input-field w-full"
            />
        </label>
    );
}

function passwordStrength(pw: string): number {
    if (!pw) return 0;
    let score = 0;
    if (pw.length >= 12) score += 1;
    if (pw.length >= 16) score += 1;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1;
    if (/\d/.test(pw)) score += 1;
    if (/[^\w\s]/.test(pw)) score += 1;
    return Math.min(score, 4);
}

function StrengthMeter({ value }: { value: number }) {
    const colors = ['bg-[var(--bg-hover)]', 'bg-red-500', 'bg-amber-500', 'bg-yellow-500', 'bg-emerald-500'];
    const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
    return (
        <div className="space-y-1">
            <div className="flex gap-1">
                {[0, 1, 2, 3].map((i) => (
                    <div
                        key={i}
                        className={`h-1.5 flex-1 rounded-full ${i < value ? colors[value] : 'bg-[var(--bg-hover)]'}`}
                    />
                ))}
            </div>
            <div className="text-[11px] text-gray-500">{labels[value] || ' '}</div>
        </div>
    );
}
