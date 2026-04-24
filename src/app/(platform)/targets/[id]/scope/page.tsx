// InjectProof — ScopeApproval management page
// Per-target written-authorization record. security_lead+ creates new approvals;
// pentesters see the current approval state and can request one via a separate flow.

'use client';

import { use, useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { trpc } from '@/trpc/client';
import { ShieldCheck, AlertTriangle, Trash2, Clock, FileText, Unlock } from 'lucide-react';

export default function ScopeApprovalPage({ params }: { params: Promise<{ id: string }> }) {
    const { id: targetId } = use(params);
    const searchParams = useSearchParams();
    const autoRationale = searchParams.get('rationale');

    const { data: me } = trpc.auth.me.useQuery();
    const { data: target } = trpc.target.getById.useQuery(targetId);
    const { data: approvals, refetch } = trpc.scope.listForTarget.useQuery({ targetId });

    const create = trpc.scope.create.useMutation({ onSuccess: () => refetch() });
    const revoke = trpc.scope.revoke.useMutation({ onSuccess: () => refetch() });

    const canSign = me && (me.role === 'security_lead' || me.role === 'admin');
    const [form, setForm] = useState({
        allowedPaths: ['/'],
        allowedMethodsText: 'GET, POST',
        exploitAllowed: false,
        osCommandAllowed: false,
        fileReadAllowed: false,
        dataExfilAllowed: false,
        rationale: '',
        expiresIso: '',
    });

    // When the user arrives from target-create (prod/staging auto-nav) with
    // ?rationale=auto-created, pre-fill a sensible default rationale so the
    // form is one "Sign" click away for a security_lead. Only runs once and
    // only when target + form are hydrated but form.rationale is still blank.
    useEffect(() => {
        if (autoRationale === 'auto-created' && target && !form.rationale) {
            setForm(prev => ({
                ...prev,
                rationale:
                    `Initial scope approval for newly registered ${target.environment} target "${target.name}" ` +
                    `(${target.baseUrl}).\n\n` +
                    `Reviewed-by: (fill in your name)\n` +
                    `Engagement ticket: (fill in)\n` +
                    `Signed: ${new Date().toISOString().slice(0, 10)}`,
            }));
        }
    }, [autoRationale, target, form.rationale]);

    function submitCreate() {
        const methods = form.allowedMethodsText
            .split(',')
            .map((m) => m.trim().toUpperCase())
            .filter((m) => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(m)) as Array<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD'>;
        create.mutate({
            targetId,
            allowedPaths: form.allowedPaths,
            allowedMethods: methods.length > 0 ? methods : ['GET'],
            exploitAllowed: form.exploitAllowed,
            osCommandAllowed: form.osCommandAllowed,
            fileReadAllowed: form.fileReadAllowed,
            dataExfilAllowed: form.dataExfilAllowed,
            rationale: form.rationale || undefined,
            expiresAt: form.expiresIso ? new Date(form.expiresIso) : undefined,
        });
    }

    const current = approvals?.history.find((a) => a.id === approvals.current);

    return (
        <div className="max-w-4xl mx-auto animate-fade-in space-y-6">
            <header className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/15 flex items-center justify-center ring-1 ring-emerald-500/25 shrink-0">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                    <h1 className="text-2xl font-semibold">Scope approval</h1>
                    <p className="text-sm text-gray-400">
                        Target: <span className="text-[var(--text-primary)] font-mono">{target?.name ?? targetId}</span>
                    </p>
                    <p className="text-sm text-gray-400 max-w-2xl mt-1">
                        Every scan with <code className="text-indigo-300">safetyMode=exploit</code> (deep scan) or against a
                        production-tagged target requires an active, unrevoked approval. security_lead or admin signs scope;
                        pentesters cannot self-approve.
                    </p>
                </div>
            </header>

            {/* Current approval */}
            <section className="glass-card p-6 space-y-3">
                <h2 className="text-lg font-semibold flex items-center gap-2">
                    <FileText className="w-4 h-4 text-gray-400" />
                    Current approval
                </h2>
                {!current ? (
                    <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-sm">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>
                            No approval attached. Scans that require scope will be refused by the server until an approval is signed.
                        </span>
                    </div>
                ) : (
                    <ApprovalCard
                        approval={current}
                        onRevoke={
                            canSign
                                ? (reason) => revoke.mutate({ approvalId: current.id, reason })
                                : null
                        }
                    />
                )}
            </section>

            {/* History */}
            {approvals && approvals.history.length > 0 && (
                <section className="glass-card p-6 space-y-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                        <Clock className="w-4 h-4 text-gray-400" />
                        History
                    </h2>
                    <ul className="space-y-2">
                        {approvals.history.map((a) => (
                            <li key={a.id} className="text-sm text-[var(--text-primary)] flex items-center gap-3">
                                <span className="font-mono text-xs text-gray-500">{a.id.slice(0, 8)}</span>
                                <span>{new Date(a.createdAt).toLocaleString()}</span>
                                {a.revokedAt && <span className="text-red-400">revoked: {a.revokedReason}</span>}
                                {a.exploitAllowed && <span className="text-amber-300 text-xs">exploit+</span>}
                            </li>
                        ))}
                    </ul>
                </section>
            )}

            {/* Create form — security_lead+ only */}
            {canSign && (
                <section className="glass-card p-6 space-y-4">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                        <Unlock className="w-4 h-4 text-gray-400" />
                        Sign a new approval
                    </h2>
                    <FormField label="Allowed path prefixes (one per line)">
                        <textarea
                            rows={4}
                            className="input-field w-full font-mono text-xs"
                            value={form.allowedPaths.join('\n')}
                            onChange={(e) => setForm({ ...form, allowedPaths: e.target.value.split('\n').filter(Boolean) })}
                        />
                    </FormField>
                    <FormField label="Allowed methods (comma separated)">
                        <input
                            className="input-field w-full font-mono text-xs"
                            value={form.allowedMethodsText}
                            onChange={(e) => setForm({ ...form, allowedMethodsText: e.target.value })}
                        />
                    </FormField>
                    <div className="grid grid-cols-2 gap-3">
                        <Toggle
                            label="Exploitation allowed"
                            hint="Enables safetyMode=exploit — deep extraction, post-exploit evidence."
                            value={form.exploitAllowed}
                            onChange={(v) => setForm({ ...form, exploitAllowed: v })}
                        />
                        <Toggle
                            label="OS command"
                            hint="Allow xp_cmdshell / UDF probes when DB is DBA."
                            value={form.osCommandAllowed}
                            onChange={(v) => setForm({ ...form, osCommandAllowed: v })}
                        />
                        <Toggle
                            label="File read"
                            hint="LOAD_FILE / pg_read_file / similar."
                            value={form.fileReadAllowed}
                            onChange={(v) => setForm({ ...form, fileReadAllowed: v })}
                        />
                        <Toggle
                            label="Data exfiltration"
                            hint="Extract rows past schema (columns + sample data)."
                            value={form.dataExfilAllowed}
                            onChange={(v) => setForm({ ...form, dataExfilAllowed: v })}
                        />
                    </div>
                    <FormField label="Expires (ISO timestamp, optional)">
                        <input
                            type="datetime-local"
                            className="input-field w-full"
                            value={form.expiresIso}
                            onChange={(e) => setForm({ ...form, expiresIso: e.target.value })}
                        />
                    </FormField>
                    <FormField label="Rationale / link to signed document (optional)">
                        <textarea
                            rows={2}
                            className="input-field w-full"
                            value={form.rationale}
                            onChange={(e) => setForm({ ...form, rationale: e.target.value })}
                        />
                    </FormField>

                    {create.error && (
                        <div className="text-sm text-red-400">{create.error.message}</div>
                    )}

                    <button
                        onClick={submitCreate}
                        disabled={create.isPending}
                        className="btn-primary flex items-center gap-2 disabled:opacity-50"
                    >
                        {create.isPending ? 'Signing…' : 'Sign approval'}
                    </button>
                </section>
            )}
        </div>
    );
}

function ApprovalCard({
    approval,
    onRevoke,
}: {
    approval: {
        id: string;
        createdAt: Date | string;
        expiresAt: Date | string | null;
        revokedAt: Date | string | null;
        revokedReason: string | null;
        exploitAllowed: boolean;
        osCommandAllowed: boolean;
        fileReadAllowed: boolean;
        dataExfilAllowed: boolean;
        allowedPaths: string;
        allowedMethods: string;
        rationale: string | null;
    };
    onRevoke: ((reason: string) => void) | null;
}) {
    const paths = safeJsonParse(approval.allowedPaths) as string[] | null;
    const methods = safeJsonParse(approval.allowedMethods) as string[] | null;
    const revoked = approval.revokedAt !== null;
    const expired = approval.expiresAt !== null && new Date(approval.expiresAt) < new Date();

    return (
        <div className={`space-y-3 p-4 rounded-lg border ${revoked || expired ? 'border-red-500/20 bg-red-500/5' : 'border-emerald-500/20 bg-emerald-500/5'}`}>
            <div className="flex items-start justify-between gap-3">
                <div>
                    <div className="font-mono text-xs text-gray-500">{approval.id}</div>
                    <div className="text-sm text-[var(--text-primary)]">
                        Signed {new Date(approval.createdAt).toLocaleString()}
                        {approval.expiresAt && <span className="ml-2">· expires {new Date(approval.expiresAt).toLocaleString()}</span>}
                    </div>
                </div>
                {onRevoke && !revoked && (
                    <button
                        onClick={() => {
                            const reason = window.prompt('Reason for revoking this approval?');
                            if (reason) onRevoke(reason);
                        }}
                        className="btn-ghost text-red-400 hover:bg-red-500/10 flex items-center gap-1.5 text-xs"
                    >
                        <Trash2 className="w-3.5 h-3.5" />
                        Revoke
                    </button>
                )}
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
                <Flag label="Exploit" on={approval.exploitAllowed} />
                <Flag label="OS cmd" on={approval.osCommandAllowed} />
                <Flag label="File read" on={approval.fileReadAllowed} />
                <Flag label="Exfil" on={approval.dataExfilAllowed} />
            </div>

            <div className="text-xs text-gray-400">
                <div><span className="text-gray-500">Paths:</span> {paths?.join(', ') ?? '—'}</div>
                <div><span className="text-gray-500">Methods:</span> {methods?.join(', ') ?? '—'}</div>
                {approval.rationale && <div className="mt-1"><span className="text-gray-500">Rationale:</span> {approval.rationale}</div>}
            </div>

            {revoked && (
                <div className="text-xs text-red-300">Revoked: {approval.revokedReason}</div>
            )}
        </div>
    );
}

function Flag({ label, on }: { label: string; on: boolean }) {
    return (
        <div className={`px-2 py-1 rounded ${on ? 'bg-emerald-500/10 text-emerald-600' : 'bg-[var(--bg-subtle)] text-[var(--text-muted)]'}`}>
            {on ? '✓' : '—'} {label}
        </div>
    );
}

function Toggle({ label, hint, value, onChange }: { label: string; hint: string; value: boolean; onChange: (v: boolean) => void }) {
    return (
        <label className="flex items-start gap-3 p-3 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-subtle)] cursor-pointer hover:bg-[var(--bg-hover)]">
            <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} className="mt-1" />
            <div>
                <div className="text-sm font-medium">{label}</div>
                <div className="text-xs text-gray-500">{hint}</div>
            </div>
        </label>
    );
}

function FormField({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <label className="block space-y-1">
            <span className="text-xs uppercase tracking-wider text-gray-400">{label}</span>
            {children}
        </label>
    );
}

function safeJsonParse(s: string | null | undefined): unknown {
    if (!s) return null;
    try { return JSON.parse(s); } catch { return null; }
}
