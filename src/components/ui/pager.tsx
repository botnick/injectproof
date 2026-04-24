// InjectProof — simple pagination control
// =========================================
// Client-side stateless pager: {page, totalPages, onPageChange} in, rendered
// button row out. Shows the first, last, current, and a sliding window of
// ±2 around current, with ellipsis gaps between non-contiguous ranges.

'use client';

import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PagerProps {
    page: number;            // 1-indexed
    totalPages: number;
    onPageChange: (page: number) => void;
    /** Total items, shown as "Showing X–Y of Z" above the buttons. Optional. */
    totalItems?: number;
    /** Items per page, needed to compute the X–Y range when totalItems is set. */
    pageSize?: number;
}

/** Build the visible page numbers with ellipsis gaps. */
function visiblePages(current: number, total: number): Array<number | '…'> {
    if (total <= 7) {
        return Array.from({ length: total }, (_, i) => i + 1);
    }
    const result: Array<number | '…'> = [];
    const push = (v: number | '…') => {
        const prev = result[result.length - 1];
        if (v === '…' && prev === '…') return;
        result.push(v);
    };
    // Always first + last.
    push(1);
    if (current > 3) push('…');
    for (let p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) {
        push(p);
    }
    if (current < total - 2) push('…');
    push(total);
    return result;
}

export function Pager({ page, totalPages, onPageChange, totalItems, pageSize }: PagerProps) {
    if (totalPages <= 1) return null;

    const pages = visiblePages(page, totalPages);
    const clamp = (p: number) => Math.max(1, Math.min(totalPages, p));

    const rangeStart = totalItems != null && pageSize ? (page - 1) * pageSize + 1 : null;
    const rangeEnd = totalItems != null && pageSize ? Math.min(page * pageSize, totalItems) : null;

    return (
        <div className="flex items-center justify-between gap-3 flex-wrap mt-4 text-xs">
            {rangeStart != null && rangeEnd != null && totalItems != null ? (
                <p className="text-[var(--text-muted)]">
                    Showing <span className="text-[var(--text-primary)]">{rangeStart}–{rangeEnd}</span> of <span className="text-[var(--text-primary)]">{totalItems}</span>
                </p>
            ) : (
                <p className="text-[var(--text-muted)]">
                    Page <span className="text-[var(--text-primary)]">{page}</span> of <span className="text-[var(--text-primary)]">{totalPages}</span>
                </p>
            )}

            <div className="flex items-center gap-1">
                <button
                    type="button"
                    onClick={() => onPageChange(clamp(page - 1))}
                    disabled={page <= 1}
                    aria-label="Previous page"
                    className="w-8 h-8 inline-flex items-center justify-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                >
                    <ChevronLeft className="w-3.5 h-3.5" />
                </button>

                {pages.map((p, i) =>
                    p === '…' ? (
                        <span key={`gap-${i}`} className="w-8 h-8 inline-flex items-center justify-center text-[var(--text-muted)]">…</span>
                    ) : (
                        <button
                            key={p}
                            type="button"
                            onClick={() => onPageChange(p)}
                            aria-current={p === page ? 'page' : undefined}
                            className={
                                'w-8 h-8 inline-flex items-center justify-center rounded-lg border text-xs font-mono transition-all ' +
                                (p === page
                                    ? 'bg-brand-500/20 border-brand-500/40 text-brand-300 font-semibold'
                                    : 'border-[var(--border-subtle)] bg-[var(--bg-card)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]')
                            }
                        >
                            {p}
                        </button>
                    )
                )}

                <button
                    type="button"
                    onClick={() => onPageChange(clamp(page + 1))}
                    disabled={page >= totalPages}
                    aria-label="Next page"
                    className="w-8 h-8 inline-flex items-center justify-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                >
                    <ChevronRight className="w-3.5 h-3.5" />
                </button>
            </div>
        </div>
    );
}
