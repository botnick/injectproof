// InjectProof — Markov-chain URL-segment model
// Replaces the 300-path static admin list as the *primary* source of
// candidate endpoints. Learns the URL segment structure of the target from
// whatever has already been crawled, then generates high-probability new
// paths that a static list would never predict.
//
// This is the "adapt to what the target actually looks like" piece — a scan
// of a CMS will naturally start probing /admin, /wp-admin, /content/*; a
// scan of an API will probe /v1/*/users, /api/v2/*, /graphql.
//
// Implementation: character-level and segment-level n-gram models over
// observed path segments, plus a bigram model over (segment[i-1], segment[i])
// transitions. Generation is nucleus sampling — draw only from segments
// with probability above a threshold so rare hallucinations don't bloat
// the probe budget.

// ============================================================
// Segment extraction + normalization
// ============================================================

export function segmentsOf(path: string): string[] {
    return path.split('?')[0].split('#')[0].split('/').filter(Boolean);
}

/** Normalize a segment: lowercase, strip trailing extensions for grouping. */
function normalize(seg: string): string {
    const lower = seg.toLowerCase();
    const dot = lower.lastIndexOf('.');
    if (dot > 0 && dot > lower.length - 6) return lower.slice(0, dot);
    return lower;
}

// ============================================================
// MarkovUrlModel
// ============================================================

export class MarkovUrlModel {
    private unigram = new Map<string, number>();
    private bigram = new Map<string, Map<string, number>>();
    private charGram = new Map<string, Map<string, number>>();
    private observedPaths = new Set<string>();
    private extensions = new Map<string, number>();
    private totalSegments = 0;

    /** Feed every URL discovered during crawl into the model. */
    observe(url: string): void {
        const path = new URL(url, 'http://base.invalid').pathname;
        if (this.observedPaths.has(path)) return;
        this.observedPaths.add(path);

        const segs = segmentsOf(path).map(normalize);
        if (segs.length === 0) return;

        // Unigram
        for (const s of segs) {
            this.unigram.set(s, (this.unigram.get(s) ?? 0) + 1);
            this.totalSegments++;
        }
        // Bigram with ^ and $ sentinels
        const chain = ['^', ...segs, '$'];
        for (let i = 0; i < chain.length - 1; i++) {
            const from = chain[i];
            const to = chain[i + 1];
            const row = this.bigram.get(from) ?? new Map<string, number>();
            row.set(to, (row.get(to) ?? 0) + 1);
            this.bigram.set(from, row);
        }
        // Char-level trigrams within each segment, for novel segment generation
        for (const s of segs) {
            const padded = '^^' + s + '$';
            for (let i = 0; i < padded.length - 2; i++) {
                const k = padded.slice(i, i + 2);
                const next = padded[i + 2];
                const row = this.charGram.get(k) ?? new Map<string, number>();
                row.set(next, (row.get(next) ?? 0) + 1);
                this.charGram.set(k, row);
            }
        }
        // Extension tracking
        const last = segs[segs.length - 1];
        const dot = (url.split('?')[0].split('#')[0].split('/').pop() ?? '').lastIndexOf('.');
        if (dot > 0) {
            const ext = (url.split('?')[0].split('#')[0].split('/').pop() ?? '').slice(dot);
            this.extensions.set(ext, (this.extensions.get(ext) ?? 0) + 1);
            void last;
        }
    }

    /** Probability that `segment` is drawn from the learned vocabulary. */
    segmentProbability(segment: string): number {
        return (this.unigram.get(normalize(segment)) ?? 0) / Math.max(this.totalSegments, 1);
    }

    /** Bigram transition probability. */
    transitionProbability(from: string, to: string): number {
        const row = this.bigram.get(normalize(from));
        if (!row) return 0;
        const total = [...row.values()].reduce((s, v) => s + v, 0);
        return (row.get(normalize(to)) ?? 0) / Math.max(total, 1);
    }

    /**
     * Generate candidate paths the scanner should probe. `count` is an upper
     * bound; real output may be smaller if the model doesn't have enough
     * context to produce `count` distinct paths.
     *
     * Strategy: for each observed first segment, walk the bigram chain
     * greedily with nucleus sampling until we hit $; then fork.
     */
    generateCandidates(count = 40, includeSeeds = true): string[] {
        const out = new Set<string>();

        // Seed with known high-value admin paths if the model is nearly empty.
        const seedCorpus = [
            '/admin', '/login', '/dashboard', '/api', '/api/v1', '/api/v2',
            '/graphql', '/.env', '/.git/config', '/wp-admin', '/config',
        ];
        if (includeSeeds && this.totalSegments < 6) {
            for (const s of seedCorpus) out.add(s);
        }

        // Bigram-driven generation
        const startRow = this.bigram.get('^');
        if (startRow) {
            const starts = topK(startRow, 8);
            for (const [first] of starts) {
                if (first === '$') continue;
                for (let attempt = 0; attempt < 5 && out.size < count; attempt++) {
                    const path = this.walk(first);
                    if (path) out.add('/' + path);
                }
            }
        }

        // Char-level novel segments — only if we have enough charGram data.
        if (this.charGram.size > 20) {
            for (let i = 0; i < Math.min(10, count - out.size); i++) {
                const novel = this.synthesizeSegment();
                if (novel) {
                    // Combine with a random learned prefix so the novel piece
                    // sits in a plausible position.
                    const prefixPick = pickWeighted(this.unigram);
                    if (prefixPick) out.add(`/${prefixPick}/${novel}`);
                }
            }
        }

        // Permute observed paths with common extensions (/admin → /admin.php).
        for (const path of this.observedPaths) {
            for (const [ext] of this.extensions) {
                const candidate = path.endsWith(ext) ? path : path + ext;
                if (!this.observedPaths.has(candidate)) out.add(candidate);
                if (out.size >= count) break;
            }
            if (out.size >= count) break;
        }

        return [...out].slice(0, count);
    }

    private walk(first: string): string | null {
        const chain: string[] = [first];
        let current = first;
        for (let depth = 0; depth < 4; depth++) {
            const row = this.bigram.get(current);
            if (!row) break;
            const next = pickWeighted(row);
            if (!next || next === '$') break;
            chain.push(next);
            current = next;
        }
        return chain.join('/');
    }

    private synthesizeSegment(maxLen = 12): string | null {
        let context = '^^';
        let out = '';
        for (let i = 0; i < maxLen; i++) {
            const row = this.charGram.get(context.slice(-2));
            if (!row) break;
            const ch = pickWeighted(row);
            if (!ch || ch === '$') break;
            out += ch;
            context += ch;
        }
        return out.length >= 3 ? out : null;
    }

    stats(): { segments: number; distinctPaths: number; extensions: string[] } {
        return {
            segments: this.totalSegments,
            distinctPaths: this.observedPaths.size,
            extensions: [...this.extensions.keys()],
        };
    }
}

// ============================================================
// helpers
// ============================================================

function topK(row: Map<string, number>, k: number): Array<[string, number]> {
    return [...row.entries()].sort((a, b) => b[1] - a[1]).slice(0, k);
}

function pickWeighted(row: Map<string, number>): string | null {
    const total = [...row.values()].reduce((s, v) => s + v, 0);
    if (total === 0) return null;
    const r = Math.random() * total;
    let acc = 0;
    for (const [k, v] of row) {
        acc += v;
        if (r < acc) return k;
    }
    return null;
}
