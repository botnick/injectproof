// InjectProof — Headless Browser Lifecycle Manager
// 4-tier auto-detection: Lightpanda (Linux) → Remote CDP → Bundled Chromium → OS browser
// Provides a managed Puppeteer connection with auto-reconnect and graceful shutdown

import puppeteer, {
    type Browser,
    type BrowserContext,
    type Page,
} from 'puppeteer';
import { existsSync } from 'fs';
import { spawn, type ChildProcess } from 'child_process';
import { platform } from 'os';

// ============================================================
// Configuration
// ============================================================

export interface HeadlessBrowserConfig {
    /** CDP WebSocket endpoint (e.g. ws://127.0.0.1:9222) — optional if using local fallback */
    cdpEndpoint?: string;
    /** Allow auto-launching local Edge/Chrome as fallback (default: true) */
    allowLocalFallback?: boolean;
    /** Port for local browser's CDP server (default: 9222) */
    localCdpPort?: number;
    /** Connection timeout in ms */
    connectTimeout?: number;
    /** Max retry attempts for CDP connection */
    maxRetries?: number;
    /** Delay between retries in ms */
    retryDelay?: number;
    /** Default navigation timeout per page in ms */
    navigationTimeout?: number;
    /** User-Agent string override */
    userAgent?: string;
    /** Extra HTTP headers injected into every request */
    extraHeaders?: Record<string, string>;
    /** Viewport width */
    viewportWidth?: number;
    /** Viewport height */
    viewportHeight?: number;
    /** Run with a visible window (MUCH harder to detect than headless-new).
     *  Set true when target is behind Cloudflare Turnstile / PerimeterX /
     *  Datadome / similar modern bot-detection. Costs more RAM + needs a
     *  display ($DISPLAY on Linux — use Xvfb for servers). Default: false. */
    headful?: boolean;
    /** Timezone to report (IANA name, e.g. "Asia/Bangkok"). Falls back to
     *  the host's timezone if unset — useful when you want a consistent
     *  fingerprint across scans from different machines. */
    timezone?: string;
    /** Primary language tag (e.g. "th-TH,th;q=0.9,en;q=0.8"). Override when
     *  target is geo-gated or your scans need to look Thai. */
    acceptLanguage?: string;
    /** Enable human-like behavioural timing — viewport/UA randomisation, slow
     *  typing, mouse path curves, scroll-before-interact, think-time pauses.
     *  Opt-in because it is 3-10× slower than the fast path; unsafe to
     *  enable during CI scanner tests. Defaults to false. */
    realMode?: boolean;
    /** Random seed for realMode (makes timing reproducible). Undefined → real
     *  randomness (non-deterministic per scan). */
    realModeSeed?: number;
}

const DEFAULT_CONFIG = {
    allowLocalFallback: true,
    localCdpPort: 9222,
    connectTimeout: 10_000,
    maxRetries: 3,
    retryDelay: 1_000,
    navigationTimeout: 15_000,
    viewportWidth: 1280,
    viewportHeight: 800,
};

/** Realistic Chrome user-agent string for stealth mode */
const REALISTIC_USER_AGENT =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ============================================================
// Lightpanda binary detection (preferred on Linux)
// ============================================================

/** Known Lightpanda binary locations */
const LIGHTPANDA_PATHS: string[] = [
    '/usr/local/bin/lightpanda',
    '/usr/bin/lightpanda',
    '/opt/lightpanda/lightpanda',
    `${process.env.HOME ?? ''}/.local/bin/lightpanda`,
    // If user has it in the project
    './node_modules/.bin/lightpanda',
    './lightpanda',
];

/**
 * Find a locally installed Lightpanda binary.
 * Lightpanda is Linux-only — this returns null on Windows/macOS.
 */
export function findLightpandaBinary(): string | null {
    if (platform() === 'win32') return null; // Lightpanda has no Windows build

    for (const p of LIGHTPANDA_PATHS) {
        if (p && existsSync(p)) {
            return p;
        }
    }
    return null;
}

/**
 * Launch Lightpanda as a local CDP server.
 */
export async function launchLightpanda(
    binaryPath: string,
    port: number = 9222,
): Promise<{ process: ChildProcess; wsEndpoint: string }> {
    const child = spawn(binaryPath, ['serve', '--host', '127.0.0.1', '--port', String(port)], {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false,
    });

    const wsEndpoint = await waitForCdpReady(port, 10_000);
    return { process: child, wsEndpoint };
}

// ============================================================
// OS browser auto-detection (last-resort fallback)
// ============================================================

/** OS-bundled browser paths — used as LAST RESORT only */
const OS_BROWSER_PATHS: Record<string, string[]> = {
    win32: [
        // Edge (pre-installed on all Windows 10/11)
        'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        // Chrome
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        `${process.env.LOCALAPPDATA ?? ''}\\Google\\Chrome\\Application\\chrome.exe`,
        // Brave
        `${process.env.LOCALAPPDATA ?? ''}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
    ],
    darwin: [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
    ],
    linux: [
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium-browser',
        '/usr/bin/chromium',
        '/usr/bin/microsoft-edge',
        '/snap/bin/chromium',
    ],
};

/**
 * Find an OS-bundled browser (last-resort fallback).
 * Returns the executable path or null.
 */
export function findLocalBrowser(): string | null {
    const os = platform();
    const candidates = OS_BROWSER_PATHS[os] || OS_BROWSER_PATHS.linux;

    for (const path of candidates) {
        if (path && existsSync(path)) {
            return path;
        }
    }

    return null;
}

/**
 * Launch a local browser in headless mode with CDP enabled.
 * Returns the child process and the WebSocket endpoint.
 */
export async function launchLocalBrowser(
    executablePath: string,
    port: number = 9222,
): Promise<{ process: ChildProcess; wsEndpoint: string }> {
    const args = [
        '--headless=new',
        `--remote-debugging-port=${port}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-gpu',
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-sync',
        '--disable-translate',
        '--disable-dev-shm-usage',
        '--no-sandbox',
        '--metrics-recording-only',
        '--mute-audio',
        'about:blank',
    ];

    const child = spawn(executablePath, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false,
    });

    // Wait for CDP to be ready
    const wsEndpoint = await waitForCdpReady(port, 10_000);

    return { process: child, wsEndpoint };
}

/**
 * Poll the CDP /json/version endpoint until a browser is ready.
 */
async function waitForCdpReady(port: number, timeout: number): Promise<string> {
    const start = Date.now();
    const url = `http://127.0.0.1:${port}/json/version`;

    while (Date.now() - start < timeout) {
        try {
            const controller = new AbortController();
            const tid = setTimeout(() => controller.abort(), 1000);
            const res = await fetch(url, { signal: controller.signal });
            clearTimeout(tid);

            if (res.ok) {
                const data = await res.json() as { webSocketDebuggerUrl?: string };
                if (data.webSocketDebuggerUrl) {
                    return data.webSocketDebuggerUrl;
                }
                // Fallback: construct from port
                return `ws://127.0.0.1:${port}`;
            }
        } catch {
            // Not ready yet
        }
        await sleep(300);
    }

    throw new HeadlessBrowserError(`Local browser CDP not ready on port ${port} within ${timeout}ms`);
}

// ============================================================
// HeadlessBrowser — managed CDP connection
// ============================================================

/**
 * Managed headless browser with 3-tier priority:
 *
 *   1. Lightpanda binary (Linux) — fastest, lightest
 *   2. Remote CDP endpoint — Lightpanda Docker / Browserless.io
 *   3. OS browser (last resort) — Edge (Windows), Chrome (Linux/Mac)
 *
 * @example
 * ```ts
 * // Auto-detect best backend (Lightpanda on Linux, Edge on Windows)
 * const browser = new HeadlessBrowser({});
 *
 * // Force remote Lightpanda
 * const browser = new HeadlessBrowser({ cdpEndpoint: 'ws://lightpanda:9222' });
 *
 * await browser.connect();
 * const page = await browser.newPage();
 * await page.goto('https://example.com');
 * await browser.disconnect();
 * ```
 */
export class HeadlessBrowser {
    private config: HeadlessBrowserConfig & typeof DEFAULT_CONFIG;
    private browser: Browser | null = null;
    private context: BrowserContext | null = null;
    private activePages: Set<Page> = new Set();
    private _connected = false;
    /** Locally spawned browser process (if using fallback) */
    private localProcess: ChildProcess | null = null;
    /** Which backend is in use */
    private _backend: 'lightpanda' | 'remote' | 'bundled-chromium' | 'os-browser' | null = null;

    constructor(config: HeadlessBrowserConfig) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /** Whether the browser is currently connected */
    get connected(): boolean {
        return this._connected && this.browser !== null;
    }

    /** Which backend is active: 'remote' (Lightpanda/CDP), 'local' (Edge/Chrome), or null */
    get backend(): string | null {
        return this._backend;
    }

    /**
     * Connect to a headless browser using 4-tier priority:
     *   1. Lightpanda binary (Linux) — fastest, lightest
     *   2. Remote CDP endpoint — if configured
     *   3. Bundled Chromium (puppeteer.launch) — works everywhere
     *   4. OS browser (last resort) — Edge (Windows), Chrome (Linux/Mac)
     */
    async connect(): Promise<void> {
        // ── Tier 1: Lightpanda local binary (Linux only) ──
        const lpBinary = findLightpandaBinary();
        if (lpBinary) {
            try {
                const { process: proc, wsEndpoint } = await launchLightpanda(
                    lpBinary,
                    this.config.localCdpPort,
                );
                this.localProcess = proc;
                await this.connectToEndpoint(wsEndpoint);
                this._backend = 'lightpanda';
                return;
            } catch {
                this.killLocalProcess();
                // Fall through to next tier
            }
        }

        // ── Tier 2: Remote CDP endpoint (Lightpanda Docker / Browserless) ──
        if (this.config.cdpEndpoint) {
            try {
                await this.connectToEndpoint(this.config.cdpEndpoint);
                this._backend = 'remote';
                return;
            } catch {
                if (!this.config.allowLocalFallback) {
                    throw new HeadlessBrowserError(
                        `Remote CDP ${this.config.cdpEndpoint} unavailable and local fallback disabled`,
                    );
                }
                // Fall through to bundled Chromium
            }
        }

        // ── Tier 3: Bundled Chromium via puppeteer.launch() ──
        if (this.config.allowLocalFallback) {
            try {
                await this.launchBundled();
                this._backend = 'bundled-chromium';
                return;
            } catch {
                // Fall through to OS browser
            }
        }

        // ── Tier 4: OS-bundled browser (last resort) ──
        if (this.config.allowLocalFallback) {
            const execPath = findLocalBrowser();
            if (execPath) {
                try {
                    const { process: proc, wsEndpoint } = await launchLocalBrowser(
                        execPath,
                        this.config.localCdpPort,
                    );
                    this.localProcess = proc;
                    await this.connectToEndpoint(wsEndpoint);
                    this._backend = 'os-browser';
                    return;
                } catch (error) {
                    this.killLocalProcess();
                    throw new HeadlessBrowserError(
                        `Failed to launch OS browser at ${execPath}`,
                        error instanceof Error ? error : null,
                    );
                }
            }
        }

        throw new HeadlessBrowserError(
            'No headless browser available.\n' +
            '  Install puppeteer (npm i puppeteer) for bundled Chromium\n' +
            '  Linux: install Lightpanda (recommended) or Chrome/Chromium\n' +
            '  Windows: Edge should be pre-installed\n' +
            '  Or provide a remote cdpEndpoint',
        );
    }

    /** Launch bundled Chromium via puppeteer.launch() with stealth config.
     *  Uses Chrome's NEW headless mode (--headless=new) when not headful —
     *  the new mode shares the same runtime binary as headful Chrome, so its
     *  JS + WebGL + navigator surface is ~99% identical to real Chrome,
     *  unlike the old headless mode which was distinguishable by dozens of
     *  feature checks. For the few anti-bot systems that still fingerprint
     *  new-headless (Datadome / PerimeterX / Kasada), set config.headful=true
     *  to launch a visible window. */
    private async launchBundled(): Promise<void> {
        const acceptLang = this.config.acceptLanguage ?? 'en-US,en;q=0.9';
        // Extract just the primary tag for --lang flag (e.g. "th-TH" from "th-TH,th;q=0.9").
        const primaryLang = acceptLang.split(',')[0];

        this.browser = await puppeteer.launch({
            // 'new' = Chrome >= 112 new headless mode. Closer-to-real than the
            // legacy 'true' boolean. When headful is explicitly requested we
            // run with a visible window — costs RAM + needs $DISPLAY but beats
            // the strongest bot-detection systems.
            headless: this.config.headful ? false : 'new' as unknown as boolean,
            // Strip the default flags that scream "automation" to the target.
            ignoreDefaultArgs: [
                '--enable-automation',
                '--enable-blink-features=IdleDetection',
            ],
            args: [
                // ── Core stealth flags ──
                '--disable-blink-features=AutomationControlled',  // removes navigator.webdriver entirely
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-infobars',                              // removes "Chrome is being controlled…" bar

                // ── Fingerprint normalization ──
                `--window-size=${this.config.viewportWidth},${this.config.viewportHeight}`,
                `--lang=${primaryLang}`,
                '--disable-features=IsolateOrigins,site-per-process,AutomationControlled',

                // ── Anti-detection networking tweaks ──
                // These change the TLS JA3 fingerprint very slightly — enough
                // to move us off the "known Puppeteer default" list without
                // needing a custom TLS layer.
                '--disable-features=TranslateUI,OptimizationHints,PrivacySandboxSettings4',
                '--disable-search-engine-choice-screen',
                '--disable-client-side-phishing-detection',
                '--disable-component-update',
                '--disable-domain-reliability',
                '--no-pings',

                // ── Media / permissions ──
                // fake-ui-for-media-stream auto-allows camera/mic prompts; tests
                // that rely on getUserMedia will at least get a stream instead
                // of a blocking dialog that freezes the scan.
                '--use-fake-ui-for-media-stream',
                '--use-fake-device-for-media-stream',

                // ── Resource optimization ──
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--disable-sync',
                '--disable-translate',
                '--disable-ipc-flooding-protection',
                '--metrics-recording-only',
                '--mute-audio',
                '--no-first-run',
                '--no-default-browser-check',
                '--password-store=basic',
                '--use-mock-keychain',

                // ── Hint: treat us as a real user interactively ──
                '--disable-hang-monitor',
                '--disable-prompt-on-repost',
                '--disable-breakpad',
                '--disable-crash-reporter',
            ],
            protocolTimeout: this.config.connectTimeout,
        });

        this.context = await this.browser.createBrowserContext();
        this._connected = true;

        this.browser.on('disconnected', () => {
            this._connected = false;
            this.browser = null;
            this.context = null;
            this.activePages.clear();
        });
    }

    /** Internal: connect Puppeteer to a specific WebSocket endpoint */
    private async connectToEndpoint(wsEndpoint: string): Promise<void> {
        let lastError: Error | null = null;

        for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
            try {
                this.browser = await puppeteer.connect({
                    browserWSEndpoint: wsEndpoint,
                    protocolTimeout: this.config.connectTimeout,
                });

                this.context = await this.browser.createBrowserContext();
                this._connected = true;

                this.browser.on('disconnected', () => {
                    this._connected = false;
                    this.browser = null;
                    this.context = null;
                    this.activePages.clear();
                });

                return;
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                if (attempt < this.config.maxRetries) {
                    await sleep(this.config.retryDelay);
                }
            }
        }

        throw new HeadlessBrowserError(
            `Failed to connect to CDP at ${wsEndpoint} after ${this.config.maxRetries} attempts`,
            lastError,
        );
    }

    /**
     * Create a new page with pre-configured settings.
     * Automatically sets viewport, user-agent, extra headers,
     * and stealth anti-fingerprinting patches for real-user emulation.
     */
    async newPage(): Promise<Page> {
        if (!this.context || !this._connected) {
            throw new HeadlessBrowserError('Browser not connected. Call connect() first.');
        }

        const page = await this.context.newPage();

        // ── Stealth evasion patches ──
        await this.applyStealthPatches(page);

        // realMode: randomise viewport + UA per-page to look like a population
        // of real users rather than one identifiable bot. Seeded so reruns are
        // reproducible when a seed is supplied.
        const { pickViewport, pickUserAgent } = await import('./humanize');
        const humanOpts = { realMode: this.config.realMode, seed: this.config.realModeSeed };
        const vp = this.config.realMode
            ? pickViewport(humanOpts)
            : { width: this.config.viewportWidth, height: this.config.viewportHeight };

        await page.setViewport(vp);
        // Update stored dims so other stealth patches (screen.width shim) pick
        // up the randomised viewport.
        (this.config as { viewportWidth: number; viewportHeight: number }).viewportWidth = vp.width;
        (this.config as { viewportWidth: number; viewportHeight: number }).viewportHeight = vp.height;

        page.setDefaultNavigationTimeout(this.config.navigationTimeout);
        page.setDefaultTimeout(this.config.navigationTimeout);

        // Set user-agent — realMode picks from a rotating pool; otherwise use
        // the configured UA or the single realistic default.
        const ua = this.config.realMode
            ? pickUserAgent(humanOpts)
            : (this.config.userAgent || REALISTIC_USER_AGENT);
        await page.setUserAgent(ua);

        // Merge Accept-Language into extraHeaders so every fetch carries it —
        // modern anti-bot cross-checks UA claim vs TLS / header order / lang.
        const headersToSet: Record<string, string> = {
            'Accept-Language': this.config.acceptLanguage ?? 'en-US,en;q=0.9',
            ...(this.config.extraHeaders ?? {}),
        };
        await page.setExtraHTTPHeaders(headersToSet);

        // Timezone — apply via CDP when config.timezone set (falls back to the
        // runtime-JS shim installed by applyStealthPatches).
        if (this.config.timezone) {
            try { await page.emulateTimezone(this.config.timezone); } catch { /* some TZ names rejected */ }
        }

        // Permissions — quietly grant the common ones so a target's permission-
        // check probe doesn't tripwire the bot-detection path.
        try {
            const ctx = page.browserContext();
            await ctx.overridePermissions(await page.url() !== 'about:blank' ? page.url() : (this.config.extraHeaders?.['Origin'] || 'http://localhost'), [
                'geolocation', 'notifications', 'clipboard-read', 'clipboard-write',
            ] as unknown as import('puppeteer').Permission[]);
        } catch { /* URL not yet set or origin-invalid — skipped */ }

        this.activePages.add(page);
        page.once('close', () => {
            this.activePages.delete(page);
        });

        return page;
    }

    /**
     * Inject stealth anti-fingerprinting patches into each new page.
     * Hides headless browser indicators to bypass WAFs and bot detection.
     */
    private async applyStealthPatches(page: Page): Promise<void> {
        // 1. Remove navigator.webdriver flag
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
        });

        // 2. Mock chrome runtime object (present in real Chrome, missing in headless)
        await page.evaluateOnNewDocument(() => {
            (window as unknown as Record<string, unknown>).chrome = {
                runtime: {
                    onConnect: { addListener: () => { }, removeListener: () => { } },
                    onMessage: { addListener: () => { }, removeListener: () => { } },
                    sendMessage: () => { },
                    connect: () => ({ onMessage: { addListener: () => { } }, postMessage: () => { } }),
                },
                loadTimes: () => ({}),
                csi: () => ({}),
            };
        });

        // 3. Override navigator.plugins (headless has empty array)
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'plugins', {
                get: () => {
                    const plugins = [
                        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                        { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
                    ];
                    const arr = Object.create(PluginArray.prototype);
                    for (let i = 0; i < plugins.length; i++) {
                        arr[i] = plugins[i];
                    }
                    Object.defineProperty(arr, 'length', { get: () => plugins.length });
                    arr.item = (i: number) => arr[i] || null;
                    arr.namedItem = (n: string) => plugins.find(p => p.name === n) || null;
                    arr.refresh = () => { };
                    return arr;
                },
            });
        });

        // 4. Override navigator.languages
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'language', { get: () => 'en-US' });
        });

        // 5. Fix permissions API (headless returns 'denied' for notifications)
        await page.evaluateOnNewDocument(() => {
            const originalQuery = Notification.permission;
            if (originalQuery === 'denied') {
                Object.defineProperty(Notification, 'permission', { get: () => 'default' });
            }
            if (navigator.permissions) {
                const origQuery = navigator.permissions.query.bind(navigator.permissions);
                navigator.permissions.query = (params: PermissionDescriptor) => {
                    if (params.name === 'notifications') {
                        return Promise.resolve({ state: 'prompt', onchange: null } as PermissionStatus);
                    }
                    return origQuery(params);
                };
            }
        });

        // 6. Fake WebGL vendor/renderer (headless exposes "Google SwiftShader")
        await page.evaluateOnNewDocument(() => {
            const getParameterProto = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function (param: number) {
                // UNMASKED_VENDOR_WEBGL
                if (param === 0x9245) return 'Intel Inc.';
                // UNMASKED_RENDERER_WEBGL
                if (param === 0x9246) return 'Intel Iris OpenGL Engine';
                return getParameterProto.call(this, param);
            };
            // Also patch WebGL2
            if (typeof WebGL2RenderingContext !== 'undefined') {
                const getParam2 = WebGL2RenderingContext.prototype.getParameter;
                WebGL2RenderingContext.prototype.getParameter = function (param: number) {
                    if (param === 0x9245) return 'Intel Inc.';
                    if (param === 0x9246) return 'Intel Iris OpenGL Engine';
                    return getParam2.call(this, param);
                };
            }
        });

        // 7. Fix screen dimensions (match viewport to avoid mismatch fingerprint)
        await page.evaluateOnNewDocument((w: number, h: number) => {
            Object.defineProperty(screen, 'width', { get: () => w });
            Object.defineProperty(screen, 'height', { get: () => h });
            Object.defineProperty(screen, 'availWidth', { get: () => w });
            Object.defineProperty(screen, 'availHeight', { get: () => h - 40 });
            Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
            Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
        }, this.config.viewportWidth, this.config.viewportHeight);

        // 8. Override navigator.hardwareConcurrency (headless often returns 1-2)
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        });

        // 9. Override navigator.deviceMemory (headless often reports low)
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        });

        // 10. Override navigator.maxTouchPoints (desktop should be 0)
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0 });
        });

        // 11. Hide automation-related CDP artifacts
        await page.evaluateOnNewDocument(() => {
            // Remove cdc_ prefix properties (Chrome DevTools)
            const props = Object.getOwnPropertyNames(document);
            for (const prop of props) {
                if (prop.startsWith('cdc_') || prop.startsWith('$cdc_')) {
                    delete (document as unknown as Record<string, unknown>)[prop];
                }
            }
        });

        // 12. Spoof iframe contentWindow (headless leaks through nested frames)
        await page.evaluateOnNewDocument(() => {
            try {
                const origHTMLIFrameElement = HTMLIFrameElement.prototype;
                const descriptor = Object.getOwnPropertyDescriptor(origHTMLIFrameElement, 'contentWindow');
                if (descriptor) {
                    Object.defineProperty(origHTMLIFrameElement, 'contentWindow', {
                        get: function () {
                            const win = descriptor.get?.call(this);
                            if (win) {
                                Object.defineProperty(win.navigator, 'webdriver', { get: () => false });
                            }
                            return win;
                        },
                    });
                }
            } catch {
                // Non-critical
            }
        });

        // 13. Canvas fingerprint noise injection
        //     Adds imperceptible random noise to canvas output so fingerprint
        //     changes between sessions (breaks canvas-based tracking)
        await page.evaluateOnNewDocument(() => {
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function (type?: string) {
                const ctx = this.getContext('2d');
                if (ctx) {
                    const shift = { r: Math.floor(Math.random() * 10) - 5, g: Math.floor(Math.random() * 10) - 5, b: Math.floor(Math.random() * 10) - 5 };
                    const imageData = ctx.getImageData(0, 0, this.width, this.height);
                    for (let i = 0; i < imageData.data.length; i += 4) {
                        imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + shift.r));
                        imageData.data[i + 1] = Math.max(0, Math.min(255, imageData.data[i + 1] + shift.g));
                        imageData.data[i + 2] = Math.max(0, Math.min(255, imageData.data[i + 2] + shift.b));
                    }
                    ctx.putImageData(imageData, 0, 0);
                }
                return origToDataURL.call(this, type);
            };
        });

        // 14. AudioContext fingerprint spoofing
        await page.evaluateOnNewDocument(() => {
            if (typeof AudioContext !== 'undefined') {
                const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                AnalyserNode.prototype.getFloatFrequencyData = function (array: any) {
                    origGetFloatFreq.call(this, array);
                    for (let i = 0; i < array.length; i++) {
                        array[i] += (Math.random() - 0.5) * 0.1;
                    }
                };
            }
        });

        // 15. Spoof navigator.connection (NetworkInformation API)
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'connection', {
                get: () => ({
                    effectiveType: '4g',
                    rtt: 50,
                    downlink: 10,
                    saveData: false,
                }),
            });
        });

        // 16. Protect function toString() from override detection
        //     When sites call func.toString() on overridden methods, they see
        //     "function () { [native code] }" instead of our patched code
        await page.evaluateOnNewDocument(() => {
            const nativeToString = Function.prototype.toString;
            const patchedFns = new WeakSet<Function>();

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const origDefineProperty = Object.defineProperty;
            const handler = {
                apply(target: typeof Object.defineProperty, thisArg: unknown, args: [object, PropertyKey, PropertyDescriptor]): unknown {
                    const [obj, prop, descriptor] = args;
                    if (descriptor?.get && typeof descriptor.get === 'function') {
                        patchedFns.add(descriptor.get);
                    }
                    return Reflect.apply(target, thisArg, args as unknown as []);
                },
            };
            // Only proxy briefly for our patches, then restore
            try {
                Object.defineProperty = new Proxy(origDefineProperty, handler);
            } catch { /* non-critical */ }

            Function.prototype.toString = function () {
                if (patchedFns.has(this)) {
                    return 'function () { [native code] }';
                }
                return nativeToString.call(this);
            };
            // Hide our toString override itself
            patchedFns.add(Function.prototype.toString);
        });

        // 17. User-Agent Client Hints (Sec-CH-UA / navigator.userAgentData) —
        //     modern bot-detection (Cloudflare Turnstile / PerimeterX) reads
        //     this instead of the classic UA string. Headless Chrome often
        //     reports brand "HeadlessChrome" here.
        const uaBrand = 'Google Chrome';
        await page.evaluateOnNewDocument((brand: string) => {
            if (!('userAgentData' in navigator)) return;
            const ua = (navigator as unknown as Record<string, unknown>).userAgentData as {
                brands: Array<{ brand: string; version: string }>;
                mobile: boolean;
                platform: string;
                getHighEntropyValues: (hints: string[]) => Promise<Record<string, unknown>>;
            };
            const fakeBrands = [
                { brand: 'Not_A Brand', version: '8' },
                { brand: brand, version: '131' },
                { brand: 'Chromium', version: '131' },
            ];
            Object.defineProperty(ua, 'brands', { get: () => fakeBrands });
            Object.defineProperty(ua, 'mobile', { get: () => false });
            Object.defineProperty(ua, 'platform', { get: () => 'Windows' });
            const origGHEV = ua.getHighEntropyValues.bind(ua);
            ua.getHighEntropyValues = (hints: string[]) => origGHEV(hints).then((values) => ({
                ...values,
                brands: fakeBrands,
                mobile: false,
                platform: 'Windows',
                platformVersion: '15.0.0',
                architecture: 'x86',
                bitness: '64',
                model: '',
                uaFullVersion: '131.0.6778.109',
                fullVersionList: fakeBrands.map(b => ({ ...b, version: b.version + '.0.6778.109' })),
            }));
        }, uaBrand);

        // 18. Worker / SharedWorker webdriver flag — detection script often
        //     spawns a web worker and checks navigator.webdriver inside it.
        //     We patch the Worker constructor so any script loaded into a
        //     fresh worker inherits our webdriver=false override.
        await page.evaluateOnNewDocument(() => {
            const origWorker = window.Worker;
            if (!origWorker) return;
            const patchedWorkerSrc = `Object.defineProperty(navigator,'webdriver',{get:()=>false});`;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (window as any).Worker = function (url: string | URL, opts?: WorkerOptions) {
                try {
                    if (typeof url === 'string' && url.startsWith('blob:')) {
                        // Can't easily prepend to an existing Blob URL — let it through.
                        return new origWorker(url, opts);
                    }
                    // For module-style workers, best-effort: patch via importScripts won't work;
                    // spawn an override worker that posts a patched navigator before importScripts.
                    const wrapped = new Blob(
                        [`${patchedWorkerSrc}importScripts(${JSON.stringify(String(url))});`],
                        { type: 'application/javascript' },
                    );
                    return new origWorker(URL.createObjectURL(wrapped), opts);
                } catch {
                    return new origWorker(url, opts);
                }
            } as unknown as typeof Worker;
            (window as unknown as { Worker: typeof Worker }).Worker.prototype = origWorker.prototype;
        });

        // 19. Battery API fake — some anti-bot systems check whether Battery
        //     resolves to a real object or rejects (Chrome headful returns a
        //     BatteryManager; some headless environments reject the promise).
        await page.evaluateOnNewDocument(() => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (navigator as any).getBattery = () => Promise.resolve({
                charging: true,
                chargingTime: 0,
                dischargingTime: Infinity,
                level: 0.88,
                addEventListener: () => { },
                removeEventListener: () => { },
                dispatchEvent: () => true,
                onchargingchange: null, onchargingtimechange: null,
                ondischargingtimechange: null, onlevelchange: null,
            });
        });

        // 20. Intl/Timezone consistency — the runtime timezone reported by
        //     Intl.DateTimeFormat must match the value the scanner wants to
        //     report (default host TZ, or explicit config override). Anti-
        //     bot systems cross-check UA-declared locale vs IP-geo vs TZ.
        const tz = this.config.timezone;
        if (tz) {
            await page.evaluateOnNewDocument((tzName: string) => {
                try {
                    const origResolve = Intl.DateTimeFormat.prototype.resolvedOptions;
                    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
                        return { ...origResolve.call(this), timeZone: tzName };
                    };
                } catch { /* non-critical */ }
            }, tz);
            // CDP-level timezone override — more robust than JS shim alone.
            try { await page.emulateTimezone(tz); } catch { /* some endpoints reject TZ names */ }
        }

        // 21. outerWidth / outerHeight must match (headless often reports 0).
        await page.evaluateOnNewDocument((w: number, h: number) => {
            try {
                Object.defineProperty(window, 'outerWidth', { get: () => w });
                Object.defineProperty(window, 'outerHeight', { get: () => h + 74 });
            } catch { /* non-critical */ }
        }, this.config.viewportWidth, this.config.viewportHeight);

        // 22. Media devices — real Chrome reports a list of enumerated devices
        //     (even without a connected camera, fake default entries are listed).
        await page.evaluateOnNewDocument(() => {
            if (navigator.mediaDevices && typeof navigator.mediaDevices.enumerateDevices === 'function') {
                const orig = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
                navigator.mediaDevices.enumerateDevices = async () => {
                    const real = await orig();
                    if (real.length > 0) return real;
                    return [
                        { deviceId: 'default', kind: 'audioinput', label: '', groupId: 'default' } as MediaDeviceInfo,
                        { deviceId: 'default', kind: 'audiooutput', label: '', groupId: 'default' } as MediaDeviceInfo,
                    ];
                };
            }
        });
    }

    /** Close a specific page */
    async closePage(page: Page): Promise<void> {
        try {
            if (!page.isClosed()) {
                await page.close();
            }
        } catch {
            // Page may already be closed
        }
        this.activePages.delete(page);
    }

    /** Disconnect from the browser and kill local process if spawned */
    async disconnect(): Promise<void> {
        // Close all tracked pages
        const closePromises = Array.from(this.activePages).map(p => this.closePage(p));
        await Promise.allSettled(closePromises);
        this.activePages.clear();

        try { if (this.context) await this.context.close(); } catch { /* noop */ }
        try { if (this.browser) await this.browser.disconnect(); } catch { /* noop */ }

        this.browser = null;
        this.context = null;
        this._connected = false;
        this._backend = null;

        // Kill locally spawned browser
        this.killLocalProcess();
    }

    /** Kill the locally spawned browser process */
    private killLocalProcess(): void {
        if (this.localProcess) {
            try {
                this.localProcess.kill('SIGTERM');
            } catch {
                try { this.localProcess.kill('SIGKILL'); } catch { /* noop */ }
            }
            this.localProcess = null;
        }
    }

    /**
     * Navigate to a URL and wait for the page to be fully loaded.
     * Returns the final HTML content after JS execution.
     */
    async fetchRenderedPage(
        url: string,
        options?: {
            waitUntil?: 'load' | 'domcontentloaded' | 'networkidle0' | 'networkidle2';
            timeout?: number;
        },
    ): Promise<{ page: Page; html: string; finalUrl: string }> {
        const page = await this.newPage();

        try {
            const response = await page.goto(url, {
                waitUntil: options?.waitUntil ?? 'networkidle2',
                timeout: options?.timeout ?? this.config.navigationTimeout,
            });

            if (!response) {
                throw new HeadlessBrowserError(`No response received for ${url}`);
            }

            const html = await page.content();
            const finalUrl = page.url();

            return { page, html, finalUrl };
        } catch (error) {
            await this.closePage(page);
            throw error;
        }
    }

    /** Capture a full-page screenshot as base64 */
    async captureScreenshot(page: Page): Promise<string> {
        const screenshot = await page.screenshot({
            encoding: 'base64',
            fullPage: true,
            type: 'png',
        });
        return screenshot as string;
    }

    /** Capture the current DOM as serialized HTML string */
    async captureDomSnapshot(page: Page): Promise<string> {
        return page.content();
    }
}

// ============================================================
// Error class
// ============================================================

export class HeadlessBrowserError extends Error {
    public readonly cause?: Error;

    constructor(message: string, cause?: Error | null) {
        super(message);
        this.name = 'HeadlessBrowserError';
        if (cause) this.cause = cause;
    }
}

// ============================================================
// Helpers
// ============================================================

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Detect if a CDP server is available at endpoint.
 * Returns true if /json/version responds OK within timeout.
 */
export async function isCdpAvailable(
    endpoint: string,
    timeout = 3_000,
): Promise<boolean> {
    try {
        const httpUrl = endpoint
            .replace('ws://', 'http://')
            .replace('wss://', 'https://')
            .replace(/\/$/, '') + '/json/version';

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(httpUrl, { signal: controller.signal });
        clearTimeout(timeoutId);

        return response.ok;
    } catch {
        return false;
    }
}
