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
 * 1. 🐼 **Lightpanda binary** (Linux) — fastest, lightest
 * 2. 🌐 **Remote CDP endpoint** — Lightpanda Docker / Browserless.io
 * 3. 🖥️ **OS browser** (last resort) — Edge (Win), Chrome (Linux/Mac)
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
     * 1. 🐼 Lightpanda binary (Linux) — fastest, lightest
     * 2. 🌐 Remote CDP endpoint — if configured
     * 3. 📦 Bundled Chromium (puppeteer.launch) — works everywhere
     * 4. 🖥️ OS browser (last resort) — Edge (Win), Chrome (Linux/Mac)
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

    /** Launch bundled Chromium via puppeteer.launch() with stealth config */
    private async launchBundled(): Promise<void> {
        this.browser = await puppeteer.launch({
            headless: true,
            // Remove the '--enable-automation' default flag (major detection vector)
            ignoreDefaultArgs: ['--enable-automation'],
            args: [
                // ── Core stealth flags ──
                '--disable-blink-features=AutomationControlled',  // #1 detection bypass
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-infobars',

                // ── Fingerprint normalization ──
                `--window-size=${this.config.viewportWidth},${this.config.viewportHeight}`,
                '--lang=en-US,en',
                '--disable-features=IsolateOrigins,site-per-process',

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

        await page.setViewport({
            width: this.config.viewportWidth,
            height: this.config.viewportHeight,
        });

        page.setDefaultNavigationTimeout(this.config.navigationTimeout);
        page.setDefaultTimeout(this.config.navigationTimeout);

        // Set realistic user-agent (fallback to a real Chrome UA)
        const ua = this.config.userAgent || REALISTIC_USER_AGENT;
        await page.setUserAgent(ua);

        if (this.config.extraHeaders) {
            await page.setExtraHTTPHeaders(this.config.extraHeaders);
        }

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
