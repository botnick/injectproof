// InjectProof — Human-like interaction helpers
// =============================================
// Layered on top of the 22 stealth DOM patches in headless-browser.ts. Those
// patches hide automation *signatures* (navigator.webdriver, UA-CH brand,
// WebGL vendor, etc.) — but modern bot-detection (Datadome / PerimeterX /
// Kasada / Cloudflare Turnstile) also fingerprints *behaviour*: how fast the
// user types, whether the mouse moves before a click, whether they scroll
// before interacting, how long they pause between actions. Zero-latency
// Puppeteer `page.type(sel, val, { delay: 0 })` is a dead giveaway.
//
// This module provides humane versions of type/click/scroll/pause that, when
// enabled via `realMode: true`, make those signals indistinguishable from a
// real human. When `realMode` is falsy, every function is a no-op that falls
// through to the fast Puppeteer default — existing tests and CI scans stay
// fast.
//
// IMPORTANT: Never use these inside tight extraction loops (blind-SQLi char
// extraction, UNION-sweep inference). Humanising those would turn a 2-minute
// scan into 6 hours for zero signal-to-noise benefit. Only humanise the
// initial "the user walks up to the form and fills it in" phase.

import type { Page } from 'puppeteer';

export interface HumanizeOpts {
    /** When true, use human-like timing. When false/absent, no-op. */
    realMode?: boolean;
    /** Seed for deterministic randomness — same seed → same timing profile. */
    seed?: number;
}

// ── Seeded PRNG (mulberry32) ────────────────────────────────────────────
// We reach for a seeded PRNG rather than Math.random() so reruns with the
// same scan seed produce the same timing profile. Reproducible = debuggable
// AND safe to use in test assertions (± a few ms tolerance).

function makeRng(seed?: number): () => number {
    // No seed → fall back to Math.random. Most production paths use this.
    if (seed == null) return Math.random;
    let s = seed >>> 0;
    return () => {
        s = (s + 0x6d2b79f5) >>> 0;
        let t = s;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function rnd(rng: () => number, lo: number, hi: number): number {
    return lo + rng() * (hi - lo);
}

// Gaussian-ish jitter using CLT sum. Good enough for timing profiles — we're
// not doing statistics, just avoiding the uniform-distribution tell.
function gauss(rng: () => number, mean: number, stdev: number): number {
    let u = 0;
    for (let i = 0; i < 6; i++) u += rng();
    return mean + (u - 3) * stdev * (1 / Math.sqrt(2));
}

const delay = (ms: number): Promise<void> => new Promise(r => setTimeout(r, Math.max(0, ms)));

// ── humanType ───────────────────────────────────────────────────────────
// Types a string key-by-key with Gaussian-jittered inter-key delay. Real
// typists:
//   - Pause longer after punctuation (thinking beat).
//   - Occasionally make a typo and backspace.
//   - Speed up on common letter pairs and slow down on unusual ones (we
//     approximate this with simple jitter rather than a full bigram model).
//
// When `opts.realMode` is false we fall back to Puppeteer's native
// `page.type(sel, text, { delay: 0 })` — fastest path.

export async function humanType(
    page: Page,
    selector: string,
    text: string,
    opts: HumanizeOpts = {},
): Promise<void> {
    if (!opts.realMode) {
        await page.type(selector, text, { delay: 0 });
        return;
    }

    const rng = makeRng(opts.seed);

    // Focus the field first — real users click in, they don't teleport.
    await page.focus(selector);

    for (let i = 0; i < text.length; i++) {
        const ch = text[i];

        // Occasional typo insertion + backspace (~1% per char).
        if (rng() < 0.01 && /[a-zA-Z]/.test(ch)) {
            const near = String.fromCharCode(ch.charCodeAt(0) + (rng() < 0.5 ? 1 : -1));
            await page.keyboard.type(near);
            await delay(gauss(rng, 140, 50));
            await page.keyboard.press('Backspace');
            await delay(gauss(rng, 80, 20));
        }

        await page.keyboard.type(ch);

        // Inter-key delay — mean 90ms, stdev 35ms. Clamp to [25, 260] to
        // avoid pathological outliers (negative times or 1s+ pauses).
        let d = gauss(rng, 90, 35);
        if (d < 25) d = 25;
        if (d > 260) d = 260;

        // Extra thinking beat after punctuation / spaces following longer words.
        if (ch === ',' || ch === '.' || ch === '!' || ch === '?') {
            d += rnd(rng, 180, 420);
        } else if (ch === ' ' && i > 0 && /\w{6,}/.test(text.slice(Math.max(0, i - 8), i))) {
            // End of a long word — brief pause.
            d += rnd(rng, 80, 220);
        }

        await delay(d);
    }
}

// ── humanClick ──────────────────────────────────────────────────────────
// Instead of clicking the centre of an element, real users:
//   1) scroll the element into view,
//   2) move the mouse along a curved path toward it,
//   3) hover briefly before pressing,
//   4) click at a variable offset from the centre.
//
// We approximate the mouse path with 20-40 micro-steps along a simple
// ease-in/out curve. Full cubic-bezier (two control points) is overkill for
// the signal we're trying to produce.

export async function humanClick(
    page: Page,
    selector: string,
    opts: HumanizeOpts = {},
): Promise<void> {
    if (!opts.realMode) {
        await page.click(selector);
        return;
    }
    const rng = makeRng(opts.seed);

    // Ensure the element is in view — real users scroll before clicking.
    const box = await page.evaluate((sel: string) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        el.scrollIntoView({ block: 'center', behavior: 'instant' as ScrollBehavior });
        const b = el.getBoundingClientRect();
        return { x: b.x, y: b.y, w: b.width, h: b.height };
    }, selector);
    if (!box || box.w === 0 || box.h === 0) {
        // Fall back to Puppeteer's click — better than throwing.
        await page.click(selector);
        return;
    }

    // Pick a target point somewhere in the "comfortable" 20-80% zone of
    // the element, not dead-centre (that's a tell).
    const targetX = box.x + rnd(rng, box.w * 0.2, box.w * 0.8);
    const targetY = box.y + rnd(rng, box.h * 0.2, box.h * 0.8);

    // Starting point: wherever the current cursor is. Puppeteer exposes no
    // getter, so we estimate with the previous click or mid-viewport.
    const vp = page.viewport() ?? { width: 1280, height: 800 };
    const startX = vp.width / 2 + rnd(rng, -40, 40);
    const startY = vp.height / 2 + rnd(rng, -40, 40);

    // Control point for the curve — pulls the path slightly off-axis.
    const ctrlX = (startX + targetX) / 2 + rnd(rng, -80, 80);
    const ctrlY = (startY + targetY) / 2 + rnd(rng, -80, 80);

    const steps = Math.floor(rnd(rng, 20, 40));
    const totalMs = rnd(rng, 400, 900);
    const stepMs = totalMs / steps;

    for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        // Quadratic Bezier — one control point.
        const x = (1 - t) * (1 - t) * startX + 2 * (1 - t) * t * ctrlX + t * t * targetX;
        const y = (1 - t) * (1 - t) * startY + 2 * (1 - t) * t * ctrlY + t * t * targetY;
        await page.mouse.move(x, y, { steps: 1 });
        await delay(stepMs);
    }

    // Brief hover — real users tend to land, pause, press.
    await delay(rnd(rng, 60, 200));
    await page.mouse.click(targetX, targetY);
}

// ── humanScroll ─────────────────────────────────────────────────────────
// Real users scroll pages before interacting — to see what's there, to
// read, to load lazy content. A Puppeteer run that jumps straight to a
// form field and fills it without scrolling is suspicious. This dispatches
// native wheel events in chunks with ease-out timing.

export async function humanScroll(page: Page, opts: HumanizeOpts = {}): Promise<void> {
    if (!opts.realMode) return;
    const rng = makeRng(opts.seed);
    const totalChunks = Math.floor(rnd(rng, 6, 12));
    for (let i = 0; i < totalChunks; i++) {
        const deltaY = rnd(rng, 80, 140);
        await page.evaluate((dy: number) => window.scrollBy({ top: dy, left: 0, behavior: 'auto' }), deltaY);
        // Ease-out — last third of chunks get longer gaps.
        const isTail = i > totalChunks * 0.66;
        await delay(rnd(rng, isTail ? 80 : 30, isTail ? 200 : 90));
    }
}

// ── humanPause ──────────────────────────────────────────────────────────
// Insert between top-level scanner phases so the whole run doesn't look
// like CPU-bound automation. Typical real-user inter-action gap is
// 500-1500ms — they move around the page, read, decide what to click next.

export async function humanPause(opts: HumanizeOpts = {}): Promise<void> {
    if (!opts.realMode) return;
    const rng = makeRng(opts.seed);
    await delay(rnd(rng, 300, 1500));
}

// ── simulateVisibilityFlicker ───────────────────────────────────────────
// Real users tab away — check Slack, look at another app, come back. We
// dispatch a visibilitychange event with document.hidden=true for a random
// stretch then flip it back. Runs in-page via evaluate. Good for defeating
// "was this tab actually in focus while the scan ran?" signals.

export async function simulateVisibilityFlicker(page: Page, opts: HumanizeOpts = {}): Promise<void> {
    if (!opts.realMode) return;
    const rng = makeRng(opts.seed);
    const awayMs = rnd(rng, 800, 3000);
    try {
        await page.evaluate(() => {
            Object.defineProperty(document, 'hidden', { get: () => true, configurable: true });
            Object.defineProperty(document, 'visibilityState', { get: () => 'hidden', configurable: true });
            document.dispatchEvent(new Event('visibilitychange'));
        });
        await delay(awayMs);
        await page.evaluate(() => {
            Object.defineProperty(document, 'hidden', { get: () => false, configurable: true });
            Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
            document.dispatchEvent(new Event('visibilitychange'));
        });
    } catch {
        // Page may have navigated or closed — non-critical, skip silently.
    }
}

// ── Viewport + UA pool ──────────────────────────────────────────────────
// Modern bot detection fingerprints the combination (UA × viewport × screen).
// Real users have a distribution; bots have a single point. These helpers let
// the headless-browser module randomise on each newPage when realMode is on.

export const REALISTIC_VIEWPORTS: Array<{ width: number; height: number }> = [
    { width: 1280, height: 720 },
    { width: 1366, height: 768 },
    { width: 1440, height: 900 },
    { width: 1536, height: 864 },
    { width: 1920, height: 1080 },
];

export const REALISTIC_UA_POOL: string[] = [
    // Chrome 131 Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    // Chrome 131 macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    // Chrome 131 Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    // Edge 131 Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    // Chrome 130 Windows (slightly older, blends the pool)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
];

export function pickViewport(opts: HumanizeOpts = {}): { width: number; height: number } {
    if (!opts.realMode) return REALISTIC_VIEWPORTS[4]; // deterministic when realMode off
    const rng = makeRng(opts.seed);
    return REALISTIC_VIEWPORTS[Math.floor(rng() * REALISTIC_VIEWPORTS.length)];
}

export function pickUserAgent(opts: HumanizeOpts = {}): string {
    if (!opts.realMode) return REALISTIC_UA_POOL[0];
    const rng = makeRng(opts.seed);
    return REALISTIC_UA_POOL[Math.floor(rng() * REALISTIC_UA_POOL.length)];
}
