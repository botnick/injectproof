// InjectProof — User-Agent rotation pool
// ใช้ตอน recovery step 4 (UA rotation) หลังจาก target ปฏิเสธ default UA ของ
// scanner. เก็บเฉพาะ UA realistic ของ desktop browser รุ่นไม่เก่าเกินไป เพื่อ
// ไม่ให้ user-agent header กลายเป็น signature ของ scanner เอง.
//
// หมายเหตุ: pool นี้ไม่ได้แก้ปัญหา TLS fingerprint (JA3/JA4) — หมุน UA
// อย่างเดียวบ่อยครั้งไม่เพียงพอสำหรับ WAF รุ่นใหม่ ต้องพึ่ง browser handoff.

export interface UserAgentEntry {
    ua: string;
    platform: 'windows' | 'macos' | 'linux';
    engine: 'blink' | 'gecko' | 'webkit';
    label: string;
}

export const DESKTOP_UA_POOL: UserAgentEntry[] = [
    {
        label: 'chrome-win',
        platform: 'windows',
        engine: 'blink',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    },
    {
        label: 'firefox-win',
        platform: 'windows',
        engine: 'gecko',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    },
    {
        label: 'edge-win',
        platform: 'windows',
        engine: 'blink',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0',
    },
    {
        label: 'chrome-mac',
        platform: 'macos',
        engine: 'blink',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    },
    {
        label: 'safari-mac',
        platform: 'macos',
        engine: 'webkit',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    },
];

/**
 * Rotate to the next UA, wrapping at the end of the pool.
 * Calling with `currentIndex = -1` is the canonical "no UA rotated yet"
 * signal; it returns the first entry (index 0).
 */
export function rotateUa(currentIndex: number): { ua: string; nextIndex: number; label: string } {
    const len = DESKTOP_UA_POOL.length;
    const nextIndex = ((currentIndex + 1) % len + len) % len;
    const entry = DESKTOP_UA_POOL[nextIndex];
    return { ua: entry.ua, nextIndex, label: entry.label };
}

/** Deterministic pick for tests. */
export function pickUa(index: number): UserAgentEntry {
    return DESKTOP_UA_POOL[Math.abs(index) % DESKTOP_UA_POOL.length];
}
