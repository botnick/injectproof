// InjectProof — SSRF guard for target-URL registration
// Reject private / link-local / loopback / cloud-metadata IPs at target
// registration time, unless the caller has an explicit `labOverride` flag
// (used for the benchmark lab). Without this, any pentester can register
// http://169.254.169.254 and have the scanner pull IAM credentials from
// AWS metadata — the textbook SSRF foot-gun.

import { resolve4, resolve6 } from 'node:dns/promises';

export interface SsrfCheckOptions {
    /** If true, allow private/loopback IPs (bench-lab mode). */
    labOverride?: boolean;
    /** Resolve hostname to IPs and check every A/AAAA record. Default true. */
    resolveHostname?: boolean;
}

export interface SsrfCheckResult {
    allowed: boolean;
    reason?: string;
    resolvedIps?: string[];
}

// ============================================================
// CIDR helpers — IPv4 only for the common case; IPv6 uses prefix check
// ============================================================

function ipv4InCidr(ip: string, cidr: string): boolean {
    const [net, bitsStr] = cidr.split('/');
    const bits = Number(bitsStr);
    const ipNum = ipv4ToInt(ip);
    const netNum = ipv4ToInt(net);
    if (ipNum === null || netNum === null) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipNum & mask) === (netNum & mask);
}

function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

const DENY_IPV4_CIDRS = [
    '127.0.0.0/8',         // loopback
    '10.0.0.0/8',          // RFC1918
    '172.16.0.0/12',       // RFC1918
    '192.168.0.0/16',      // RFC1918
    '169.254.0.0/16',      // link-local + AWS metadata
    '100.64.0.0/10',       // Carrier-grade NAT
    '0.0.0.0/8',           // this network
    '224.0.0.0/4',         // multicast
    '240.0.0.0/4',         // reserved
    '::1/128',             // (handled via ipv6 branch below)
];

function isPrivateIpv4(ip: string): string | null {
    for (const cidr of DENY_IPV4_CIDRS) {
        if (cidr.includes(':')) continue;
        if (ipv4InCidr(ip, cidr)) return cidr;
    }
    return null;
}

function isPrivateIpv6(ip: string): string | null {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return '::1/128';
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'fc00::/7 (ULA)';
    if (lower.startsWith('fe80')) return 'fe80::/10 (link-local)';
    if (lower.startsWith('::ffff:')) {
        // IPv4-mapped IPv6
        const mapped = lower.slice(7);
        const priv = isPrivateIpv4(mapped);
        if (priv) return `IPv4-mapped ${priv}`;
    }
    return null;
}

// ============================================================
// URL-level guard
// ============================================================

export async function checkTargetUrl(url: string, opts: SsrfCheckOptions = {}): Promise<SsrfCheckResult> {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return { allowed: false, reason: 'invalid URL' };
    }
    if (!/^https?:$/.test(parsed.protocol)) {
        return { allowed: false, reason: `protocol ${parsed.protocol} is not allowed — use http:// or https://` };
    }

    const host = parsed.hostname;
    const resolvedIps: string[] = [];

    // Literal-IP check first (covers the obvious `http://169.254.169.254/`)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        const priv = isPrivateIpv4(host);
        if (priv && !opts.labOverride) {
            return { allowed: false, reason: `refuses private IPv4 literal ${host} (${priv})`, resolvedIps: [host] };
        }
        resolvedIps.push(host);
    } else if (host.includes(':')) {
        const priv = isPrivateIpv6(host);
        if (priv && !opts.labOverride) {
            return { allowed: false, reason: `refuses private IPv6 literal ${host} (${priv})`, resolvedIps: [host] };
        }
        resolvedIps.push(host);
    } else if (opts.resolveHostname !== false) {
        // Hostname — resolve to IPs and check each. Stops DNS-rebinding
        // attacks that would route localhost through a public name.
        try {
            const [a, aaaa] = await Promise.all([
                resolve4(host).catch(() => [] as string[]),
                resolve6(host).catch(() => [] as string[]),
            ]);
            resolvedIps.push(...a, ...aaaa);
            for (const ip of a) {
                const priv = isPrivateIpv4(ip);
                if (priv && !opts.labOverride) {
                    return {
                        allowed: false,
                        reason: `hostname ${host} resolves to private IP ${ip} (${priv})`,
                        resolvedIps,
                    };
                }
            }
            for (const ip of aaaa) {
                const priv = isPrivateIpv6(ip);
                if (priv && !opts.labOverride) {
                    return {
                        allowed: false,
                        reason: `hostname ${host} resolves to private IPv6 ${ip} (${priv})`,
                        resolvedIps,
                    };
                }
            }
        } catch (err) {
            return { allowed: false, reason: `DNS resolution failed: ${err instanceof Error ? err.message : String(err)}` };
        }
    }

    // Special-case "localhost" hostname even without resolution.
    if (host === 'localhost' && !opts.labOverride) {
        return { allowed: false, reason: 'literal "localhost" is blocked — use labOverride for bench targets' };
    }

    return { allowed: true, resolvedIps };
}
