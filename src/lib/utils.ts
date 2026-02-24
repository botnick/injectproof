// VibeCode — Utility Functions
// Common helpers used across the platform

import { v4 as uuidv4 } from 'uuid';
import { format, formatDistanceToNow } from 'date-fns';

// ============================================================
// ID Generation
// ============================================================

/** Generate a UUID v4 */
export function generateId(): string {
    return uuidv4();
}

/** Generate a short ID (8 chars) for display */
export function shortId(id: string): string {
    return id.slice(0, 8);
}

// ============================================================
// Date Formatting
// ============================================================

/** Format date to ISO string */
export function formatDate(date: Date | string): string {
    return format(new Date(date), 'yyyy-MM-dd HH:mm:ss');
}

/** Format date for display */
export function formatDateShort(date: Date | string): string {
    return format(new Date(date), 'MMM dd, yyyy');
}

/** Relative time (e.g., "2 hours ago") */
export function timeAgo(date: Date | string): string {
    return formatDistanceToNow(new Date(date), { addSuffix: true });
}

/** Format duration in seconds to human-readable */
export function formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
}

// ============================================================
// URL Helpers
// ============================================================

/** Parse URL safely */
export function parseUrl(url: string): URL | null {
    try {
        return new URL(url);
    } catch {
        return null;
    }
}

/** Get domain from URL */
export function getDomain(url: string): string {
    const parsed = parseUrl(url);
    return parsed?.hostname || url;
}

/** Normalize URL for comparison */
export function normalizeUrl(url: string): string {
    try {
        const parsed = new URL(url);
        parsed.hash = '';
        // Remove trailing slash
        let normalized = parsed.toString();
        if (normalized.endsWith('/') && parsed.pathname === '/') {
            normalized = normalized.slice(0, -1);
        }
        return normalized;
    } catch {
        return url;
    }
}

/** Check if URL is a same-origin relative to base */
export function isSameOrigin(url: string, baseUrl: string): boolean {
    try {
        const a = new URL(url);
        const b = new URL(baseUrl);
        return a.origin === b.origin;
    } catch {
        return false;
    }
}

// ============================================================
// String Helpers
// ============================================================

/** Truncate string with ellipsis */
export function truncate(str: string, maxLen: number): string {
    if (str.length <= maxLen) return str;
    return str.slice(0, maxLen - 3) + '...';
}

/** Sanitize HTML to prevent XSS in displayed content */
export function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/** Convert snake_case to Title Case */
export function snakeToTitle(str: string): string {
    return str
        .split('_')
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
}

// ============================================================
// JSON Helpers (for SQLite JSON storage)
// ============================================================

/** Safely parse JSON string, return default on failure */
export function safeJsonParse<T>(json: string | null | undefined, defaultValue: T): T {
    if (!json) return defaultValue;
    try {
        return JSON.parse(json) as T;
    } catch {
        return defaultValue;
    }
}

/** Stringify value for SQLite JSON storage */
export function toJsonString(value: unknown): string {
    return JSON.stringify(value);
}

// ============================================================
// Number Helpers
// ============================================================

/** Format number with commas */
export function formatNumber(num: number): string {
    return num.toLocaleString('en-US');
}

/** Calculate percentage */
export function percentage(part: number, total: number): number {
    if (total === 0) return 0;
    return Math.round((part / total) * 100);
}

// ============================================================
// Color Helpers (for UI)
// ============================================================

export const SEVERITY_COLORS: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#2563eb',
    info: '#6b7280',
};

export const SEVERITY_BG_COLORS: Record<string, string> = {
    critical: 'bg-red-600/10 text-red-400 border-red-600/20',
    high: 'bg-orange-600/10 text-orange-400 border-orange-600/20',
    medium: 'bg-amber-600/10 text-amber-400 border-amber-600/20',
    low: 'bg-blue-600/10 text-blue-400 border-blue-600/20',
    info: 'bg-gray-600/10 text-gray-400 border-gray-600/20',
};

export const STATUS_COLORS: Record<string, string> = {
    open: 'bg-red-600/10 text-red-400 border-red-600/20',
    confirmed: 'bg-orange-600/10 text-orange-400 border-orange-600/20',
    fixed: 'bg-green-600/10 text-green-400 border-green-600/20',
    false_positive: 'bg-gray-600/10 text-gray-400 border-gray-600/20',
    accepted: 'bg-yellow-600/10 text-yellow-400 border-yellow-600/20',
    reopened: 'bg-purple-600/10 text-purple-400 border-purple-600/20',
};

export const SCAN_STATUS_COLORS: Record<string, string> = {
    queued: 'bg-yellow-600/10 text-yellow-400 border-yellow-600/20',
    running: 'bg-green-600/10 text-green-400 border-green-600/20',
    completed: 'bg-blue-600/10 text-blue-400 border-blue-600/20',
    failed: 'bg-red-600/10 text-red-400 border-red-600/20',
    cancelled: 'bg-gray-600/10 text-gray-400 border-gray-600/20',
    paused: 'bg-purple-600/10 text-purple-400 border-purple-600/20',
};

// ============================================================
// HTTP Helpers
// ============================================================

/** Standard HTTP methods */
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

/** Common content types */
export const CONTENT_TYPES = {
    JSON: 'application/json',
    FORM: 'application/x-www-form-urlencoded',
    MULTIPART: 'multipart/form-data',
    XML: 'application/xml',
    HTML: 'text/html',
    TEXT: 'text/plain',
} as const;

/** Build HTTP request string for evidence */
export function buildRequestString(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string
): string {
    const parsed = parseUrl(url);
    const path = parsed ? parsed.pathname + parsed.search : url;

    let request = `${method} ${path} HTTP/1.1\r\n`;
    request += `Host: ${parsed?.host || 'unknown'}\r\n`;

    for (const [key, value] of Object.entries(headers)) {
        request += `${key}: ${value}\r\n`;
    }

    request += '\r\n';
    if (body) request += body;

    return request;
}

/** Build HTTP response string for evidence */
export function buildResponseString(
    statusCode: number,
    headers: Record<string, string>,
    body: string,
    maxBodyLength = 5000
): string {
    let response = `HTTP/1.1 ${statusCode}\r\n`;

    for (const [key, value] of Object.entries(headers)) {
        response += `${key}: ${value}\r\n`;
    }

    response += '\r\n';
    if (body.length > maxBodyLength) {
        response += body.slice(0, maxBodyLength) + '\n\n[... truncated ...]';
    } else {
        response += body;
    }

    return response;
}
