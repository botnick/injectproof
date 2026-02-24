// InjectProof — Authentication Library
// JWT token creation/verification + password hashing using jose + bcryptjs

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import bcrypt from 'bcryptjs';

const JWT_SECRET = new TextEncoder().encode(
    process.env.JWT_SECRET || 'InjectProof-fallback-secret-change-me'
);

const TOKEN_EXPIRY = '24h';
const SALT_ROUNDS = 12;

// ============================================================
// JWT Token Management
// ============================================================

export interface TokenPayload extends JWTPayload {
    userId: string;
    email: string;
    role: string;
    name: string;
}

/**
 * Create a signed JWT token for authenticated user
 * @param payload - User data to encode in token
 * @returns Signed JWT string
 */
export async function createToken(payload: Omit<TokenPayload, 'iat' | 'exp' | 'iss'>): Promise<string> {
    return new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setIssuer('injectproof')
        .setExpirationTime(TOKEN_EXPIRY)
        .sign(JWT_SECRET);
}

/**
 * Verify and decode a JWT token
 * @param token - JWT string to verify
 * @returns Decoded payload or null if invalid
 */
export async function verifyToken(token: string): Promise<TokenPayload | null> {
    try {
        const { payload } = await jwtVerify(token, JWT_SECRET, {
            issuer: 'injectproof',
        });
        return payload as TokenPayload;
    } catch {
        return null;
    }
}

// ============================================================
// Password Management
// ============================================================

/**
 * Hash a plaintext password using bcrypt
 * @param password - Plaintext password
 * @returns Hashed password string
 */
export async function hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Compare plaintext password with hashed password
 * @param password - Plaintext password to check
 * @param hash - Stored hash to compare against
 * @returns True if password matches
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
}

// ============================================================
// Auth Helpers
// ============================================================

/**
 * Extract JWT token from cookie string or Authorization header
 * @param cookieHeader - Cookie header string
 * @param authHeader - Authorization header string
 * @returns Token string or null
 */
export function extractToken(cookieHeader?: string, authHeader?: string): string | null {
    // Try Authorization header first (Bearer token)
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.slice(7);
    }

    // Try cookie
    if (cookieHeader) {
        const cookies = cookieHeader.split(';').map(c => c.trim());
        const tokenCookie = cookies.find(c => c.startsWith('injectproof_token='));
        if (tokenCookie) {
            return tokenCookie.split('=')[1];
        }
    }

    return null;
}

/**
 * Role hierarchy for permission checks
 * Higher index = more privileges
 */
const ROLE_HIERARCHY: Record<string, number> = {
    viewer: 0,
    developer: 1,
    pentester: 2,
    security_lead: 3,
    admin: 4,
};

/**
 * Check if a user role has at least the minimum required role
 * @param userRole - The user's current role
 * @param requiredRole - Minimum role required
 * @returns True if user has sufficient privileges
 */
export function hasRole(userRole: string, requiredRole: string): boolean {
    const userLevel = ROLE_HIERARCHY[userRole] ?? -1;
    const requiredLevel = ROLE_HIERARCHY[requiredRole] ?? 999;
    return userLevel >= requiredLevel;
}

/**
 * Check specific permissions by role
 */
export const ROLE_PERMISSIONS: Record<string, string[]> = {
    admin: ['*'], // All permissions
    security_lead: [
        'view_dashboard', 'manage_targets', 'run_scans', 'view_vulns', 'update_vulns',
        'generate_reports', 'manage_users', 'view_audit', 'manage_notifications',
    ],
    pentester: [
        'view_dashboard', 'manage_targets', 'run_scans', 'view_vulns', 'update_vulns',
        'generate_reports', 'view_audit',
    ],
    developer: [
        'view_dashboard', 'view_targets', 'view_vulns', 'update_vulns',
        'generate_reports',
    ],
    viewer: [
        'view_dashboard', 'view_targets', 'view_vulns', 'generate_reports',
    ],
};

/**
 * Check if a role has a specific permission
 */
export function hasPermission(role: string, permission: string): boolean {
    const permissions = ROLE_PERMISSIONS[role] || [];
    return permissions.includes('*') || permissions.includes(permission);
}
