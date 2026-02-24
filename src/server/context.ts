// VibeCode — tRPC Context
// Creates request context with database connection and authenticated user

import { type FetchCreateContextFnOptions } from '@trpc/server/adapters/fetch';
import prisma from '@/lib/prisma';
import { verifyToken, extractToken, type TokenPayload } from '@/lib/auth';

export interface Context {
    prisma: typeof prisma;
    user: TokenPayload | null;
}

/**
 * Create tRPC context for each request
 * Extracts JWT from cookies/headers and verifies authentication
 */
export async function createContext(opts: FetchCreateContextFnOptions): Promise<Context> {
    const cookieHeader = opts.req.headers.get('cookie') || undefined;
    const authHeader = opts.req.headers.get('authorization') || undefined;

    const token = extractToken(cookieHeader, authHeader);
    let user: TokenPayload | null = null;

    if (token) {
        user = await verifyToken(token);
    }

    return {
        prisma,
        user,
    };
}
