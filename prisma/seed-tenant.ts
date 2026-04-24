#!/usr/bin/env tsx
// Seed script: ensures the `default` Organization exists and back-fills
// every existing row that has `tenantId IS NULL` to its id. Idempotent —
// safe to run multiple times.
//
// Usage:  npm run db:seed:tenant

/* eslint-disable no-console */

import 'dotenv/config';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';

const DEFAULT_SLUG = 'default';

async function main(): Promise<void> {
    const adapter = new PrismaBetterSqlite3({
        url: process.env.DATABASE_URL || 'file:./injectproof.db',
    });
    const prisma = new PrismaClient({ adapter });
    try {
        const existing = await prisma.organization.findUnique({
            where: { slug: DEFAULT_SLUG },
        });
        const org =
            existing ??
            (await prisma.organization.create({
                data: { slug: DEFAULT_SLUG, name: 'Default Organization' },
            }));
        console.log(`[seed-tenant] default org id = ${org.id}`);

        // Back-fill tenantId=null rows on the three main entities. The
        // Prisma client may not have the column yet if db push hasn't run —
        // detect and log accordingly.
        const counts = { user: 0, target: 0, scan: 0 };
        try {
            const r = await prisma.user.updateMany({
                where: { tenantId: null },
                data: { tenantId: org.id },
            });
            counts.user = r.count;
        } catch (e) {
            console.warn('[seed-tenant] skipped User back-fill:', (e as Error).message);
        }
        try {
            const r = await prisma.target.updateMany({
                where: { tenantId: null },
                data: { tenantId: org.id },
            });
            counts.target = r.count;
        } catch (e) {
            console.warn('[seed-tenant] skipped Target back-fill:', (e as Error).message);
        }
        try {
            const r = await prisma.scan.updateMany({
                where: { tenantId: null },
                data: { tenantId: org.id },
            });
            counts.scan = r.count;
        } catch (e) {
            console.warn('[seed-tenant] skipped Scan back-fill:', (e as Error).message);
        }

        console.log(`[seed-tenant] back-filled: User=${counts.user} Target=${counts.target} Scan=${counts.scan}`);
    } finally {
        await prisma.$disconnect();
    }
}

main().catch((err) => {
    console.error('[seed-tenant] fatal:', err);
    process.exit(1);
});
