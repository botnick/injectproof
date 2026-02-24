// InjectProof — Database Seed Script
// Creates default admin user and sample data

import 'dotenv/config';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';
import bcrypt from 'bcryptjs';

const adapter = new PrismaBetterSqlite3({
    url: process.env.DATABASE_URL || 'file:./injectproof.db',
});
const prisma = new PrismaClient({ adapter });

async function main() {
    console.log('🌱 Seeding InjectProof database...');

    // Create admin user
    const passwordHash = await bcrypt.hash('admin123', 12);

    const admin = await prisma.user.upsert({
        where: { email: 'admin@injectproof.local' },
        update: {},
        create: {
            email: 'admin@injectproof.local',
            passwordHash,
            name: 'Admin',
            role: 'admin',
            isActive: true,
        },
    });

    console.log(`✅ Admin user created: ${admin.email}`);

    // Create pentester user
    const pentesterHash = await bcrypt.hash('pentester123', 12);

    const pentester = await prisma.user.upsert({
        where: { email: 'pentester@injectproof.local' },
        update: {},
        create: {
            email: 'pentester@injectproof.local',
            passwordHash: pentesterHash,
            name: 'Pentester',
            role: 'pentester',
            isActive: true,
        },
    });

    console.log(`✅ Pentester user created: ${pentester.email}`);

    // Create sample target
    const target = await prisma.target.upsert({
        where: { id: 'sample-target-001' },
        update: {},
        create: {
            id: 'sample-target-001',
            name: 'OWASP Juice Shop',
            baseUrl: 'https://juice-shop.herokuapp.com',
            description: 'Intentionally vulnerable web application for security training — OWASP Juice Shop',
            environment: 'development',
            criticality: 'low',
            tags: JSON.stringify(['training', 'vuln-app', 'owasp']),
            maxCrawlDepth: 5,
            maxUrls: 100,
            rateLimit: 5,
            requestTimeout: 15000,
            createdById: admin.id,
        },
    });

    console.log(`✅ Sample target created: ${target.name}`);

    console.log('\n🎉 Seed complete! You can now log in with:');
    console.log('   Email: admin@injectproof.local');
    console.log('   Password: admin123');
}

main()
    .then(async () => {
        await prisma.$disconnect();
    })
    .catch(async (e) => {
        console.error('❌ Seed error:', e);
        await prisma.$disconnect();
        process.exit(1);
    });
