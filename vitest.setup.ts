// Vitest global setup — runs before any test file is imported.
// Provides env defaults so modules that enforce secrets at import-time
// (auth.ts now throws if JWT_SECRET is missing) don't crash the test run.

if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = 'vitest-jwt-secret-must-be-at-least-32-bytes-long-or-auth-refuses-to-boot';
}
if (!process.env.EVIDENCE_KEY) {
    // Exactly 32 bytes of base64 — zeros are fine for tests (we're not
    // testing KDF, just AES-GCM round-trip semantics).
    process.env.EVIDENCE_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
}
if (!process.env.DATABASE_URL) {
    process.env.DATABASE_URL = 'file:./injectproof-test.db';
}
