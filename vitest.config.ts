import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
    test: {
        include: ['src/**/*.{test,spec}.ts', 'src/**/*.{test,spec}.tsx', 'bench/**/*.{test,spec}.ts'],
        environment: 'node',
        globals: false,
        reporters: ['default'],
        setupFiles: ['./vitest.setup.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'html'],
            include: ['src/lib/**', 'src/scanner/engine/**'],
            exclude: ['src/generated/**', '**/*.d.ts'],
        },
    },
    resolve: {
        alias: {
            '@': resolve(import.meta.dirname, 'src'),
            '@/components': resolve(import.meta.dirname, 'src/components'),
            '@/lib': resolve(import.meta.dirname, 'src/lib'),
            '@/scanner': resolve(import.meta.dirname, 'src/scanner'),
            '@/server': resolve(import.meta.dirname, 'src/server'),
            '@/types': resolve(import.meta.dirname, 'src/types'),
            '@/trpc': resolve(import.meta.dirname, 'src/trpc'),
        },
    },
});
