import type { Config } from 'tailwindcss';

const config: Config = {
    content: [
        './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
        './src/components/**/*.{js,ts,jsx,tsx,mdx}',
        './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    ],
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                brand: {
                    50: '#eef2ff',
                    100: '#e0e7ff',
                    200: '#c7d2fe',
                    300: '#a5b4fc',
                    400: '#818cf8',
                    500: '#6366f1',
                    600: '#4f46e5',
                    700: '#4338ca',
                    800: '#3730a3',
                    900: '#312e81',
                    950: '#1e1b4b',
                },
                surface: {
                    50: '#f8fafc',
                    100: '#f1f5f9',
                    200: '#e2e8f0',
                    300: '#cbd5e1',
                    400: '#94a3b8',
                    500: '#64748b',
                    600: '#475569',
                    700: '#1e293b',
                    800: '#131a2e',
                    900: '#0d1220',
                    950: '#080c18',
                },
                severity: {
                    critical: '#f87171',
                    high: '#fb923c',
                    medium: '#fbbf24',
                    low: '#60a5fa',
                    info: '#6b7280',
                },
                status: {
                    running: '#34d399',
                    queued: '#fbbf24',
                    completed: '#60a5fa',
                    failed: '#f87171',
                    cancelled: '#6b7280',
                },
                cyber: {
                    green: '#22d3ee',
                    purple: '#c084fc',
                    pink: '#f472b6',
                },
            },
            fontFamily: {
                sans: ['Outfit', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-out',
                'slide-up': 'slideUp 0.4s ease-out',
                'slide-down': 'slideDown 0.4s ease-out',
                'slide-left': 'slideLeft 0.4s ease-out',
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'spin-slow': 'spin 8s linear infinite',
                'scan-line': 'scanLine 3s linear infinite',
                'scan-sweep': 'scanSweep 2.5s ease-in-out infinite',
                'shimmer': 'shimmer 2s linear infinite',
                'glow': 'glow 3s ease-in-out infinite alternate',
                'float': 'float 6s ease-in-out infinite',
                'gradient-shift': 'gradientShift 4s ease infinite',
                'aurora': 'auroraMove 20s ease-in-out infinite',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0', transform: 'translateY(8px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideUp: {
                    '0%': { opacity: '0', transform: 'translateY(16px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideDown: {
                    '0%': { opacity: '0', transform: 'translateY(-16px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideLeft: {
                    '0%': { opacity: '0', transform: 'translateX(16px)' },
                    '100%': { opacity: '1', transform: 'translateX(0)' },
                },
                scanLine: {
                    '0%': { transform: 'translateX(-100%)' },
                    '100%': { transform: 'translateX(100%)' },
                },
                glow: {
                    '0%': { boxShadow: '0 0 5px rgba(129, 140, 248, 0.15)' },
                    '100%': { boxShadow: '0 0 25px rgba(129, 140, 248, 0.4)' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-10px)' },
                },
                gradientShift: {
                    '0%, 100%': { backgroundPosition: '0% 50%' },
                    '50%': { backgroundPosition: '100% 50%' },
                },
                auroraMove: {
                    '0%, 100%': { transform: 'translate(0, 0) rotate(0deg)' },
                    '33%': { transform: 'translate(2%, -2%) rotate(1deg)' },
                    '66%': { transform: 'translate(-1%, 1%) rotate(-1deg)' },
                },
                scanSweep: {
                    '0%': { transform: 'translateX(-100%)', opacity: '0' },
                    '30%': { opacity: '1' },
                    '70%': { opacity: '1' },
                    '100%': { transform: 'translateX(100%)', opacity: '0' },
                },
                shimmer: {
                    '0%': { transform: 'translateX(-200%)' },
                    '100%': { transform: 'translateX(200%)' },
                },
            },
            backdropBlur: {
                xs: '2px',
            },
            boxShadow: {
                'glass': '0 8px 32px rgba(0, 0, 0, 0.12)',
                'glass-lg': '0 12px 48px rgba(0, 0, 0, 0.2)',
                'neon': '0 0 8px rgba(129, 140, 248, 0.3), 0 0 24px rgba(129, 140, 248, 0.15)',
                'neon-strong': '0 0 12px rgba(129, 140, 248, 0.4), 0 0 40px rgba(129, 140, 248, 0.2)',
                'aurora': '0 0 60px rgba(99, 102, 241, 0.1), 0 0 120px rgba(168, 85, 247, 0.05)',
            },
            borderRadius: {
                '2xl': '16px',
                '3xl': '24px',
            },
        },
    },
    plugins: [],
};

export default config;
