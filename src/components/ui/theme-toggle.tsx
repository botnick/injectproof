// Theme toggle — light default, dark optional. Stored in localStorage so it
// persists per-browser. Server renders light; hydration on client applies
// stored preference. Avoids FOUC for the default (light) path.

'use client';

import { useEffect, useState } from 'react';
import { Sun, Moon } from 'lucide-react';

const LS_KEY = 'injectproof:theme';
type Theme = 'light' | 'dark';

export function ThemeToggle(): JSX.Element {
    const [theme, setTheme] = useState<Theme>('light');

    useEffect(() => {
        if (typeof window === 'undefined') return;
        const stored = window.localStorage.getItem(LS_KEY);
        const initial: Theme = stored === 'dark' ? 'dark' : 'light';
        setTheme(initial);
        document.documentElement.dataset.theme = initial;
    }, []);

    function flip(): void {
        const next: Theme = theme === 'light' ? 'dark' : 'light';
        setTheme(next);
        document.documentElement.dataset.theme = next;
        window.localStorage.setItem(LS_KEY, next);
    }

    return (
        <button
            type="button"
            onClick={flip}
            title={theme === 'light' ? 'Switch to dark / เปลี่ยนเป็นโหมดมืด' : 'Switch to light / เปลี่ยนเป็นโหมดสว่าง'}
            aria-label="Theme toggle"
            className="inline-flex items-center justify-center w-8 h-8 rounded-md border border-[color:var(--border-subtle)] hover:bg-[color:var(--bg-hover)] transition-colors"
        >
            {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
        </button>
    );
}
