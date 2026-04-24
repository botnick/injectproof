// InjectProof — `useT()` language hook + LanguageProvider
// SSR-safe: server renders with 'en'; client reads localStorage on mount and
// re-renders. No runtime dependency on Next.js router — works anywhere a
// React tree does.

'use client';

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { EN, type I18nKey } from './en';
import { TH } from './th';

export type Lang = 'en' | 'th';

const BUNDLES: Record<Lang, Record<string, string>> = {
    en: EN,
    th: TH,
};

const LS_KEY = 'injectproof:lang';

interface I18nContextValue {
    lang: Lang;
    setLang: (l: Lang) => void;
    t: (key: I18nKey, fallback?: string) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }): JSX.Element {
    const [lang, setLangState] = useState<Lang>('en');

    useEffect(() => {
        if (typeof window === 'undefined') return;
        const stored = window.localStorage.getItem(LS_KEY);
        if (stored === 'th' || stored === 'en') setLangState(stored);
    }, []);

    useEffect(() => {
        if (typeof document !== 'undefined') document.documentElement.lang = lang;
    }, [lang]);

    const value = useMemo<I18nContextValue>(() => ({
        lang,
        setLang: (l) => {
            setLangState(l);
            if (typeof window !== 'undefined') window.localStorage.setItem(LS_KEY, l);
        },
        t: (key, fallback) => {
            const bundle = BUNDLES[lang];
            return (bundle[key] as string | undefined) ?? fallback ?? (EN[key] as string) ?? String(key);
        },
    }), [lang]);

    return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

/**
 * Hook form for components inside `<LanguageProvider>`. Gracefully degrades
 * when provider is absent (renders English bundle and no-op setLang).
 */
export function useT(): I18nContextValue {
    const ctx = useContext(I18nContext);
    if (ctx) return ctx;
    return {
        lang: 'en',
        setLang: () => undefined,
        t: (key, fallback) => (EN[key] as string | undefined) ?? fallback ?? String(key),
    };
}
