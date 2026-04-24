// Language toggle — EN / TH. Thin wrapper over the `useT()` context.

'use client';

import { useT, type Lang } from '@/lib/i18n/use-t';

export function LanguageToggle(): JSX.Element {
    const { lang, setLang } = useT();

    function flip(): void {
        const next: Lang = lang === 'en' ? 'th' : 'en';
        setLang(next);
    }

    return (
        <button
            type="button"
            onClick={flip}
            aria-label="Language toggle"
            title={lang === 'en' ? 'สลับเป็นภาษาไทย' : 'Switch to English'}
            className="inline-flex items-center justify-center min-w-[36px] h-8 px-2 rounded-md border border-[color:var(--border-subtle)] text-xs font-medium hover:bg-[color:var(--bg-hover)] transition-colors"
        >
            {lang === 'en' ? 'EN' : 'ไทย'}
        </button>
    );
}
