// InjectProof — Root Layout
import type { Metadata } from 'next';
import { TRPCProvider } from '@/components/providers';
import { LanguageProvider } from '@/lib/i18n/use-t';
import './globals.css';

export const metadata: Metadata = {
    title: 'InjectProof — Deep SQLi Verification Engine',
    description: 'Deep SQLi verification engine for authorized security testing with differential analysis and reproducible evidence.',
    keywords: ['pentest', 'security', 'vulnerability', 'scanner', 'OWASP', 'CVE', 'CWE'],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en" suppressHydrationWarning>
            <body className="min-h-screen antialiased" suppressHydrationWarning>
                <TRPCProvider>
                    <LanguageProvider>
                        {children}
                    </LanguageProvider>
                </TRPCProvider>
            </body>
        </html>
    );
}
