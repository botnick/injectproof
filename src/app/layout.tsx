// InjectProof — Root Layout
import type { Metadata } from 'next';
import { TRPCProvider } from '@/components/providers';
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
        <html lang="en" className="dark" suppressHydrationWarning>
            <body className="min-h-screen bg-[#030712] antialiased" suppressHydrationWarning>
                <TRPCProvider>
                    {children}
                </TRPCProvider>
            </body>
        </html>
    );
}
