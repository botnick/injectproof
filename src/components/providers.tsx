// VibeCode — tRPC Provider
// Wraps app with tRPC + React Query providers

'use client';

import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { httpBatchLink } from '@trpc/client';
import { trpc } from '@/trpc/client';
import superjson from 'superjson';

function getBaseUrl() {
    if (typeof window !== 'undefined') return '';
    return `http://localhost:${process.env.PORT ?? 3000}`;
}

function getToken(): string | null {
    if (typeof window === 'undefined') return null;
    // Try cookie first
    const cookies = document.cookie.split(';').map(c => c.trim());
    const tokenCookie = cookies.find(c => c.startsWith('vibecode_token='));
    if (tokenCookie) return tokenCookie.split('=')[1];
    // Try localStorage
    return localStorage.getItem('vibecode_token');
}

export function TRPCProvider({ children }: { children: React.ReactNode }) {
    const [queryClient] = useState(
        () =>
            new QueryClient({
                defaultOptions: {
                    queries: {
                        staleTime: 30 * 1000,
                        refetchOnWindowFocus: false,
                    },
                },
            }),
    );

    const [trpcClient] = useState(() =>
        trpc.createClient({
            links: [
                httpBatchLink({
                    url: `${getBaseUrl()}/api/trpc`,
                    transformer: superjson,
                    headers() {
                        const token = getToken();
                        return token ? { Authorization: `Bearer ${token}` } : {};
                    },
                }),
            ],
        }),
    );

    return (
        <trpc.Provider client={trpcClient} queryClient={queryClient}>
            <QueryClientProvider client={queryClient}>
                {children}
            </QueryClientProvider>
        </trpc.Provider>
    );
}
