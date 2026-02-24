// VibeCode — Landing page → redirect to dashboard or login
'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
    const router = useRouter();

    useEffect(() => {
        const token = localStorage.getItem('vibecode_token');
        if (token) {
            router.push('/dashboard');
        } else {
            router.push('/login');
        }
    }, [router]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-[#0a0e1a]">
            <div className="flex flex-col items-center gap-4">
                <div className="w-12 h-12 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-gray-400 text-sm">Loading InjectProof...</p>
            </div>
        </div>
    );
}
