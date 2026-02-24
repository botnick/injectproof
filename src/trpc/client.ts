// VibeCode — tRPC Client Setup
// React Query + tRPC client for use in client components

'use client';

import { createTRPCReact } from '@trpc/react-query';
import type { AppRouter } from '@/server/root';

export const trpc = createTRPCReact<AppRouter>();
