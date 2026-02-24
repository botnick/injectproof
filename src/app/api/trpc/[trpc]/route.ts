// VibeCode — tRPC API Route Handler
// Next.js App Router handler for tRPC

import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { appRouter } from '@/server/root';
import { createContext } from '@/server/context';

const handler = (req: Request) =>
    fetchRequestHandler({
        endpoint: '/api/trpc',
        req,
        router: appRouter,
        createContext,
    });

export { handler as GET, handler as POST };
