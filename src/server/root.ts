// InjectProof — Root Router
// Merges all sub-routers into a single tRPC router

import { router } from '@/server/trpc';
import { authRouter } from '@/server/routers/auth';
import { targetRouter } from '@/server/routers/target';
import { scanRouter } from '@/server/routers/scan';
import { vulnerabilityRouter } from '@/server/routers/vulnerability';
import { dashboardRouter } from '@/server/routers/dashboard';
import { reportRouter } from '@/server/routers/report';

export const appRouter = router({
    auth: authRouter,
    target: targetRouter,
    scan: scanRouter,
    vulnerability: vulnerabilityRouter,
    dashboard: dashboardRouter,
    report: reportRouter,
});

export type AppRouter = typeof appRouter;
