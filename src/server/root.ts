// InjectProof — Root Router
// Merges all sub-routers into a single tRPC router

import { router } from '@/server/trpc';
import { authRouter } from '@/server/routers/auth';
import { targetRouter } from '@/server/routers/target';
import { scanRouter } from '@/server/routers/scan';
import { vulnerabilityRouter } from '@/server/routers/vulnerability';
import { dashboardRouter } from '@/server/routers/dashboard';
import { reportRouter } from '@/server/routers/report';
import { scopeRouter } from '@/server/routers/scope';
import { settingsRouter } from '@/server/routers/settings';

export const appRouter = router({
    auth: authRouter,
    target: targetRouter,
    scan: scanRouter,
    vulnerability: vulnerabilityRouter,
    dashboard: dashboardRouter,
    report: reportRouter,
    scope: scopeRouter,
    settings: settingsRouter,
});

export type AppRouter = typeof appRouter;
