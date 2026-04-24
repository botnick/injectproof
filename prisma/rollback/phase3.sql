-- InjectProof — Phase 3 rollback (tenant primitives + policy + surface graph + kill switch)
-- Safe to re-run. Removes the new tables but leaves existing columns alone
-- (SQLite < 3.35 cannot DROP COLUMN; operator should redeploy the previous
-- schema if they want to drop the nullable tenantId columns).

DROP TABLE IF EXISTS "KillSwitch";
DROP TABLE IF EXISTS "SurfaceEdge";
DROP TABLE IF EXISTS "SurfaceNode";
DROP TABLE IF EXISTS "Checkpoint";
DROP TABLE IF EXISTS "Policy";
DROP TABLE IF EXISTS "ApiKey";
DROP TABLE IF EXISTS "Membership";
DROP TABLE IF EXISTS "Organization";
