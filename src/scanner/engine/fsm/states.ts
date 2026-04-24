// InjectProof — Scan lifecycle state machine
// แทนที่ linear sequence of awaits ใน `scanner/index.ts:runScan` ด้วย typed
// FSM. ทุก state มี contract (input/output zod) + timeout + retry + checkpoint
// + audit event + metric name. ทำให้:
//   - resume ได้ทุก state ที่ checkpoint แล้ว
//   - cancel ได้ทุก state
//   - หา bottleneck ได้ง่าย (เห็น latency per state)
//   - monitor coverage ได้ว่า scan ไหนเคยข้าม state อะไร
//
// ตั้งใจให้ off-by-default (SCANNER_FSM=true เปิดใช้) — backward-compat 100%
// กับ scan เก่า ที่ยังใช้ linear flow เดิมใน runScan().

import { z } from 'zod';

// ────────────────────────────────────────────────────────────
// State enum
// ────────────────────────────────────────────────────────────

export const ScanState = {
    CREATED: 'CREATED',
    VALIDATING_SCOPE: 'VALIDATING_SCOPE',
    INITIALIZING: 'INITIALIZING',
    PROFILING_TARGET: 'PROFILING_TARGET',
    AUTHENTICATING: 'AUTHENTICATING',
    CRAWLING_HTTP: 'CRAWLING_HTTP',
    CRAWLING_BROWSER: 'CRAWLING_BROWSER',
    IMPORTING_API_SCHEMA: 'IMPORTING_API_SCHEMA',
    BUILDING_SURFACE_GRAPH: 'BUILDING_SURFACE_GRAPH',
    MODELING_INPUTS: 'MODELING_INPUTS',
    PLANNING_DETECTION: 'PLANNING_DETECTION',
    RUNNING_PASSIVE_ANALYSIS: 'RUNNING_PASSIVE_ANALYSIS',
    RUNNING_ACTIVE_PROBES: 'RUNNING_ACTIVE_PROBES',
    CORRELATING_EVIDENCE: 'CORRELATING_EVIDENCE',
    SCORING_FINDINGS: 'SCORING_FINDINGS',
    GENERATING_REPORT: 'GENERATING_REPORT',
    COMPLETED: 'COMPLETED',
    COMPLETED_WITH_WARNINGS: 'COMPLETED_WITH_WARNINGS',
    PAUSED: 'PAUSED',
    CANCELLED: 'CANCELLED',
    FAILED: 'FAILED',
} as const;

export type ScanState = (typeof ScanState)[keyof typeof ScanState];

// ────────────────────────────────────────────────────────────
// Contract per state
// ────────────────────────────────────────────────────────────

const emptyObject = z.object({}).passthrough();

export interface StateDefinition {
    state: ScanState;
    /** Zod schema for the input context required to enter this state. */
    input: z.ZodTypeAny;
    /** Zod schema for the output this state must produce. */
    output: z.ZodTypeAny;
    timeoutMs: number;
    retry: { maxAttempts: number; backoffMs: number; on: string[] };
    checkpointKey: string;
    auditEvent: string;
    metrics: { histogram: string; counter: string };
    idempotencyKey: (scanId: string) => string;
    terminal: boolean;
    successors: ScanState[];
}

// ────────────────────────────────────────────────────────────
// Definitions
// ────────────────────────────────────────────────────────────

export const STATE_DEFS: Record<ScanState, StateDefinition> = {
    CREATED: def({
        state: ScanState.CREATED,
        successors: [ScanState.VALIDATING_SCOPE, ScanState.CANCELLED],
        timeoutMs: 0,
        output: z.object({ scanId: z.string(), createdAt: z.date() }),
    }),
    VALIDATING_SCOPE: def({
        state: ScanState.VALIDATING_SCOPE,
        successors: [ScanState.INITIALIZING, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 10_000,
        input: z.object({ scanId: z.string(), targetId: z.string() }),
        output: z.object({ policy: emptyObject, scopeApprovalId: z.string().nullable() }),
    }),
    INITIALIZING: def({
        state: ScanState.INITIALIZING,
        successors: [ScanState.PROFILING_TARGET, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 15_000,
        output: z.object({ budgetReady: z.boolean(), killSwitchOk: z.boolean() }),
    }),
    PROFILING_TARGET: def({
        state: ScanState.PROFILING_TARGET,
        successors: [ScanState.AUTHENTICATING, ScanState.CRAWLING_HTTP, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 60_000,
        output: z.object({ techHints: z.array(z.string()), wafHint: z.string().nullable() }),
    }),
    AUTHENTICATING: def({
        state: ScanState.AUTHENTICATING,
        successors: [ScanState.CRAWLING_HTTP, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 60_000,
        output: z.object({ authenticated: z.boolean(), cookies: z.array(z.string()).optional() }),
        retry: { maxAttempts: 2, backoffMs: 3_000, on: ['NetworkError', 'TimeoutError'] },
    }),
    CRAWLING_HTTP: def({
        state: ScanState.CRAWLING_HTTP,
        successors: [ScanState.CRAWLING_BROWSER, ScanState.IMPORTING_API_SCHEMA, ScanState.BUILDING_SURFACE_GRAPH, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 30 * 60_000,
        output: z.object({ endpointCount: z.number(), formCount: z.number() }),
    }),
    CRAWLING_BROWSER: def({
        state: ScanState.CRAWLING_BROWSER,
        successors: [ScanState.IMPORTING_API_SCHEMA, ScanState.BUILDING_SURFACE_GRAPH, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 30 * 60_000,
        output: z.object({ jsRoutes: z.number(), xhrCaptured: z.number() }),
    }),
    IMPORTING_API_SCHEMA: def({
        state: ScanState.IMPORTING_API_SCHEMA,
        successors: [ScanState.BUILDING_SURFACE_GRAPH, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 5 * 60_000,
        output: z.object({ schemasImported: z.number() }),
    }),
    BUILDING_SURFACE_GRAPH: def({
        state: ScanState.BUILDING_SURFACE_GRAPH,
        successors: [ScanState.MODELING_INPUTS, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 5 * 60_000,
        output: z.object({ nodeCount: z.number(), edgeCount: z.number() }),
    }),
    MODELING_INPUTS: def({
        state: ScanState.MODELING_INPUTS,
        successors: [ScanState.PLANNING_DETECTION, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 2 * 60_000,
        output: z.object({ inputCount: z.number() }),
    }),
    PLANNING_DETECTION: def({
        state: ScanState.PLANNING_DETECTION,
        successors: [ScanState.RUNNING_PASSIVE_ANALYSIS, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 60_000,
        output: z.object({ plannedProbes: z.number(), detectorIds: z.array(z.string()) }),
    }),
    RUNNING_PASSIVE_ANALYSIS: def({
        state: ScanState.RUNNING_PASSIVE_ANALYSIS,
        successors: [ScanState.RUNNING_ACTIVE_PROBES, ScanState.CORRELATING_EVIDENCE, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 15 * 60_000,
        output: z.object({ passiveFindings: z.number() }),
    }),
    RUNNING_ACTIVE_PROBES: def({
        state: ScanState.RUNNING_ACTIVE_PROBES,
        successors: [ScanState.CORRELATING_EVIDENCE, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 60 * 60_000,
        output: z.object({ probesSent: z.number(), candidateFindings: z.number() }),
    }),
    CORRELATING_EVIDENCE: def({
        state: ScanState.CORRELATING_EVIDENCE,
        successors: [ScanState.SCORING_FINDINGS, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 5 * 60_000,
        output: z.object({ correlatedFindings: z.number() }),
    }),
    SCORING_FINDINGS: def({
        state: ScanState.SCORING_FINDINGS,
        successors: [ScanState.GENERATING_REPORT, ScanState.FAILED, ScanState.CANCELLED],
        timeoutMs: 2 * 60_000,
        output: z.object({ scoredFindings: z.number() }),
    }),
    GENERATING_REPORT: def({
        state: ScanState.GENERATING_REPORT,
        successors: [ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS, ScanState.FAILED],
        timeoutMs: 5 * 60_000,
        output: z.object({ reportId: z.string() }),
    }),
    COMPLETED: def({
        state: ScanState.COMPLETED, successors: [], terminal: true, timeoutMs: 0,
    }),
    COMPLETED_WITH_WARNINGS: def({
        state: ScanState.COMPLETED_WITH_WARNINGS, successors: [], terminal: true, timeoutMs: 0,
    }),
    PAUSED: def({
        state: ScanState.PAUSED, successors: Object.values(ScanState).filter((s) => s !== 'PAUSED') as ScanState[], timeoutMs: 0,
    }),
    CANCELLED: def({
        state: ScanState.CANCELLED, successors: [], terminal: true, timeoutMs: 0,
    }),
    FAILED: def({
        state: ScanState.FAILED, successors: [], terminal: true, timeoutMs: 0,
    }),
};

// ────────────────────────────────────────────────────────────
// Factory helper
// ────────────────────────────────────────────────────────────

function def(partial: Partial<StateDefinition> & { state: ScanState; successors: ScanState[]; timeoutMs: number }): StateDefinition {
    const name = partial.state.toLowerCase();
    return {
        state: partial.state,
        input: partial.input ?? emptyObject,
        output: partial.output ?? emptyObject,
        timeoutMs: partial.timeoutMs,
        retry: partial.retry ?? { maxAttempts: 1, backoffMs: 1_000, on: [] },
        checkpointKey: partial.checkpointKey ?? `checkpoint:${partial.state}`,
        auditEvent: partial.auditEvent ?? `scan.${name}`,
        metrics: partial.metrics ?? {
            histogram: `scan_state_duration_ms:${name}`,
            counter: `scan_state_enter_total:${name}`,
        },
        idempotencyKey: partial.idempotencyKey ?? ((scanId: string) => `${scanId}:${partial.state}`),
        terminal: partial.terminal ?? false,
        successors: partial.successors,
    };
}

// ────────────────────────────────────────────────────────────
// Transition validation
// ────────────────────────────────────────────────────────────

export function canTransition(from: ScanState, to: ScanState): boolean {
    // CANCELLED, FAILED, PAUSED reachable from anywhere non-terminal.
    const fromDef = STATE_DEFS[from];
    if (fromDef.terminal) return false;
    if (to === ScanState.CANCELLED || to === ScanState.FAILED || to === ScanState.PAUSED) return true;
    return fromDef.successors.includes(to);
}

/** True if `state` is a terminal outcome. */
export function isTerminal(state: ScanState): boolean {
    return STATE_DEFS[state].terminal;
}
