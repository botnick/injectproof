// InjectProof — FSM runner
// Driver ที่รัน state per scanId:
//   - ตรวจสอบ transition ก่อนย้าย
//   - จับเวลาต่อ state, เทียบกับ timeoutMs, abort ถ้าเกิน
//   - retry ตาม policy ถ้า error class ตรง retry.on
//   - persist checkpoint ลง DB เพื่อ resume
//
// Driver ไม่ขึ้นกับ detector หรือ crawler — รับ Handler function มาจาก caller.
// การ wrap orchestrator เดิม (`runScan`) ทำใน `integration.ts` แยก.

import prisma from '@/lib/prisma';
import { logScan } from '@/scanner/engine/log';
import { STATE_DEFS, ScanState, canTransition, isTerminal, type StateDefinition } from './states';

export interface StateContext {
    scanId: string;
    state: ScanState;
    definition: StateDefinition;
    signal: AbortSignal;
    /** Optional — any caller-supplied carry-over from the previous state's output. */
    input: Record<string, unknown>;
}

export type StateHandler = (ctx: StateContext) => Promise<Record<string, unknown>>;

export interface RunOptions {
    handlers: Partial<Record<ScanState, StateHandler>>;
    /** Optional explicit starting state (default CREATED). */
    startAt?: ScanState;
    /** Initial input carried into the first state. */
    initialInput?: Record<string, unknown>;
    signal?: AbortSignal;
    /** Persist checkpoints to DB. Default true. */
    persistCheckpoints?: boolean;
}

export interface StepRecord {
    state: ScanState;
    startedAt: number;
    durationMs: number;
    attempts: number;
    ok: boolean;
    error?: string;
    output?: Record<string, unknown>;
}

export interface RunResult {
    finalState: ScanState;
    history: StepRecord[];
}

// ────────────────────────────────────────────────────────────
// Runner
// ────────────────────────────────────────────────────────────

export async function runStateMachine(scanId: string, opts: RunOptions): Promise<RunResult> {
    const history: StepRecord[] = [];
    let current: ScanState = opts.startAt ?? ScanState.CREATED;
    let carryInput: Record<string, unknown> = opts.initialInput ?? {};
    const signal = opts.signal ?? new AbortController().signal;

    while (!isTerminal(current)) {
        if (signal.aborted) {
            current = ScanState.CANCELLED;
            break;
        }

        const def = STATE_DEFS[current];
        const handler = opts.handlers[current];
        const started = Date.now();
        let attempts = 0;
        let ok = false;
        let lastError: Error | null = null;
        let output: Record<string, unknown> | undefined;

        if (!handler) {
            // No handler registered — pick the first successor and move on. This
            // lets the FSM work in "shadow mode" where only some states have
            // real implementations; the rest no-op through.
            const next = def.successors[0];
            if (!next) {
                current = ScanState.COMPLETED;
                break;
            }
            history.push({ state: current, startedAt: started, durationMs: 0, attempts: 0, ok: true, output: {} });
            current = next;
            carryInput = {};
            continue;
        }

        while (attempts < def.retry.maxAttempts) {
            attempts++;
            try {
                const result = await runWithTimeout(
                    def.timeoutMs,
                    signal,
                    () => handler({ scanId, state: current, definition: def, signal, input: carryInput }),
                );
                output = result;
                // Validate output contract.
                const parse = def.output.safeParse(result);
                if (!parse.success) {
                    throw new Error(`state ${current} output failed schema: ${parse.error.issues.map((i) => i.message).join('; ')}`);
                }
                ok = true;
                break;
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));
                const className = lastError.name;
                const retriable = def.retry.on.includes(className);
                if (!retriable || attempts >= def.retry.maxAttempts) break;
                await sleep(def.retry.backoffMs * Math.pow(2, attempts - 1));
            }
        }

        const durationMs = Date.now() - started;
        const record: StepRecord = { state: current, startedAt: started, durationMs, attempts, ok, output };
        if (!ok && lastError) record.error = lastError.message;
        history.push(record);

        if (opts.persistCheckpoints !== false) await persistCheckpoint(scanId, current, ok, record);

        if (!ok) {
            await logScan({
                scanId,
                level: 'error',
                module: 'fsm',
                message: `state ${current} failed after ${attempts} attempt(s): ${lastError?.message ?? 'unknown'}`,
            });
            current = ScanState.FAILED;
            break;
        }

        // Choose next state — first successor by default; a handler can
        // override by including `__nextState` in its output.
        const desired = (output?.__nextState as ScanState | undefined) ?? def.successors[0];
        if (!desired) {
            current = ScanState.COMPLETED;
            break;
        }
        if (!canTransition(current, desired)) {
            await logScan({
                scanId,
                level: 'error',
                module: 'fsm',
                message: `illegal transition ${current} → ${desired}`,
            });
            current = ScanState.FAILED;
            break;
        }
        current = desired;
        carryInput = { ...output };
        delete (carryInput as Record<string, unknown>).__nextState;
    }

    return { finalState: current, history };
}

// ────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────

async function runWithTimeout<T>(timeoutMs: number, parentSignal: AbortSignal, fn: () => Promise<T>): Promise<T> {
    if (timeoutMs <= 0) return fn();
    return new Promise<T>((resolve, reject) => {
        const ctrl = new AbortController();
        const forward = () => ctrl.abort(parentSignal.reason);
        if (parentSignal.aborted) forward();
        else parentSignal.addEventListener('abort', forward, { once: true });

        const timer = setTimeout(() => {
            const err = new Error(`state timed out after ${timeoutMs} ms`);
            err.name = 'TimeoutError';
            ctrl.abort(err);
            reject(err);
        }, timeoutMs);

        fn().then(
            (v) => {
                clearTimeout(timer);
                resolve(v);
            },
            (e) => {
                clearTimeout(timer);
                reject(e);
            },
        );
    });
}

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

async function persistCheckpoint(scanId: string, state: ScanState, ok: boolean, record: StepRecord): Promise<void> {
    try {
        // Use raw insert so we don't depend on the Checkpoint model being
        // generated before the DB migration runs. Missing table → silent.
        await prisma.$executeRawUnsafe(
            `INSERT INTO "Checkpoint" (id, scanId, state, ok, durationMs, attempts, output, createdAt)
             VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)`,
            `${scanId}:${state}:${record.startedAt}`,
            scanId,
            state,
            ok ? 1 : 0,
            record.durationMs,
            record.attempts,
            record.output ? JSON.stringify(record.output) : null,
        );
    } catch {
        // Table missing / schema mismatch — fall back to scan log.
        await logScan({
            scanId,
            level: 'debug',
            module: 'fsm',
            message: `checkpoint ${state} ${ok ? 'ok' : 'fail'} (${record.durationMs}ms, attempts=${record.attempts})`,
        });
    }
}
