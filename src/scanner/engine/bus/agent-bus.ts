// InjectProof — Typed inter-agent event bus
// Findings from any module propagate to all subscribers.
// This turns the scanner from a static pipeline into a reactive system:
// admin panel found → immediately trigger auth bypass + focused SQLi.

import { EventEmitter } from 'events';

// ── Finding event types ────────────────────────────────────────────────────
export interface FormFoundEvent       { type: 'form:found';      url: string; formType: string; fields: string[]; attackPriority: 'critical'|'high'|'medium'|'low'; confidence: number }
export interface EndpointFoundEvent   { type: 'endpoint:found';  url: string; method: string; params: string[]; source: string }
export interface SqliCandidateEvent   { type: 'sqli:candidate';  url: string; param: string; technique: string; dbms?: string; confidence: number }
export interface SqliConfirmedEvent   { type: 'sqli:confirmed';  url: string; param: string; dbms: string; technique: string; severity: 'critical'|'high' }
export interface XssCandidateEvent    { type: 'xss:candidate';   url: string; param: string; context: string; confidence: number }
export interface SsrfCandidateEvent   { type: 'ssrf:candidate';  url: string; param: string; confidence: number }
export interface AuthBypassEvent      { type: 'auth:bypass';     url: string; method: string; technique: string }
export interface AdminPanelEvent      { type: 'admin:panel';     url: string; confidence: number; statusCode: number }
export interface BackupFileEvent      { type: 'backup:found';    url: string; fileType: string; confidence: number }
export interface SubdomainFoundEvent  { type: 'subdomain:found'; domain: string; ip?: string; source: string }
export interface TechDetectedEvent    { type: 'tech:detected';   tech: string; version?: string; category: string }
export interface WafDetectedEvent     { type: 'waf:detected';    vendor: string; confidence: number; url: string }
export interface ScanErrorEvent       { type: 'scan:error';      module: string; url?: string; error: string }

export type BusEvent =
  | FormFoundEvent | EndpointFoundEvent
  | SqliCandidateEvent | SqliConfirmedEvent
  | XssCandidateEvent | SsrfCandidateEvent
  | AuthBypassEvent | AdminPanelEvent | BackupFileEvent
  | SubdomainFoundEvent | TechDetectedEvent | WafDetectedEvent
  | ScanErrorEvent;

export type BusEventType = BusEvent['type'];
export type EventOfType<T extends BusEventType> = Extract<BusEvent, { type: T }>;

export interface BusStats {
  totalEmitted: number;
  byType: Partial<Record<BusEventType, number>>;
  subscriberCount: Partial<Record<BusEventType, number>>;
  startedAt: string;
}

// ── ScanAgentBus ──────────────────────────────────────────────────────────
export class ScanAgentBus {
  private readonly emitter = new EventEmitter();
  private readonly stats: BusStats;

  constructor(readonly scanId: string) {
    this.emitter.setMaxListeners(200);
    this.stats = { totalEmitted: 0, byType: {}, subscriberCount: {}, startedAt: new Date().toISOString() };
  }

  /** Emit a typed finding event to all subscribers */
  emit<T extends BusEvent>(event: T): void {
    this.stats.totalEmitted++;
    this.stats.byType[event.type] = ((this.stats.byType[event.type] ?? 0) as number) + 1;
    this.emitter.emit(event.type, event);
    this.emitter.emit('*', event);
  }

  /** Subscribe to a specific event type; returns unsubscribe function */
  on<T extends BusEventType>(type: T, handler: (event: EventOfType<T>) => void): () => void {
    this.stats.subscriberCount[type] = ((this.stats.subscriberCount[type] ?? 0) as number) + 1;
    const safe = (e: unknown) => { try { handler(e as EventOfType<T>); } catch { /* subscriber errors must not crash bus */ } };
    this.emitter.on(type, safe);
    return () => this.emitter.off(type, safe);
  }

  /** Subscribe to all event types (useful for logging) */
  onAny(handler: (event: BusEvent) => void): () => void {
    const safe = (e: unknown) => { try { handler(e as BusEvent); } catch { /* */ } };
    this.emitter.on('*', safe);
    return () => this.emitter.off('*', safe);
  }

  snapshot(): BusStats {
    return {
      ...this.stats,
      byType: { ...this.stats.byType },
      subscriberCount: { ...this.stats.subscriberCount },
    };
  }
}
