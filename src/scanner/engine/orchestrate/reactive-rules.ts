// InjectProof — Reactive rule engine for dynamic scan orchestration
// Rules are data-driven: trigger(event) → condition(probability) → actions(priority-boosted tasks).
// Adding new behavior = adding a new rule object; no if/else chains.

import type { BusEvent, BusEventType, AdminPanelEvent, SqliConfirmedEvent, WafDetectedEvent, TechDetectedEvent, SubdomainFoundEvent, BackupFileEvent, AuthBypassEvent } from '@/scanner/engine/bus/agent-bus';

// ── Task types ────────────────────────────────────────────────────────────

export type AgentTaskType =
  | 'crawl-url'
  | 'sqli-focused'
  | 'auth-bypass'
  | 'deep-exploit'
  | 'tech-fingerprint'
  | 'waf-bypass-activate'
  | 'scope-expand'
  | 'backup-enumerate'
  | 'admin-enumerate';

export interface AgentTask {
  type: AgentTaskType;
  url: string;
  priority: number;         // 0–100; higher = run sooner
  context: Record<string, unknown>;
  reason: string;           // human-readable why this task was created
  triggeredBy: BusEventType;
}

// ── Scan context shared across rules ─────────────────────────────────────

export interface ReactiveContext {
  baseUrl: string;
  scanId: string;
  wafMode: boolean;
  wafVendor?: string;
  confirmedDbms?: string;
  techStack: string[];
  confirmedAdminPanels: string[];
  pendingTasks: AgentTask[];
}

// ── Rule definition ───────────────────────────────────────────────────────

interface Rule<T extends BusEvent = BusEvent> {
  /** Event type this rule responds to */
  trigger: T['type'];
  /**
   * Probability-weighted condition — returns a number in [0, 1].
   * 0 = rule doesn't fire. 1 = rule always fires.
   * Values in between mean "fire with this confidence weight".
   * The actual firing threshold is > 0.3 (configurable).
   */
  condition: (event: T, ctx: ReactiveContext) => number;
  /** Produces zero or more new tasks; may mutate ctx (e.g. set wafMode) */
  actions: (event: T, ctx: ReactiveContext, weight: number) => AgentTask[];
  description: string;
}

const FIRE_THRESHOLD = 0.3;

// ── Rule table ─────────────────────────────────────────────────────────────
// To add new behavior: add a new entry. No other changes needed.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const RULES: Rule<any>[] = [
  // Admin panel found → immediately run focused auth bypass + SQLi at that URL
  {
    trigger: 'admin:panel',
    description: 'Admin panel → high-priority auth bypass + focused SQLi',
    condition: (e: AdminPanelEvent) => e.confidence,
    actions:   (e: AdminPanelEvent, ctx: ReactiveContext, weight: number): AgentTask[] => {
      if (ctx.confirmedAdminPanels.includes(e.url)) return [];
      ctx.confirmedAdminPanels.push(e.url);
      return [
        { type: 'auth-bypass',   url: e.url, priority: Math.round(90 * weight), context: { statusCode: e.statusCode }, reason: `admin panel found (confidence=${e.confidence.toFixed(2)})`, triggeredBy: 'admin:panel' },
        { type: 'sqli-focused',  url: e.url, priority: Math.round(85 * weight), context: { adminPanel: true },          reason: `admin panel is a high-value SQLi target`,                    triggeredBy: 'admin:panel' },
      ];
    },
  } as Rule<AdminPanelEvent>,

  // WAF detected → activate WAF bypass mode; log vendor for encoding chain selection
  {
    trigger: 'waf:detected',
    description: 'WAF detected → enable WAF bypass mode for all subsequent requests',
    condition: (e: WafDetectedEvent) => e.confidence,
    actions:   (e: WafDetectedEvent, ctx: ReactiveContext): AgentTask[] => {
      ctx.wafMode = true;
      ctx.wafVendor = e.vendor;
      return [
        { type: 'waf-bypass-activate', url: ctx.baseUrl, priority: 95, context: { vendor: e.vendor, confidence: e.confidence }, reason: `WAF ${e.vendor} detected`, triggeredBy: 'waf:detected' },
      ];
    },
  } as Rule<WafDetectedEvent>,

  // SQLi confirmed → immediately escalate to deep exploitation
  {
    trigger: 'sqli:confirmed',
    description: 'SQLi confirmed → spawn deep-exploit task immediately',
    condition: () => 1.0,
    actions:   (e: SqliConfirmedEvent, ctx: ReactiveContext): AgentTask[] => {
      ctx.confirmedDbms = e.dbms;
      return [
        { type: 'deep-exploit', url: e.url, priority: 100, context: { param: e.param, dbms: e.dbms, technique: e.technique }, reason: `SQLi confirmed on ${e.param} via ${e.technique}`, triggeredBy: 'sqli:confirmed' },
      ];
    },
  } as Rule<SqliConfirmedEvent>,

  // Tech detected → record for context-aware payload selection
  {
    trigger: 'tech:detected',
    description: 'Tech detected → update context for DBMS-specific payloads',
    condition: () => 1.0,
    actions:   (e: TechDetectedEvent, ctx: ReactiveContext): AgentTask[] => {
      if (!ctx.techStack.includes(e.tech)) ctx.techStack.push(e.tech);
      // If a DB tech is detected, update confirmedDbms for SQLi grammar
      const dbmsMap: Record<string, string> = { MySQL: 'mysql', PostgreSQL: 'postgresql', 'Microsoft SQL Server': 'mssql', Oracle: 'oracle', SQLite: 'sqlite' };
      if (e.category === 'database' && dbmsMap[e.tech]) ctx.confirmedDbms = dbmsMap[e.tech];
      return [];
    },
  } as Rule<TechDetectedEvent>,

  // Subdomain found → expand scope to crawl it
  {
    trigger: 'subdomain:found',
    description: 'Subdomain found → expand scope, spawn crawl task',
    condition: () => 0.8,
    actions:   (e: SubdomainFoundEvent, _ctx: ReactiveContext, weight: number): AgentTask[] => [
      { type: 'scope-expand', url: `https://${e.domain}`, priority: Math.round(60 * weight), context: { ip: e.ip, source: e.source }, reason: `subdomain discovered via ${e.source}`, triggeredBy: 'subdomain:found' },
    ],
  } as Rule<SubdomainFoundEvent>,

  // Backup file found → enumerate sibling backup files and analyze
  {
    trigger: 'backup:found',
    description: 'Backup file found → enumerate adjacent backup paths',
    condition: (e: BackupFileEvent) => e.confidence,
    actions:   (e: BackupFileEvent, _ctx: ReactiveContext, weight: number): AgentTask[] => [
      { type: 'backup-enumerate', url: e.url, priority: Math.round(75 * weight), context: { fileType: e.fileType }, reason: `backup file ${e.fileType} found`, triggeredBy: 'backup:found' },
    ],
  } as Rule<BackupFileEvent>,

  // Auth bypass found → re-crawl as elevated user
  {
    trigger: 'auth:bypass',
    description: 'Auth bypass confirmed → crawl as elevated user to discover post-auth surface',
    condition: () => 1.0,
    actions:   (e: AuthBypassEvent, _ctx: ReactiveContext): AgentTask[] => [
      { type: 'crawl-url', url: e.url, priority: 88, context: { elevated: true, method: e.method, technique: e.technique }, reason: `auth bypass via ${e.technique} — crawling as elevated user`, triggeredBy: 'auth:bypass' },
    ],
  } as Rule<AuthBypassEvent>,
];

// Build fast lookup map: eventType → rules[]
const RULE_INDEX = new Map<BusEventType, Rule[]>();
for (const rule of RULES) {
  const list = RULE_INDEX.get(rule.trigger) ?? [];
  list.push(rule);
  RULE_INDEX.set(rule.trigger, list);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Evaluate all rules matching the event type.
 * Returns a (possibly empty) list of new tasks to enqueue.
 * Mutates `ctx` for state side-effects (e.g. wafMode = true).
 */
export function evaluateRules(event: BusEvent, ctx: ReactiveContext): AgentTask[] {
  const rules = RULE_INDEX.get(event.type as BusEventType) ?? [];
  const tasks: AgentTask[] = [];
  for (const rule of rules) {
    const weight = (rule.condition as (e: BusEvent, c: ReactiveContext) => number)(event, ctx);
    if (weight > FIRE_THRESHOLD) {
      const newTasks = (rule.actions as (e: BusEvent, c: ReactiveContext, w: number) => AgentTask[])(event, ctx, weight);
      tasks.push(...newTasks);
    }
  }
  return tasks;
}

/** Returns summary of loaded rules (for logging) */
export function rulesSummary(): string {
  const byTrigger: Record<string, number> = {};
  for (const rule of RULES) byTrigger[rule.trigger] = (byTrigger[rule.trigger] ?? 0) + 1;
  return Object.entries(byTrigger).map(([t, n]) => `${t}(${n})`).join(', ');
}
