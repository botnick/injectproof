// InjectProof — Cross-scan learning persistence
// Bandit states, effective payloads, WAF/DBMS/tech fingerprints survive across scans.
// The scanner improves automatically — each confirmed finding enriches future priors.

import fs from 'fs';
import path from 'path';
import type { BanditArm } from '@/scanner/engine/synth/bandit';

export interface ArmState { alpha: number; beta: number; pulls: number; meanReward: number }

const INITIAL_PRIORS: Record<BanditArm, ArmState> = {
  union:           { alpha: 3,   beta: 2, pulls: 0, meanReward: 0 },
  error:           { alpha: 2,   beta: 2, pulls: 0, meanReward: 0 },
  'boolean-blind': { alpha: 2,   beta: 2, pulls: 0, meanReward: 0 },
  'time-blind':    { alpha: 1.5, beta: 2, pulls: 0, meanReward: 0 },
  stacked:         { alpha: 1.2, beta: 3, pulls: 0, meanReward: 0 },
  oob:             { alpha: 1.2, beta: 3, pulls: 0, meanReward: 0 },
};

interface TargetLearning {
  domain: string;
  lastSeen: string;
  scanCount: number;
  banditState: Record<BanditArm, ArmState>;
  effectivePayloads: Record<string, string[]>;
  wafVendor?: string;
  techStack: string[];
  confirmedDbms?: string;
}

interface GlobalStore {
  version: 2;
  updatedAt: string;
  targets: Record<string, TargetLearning>;
  globalBandit: Record<BanditArm, ArmState>;
}

export class CrossScanLearningStore {
  private data: GlobalStore;

  constructor(private readonly storePath: string = path.join(process.cwd(), '.injectproof-learning.json')) {
    this.data = this.load();
  }

  private load(): GlobalStore {
    try {
      const raw = fs.readFileSync(this.storePath, 'utf8');
      const parsed = JSON.parse(raw) as GlobalStore;
      if (parsed.version === 2) return parsed;
    } catch { /* first run or corrupt — start fresh */ }
    return this.empty();
  }

  private empty(): GlobalStore {
    return { version: 2, updatedAt: new Date().toISOString(), targets: {}, globalBandit: JSON.parse(JSON.stringify(INITIAL_PRIORS)) };
  }

  private persist(): void {
    this.data.updatedAt = new Date().toISOString();
    try { fs.writeFileSync(this.storePath, JSON.stringify(this.data, null, 2), 'utf8'); } catch { /* non-critical */ }
  }

  private key(url: string): string {
    try { return new URL(url).hostname; } catch { return url; }
  }

  private ensureTarget(domain: string): TargetLearning {
    if (!this.data.targets[domain]) {
      this.data.targets[domain] = {
        domain, lastSeen: new Date().toISOString(), scanCount: 0,
        banditState: JSON.parse(JSON.stringify(INITIAL_PRIORS)),
        effectivePayloads: {}, techStack: [],
      };
    }
    return this.data.targets[domain];
  }

  /**
   * Warm-started bandit priors: blends target-specific history with global.
   * Targets with more scan history get more weight on their local priors.
   */
  getWarmPriors(targetUrl: string): Record<BanditArm, ArmState> {
    const t = this.data.targets[this.key(targetUrl)];
    const g = this.data.globalBandit;
    if (!t) return JSON.parse(JSON.stringify(g));

    const arms = Object.keys(INITIAL_PRIORS) as BanditArm[];
    const blended = {} as Record<BanditArm, ArmState>;
    // Trust target-specific priors more as we accumulate scan history (caps at 70%)
    const targetWeight = Math.min(t.scanCount / 5, 0.7);
    for (const arm of arms) {
      const ta = t.banditState[arm];
      const ga = g[arm];
      blended[arm] = {
        alpha:      ga.alpha      * (1 - targetWeight) + ta.alpha      * targetWeight,
        beta:       ga.beta       * (1 - targetWeight) + ta.beta       * targetWeight,
        meanReward: ga.meanReward * (1 - targetWeight) + ta.meanReward * targetWeight,
        pulls: ta.pulls,
      };
    }
    return blended;
  }

  /** Save scan's bandit outcome; updates both domain-specific and global state */
  saveBanditState(targetUrl: string, state: Record<BanditArm, ArmState>): void {
    const domain = this.key(targetUrl);
    const target = this.ensureTarget(domain);
    target.banditState = state;
    target.lastSeen = new Date().toISOString();
    target.scanCount++;

    const arms = Object.keys(INITIAL_PRIORS) as BanditArm[];
    const ema = 0.1;
    for (const arm of arms) {
      const s = state[arm];
      const gArm = this.data.globalBandit[arm];
      if (s.pulls > 0) {
        gArm.meanReward = gArm.meanReward * (1 - ema) + s.meanReward * ema;
        gArm.pulls     += s.pulls;
        gArm.alpha      = Math.max(INITIAL_PRIORS[arm].alpha, gArm.alpha * 0.95 + s.alpha * 0.05);
        gArm.beta       = Math.max(INITIAL_PRIORS[arm].beta,  gArm.beta  * 0.95 + s.beta  * 0.05);
      }
    }
    this.persist();
  }

  recordEffectivePayload(targetUrl: string, context: string, payload: string): void {
    const target = this.ensureTarget(this.key(targetUrl));
    const list = (target.effectivePayloads[context] ??= []);
    if (!list.includes(payload)) { list.unshift(payload); if (list.length > 30) list.length = 30; }
    this.persist();
  }

  getEffectivePayloads(targetUrl: string, context: string): string[] {
    return this.data.targets[this.key(targetUrl)]?.effectivePayloads[context] ?? [];
  }

  recordWaf(targetUrl: string, vendor: string): void {
    this.ensureTarget(this.key(targetUrl)).wafVendor = vendor;
    this.persist();
  }
  getWaf(targetUrl: string): string | undefined { return this.data.targets[this.key(targetUrl)]?.wafVendor; }

  recordDbms(targetUrl: string, dbms: string): void {
    this.ensureTarget(this.key(targetUrl)).confirmedDbms = dbms;
    this.persist();
  }
  getDbms(targetUrl: string): string | undefined { return this.data.targets[this.key(targetUrl)]?.confirmedDbms; }

  recordTech(targetUrl: string, tech: string): void {
    const t = this.ensureTarget(this.key(targetUrl));
    if (!t.techStack.includes(tech)) { t.techStack.push(tech); this.persist(); }
  }
  getTechStack(targetUrl: string): string[] { return this.data.targets[this.key(targetUrl)]?.techStack ?? []; }

  summary(targetUrl: string): string {
    const t = this.data.targets[this.key(targetUrl)];
    if (!t) return `first scan of ${this.key(targetUrl)}`;
    return `${this.key(targetUrl)} | scans=${t.scanCount} waf=${t.wafVendor ?? '?'} dbms=${t.confirmedDbms ?? '?'} tech=[${t.techStack.slice(0,5).join(',')}] payloadContexts=${Object.keys(t.effectivePayloads).length}`;
  }
}

let _store: CrossScanLearningStore | null = null;
export function getLearningStore(): CrossScanLearningStore {
  return (_store ??= new CrossScanLearningStore());
}
