// VibeCode — Shared TypeScript Types
// All type definitions used across the platform

// ============================================================
// ENUMS (as const objects for runtime + type safety)
// ============================================================

export const UserRole = {
    ADMIN: 'admin',
    SECURITY_LEAD: 'security_lead',
    PENTESTER: 'pentester',
    DEVELOPER: 'developer',
    VIEWER: 'viewer',
} as const;
export type UserRole = (typeof UserRole)[keyof typeof UserRole];

export const Severity = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    INFO: 'info',
} as const;
export type Severity = (typeof Severity)[keyof typeof Severity];

export const VulnStatus = {
    OPEN: 'open',
    CONFIRMED: 'confirmed',
    FIXED: 'fixed',
    FALSE_POSITIVE: 'false_positive',
    ACCEPTED: 'accepted',
    REOPENED: 'reopened',
} as const;
export type VulnStatus = (typeof VulnStatus)[keyof typeof VulnStatus];

export const ScanStatus = {
    QUEUED: 'queued',
    RUNNING: 'running',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled',
    PAUSED: 'paused',
} as const;
export type ScanStatus = (typeof ScanStatus)[keyof typeof ScanStatus];

export const ScanType = {
    QUICK: 'quick',
    STANDARD: 'standard',
    DEEP: 'deep',
    CUSTOM: 'custom',
} as const;
export type ScanType = (typeof ScanType)[keyof typeof ScanType];

export const Environment = {
    PRODUCTION: 'production',
    STAGING: 'staging',
    DEVELOPMENT: 'development',
    INTERNAL: 'internal',
} as const;
export type Environment = (typeof Environment)[keyof typeof Environment];

export const Criticality = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
} as const;
export type Criticality = (typeof Criticality)[keyof typeof Criticality];

export const VulnCategory = {
    XSS: 'xss',
    SQLI: 'sqli',
    SSRF: 'ssrf',
    PATH_TRAVERSAL: 'path_traversal',
    OPEN_REDIRECT: 'open_redirect',
    HEADERS: 'headers',
    INFO_DISCLOSURE: 'info_disclosure',
    AUTH: 'auth',
    CORS: 'cors',
    CVE: 'cve',
    JWT: 'jwt',
    IDOR: 'idor',
    CMD_INJECTION: 'cmd_injection',
    NOSQL_INJECTION: 'nosql_injection',
    DESERIALIZATION: 'deserialization',
    RCE: 'rce',
    CSRF: 'csrf',
    CLICKJACKING: 'clickjacking',
    XXE: 'xxe',
    SSTI: 'ssti',
    LDAP_INJECTION: 'ldap_injection',
    INSECURE_DESIGN: 'insecure_design',
    MISCONFIG: 'misconfig',
    OUTDATED_COMPONENT: 'outdated_component',
    DATA_INTEGRITY: 'data_integrity',
    RACE_CONDITION: 'race_condition',
    HTTP_DESYNC: 'http_desync',
    PROTOTYPE_POLLUTION: 'prototype_pollution',
    CACHE_POISONING: 'cache_poisoning',
    CLOUD_EXPOSURE: 'cloud_exposure',
    LEAKED_SECRET: 'leaked_secret',
    SHADOW_API: 'shadow_api',
    CONTAINER_EXPOSURE: 'container_exposure',
    CICD_POISONING: 'cicd_poisoning',
    POST_EXPLOITATION: 'post_exploitation',
    BUSINESS_LOGIC: 'business_logic',
} as const;
export type VulnCategory = (typeof VulnCategory)[keyof typeof VulnCategory];

export const Confidence = {
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
} as const;
export type Confidence = (typeof Confidence)[keyof typeof Confidence];

export const AuthType = {
    NONE: 'none',
    TOKEN: 'token',
    COOKIE: 'cookie',
    SESSION: 'session',
    SCRIPTED: 'scripted',
} as const;
export type AuthType = (typeof AuthType)[keyof typeof AuthType];

export const EvidenceType = {
    REQUEST: 'request',
    RESPONSE: 'response',
    SCREENSHOT: 'screenshot',
    DOM_SNAPSHOT: 'dom_snapshot',
    TIMING_LOG: 'timing_log',
    EXECUTION_TRACE: 'execution_trace',
    REPLAY_SCRIPT: 'replay_script',
    RAW_TRACE: 'raw_trace',
} as const;
export type EvidenceType = (typeof EvidenceType)[keyof typeof EvidenceType];

export const ReportType = {
    EXECUTIVE: 'executive',
    TECHNICAL: 'technical',
    COMPLIANCE: 'compliance',
    FULL: 'full',
} as const;
export type ReportType = (typeof ReportType)[keyof typeof ReportType];

export const ReportFormat = {
    PDF: 'pdf',
    HTML: 'html',
    MARKDOWN: 'markdown',
    JSON: 'json',
} as const;
export type ReportFormat = (typeof ReportFormat)[keyof typeof ReportFormat];

export const NotificationChannel = {
    EMAIL: 'email',
    SLACK: 'slack',
    DISCORD: 'discord',
    TEAMS: 'teams',
    WEBHOOK: 'webhook',
} as const;
export type NotificationChannel = (typeof NotificationChannel)[keyof typeof NotificationChannel];

export const NotificationEvent = {
    CRITICAL_VULN: 'critical_vuln',
    HIGH_VULN: 'high_vuln',
    SCAN_COMPLETED: 'scan_completed',
    SCAN_FAILED: 'scan_failed',
    SLA_OVERDUE: 'sla_overdue',
    ASSET_ONBOARDED: 'asset_onboarded',
} as const;
export type NotificationEvent = (typeof NotificationEvent)[keyof typeof NotificationEvent];

export const AuditAction = {
    LOGIN: 'login',
    LOGOUT: 'logout',
    CREATE_TARGET: 'create_target',
    UPDATE_TARGET: 'update_target',
    DELETE_TARGET: 'delete_target',
    START_SCAN: 'start_scan',
    STOP_SCAN: 'stop_scan',
    UPDATE_VULN: 'update_vuln',
    GENERATE_REPORT: 'generate_report',
    CREATE_USER: 'create_user',
    UPDATE_USER: 'update_user',
    DELETE_USER: 'delete_user',
    UPDATE_SETTINGS: 'update_settings',
} as const;
export type AuditAction = (typeof AuditAction)[keyof typeof AuditAction];

// ============================================================
// SCANNER TYPES
// ============================================================

/** Discovered endpoint from crawling */
export interface CrawledEndpoint {
    url: string;
    method: string;
    params: DiscoveredParam[];
    forms: DiscoveredForm[];
    headers: Record<string, string>;
    depth: number;
    source: string; // where we found this URL
}

/** Parameter discovered during crawling */
export interface DiscoveredParam {
    name: string;
    type: 'query' | 'body' | 'header' | 'cookie' | 'path' | 'json' | 'multipart';
    value?: string;
    required?: boolean;
}

/** Form discovered during crawling */
export interface DiscoveredForm {
    action: string;
    method: string;
    fields: FormField[];
    enctype?: string;
}

/** Individual form field */
export interface FormField {
    name: string;
    type: string;
    value?: string;
    required?: boolean;
    hidden?: boolean;
}

/** Scan configuration passed to the scan engine */
export interface ScanConfig {
    targetId: string;
    scanId: string;
    baseUrl: string;
    maxCrawlDepth: number;
    maxUrls: number;
    requestTimeout: number;
    rateLimit: number;
    modules: string[];
    authType?: string;
    authConfig?: Record<string, unknown>;
    customHeaders?: Record<string, string>;
    excludePaths?: string[];
    includePaths?: string[];
    userAgent?: string;
    /** Enable headless browser crawling (Lightpanda/Chrome via CDP) */
    enableHeadless?: boolean;
    /** CDP WebSocket endpoint (e.g. ws://127.0.0.1:9222 for Lightpanda) */
    cdpEndpoint?: string;
}

/** Result from a single detector check */
export interface DetectorResult {
    found: boolean;
    title: string;
    description: string;
    category: VulnCategory;
    severity: Severity;
    confidence: Confidence;
    cweId?: string;
    cweTitle?: string;
    cvssVector?: string;
    cvssScore?: number;
    affectedUrl: string;
    httpMethod: string;
    parameter?: string;
    parameterType?: string;
    injectionPoint?: string;
    payload?: string;
    request?: string;
    response?: string;
    responseCode?: number;
    responseTime?: number;
    timingEvidence?: Record<string, unknown>;
    domSnapshot?: string;
    screenshotPath?: string;
    impact?: string;
    technicalDetail?: string;
    remediation?: string;
    reproductionSteps?: string[];
    references?: string[];
    mappedCveIds?: string[];
    mappedOwasp?: string[];
    mappedOwaspAsvs?: string[];
    mappedNist?: string[];
    rawEvidence?: Record<string, unknown>;
    // Red-Team operation fields
    raceConditionConfirmed?: boolean;
    cloudMetadataExtracted?: boolean;
    cachePoisoningImpact?: string;
    attackChainGraph?: string; // JSON DAG
    // EASM & Recon fields
    assetDiscoveryPath?: string;
    sourceMapReconstructed?: boolean;
    // Post-exploitation fields
    internalNetworkExposure?: boolean;
    extractedCloudSecrets?: string; // JSON
    postExploitationEvidence?: string; // JSON/text
    // Deep SQLi exploitation data (Havij-style DB enumeration)
    sqliExploitData?: string; // JSON: SqliExploitResult from sqli-exploiter.ts
}

/** Scanner progress update */
export interface ScanProgress {
    scanId: string;
    phase: 'crawling' | 'scanning' | 'analyzing' | 'evidence' | 'completed' | 'failed';
    progress: number; // 0-100
    currentModule?: string;
    currentUrl?: string;
    urlsDiscovered: number;
    urlsScanned: number;
    vulnsFound: number;
    message?: string;
}

// ============================================================
// DASHBOARD TYPES
// ============================================================

export interface DashboardStats {
    totalTargets: number;
    totalScans: number;
    totalVulnerabilities: number;
    activeScans: number;
    criticalVulns: number;
    highVulns: number;
    mediumVulns: number;
    lowVulns: number;
    infoVulns: number;
    openVulns: number;
    fixedVulns: number;
    avgScanDuration: number;
    lastScanDate?: string;
}

export interface SeverityDistribution {
    severity: string;
    count: number;
    color: string;
}

export interface TrendDataPoint {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
}

export interface HeatmapCell {
    targetName: string;
    category: string;
    count: number;
    maxSeverity: string;
}

// ============================================================
// API RESPONSE TYPES
// ============================================================

export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: {
        code: string;
        message: string;
        details?: unknown;
    };
}

export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

// ============================================================
// CVSS TYPES
// ============================================================

export interface CvssMetrics {
    attackVector: 'N' | 'A' | 'L' | 'P';
    attackComplexity: 'L' | 'H';
    privilegesRequired: 'N' | 'L' | 'H';
    userInteraction: 'N' | 'R';
    scope: 'U' | 'C';
    confidentialityImpact: 'N' | 'L' | 'H';
    integrityImpact: 'N' | 'L' | 'H';
    availabilityImpact: 'N' | 'L' | 'H';
}

// ============================================================
// SQLi EXPLOITATION TYPES (re-exported from sqli-exploiter)
// ============================================================

export type {
    SqliExploitResult,
    DatabaseInfo,
    TableInfo,
    ColumnInfo,
    ExploitStep,
    DbmsFamily,
    ExploitTechnique,
    InjectionPoint,
    UserInfo,
    PasswordHash,
    FileReadResult,
    OsCommandResult,
    TestedTechnique,
} from '@/scanner/sqli-exploiter';
