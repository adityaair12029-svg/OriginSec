export type ThemeMode = 'dark' | 'light';

export type ScanProfileId =
  | 'quick'
  | 'standard'
  | 'comprehensive'
  | 'verified_owner'
  | 'performance'
  | 'frontend_quality';

export type ScanStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'partially_completed'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type FindingCategory =
  | 'security'
  | 'frontend'
  | 'backend'
  | 'engagement'
  | 'api'
  | 'database'
  | 'hosting'
  | 'backup'
  | 'monitoring';

export type SeverityLevel =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'
  | 'passed';

export type PriorityGroup =
  | 'fix_immediately'
  | 'fix_soon'
  | 'optimization'
  | 'best_practice'
  | 'long_term';

export type FindingStatus =
  | 'open'
  | 'acknowledged'
  | 'in_progress'
  | 'ready_for_verification'
  | 'resolved'
  | 'accepted_risk'
  | 'passed'
  | 'not_assessed';

export interface ScanCoverage {
  pagesScanned: number;
  maxPages: number;
  crawlDepth: number;
  scanProfile?: ScanProfileId;
  httpsVerified: boolean;
  dnsVerified: boolean;
  tlsVerified: boolean;
  lighthouseVerified: boolean;
  apiVerified: boolean;
  databaseVerified: boolean;
  hostingVerified: boolean;
  backupVerified: boolean;
}

export interface CategoryScores {
  security: number | null;
  frontend: number | null;
  backend: number | null;
  engagement: number | null;
  overall: number | null;
  seo?: number | null;
  accessibility?: number | null;
  performance?: number | null;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  passed: number;
}

export interface LighthouseMetrics {
  available: boolean;
  source: 'google_pagespeed_insights' | 'not_configured' | 'unavailable';
  strategy: 'mobile' | 'desktop';
  performanceScore?: number;
  accessibilityScore?: number;
  bestPracticesScore?: number;
  seoScore?: number;
  lcpMs?: number;
  cls?: number;
  fcpMs?: number;
  tbtMs?: number;
  speedIndexMs?: number;
  inpMs?: number | null;
  dataType: 'lab' | 'field_and_lab' | 'none';
  errorNote?: string;
}

export interface TlsCertificateInfo {
  available: boolean;
  authorized: boolean;
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  hostnameMatch: boolean | null;
  error?: string;
}

export interface DnsSignals {
  resolved: boolean;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: string[];
  txtRecords: string[];
  caaRecords: string[];
  cnameRecords?: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  hasDnssec?: boolean | null;
  dmarcRecord?: string;
  error?: string;
}

export interface TimingBreakdownMs {
  dnsLookupMs: number;
  tlsHandshakeMs: number;
  ttfbMs: number;
  warmTtfbMs: number;
  contentTransferMs: number;
  totalResponseTimeMs: number;
}

export interface ExtendedFrontendMetrics {
  formCount: number;
  inputsWithoutLabel: number;
  buttonsWithoutText: number;
  emptyLinks: number;
  imagesWithoutLazyLoading: number;
  headingOrderIssues: number;
  hasCanonical: boolean;
  canonicalUrl: string | null;
  hasMetaDescription: boolean;
  metaDescriptionLength: number;
  hasOpenGraph: boolean;
  hasTwitterCard: boolean;
  hasRobotsTxt: boolean;
  hasSitemapXml: boolean;
  hasSecurityTxt: boolean;
  htmlLang: string | null;
  pageTitle: string | null;
}

export interface ScreenshotCaptureInfo {
  available: boolean;
  imageUrl?: string;
  width?: number;
  height?: number;
  capturedAt?: string;
  finalUrl?: string;
  source?: 'microlink' | 'unavailable';
  error?: string;
}

export interface ScanMetrics {
  ttfbMs: number;
  totalResponseTimeMs: number;
  statusCode: number;
  redirectCount: number;
  finalUrl: string;
  htmlSizeBytes: number;
  domNodeCount: number;
  scriptCount: number;
  stylesheetCount: number;
  renderBlockingScripts: number;
  imageCount: number;
  imagesWithoutAlt: number;
  imagesWithoutDimensions: number;
  linkCount: number;
  brokenInternalLinks: number;
  headingCount: { h1: number; h2: number; h3: number };
  compression: string | null;
  serverBanner: string | null;
  tls: TlsCertificateInfo;
  dns: DnsSignals;
  lighthouse: LighthouseMetrics;
  timingBreakdown?: TimingBreakdownMs;
  frontendDetails?: ExtendedFrontendMetrics;
  headersSnapshot?: Record<string, string>;
  crawledUrls?: string[];
  crawledPageDetails?: Array<{
    url: string;
    statusCode: number;
    title: string | null;
    ttfbMs: number;
  }>;
  screenshot?: ScreenshotCaptureInfo;
}

export interface ScanFinding {
  findingId: string;
  ruleId?: string;
  scanId: string;
  ownerUid: string;
  category: FindingCategory;
  subCategory?: 'seo' | 'accessibility' | 'performance' | 'headers' | 'tls' | 'dns' | 'api' | 'content' | 'infrastructure';
  title: string;
  severity: SeverityLevel;
  priorityGroup: PriorityGroup;
  description: string;
  evidence: string;
  affectedUrl: string;
  observedValue: string;
  impact: string;
  recommendation: string;
  remediation: string;
  verification: string;
  status: FindingStatus;
  confidence?: 'verified_direct' | 'static_html' | 'heuristic' | 'not_assessed';
  manualReviewRequired?: boolean;
  remediationNote?: string;
  dueDate?: string | null;
  resolvedAt?: string | null;
  createdAt: string;
}

export interface GroundingSource {
  title: string;
  uri: string;
}

export interface WebsiteScan {
  scanId: string;
  ownerUid: string;
  targetUrl: string;
  normalizedDomain: string;
  scanProfile?: ScanProfileId;
  postureFingerprint?: string;
  status: ScanStatus;
  currentStage: string;
  progressPercent: number;
  authorizedConfirmed: boolean;
  coverage: ScanCoverage;
  scores: CategoryScores;
  summary: string;
  aiExplanation?: string;
  aiSources?: GroundingSource[];
  metrics: ScanMetrics;
  findingsCount: FindingsCount;
  scannerVersion: string;
  startedAt: string;
  completedAt: string | null;
  updatedAt: string;
  findings?: ScanFinding[];
  stagesLog?: Array<{ stage: string; status: 'completed' | 'skipped' | 'failed'; detail: string; timestamp: string }>;
}

export interface WebsiteRecord {
  websiteId: string;
  ownerUid: string;
  name: string;
  targetUrl: string;
  normalizedDomain: string;
  verificationStatus: 'unverified' | 'pending' | 'verified';
  defaultProfile: ScanProfileId;
  monitoringPaused: boolean;
  latestScanId?: string | null;
  latestOverallScore?: number | null;
  lastScannedAt?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface RemediationTask {
  taskId: string;
  ownerUid: string;
  scanId: string;
  findingId: string;
  ruleId?: string;
  domain: string;
  targetUrl: string;
  title: string;
  category: FindingCategory;
  severity: SeverityLevel;
  status: 'open' | 'acknowledged' | 'in_progress' | 'ready_for_verification' | 'resolved' | 'accepted_risk';
  priority: 'p1_critical' | 'p2_high' | 'p3_medium' | 'p4_low';
  notes: string;
  dueDate: string | null;
  lastVerifiedAt: string | null;
  verificationResult?: string;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationItem {
  notificationId: string;
  ownerUid: string;
  type: 'scan_completed' | 'critical_finding' | 'tls_expiry' | 'monitoring_incident' | 'verification_success';
  title: string;
  message: string;
  domain?: string;
  relatedId?: string;
  read: boolean;
  createdAt: string;
}

export interface ApiProbeResult {
  endpoint: string;
  method: string;
  statusCode: number | null;
  responseTimeMs: number;
  contentType: string | null;
  corsHeader: string | null;
  cacheControl: string | null;
  timestamp: string;
  evidence: string;
  severity: SeverityLevel;
  description: string;
  recommendation: string;
  verificationStatus: 'verified_owner' | 'public_observed' | 'blocked_ssrf' | 'error';
}

export interface VerifiedDomain {
  domainId: string;
  ownerUid: string;
  domain: string;
  method: 'dns_txt' | 'html_meta' | 'well_known';
  challengeToken: string;
  verified: boolean;
  verifiedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface IntegrationRecord {
  integrationId: string;
  ownerUid: string;
  provider: string;
  category: 'auth_db' | 'ai' | 'performance' | 'hosting' | 'database' | 'backup' | 'monitoring';
  connectionStatus: 'connected' | 'not_configured' | 'requires_auth' | 'error';
  permissions: string;
  accountLabel?: string;
  configMeta?: Record<string, string | boolean | number>;
  lastSyncAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MonitoringTarget {
  targetId: string;
  ownerUid: string;
  domain: string;
  targetUrl: string;
  frequencyMinutes: number;
  enabled: boolean;
  lastStatus: 'up' | 'degraded' | 'down' | 'pending';
  lastHttpStatus: number | null;
  lastResponseTimeMs: number | null;
  sslExpiryDays: number | null;
  alertEmailEnabled: boolean;
  webhookUrl?: string;
  lastCheckAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MonitoringEvent {
  eventId: string;
  ownerUid: string;
  targetId: string;
  status: 'up' | 'degraded' | 'down';
  httpStatus: number | null;
  responseTimeMs: number;
  details: string;
  timestamp: string;
}

export interface BackupStatusRecord {
  recordId: string;
  ownerUid: string;
  provider: string;
  verifiedStatus: 'unavailable' | 'verified' | 'warning';
  lastBackupAt: string | null;
  frequency?: string;
  retentionPolicy?: string;
  encrypted?: boolean | null;
  storageLocation?: string;
  evidence: string;
  lastCheckedAt: string;
  createdAt: string;
}

export interface UserProfile {
  uid: string;
  displayName: string;
  email: string;
  photoURL: string;
  role: 'user' | 'owner';
  theme: ThemeMode;
  defaultCrawlLimit: number;
  defaultCrawlDepth: number;
  emailAlerts: boolean;
  webhookAlerts: boolean;
  createdAt: string;
  updatedAt: string;
}
