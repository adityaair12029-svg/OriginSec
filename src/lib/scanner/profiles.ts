import type { ScanFinding, ScanProfileId, WebsiteScan } from '../../types/audit';

export interface ScanProfileDefinition {
  id: ScanProfileId;
  label: string;
  shortLabel: string;
  description: string;
  maxPages: number;
  crawlDepth: number;
  runPageSpeed: boolean;
  requiresVerifiedOwner?: boolean;
}

export const SCAN_PROFILES: Record<ScanProfileId, ScanProfileDefinition> = {
  quick: {
    id: 'quick',
    label: 'Quick Audit',
    shortLabel: 'Quick (1 page)',
    description: 'Single-page fast HTTPS/TLS, HTTP security headers, DNS, and static HTML triage.',
    maxPages: 1,
    crawlDepth: 0,
    runPageSpeed: false,
  },
  standard: {
    id: 'standard',
    label: 'Standard Audit',
    shortLabel: 'Standard (8 pages)',
    description: 'Default deterministic multi-page audit covering Security, Front-End, Back-End & Engagement.',
    maxPages: 8,
    crawlDepth: 1,
    runPageSpeed: true,
  },
  comprehensive: {
    id: 'comprehensive',
    label: 'Comprehensive External',
    shortLabel: 'Comprehensive (15 pages)',
    description: 'Expanded same-origin crawl with full SEO, accessibility, header, and link checks.',
    maxPages: 15,
    crawlDepth: 1,
    runPageSpeed: true,
  },
  verified_owner: {
    id: 'verified_owner',
    label: 'Verified Owner Deep',
    shortLabel: 'Verified Owner (20 pages)',
    description: 'Deeper authorized crawl for verified domain owners with extended endpoint & asset checks.',
    maxPages: 20,
    crawlDepth: 2,
    runPageSpeed: true,
    requiresVerifiedOwner: true,
  },
  performance: {
    id: 'performance',
    label: 'Performance Lab',
    shortLabel: 'Performance Lab (5 pages)',
    description: 'Focused DNS/TLS/TTFB timing breakdown, compression, asset weight, and PageSpeed Web Vitals.',
    maxPages: 5,
    crawlDepth: 1,
    runPageSpeed: true,
  },
  frontend_quality: {
    id: 'frontend_quality',
    label: 'Frontend Quality',
    shortLabel: 'Frontend & WCAG (8 pages)',
    description: 'Focused DOM, accessibility (WCAG signals), heading sequence, forms, images, and SEO audit.',
    maxPages: 8,
    crawlDepth: 1,
    runPageSpeed: true,
  },
};

export const ORDERED_PROGRESS_STAGES = [
  'Validating target',
  'Resolving DNS & SSRF checks',
  'Inspecting TLS certificate',
  'Checking HTTP headers & cookies',
  'Fetching auxiliary policy files',
  'Analysing homepage DOM',
  'Crawling same-origin pages',
  'Evaluating frontend & accessibility',
  'Auditing backend & performance',
  'Evaluating SEO & engagement',
  'Computing deterministic scores',
  'Generating audit report',
] as const;

export interface ScanComparisonDiff {
  scoreDeltas: {
    security: number | null;
    frontend: number | null;
    backend: number | null;
    engagement: number | null;
    overall: number | null;
  };
  newlyDiscovered: ScanFinding[];
  resolvedFindings: ScanFinding[];
  unchangedCount: number;
  changedHeaders: Array<{ header: string; before: string | null; after: string | null }>;
  metricChanges: {
    domNodesDelta: number | null;
    scriptsDelta: number | null;
    ttfbDeltaMs: number | null;
    brokenLinksDelta: number | null;
  };
  identicalPosture: boolean;
}

const TRACKED_SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cache-control',
  'content-encoding',
  'server',
];

function findingKey(f: ScanFinding): string {
  return f.ruleId ? `${f.category}:${f.ruleId}` : `${f.category}:${f.title.toLowerCase()}`;
}

export function compareTwoScans(older: WebsiteScan, newer: WebsiteScan): ScanComparisonDiff {
  const delta = (a?: number | null, b?: number | null) =>
    a !== null && a !== undefined && b !== null && b !== undefined ? b - a : null;

  const olderIssues = (older.findings || []).filter((f) => f.severity !== 'passed' && f.status !== 'not_assessed');
  const newerIssues = (newer.findings || []).filter((f) => f.severity !== 'passed' && f.status !== 'not_assessed');

  const olderMap = new Map(olderIssues.map((f) => [findingKey(f), f]));
  const newerMap = new Map(newerIssues.map((f) => [findingKey(f), f]));

  const newlyDiscovered: ScanFinding[] = [];
  const resolvedFindings: ScanFinding[] = [];
  let unchangedCount = 0;

  for (const [key, nf] of newerMap.entries()) {
    if (!olderMap.has(key)) {
      newlyDiscovered.push(nf);
    } else {
      unchangedCount++;
    }
  }
  for (const [key, of] of olderMap.entries()) {
    if (!newerMap.has(key)) {
      resolvedFindings.push(of);
    }
  }

  const hBefore = older.metrics?.headersSnapshot || {};
  const hAfter = newer.metrics?.headersSnapshot || {};
  const changedHeaders: Array<{ header: string; before: string | null; after: string | null }> = [];
  for (const hdr of TRACKED_SECURITY_HEADERS) {
    const v1 = hBefore[hdr] ?? null;
    const v2 = hAfter[hdr] ?? null;
    if (v1 !== v2) {
      changedHeaders.push({ header: hdr, before: v1, after: v2 });
    }
  }

  const dom1 = older.metrics?.domNodeCount;
  const dom2 = newer.metrics?.domNodeCount;
  const sc1 = older.metrics?.scriptCount;
  const sc2 = newer.metrics?.scriptCount;
  const ttfb1 = older.metrics?.ttfbMs;
  const ttfb2 = newer.metrics?.ttfbMs;
  const bl1 = older.metrics?.brokenInternalLinks;
  const bl2 = newer.metrics?.brokenInternalLinks;

  const identicalPosture =
    Boolean(older.postureFingerprint && newer.postureFingerprint && older.postureFingerprint === newer.postureFingerprint) ||
    (newlyDiscovered.length === 0 &&
      resolvedFindings.length === 0 &&
      delta(older.scores?.overall, newer.scores?.overall) === 0);

  return {
    scoreDeltas: {
      security: delta(older.scores?.security, newer.scores?.security),
      frontend: delta(older.scores?.frontend, newer.scores?.frontend),
      backend: delta(older.scores?.backend, newer.scores?.backend),
      engagement: delta(older.scores?.engagement, newer.scores?.engagement),
      overall: delta(older.scores?.overall, newer.scores?.overall),
    },
    newlyDiscovered,
    resolvedFindings,
    unchangedCount,
    changedHeaders,
    metricChanges: {
      domNodesDelta: delta(dom1, dom2),
      scriptsDelta: delta(sc1, sc2),
      ttfbDeltaMs: delta(ttfb1, ttfb2),
      brokenLinksDelta: delta(bl1, bl2),
    },
    identicalPosture,
  };
}
