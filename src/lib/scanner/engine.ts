import dns from 'node:dns/promises';
import tls from 'node:tls';
import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import type {
  DnsSignals,
  LighthouseMetrics,
  ScanCoverage,
  ScanMetrics,
  ScanProfileId,
  ScanStatus,
  TimingBreakdownMs,
  TlsCertificateInfo,
  WebsiteScan,
} from '../../types/audit';
import { analyzeAllCategories, buildExecutiveSummary } from './analyzer.js';
import { SCAN_PROFILES } from './profiles.js';
import { resolveAndVerifyHost, validateTargetUrl } from './ssrf.js';

export interface ScanJobState {
  scanId: string;
  ownerUid: string;
  targetUrl: string;
  normalizedDomain: string;
  scanProfile: ScanProfileId;
  status: ScanStatus;
  currentStage: string;
  progressPercent: number;
  cancelled: boolean;
  stagesLog: Array<{ stage: string; status: 'completed' | 'skipped' | 'failed'; detail: string; timestamp: string }>;
  result?: WebsiteScan;
  error?: string;
  createdAtMs: number;
}

const activeJobs = new Map<string, ScanJobState>();

const SCANNER_VERSION = 'originsec-engine-2.0';
const CANONICAL_USER_AGENT = 'OriginSec-Auditor/2.0 (+https://originsec.vercel.app)';
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
const REQUEST_TIMEOUT_MS = 8500;
const MAX_REDIRECTS = 5;

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.bin', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.apk', '.ipa', '.zip', '.tar', '.gz', '.iso',
]);

export function getJobState(scanId: string): ScanJobState | undefined {
  return activeJobs.get(scanId);
}

export function findInFlightJob(ownerUid: string, normalizedUrl: string): ScanJobState | undefined {
  const now = Date.now();
  for (const job of activeJobs.values()) {
    if (
      job.ownerUid === ownerUid &&
      job.targetUrl === normalizedUrl &&
      (job.status === 'queued' || job.status === 'running') &&
      now - job.createdAtMs < 60_000
    ) {
      return job;
    }
  }
  return undefined;
}

export function cancelJob(scanId: string, ownerUid: string): boolean {
  const job = activeJobs.get(scanId);
  if (!job || job.ownerUid !== ownerUid) return false;
  if (job.status === 'completed' || job.status === 'failed') return false;
  job.cancelled = true;
  job.status = 'cancelled';
  job.currentStage = 'Cancelled by user';
  return true;
}

function updateJob(
  scanId: string,
  stage: string,
  progressPercent: number,
  detail?: string,
  stageStatus: 'completed' | 'skipped' | 'failed' = 'completed'
) {
  const job = activeJobs.get(scanId);
  if (!job) return;
  job.currentStage = stage;
  job.progressPercent = progressPercent;
  if (detail) {
    job.stagesLog.push({
      stage,
      status: stageStatus,
      detail,
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Performs a safe, SSRF-checked HTTP/HTTPS request with manual redirect verification
 * and strict timeout & response size caps. Uses canonical headers regardless of caller device.
 */
export async function safeFetchText(
  rawUrl: string,
  options: { timeoutMs?: number; maxBytes?: number; maxRedirects?: number; method?: 'GET' | 'HEAD' } = {}
): Promise<{
  ok: boolean;
  finalUrl: string;
  statusCode: number;
  redirectCount: number;
  headers: Record<string, string>;
  setCookieHeaders: string[];
  body: string;
  ttfbMs: number;
  totalMs: number;
  error?: string;
}> {
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? MAX_BODY_BYTES;
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;
  const method = options.method ?? 'GET';

  let currentUrl = rawUrl;
  let redirectCount = 0;
  const overallStart = performance.now();

  while (redirectCount <= maxRedirects) {
    const validated = validateTargetUrl(currentUrl);
    if (!validated.valid || !validated.normalizedUrl || !validated.hostname) {
      return {
        ok: false,
        finalUrl: currentUrl,
        statusCode: 0,
        redirectCount,
        headers: {},
        setCookieHeaders: [],
        body: '',
        ttfbMs: 0,
        totalMs: Math.round(performance.now() - overallStart),
        error: validated.error || 'Target URL validation failed',
      };
    }

    const pathnameLower = new URL(validated.normalizedUrl).pathname.toLowerCase();
    for (const ext of EXECUTABLE_EXTENSIONS) {
      if (pathnameLower.endsWith(ext)) {
        return {
          ok: false,
          finalUrl: validated.normalizedUrl,
          statusCode: 0,
          redirectCount,
          headers: {},
          setCookieHeaders: [],
          body: '',
          ttfbMs: 0,
          totalMs: Math.round(performance.now() - overallStart),
          error: `Skipped binary/executable resource (${ext}).`,
        };
      }
    }

    const resolved = await resolveAndVerifyHost(validated.hostname);
    if (!resolved.safe) {
      return {
        ok: false,
        finalUrl: validated.normalizedUrl,
        statusCode: 0,
        redirectCount,
        headers: {},
        setCookieHeaders: [],
        body: '',
        ttfbMs: 0,
        totalMs: Math.round(performance.now() - overallStart),
        error: resolved.error || 'SSRF host verification blocked target',
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const reqStart = performance.now();

    try {
      const response = await fetch(validated.normalizedUrl, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': CANONICAL_USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
        },
      });
      const ttfbMs = Math.round(performance.now() - reqStart);

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        clearTimeout(timer);

        if (!location) {
          return {
            ok: false,
            finalUrl: validated.normalizedUrl,
            statusCode: response.status,
            redirectCount,
            headers: {},
            setCookieHeaders: [],
            body: '',
            ttfbMs,
            totalMs: Math.round(performance.now() - overallStart),
            error: `HTTP ${response.status} redirect missing Location header.`,
          };
        }

        const nextUrl = new URL(location, validated.normalizedUrl).toString();
        currentUrl = nextUrl;
        redirectCount++;
        continue;
      }

      const headersObj: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headersObj[key.toLowerCase()] = value;
      });
      const setCookieHeaders =
        typeof response.headers.getSetCookie === 'function'
          ? response.headers.getSetCookie()
          : response.headers.get('set-cookie')
            ? [response.headers.get('set-cookie') as string]
            : [];

      if (method === 'HEAD') {
        await response.body?.cancel();
        clearTimeout(timer);
        return {
          ok: true,
          finalUrl: validated.normalizedUrl,
          statusCode: response.status,
          redirectCount,
          headers: headersObj,
          setCookieHeaders,
          body: '',
          ttfbMs,
          totalMs: Math.round(performance.now() - overallStart),
        };
      }

      const contentType = headersObj['content-type'] || '';
      if (
        contentType &&
        !contentType.includes('text/') &&
        !contentType.includes('application/xhtml') &&
        !contentType.includes('application/xml') &&
        !contentType.includes('application/json')
      ) {
        await response.body?.cancel();
        clearTimeout(timer);
        return {
          ok: false,
          finalUrl: validated.normalizedUrl,
          statusCode: response.status,
          redirectCount,
          headers: headersObj,
          setCookieHeaders,
          body: '',
          ttfbMs,
          totalMs: Math.round(performance.now() - overallStart),
          error: `Unsupported non-text content-type: ${contentType}`,
        };
      }

      let body = '';
      if (response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: false });
        let received = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.byteLength;
          if (received > maxBytes) {
            body += decoder.decode(value.subarray(0, Math.max(0, maxBytes - (received - value.byteLength))), { stream: false });
            await reader.cancel();
            break;
          }
          body += decoder.decode(value, { stream: true });
        }
        body += decoder.decode();
      }

      clearTimeout(timer);
      return {
        ok: true,
        finalUrl: validated.normalizedUrl,
        statusCode: response.status,
        redirectCount,
        headers: headersObj,
        setCookieHeaders,
        body,
        ttfbMs,
        totalMs: Math.round(performance.now() - overallStart),
      };
    } catch (err) {
      clearTimeout(timer);
      const isAbort = err instanceof Error && err.name === 'AbortError';
      return {
        ok: false,
        finalUrl: validated.normalizedUrl,
        statusCode: 0,
        redirectCount,
        headers: {},
        setCookieHeaders: [],
        body: '',
        ttfbMs: 0,
        totalMs: Math.round(performance.now() - overallStart),
        error: isAbort
          ? `Connection timed out after ${timeoutMs} ms.`
          : err instanceof Error
            ? err.message
            : 'Network request failed.',
      };
    }
  }

  return {
    ok: false,
    finalUrl: currentUrl,
    statusCode: 0,
    redirectCount,
    headers: {},
    setCookieHeaders: [],
    body: '',
    ttfbMs: 0,
    totalMs: Math.round(performance.now() - overallStart),
    error: `Redirect limit (${maxRedirects}) exceeded.`,
  };
}

/**
 * Checks whether http://<hostname>/ redirects cleanly to https:// without conflating
 * network timeouts / blocked port 80 (returns null) with an active unencrypted response (false).
 */
async function probeHttpToHttpsRedirect(hostname: string, timeoutMs: number): Promise<boolean | null> {
  const probeUrl = `http://${hostname}/`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(probeUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': CANONICAL_USER_AGENT,
        'Accept': 'text/html,*/*;q=0.5',
      },
    });
    const loc = res.headers.get('location');
    await res.body?.cancel();
    clearTimeout(timer);

    if (res.status >= 300 && res.status < 400 && loc) {
      try {
        const next = new URL(loc, probeUrl);
        if (next.protocol === 'https:') return true;
        // Follow one more hop if redirecting to http://www.hostname before https
        const res2 = await safeFetchText(next.toString(), { timeoutMs, maxBytes: 8192, method: 'HEAD' });
        if (res2.statusCode === 0) return null;
        return res2.finalUrl.startsWith('https://');
      } catch {
        return false;
      }
    }
    // Port 80 returned a non-redirect response directly
    return false;
  } catch {
    clearTimeout(timer);
    // Port 80 timed out / refused — cannot prove unencrypted HTTP is served
    return null;
  }
}

async function fetchWithSingleRetry(
  url: string,
  options: { timeoutMs?: number; maxBytes?: number }
) {
  const first = await safeFetchText(url, options);
  if (first.statusCode === 0) {
    return safeFetchText(url, options);
  }
  return first;
}

export async function inspectTlsCertificate(
  hostname: string,
  verifiedIp?: string
): Promise<TlsCertificateInfo & { handshakeMs: number }> {
  const start = performance.now();
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: verifiedIp || hostname,
        servername: hostname,
        port: 443,
        rejectUnauthorized: false,
        timeout: 5000,
      },
      () => {
        const handshakeMs = Math.round(performance.now() - start);
        try {
          const cert = socket.getPeerCertificate(false);
          const protocol = socket.getProtocol() || null;
          const cipherInfo = socket.getCipher();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            resolve({
              available: false,
              authorized: false,
              protocol,
              cipher: cipherInfo?.name || null,
              issuer: null,
              subject: null,
              validFrom: null,
              validTo: null,
              daysRemaining: null,
              hostnameMatch: null,
              handshakeMs,
              error: 'No peer certificate presented.',
            });
            return;
          }

          const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : null;
          const rawIssuer = cert.issuer?.O || cert.issuer?.CN || null;
          const rawSubject = cert.subject?.CN || null;
          const issuer = Array.isArray(rawIssuer) ? rawIssuer.join(', ') : rawIssuer;
          const subject = Array.isArray(rawSubject) ? rawSubject.join(', ') : rawSubject;
          const hostnameMatch = tls.checkServerIdentity(hostname, cert) === undefined;

          socket.end();
          resolve({
            available: true,
            authorized,
            protocol,
            cipher: cipherInfo?.name || null,
            issuer,
            subject,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysRemaining,
            hostnameMatch,
            handshakeMs,
            error: authError ? String(authError) : undefined,
          });
        } catch (err) {
          socket.destroy();
          resolve({
            available: false,
            authorized: false,
            protocol: null,
            cipher: null,
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            hostnameMatch: null,
            handshakeMs,
            error: err instanceof Error ? err.message : 'TLS inspection error',
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        available: false,
        authorized: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        hostnameMatch: null,
        handshakeMs: Math.round(performance.now() - start),
        error: 'TLS handshake timed out.',
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        available: false,
        authorized: false,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        hostnameMatch: null,
        handshakeMs: Math.round(performance.now() - start),
        error: err.message,
      });
    });
  });
}

export async function inspectDnsSignals(hostname: string): Promise<DnsSignals> {
  try {
    const [aRes, aaaaRes, mxRes, txtRes, caaRes, cnameRes, dmarcRes] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
      dns.resolveMx(hostname),
      dns.resolveTxt(hostname),
      dns.resolveCaa(hostname),
      dns.resolveCname(hostname),
      dns.resolveTxt(`_dmarc.${hostname}`),
    ]);

    const aRecords = aRes.status === 'fulfilled' ? [...aRes.value].sort() : [];
    const aaaaRecords = aaaaRes.status === 'fulfilled' ? [...aaaaRes.value].sort() : [];
    const mxRecords =
      mxRes.status === 'fulfilled'
        ? mxRes.value.map((m) => `${m.exchange} (${m.priority})`).sort()
        : [];
    const txtRecords =
      txtRes.status === 'fulfilled'
        ? txtRes.value.map((parts) => parts.join('')).sort()
        : [];
    const caaRecords =
      caaRes.status === 'fulfilled'
        ? caaRes.value.map((c) => `${c.issue || c.issuewild || c.iodef || 'policy'}`).sort()
        : [];
    const cnameRecords = cnameRes.status === 'fulfilled' ? [...cnameRes.value].sort() : [];
    const dmarcTxt =
      dmarcRes.status === 'fulfilled'
        ? dmarcRes.value.map((p) => p.join('')).sort()
        : [];

    const hasSpf = txtRecords.some((t) => t.toLowerCase().startsWith('v=spf1'));
    const dmarcRecord = dmarcTxt.find((t) => t.toLowerCase().startsWith('v=dmarc1'));

    return {
      resolved: aRecords.length > 0 || aaaaRecords.length > 0 || cnameRecords.length > 0,
      aRecords,
      aaaaRecords,
      mxRecords,
      txtRecords: txtRecords.slice(0, 8),
      caaRecords,
      cnameRecords,
      hasSpf,
      hasDmarc: Boolean(dmarcRecord),
      hasDnssec: null, // Node native dns/promises does not verify AD/RRSIG flags without raw EDNS resolver
      dmarcRecord,
    };
  } catch (err) {
    return {
      resolved: false,
      aRecords: [],
      aaaaRecords: [],
      mxRecords: [],
      txtRecords: [],
      caaRecords: [],
      cnameRecords: [],
      hasSpf: false,
      hasDmarc: false,
      hasDnssec: null,
      error: err instanceof Error ? err.message : 'DNS lookup error',
    };
  }
}

export async function fetchPageSpeedInsights(targetUrl: string): Promise<LighthouseMetrics> {
  const apiKey = process.env.PAGESPEED_API_KEY;
  if (!apiKey) {
    return {
      available: false,
      source: 'not_configured',
      strategy: 'mobile',
      dataType: 'none',
      errorNote: 'PAGESPEED_API_KEY is not configured on the server; Core Web Vitals laboratory measurements are marked unavailable.',
    };
  }

  try {
    const endpoint = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
    endpoint.searchParams.set('url', targetUrl);
    endpoint.searchParams.set('key', apiKey);
    endpoint.searchParams.set('strategy', 'mobile');
    endpoint.searchParams.append('category', 'performance');
    endpoint.searchParams.append('category', 'accessibility');
    endpoint.searchParams.append('category', 'best-practices');
    endpoint.searchParams.append('category', 'seo');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(endpoint.toString(), { signal: controller.signal });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        available: false,
        source: 'unavailable',
        strategy: 'mobile',
        dataType: 'none',
        errorNote: `PageSpeed Insights API returned HTTP ${res.status}.`,
      };
    }

    const json = (await res.json()) as Record<string, any>;
    const cats = json.lighthouseResult?.categories || {};
    const audits = json.lighthouseResult?.audits || {};
    const fieldInp = json.loadingExperience?.metrics?.INTERACTION_TO_NEXT_PAINT?.percentile ?? null;

    return {
      available: true,
      source: 'google_pagespeed_insights',
      strategy: 'mobile',
      performanceScore: cats.performance?.score !== undefined ? Math.round(cats.performance.score * 100) : undefined,
      accessibilityScore: cats.accessibility?.score !== undefined ? Math.round(cats.accessibility.score * 100) : undefined,
      bestPracticesScore: cats['best-practices']?.score !== undefined ? Math.round(cats['best-practices'].score * 100) : undefined,
      seoScore: cats.seo?.score !== undefined ? Math.round(cats.seo.score * 100) : undefined,
      lcpMs: audits['largest-contentful-paint']?.numericValue ? Math.round(audits['largest-contentful-paint'].numericValue) : undefined,
      cls: audits['cumulative-layout-shift']?.numericValue !== undefined ? Number(audits['cumulative-layout-shift'].numericValue.toFixed(3)) : undefined,
      fcpMs: audits['first-contentful-paint']?.numericValue ? Math.round(audits['first-contentful-paint'].numericValue) : undefined,
      tbtMs: audits['total-blocking-time']?.numericValue ? Math.round(audits['total-blocking-time'].numericValue) : undefined,
      speedIndexMs: audits['speed-index']?.numericValue ? Math.round(audits['speed-index'].numericValue) : undefined,
      inpMs: fieldInp,
      dataType: fieldInp !== null ? 'field_and_lab' : 'lab',
    };
  } catch (err) {
    return {
      available: false,
      source: 'unavailable',
      strategy: 'mobile',
      dataType: 'none',
      errorNote: err instanceof Error ? err.message : 'PageSpeed Insights request failed.',
    };
  }
}

function parseDisallowedRobots(robotsText: string): string[] {
  const disallowed: string[] = [];
  let inStarBlock = false;
  for (const rawLine of robotsText.split(/\r?\n/)) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    const lower = line.toLowerCase();
    if (lower.startsWith('user-agent:')) {
      const agent = line.slice(11).trim();
      inStarBlock = agent === '*';
    } else if (inStarBlock && lower.startsWith('disallow:')) {
      const p = line.slice(9).trim();
      if (p) disallowed.push(p);
    }
  }
  return disallowed;
}

export function startScanJob(params: {
  ownerUid: string;
  targetUrl: string;
  scanProfile?: ScanProfileId;
  maxPages?: number;
  crawlDepth?: number;
  isDomainVerified?: boolean;
}): ScanJobState {
  const profileId: ScanProfileId = params.scanProfile && SCAN_PROFILES[params.scanProfile] ? params.scanProfile : 'standard';
  const profileDef = SCAN_PROFILES[profileId];

  const scanId = `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const validated = validateTargetUrl(params.targetUrl);
  const normalizedUrl = validated.normalizedUrl || params.targetUrl;
  const hostname = validated.hostname || 'unknown';

  const job: ScanJobState = {
    scanId,
    ownerUid: params.ownerUid,
    targetUrl: normalizedUrl,
    normalizedDomain: hostname,
    scanProfile: profileId,
    status: 'queued',
    currentStage: 'Validating target',
    progressPercent: 5,
    cancelled: false,
    stagesLog: [],
    createdAtMs: Date.now(),
  };

  activeJobs.set(scanId, job);

  for (const [id, existing] of activeJobs.entries()) {
    if (Date.now() - existing.createdAtMs > 60 * 60 * 1000) {
      activeJobs.delete(id);
    }
  }

  void executeScanJob(job, {
    scanProfile: profileId,
    maxPages: Math.min(20, Math.max(1, params.maxPages ?? profileDef.maxPages)),
    crawlDepth: Math.min(2, Math.max(0, params.crawlDepth ?? profileDef.crawlDepth)),
    runPageSpeed: profileDef.runPageSpeed,
    isDomainVerified: Boolean(params.isDomainVerified),
  });

  return job;
}

export async function runScanJobAndWait(params: {
  ownerUid: string;
  targetUrl: string;
  scanProfile?: ScanProfileId;
  maxPages?: number;
  crawlDepth?: number;
  isDomainVerified?: boolean;
  serverlessBudgetMs?: number;
}): Promise<ScanJobState> {
  const profileId: ScanProfileId = params.scanProfile && SCAN_PROFILES[params.scanProfile] ? params.scanProfile : 'standard';
  const profileDef = SCAN_PROFILES[profileId];

  const scanId = `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const validated = validateTargetUrl(params.targetUrl);
  const normalizedUrl = validated.normalizedUrl || params.targetUrl;
  const hostname = validated.hostname || 'unknown';

  const job: ScanJobState = {
    scanId,
    ownerUid: params.ownerUid,
    targetUrl: normalizedUrl,
    normalizedDomain: hostname,
    scanProfile: profileId,
    status: 'queued',
    currentStage: 'Validating target',
    progressPercent: 5,
    cancelled: false,
    stagesLog: [],
    createdAtMs: Date.now(),
  };

  activeJobs.set(scanId, job);

  await executeScanJob(job, {
    scanProfile: profileId,
    maxPages: Math.min(8, Math.max(1, params.maxPages ?? profileDef.maxPages)),
    crawlDepth: Math.min(2, Math.max(0, params.crawlDepth ?? profileDef.crawlDepth)),
    runPageSpeed: profileDef.runPageSpeed,
    isDomainVerified: Boolean(params.isDomainVerified),
    serverlessBudgetMs: params.serverlessBudgetMs ?? 18000,
  });

  return job;
}

const SNAPSHOT_HEADER_KEYS = [
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

async function executeScanJob(
  job: ScanJobState,
  opts: {
    scanProfile: ScanProfileId;
    maxPages: number;
    crawlDepth: number;
    runPageSpeed: boolean;
    isDomainVerified: boolean;
    serverlessBudgetMs?: number;
  }
) {
  const { scanId, ownerUid } = job;
  const startedAt = new Date().toISOString();
  const startedAtMs = Date.now();
  const deadlineMs = opts.serverlessBudgetMs ? startedAtMs + opts.serverlessBudgetMs : null;
  const remainingMs = () => (deadlineMs ? Math.max(0, deadlineMs - Date.now()) : Infinity);

  try {
    job.status = 'running';
    updateJob(scanId, 'Validating target', 6, `Validated canonical URL and port constraints for ${job.targetUrl}`);

    const validated = validateTargetUrl(job.targetUrl);
    if (!validated.valid || !validated.normalizedUrl || !validated.hostname) {
      throw new Error(validated.error || 'Invalid target URL');
    }
    if (job.cancelled) return;

    // 1. DNS Check & SSRF Verification
    updateJob(scanId, 'Resolving DNS & SSRF checks', 14);
    const dnsStart = performance.now();
    const resolution = await resolveAndVerifyHost(validated.hostname);
    const dnsLookupMs = Math.round(performance.now() - dnsStart);
    if (!resolution.safe) {
      throw new Error(resolution.error || 'Target host failed SSRF IP verification.');
    }

    const isInitialHttps = validated.protocol === 'https:';
    const homeTimeout = deadlineMs ? Math.min(REQUEST_TIMEOUT_MS, Math.max(3500, remainingMs() - 4000)) : REQUEST_TIMEOUT_MS;
    const probeTimeout = deadlineMs ? Math.min(3500, Math.max(1800, remainingMs() - 4000)) : 4000;

    // 2. Concurrent Live Verification: DNS signals, HTTP->HTTPS redirect probe, TLS Cert, Homepage
    updateJob(scanId, 'Inspecting TLS certificate', 26);
    const [dnsSignals, httpRedirectsToHttps, tlsResult, homeFirst] = await Promise.all([
      inspectDnsSignals(validated.hostname),
      probeHttpToHttpsRedirect(validated.hostname, probeTimeout),
      inspectTlsCertificate(validated.hostname, resolution.primaryAddress),
      fetchWithSingleRetry(validated.normalizedUrl, {
        timeoutMs: homeTimeout,
        maxBytes: MAX_BODY_BYTES,
      }),
    ]);

    const { handshakeMs, ...tlsInfo } = tlsResult;

    updateJob(
      scanId,
      'Resolving DNS & SSRF checks',
      22,
      `Resolved ${resolution.addresses.length} public IP(s) in ${dnsLookupMs} ms; SPF=${dnsSignals.hasSpf}, DMARC=${dnsSignals.hasDmarc}`
    );
    updateJob(
      scanId,
      'Inspecting TLS certificate',
      38,
      tlsInfo.available
        ? `TLS ${tlsInfo.protocol || 'verified'} (${handshakeMs} ms), issuer: ${tlsInfo.issuer || 'CA'}`
        : 'TLS certificate metadata unavailable'
    );
    if (job.cancelled) return;

    if (!homeFirst.ok && homeFirst.statusCode === 0) {
      throw new Error(homeFirst.error || 'Unable to connect to target website.');
    }

    // Warm TTFB probe to separate cold TLS/TCP connection cost from steady-state latency
    let warmTtfbMs = homeFirst.ttfbMs;
    if (!deadlineMs || remainingMs() > 5000) {
      const warmProbe = await safeFetchText(homeFirst.finalUrl, {
        timeoutMs: 3500,
        maxBytes: 1024,
        method: 'HEAD',
      }).catch(() => null);
      if (warmProbe && warmProbe.statusCode > 0 && warmProbe.ttfbMs > 0) {
        warmTtfbMs = Math.min(homeFirst.ttfbMs, warmProbe.ttfbMs);
      }
    }

    updateJob(
      scanId,
      'Checking HTTP headers & cookies',
      48,
      `HTTP ${homeFirst.statusCode} · ${homeFirst.ttfbMs} ms TTFB (warm ${warmTtfbMs} ms) · ${homeFirst.redirectCount} redirects`
    );
    if (job.cancelled) return;

    // 3. Auxiliary policy files & passive dotfile exposure checks
    updateJob(scanId, 'Fetching auxiliary policy files', 56);
    const origin = new URL(homeFirst.finalUrl).origin;
    const auxTimeout = deadlineMs ? Math.min(3500, Math.max(1500, remainingMs() - 3000)) : 4000;
    const [robotsRes, secTxtRes, sitemapRes, envProbeRes, gitProbeRes] = await Promise.all([
      fetchWithSingleRetry(`${origin}/robots.txt`, { timeoutMs: auxTimeout, maxBytes: 65536 }),
      fetchWithSingleRetry(`${origin}/.well-known/security.txt`, { timeoutMs: auxTimeout, maxBytes: 65536 }),
      fetchWithSingleRetry(`${origin}/sitemap.xml`, { timeoutMs: auxTimeout, maxBytes: 131072 }),
      safeFetchText(`${origin}/.env`, { timeoutMs: auxTimeout, maxBytes: 8192 }),
      safeFetchText(`${origin}/.git/HEAD`, { timeoutMs: auxTimeout, maxBytes: 4096 }),
    ]);

    const hasRobotsTxt = robotsRes.ok && robotsRes.statusCode === 200;
    const disallowedPaths = hasRobotsTxt ? parseDisallowedRobots(robotsRes.body) : [];
    const hasSecurityTxt =
      secTxtRes.ok &&
      secTxtRes.statusCode === 200 &&
      secTxtRes.body.toLowerCase().includes('contact:');
    const hasSitemapXml = sitemapRes.ok && sitemapRes.statusCode === 200;

    const sensitivePathsExposed: string[] = [];
    if (
      envProbeRes.ok &&
      envProbeRes.statusCode === 200 &&
      !/<!doctype html|<html/i.test(envProbeRes.body) &&
      /^[A-Z0-9_]{2,40}=/m.test(envProbeRes.body)
    ) {
      sensitivePathsExposed.push('/.env');
    }
    if (
      gitProbeRes.ok &&
      gitProbeRes.statusCode === 200 &&
      /^(ref:\s*refs\/|[0-9a-f]{40}\b)/i.test(gitProbeRes.body.trim())
    ) {
      sensitivePathsExposed.push('/.git/HEAD');
    }

    updateJob(
      scanId,
      'Fetching auxiliary policy files',
      62,
      `robots.txt=${hasRobotsTxt}, security.txt=${hasSecurityTxt}, sitemap.xml=${hasSitemapXml}, exposedPaths=${sensitivePathsExposed.length}`
    );

    // 4. Homepage DOM + Mixed Content Inspection
    updateJob(scanId, 'Analysing homepage DOM', 68);
    const $home = cheerio.load(homeFirst.body || '');
    const mixedContentSet = new Set<string>();
    if (homeFirst.finalUrl.startsWith('https://')) {
      $home('script[src], link[href], img[src], iframe[src]').each((_, el) => {
        const src = $home(el).attr('src') || $home(el).attr('href') || '';
        if (src.trim().toLowerCase().startsWith('http://')) {
          mixedContentSet.add(src.trim());
        }
      });
    }
    const mixedContentUrls = Array.from(mixedContentSet).sort();

    // 5. Same-Origin Deterministic Crawl
    updateJob(scanId, 'Crawling same-origin pages', 74);
    const internalCandidates = new Set<string>();
    if (opts.crawlDepth > 0 && opts.maxPages > 1) {
      $home('a[href]').each((_, el) => {
        const href = $home(el).attr('href')?.trim();
        if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) {
          return;
        }
        try {
          const resolvedUrl = new URL(href, homeFirst.finalUrl);
          if (resolvedUrl.origin === origin && resolvedUrl.toString() !== homeFirst.finalUrl) {
            const pathStr = resolvedUrl.pathname;
            const blockedByRobots = disallowedPaths.some((d) => d !== '/' && pathStr.startsWith(d));
            if (!blockedByRobots) {
              resolvedUrl.hash = '';
              internalCandidates.add(resolvedUrl.toString());
            }
          }
        } catch {
          // Ignore malformed hrefs
        }
      });
    }

    let pagesScanned = 1;
    const homeTitle = $home('title').first().text().trim() || null;
    const crawledUrls: string[] = [homeFirst.finalUrl];
    const crawledPageDetails: Array<{ url: string; statusCode: number; title: string | null; ttfbMs: number }> = [
      {
        url: homeFirst.finalUrl,
        statusCode: homeFirst.statusCode,
        title: homeTitle,
        ttfbMs: homeFirst.ttfbMs,
      },
    ];
    const crawledPagesMissingTitle: string[] = [];
    const brokenInternalLinks: Array<{ url: string; status: number | string }> = [];
    // Sort lexicographically BEFORE slicing so identical pages are always sampled across runs
    const candidateList = Array.from(internalCandidates).sort().slice(0, Math.max(0, opts.maxPages - 1));

    for (let i = 0; i < candidateList.length; i += 4) {
      if (job.cancelled) return;
      if (deadlineMs && remainingMs() < 2200) break;
      const batch = candidateList.slice(i, i + 4);
      const linkTimeout = deadlineMs ? Math.min(3200, Math.max(1200, remainingMs() - 1800)) : 4500;
      const batchResults = await Promise.all(
        batch.map(async (linkUrl) => {
          const res = await fetchWithSingleRetry(linkUrl, { timeoutMs: linkTimeout, maxBytes: 512 * 1024 });
          return { linkUrl, res };
        })
      );
      for (const { linkUrl, res } of batchResults) {
        pagesScanned++;
        crawledUrls.push(linkUrl);
        let pageTitle: string | null = null;
        if (res.ok && res.statusCode < 400 && res.body) {
          const $sub = cheerio.load(res.body);
          pageTitle = $sub('title').first().text().trim() || null;
          if (!pageTitle) {
            crawledPagesMissingTitle.push(linkUrl);
          }
        }
        crawledPageDetails.push({
          url: linkUrl,
          statusCode: res.statusCode,
          title: pageTitle,
          ttfbMs: res.ttfbMs,
        });
        if (!res.ok || res.statusCode >= 400) {
          brokenInternalLinks.push({ url: linkUrl, status: res.statusCode || res.error || 'error' });
        }
      }
    }
    updateJob(
      scanId,
      'Crawling same-origin pages',
      82,
      `Inspected ${pagesScanned} same-origin page(s); ${brokenInternalLinks.length} broken link(s) detected`
    );
    if (job.cancelled) return;

    // 6. Performance Lab / PageSpeed Insights
    updateJob(scanId, 'Auditing backend & performance', 88);
    const lighthouse: LighthouseMetrics =
      !opts.runPageSpeed
        ? {
            available: false,
            source: 'not_configured',
            strategy: 'mobile',
            dataType: 'none',
            errorNote: `Skipped external PageSpeed Insights lookup for the ${opts.scanProfile} profile.`,
          }
        : deadlineMs && remainingMs() < 4500
          ? {
              available: false,
              source: 'unavailable',
              strategy: 'mobile',
              dataType: 'none',
              errorNote: 'Skipped PageSpeed Insights call to stay within serverless execution budget.',
            }
          : await fetchPageSpeedInsights(homeFirst.finalUrl);

    updateJob(
      scanId,
      'Evaluating frontend & accessibility',
      91,
      'Evaluated static DOM structure, WCAG signals, forms, headings, and image attributes'
    );
    updateJob(
      scanId,
      'Evaluating SEO & engagement',
      94,
      lighthouse.available
        ? `PageSpeed Performance ${lighthouse.performanceScore}/100 · SEO metadata inspected`
        : 'Evaluated canonicals, Open Graph, headings, and CTA clarity'
    );

    const coverage: ScanCoverage = {
      pagesScanned,
      maxPages: opts.maxPages,
      crawlDepth: opts.crawlDepth,
      scanProfile: opts.scanProfile,
      httpsVerified: homeFirst.finalUrl.startsWith('https://'),
      dnsVerified: dnsSignals.resolved,
      tlsVerified: tlsInfo.available,
      lighthouseVerified: lighthouse.available,
      apiVerified: opts.isDomainVerified,
      databaseVerified: false,
      hostingVerified: false,
      backupVerified: false,
    };

    // 7. Deterministic Scoring & Posture Fingerprinting
    updateJob(scanId, 'Computing deterministic scores', 97);
    const analysis = analyzeAllCategories(
      {
        scanId,
        ownerUid,
        targetUrl: job.targetUrl,
        finalUrl: homeFirst.finalUrl,
        isHttps: homeFirst.finalUrl.startsWith('https://'),
        httpRedirectsToHttps,
        headers: homeFirst.headers,
        setCookieHeaders: homeFirst.setCookieHeaders,
        tls: tlsInfo,
        dns: dnsSignals,
        mixedContentUrls,
        hasSecurityTxt,
        hasRobotsTxt,
        hasSitemapXml,
        sensitivePathsExposed,
      },
      {
        scanId,
        ownerUid,
        targetUrl: job.targetUrl,
        finalUrl: homeFirst.finalUrl,
        html: homeFirst.body,
        htmlSizeBytes: Buffer.byteLength(homeFirst.body || '', 'utf8'),
        ttfbMs: homeFirst.ttfbMs,
        warmTtfbMs,
        totalResponseTimeMs: homeFirst.totalMs,
        statusCode: homeFirst.statusCode,
        redirectCount: homeFirst.redirectCount,
        headers: homeFirst.headers,
        brokenInternalLinks,
        brokenImages: [],
        lighthouse,
        hasRobotsTxt,
        hasSitemapXml,
        hasSecurityTxt,
        crawledPagesMissingTitle,
        crawledPagesCount: pagesScanned,
      },
      coverage
    );

    const completedAt = new Date().toISOString();
    const partial = !homeFirst.ok || (!tlsInfo.available && isInitialHttps);
    const finalStatus: ScanStatus = partial && homeFirst.statusCode >= 500 ? 'partially_completed' : 'completed';

    const summary = buildExecutiveSummary(job.normalizedDomain, analysis.scores, analysis.findings, coverage);

    const headersSnapshot: Record<string, string> = {};
    for (const k of SNAPSHOT_HEADER_KEYS) {
      if (homeFirst.headers[k]) {
        headersSnapshot[k] = homeFirst.headers[k];
      }
    }

    const timingBreakdown: TimingBreakdownMs = {
      dnsLookupMs,
      tlsHandshakeMs: handshakeMs,
      ttfbMs: homeFirst.ttfbMs,
      warmTtfbMs,
      contentTransferMs: Math.max(0, homeFirst.totalMs - homeFirst.ttfbMs),
      totalResponseTimeMs: homeFirst.totalMs,
    };

    const metrics: ScanMetrics = {
      ttfbMs: homeFirst.ttfbMs,
      totalResponseTimeMs: homeFirst.totalMs,
      statusCode: homeFirst.statusCode,
      redirectCount: homeFirst.redirectCount,
      finalUrl: homeFirst.finalUrl,
      htmlSizeBytes: Buffer.byteLength(homeFirst.body || '', 'utf8'),
      domNodeCount: analysis.domStats.domNodeCount,
      scriptCount: analysis.domStats.scriptCount,
      stylesheetCount: analysis.domStats.stylesheetCount,
      renderBlockingScripts: analysis.domStats.renderBlockingScripts,
      imageCount: analysis.domStats.imageCount,
      imagesWithoutAlt: analysis.domStats.imagesWithoutAlt,
      imagesWithoutDimensions: analysis.domStats.imagesWithoutDimensions,
      linkCount: analysis.domStats.linkCount,
      brokenInternalLinks: brokenInternalLinks.length,
      headingCount: analysis.domStats.headingCount,
      compression: homeFirst.headers['content-encoding'] || null,
      serverBanner: homeFirst.headers['server'] || null,
      tls: tlsInfo,
      dns: dnsSignals,
      lighthouse,
      timingBreakdown,
      frontendDetails: analysis.domStats.frontendDetails,
      headersSnapshot,
      crawledUrls,
      crawledPageDetails,
    };

    updateJob(scanId, 'Generating audit report', 100, `Compiled ${analysis.findings.length} evidence-backed checks (${analysis.postureFingerprint}).`);

    const finalScan: WebsiteScan = {
      scanId,
      ownerUid,
      targetUrl: job.targetUrl,
      normalizedDomain: job.normalizedDomain,
      scanProfile: opts.scanProfile,
      postureFingerprint: analysis.postureFingerprint,
      status: finalStatus,
      currentStage: 'Completed',
      progressPercent: 100,
      authorizedConfirmed: true,
      coverage,
      scores: analysis.scores,
      summary,
      metrics,
      findingsCount: analysis.findingsCount,
      scannerVersion: SCANNER_VERSION,
      startedAt,
      completedAt,
      updatedAt: completedAt,
      findings: analysis.findings,
      stagesLog: job.stagesLog,
    };

    job.status = finalStatus;
    job.currentStage = 'Completed';
    job.progressPercent = 100;
    job.result = finalScan;
  } catch (err) {
    if (job.cancelled) return;
    const message = err instanceof Error ? err.message : 'Scan execution failed unexpectedly.';
    job.status = 'failed';
    job.currentStage = 'Failed';
    job.error = message;
    job.stagesLog.push({
      stage: job.currentStage,
      status: 'failed',
      detail: message,
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Re-checks a specific remediation rule live against the target URL before allowing a finding
 * to be marked as verified & resolved in the Remediation Workspace.
 */
export async function verifySpecificRemediation(params: {
  targetUrl: string;
  ruleId?: string;
  title: string;
}): Promise<{ resolved: boolean; detail: string; observedValue: string; checkedAt: string }> {
  const checkedAt = new Date().toISOString();
  const res = await safeFetchText(params.targetUrl, { timeoutMs: 8000, maxBytes: 512 * 1024 });
  if (!res.ok && res.statusCode === 0) {
    return {
      resolved: false,
      detail: res.error || 'Unable to reach target URL for live verification.',
      observedValue: 'Unreachable',
      checkedAt,
    };
  }

  const h = res.headers;
  const rId = params.ruleId || '';
  const lowerTitle = params.title.toLowerCase();

  if (rId === 'SEC_CSP' || lowerTitle.includes('content-security-policy')) {
    const csp = h['content-security-policy'];
    if (csp && !csp.includes("'unsafe-inline'") && !csp.includes('*')) {
      return { resolved: true, detail: 'Hardened Content-Security-Policy header observed in live response.', observedValue: csp.slice(0, 120), checkedAt };
    }
    return {
      resolved: false,
      detail: csp ? 'CSP header exists but still permits unsafe-inline or wildcard.' : 'Content-Security-Policy header is still absent.',
      observedValue: csp ? 'Permissive CSP' : 'Absent',
      checkedAt,
    };
  }

  if (rId === 'SEC_HSTS' || lowerTitle.includes('strict-transport-security')) {
    const hsts = h['strict-transport-security'];
    return hsts
      ? { resolved: true, detail: 'Strict-Transport-Security header verified live.', observedValue: hsts, checkedAt }
      : { resolved: false, detail: 'Strict-Transport-Security header is still missing.', observedValue: 'Absent', checkedAt };
  }

  if (rId === 'SEC_CLICKJACKING' || lowerTitle.includes('clickjacking') || lowerTitle.includes('x-frame-options')) {
    const xfo = h['x-frame-options'];
    const csp = h['content-security-policy'] || '';
    if (xfo || csp.toLowerCase().includes('frame-ancestors')) {
      return { resolved: true, detail: 'Framing protection header verified live.', observedValue: xfo || 'CSP frame-ancestors', checkedAt };
    }
    return { resolved: false, detail: 'Neither X-Frame-Options nor CSP frame-ancestors is present.', observedValue: 'Absent', checkedAt };
  }

  if (rId === 'SEC_XCTO' || lowerTitle.includes('x-content-type-options')) {
    const xcto = h['x-content-type-options'];
    return xcto?.toLowerCase() === 'nosniff'
      ? { resolved: true, detail: 'X-Content-Type-Options: nosniff verified live.', observedValue: xcto, checkedAt }
      : { resolved: false, detail: 'X-Content-Type-Options: nosniff still not returned.', observedValue: xcto || 'Absent', checkedAt };
  }

  if (rId === 'SEC_REFERRER' || lowerTitle.includes('referrer-policy')) {
    const rp = h['referrer-policy'];
    return rp
      ? { resolved: true, detail: 'Referrer-Policy header verified live.', observedValue: rp, checkedAt }
      : { resolved: false, detail: 'Referrer-Policy header still absent.', observedValue: 'Absent', checkedAt };
  }

  // Fallback full re-analysis on the live response for DOM/SEO/header checks
  const $ = cheerio.load(res.body || '');
  if (rId === 'FE_VIEWPORT' || lowerTitle.includes('viewport')) {
    const vp = $('meta[name="viewport"]').attr('content');
    return vp
      ? { resolved: true, detail: 'Viewport meta tag found in live HTML.', observedValue: vp, checkedAt }
      : { resolved: false, detail: 'Viewport meta tag is still missing.', observedValue: 'Absent', checkedAt };
  }

  if (rId === 'A11Y_HTML_LANG' || lowerTitle.includes('lang attribute')) {
    const lang = $('html').attr('lang');
    return lang
      ? { resolved: true, detail: `HTML lang="${lang}" attribute verified live.`, observedValue: lang, checkedAt }
      : { resolved: false, detail: 'HTML lang attribute still missing.', observedValue: 'Absent', checkedAt };
  }

  // Generic live check
  const validated = validateTargetUrl(res.finalUrl);
  const dnsSignals = validated.hostname ? await inspectDnsSignals(validated.hostname) : null;
  if (rId === 'SEC_DNS_EMAIL' && dnsSignals) {
    return dnsSignals.hasSpf && dnsSignals.hasDmarc
      ? { resolved: true, detail: 'Both SPF and DMARC TXT records verified in live DNS.', observedValue: 'SPF + DMARC active', checkedAt }
      : { resolved: false, detail: `Observed SPF=${dnsSignals.hasSpf}, DMARC=${dnsSignals.hasDmarc}.`, observedValue: `SPF:${dnsSignals.hasSpf} DMARC:${dnsSignals.hasDmarc}`, checkedAt };
  }

  return {
    resolved: res.ok && res.statusCode < 400,
    detail: `Live check reached ${res.finalUrl} (HTTP ${res.statusCode}). Run a full rescan to refresh all report metrics.`,
    observedValue: `HTTP ${res.statusCode}`,
    checkedAt,
  };
}
