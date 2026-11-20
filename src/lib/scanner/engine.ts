import dns from 'node:dns/promises';
import tls from 'node:tls';
import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import type {
  DnsSignals,
  LighthouseMetrics,
  ScanCoverage,
  ScanMetrics,
  ScanStatus,
  TlsCertificateInfo,
  WebsiteScan,
} from '../../types/audit';
import { analyzeAllCategories, buildExecutiveSummary } from './analyzer';
import { resolveAndVerifyHost, validateTargetUrl } from './ssrf';

export interface ScanJobState {
  scanId: string;
  ownerUid: string;
  targetUrl: string;
  normalizedDomain: string;
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

const SCANNER_VERSION = 'originsec-engine-1.0';
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
const REQUEST_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.bin', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.apk', '.ipa', '.zip', '.tar', '.gz', '.iso',
]);

export function getJobState(scanId: string): ScanJobState | undefined {
  return activeJobs.get(scanId);
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
 * and strict timeout & response size caps. Never forwards client cookies/auth tokens.
 */
export async function safeFetchText(
  rawUrl: string,
  options: { timeoutMs?: number; maxBytes?: number; maxRedirects?: number } = {}
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

    // Reject executable file extensions upfront
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

    // DNS & SSRF check before every hop
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
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'OriginSec-Auditor/1.0 (+https://originsec.app)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5',
          'Accept-Encoding': 'gzip, deflate, br',
        },
      });
      const ttfbMs = Math.round(performance.now() - reqStart);

      // Handle redirects safely
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

      // Normalize headers
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

      // Bounded stream read
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

export async function inspectTlsCertificate(hostname: string, verifiedIp?: string): Promise<TlsCertificateInfo> {
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
        error: err.message,
      });
    });
  });
}

export async function inspectDnsSignals(hostname: string): Promise<DnsSignals> {
  try {
    const [aRes, aaaaRes, mxRes, txtRes, caaRes, dmarcRes] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
      dns.resolveMx(hostname),
      dns.resolveTxt(hostname),
      dns.resolveCaa(hostname),
      dns.resolveTxt(`_dmarc.${hostname}`),
    ]);

    const aRecords = aRes.status === 'fulfilled' ? aRes.value : [];
    const aaaaRecords = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
    const mxRecords = mxRes.status === 'fulfilled' ? mxRes.value.map((m) => `${m.exchange} (${m.priority})`) : [];
    const txtRecords = txtRes.status === 'fulfilled' ? txtRes.value.map((parts) => parts.join('')) : [];
    const caaRecords = caaRes.status === 'fulfilled' ? caaRes.value.map((c) => `${c.issue || c.issuewild || c.iodef || 'policy'}`) : [];
    const dmarcTxt = dmarcRes.status === 'fulfilled' ? dmarcRes.value.map((p) => p.join('')) : [];

    const hasSpf = txtRecords.some((t) => t.toLowerCase().startsWith('v=spf1'));
    const dmarcRecord = dmarcTxt.find((t) => t.toLowerCase().startsWith('v=dmarc1'));

    return {
      resolved: aRecords.length > 0 || aaaaRecords.length > 0,
      aRecords,
      aaaaRecords,
      mxRecords,
      txtRecords: txtRecords.slice(0, 8),
      caaRecords,
      hasSpf,
      hasDmarc: Boolean(dmarcRecord),
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
      hasSpf: false,
      hasDmarc: false,
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
  maxPages?: number;
  crawlDepth?: number;
  isDomainVerified?: boolean;
}): ScanJobState {
  const scanId = `scan_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const validated = validateTargetUrl(params.targetUrl);
  const normalizedUrl = validated.normalizedUrl || params.targetUrl;
  const hostname = validated.hostname || 'unknown';

  const job: ScanJobState = {
    scanId,
    ownerUid: params.ownerUid,
    targetUrl: normalizedUrl,
    normalizedDomain: hostname,
    status: 'queued',
    currentStage: 'Validating target',
    progressPercent: 5,
    cancelled: false,
    stagesLog: [],
    createdAtMs: Date.now(),
  };

  activeJobs.set(scanId, job);

  // Prune stale jobs > 1 hour old
  for (const [id, existing] of activeJobs.entries()) {
    if (Date.now() - existing.createdAtMs > 60 * 60 * 1000) {
      activeJobs.delete(id);
    }
  }

  // Execute asynchronously with bounded resources
  void executeScanJob(job, {
    maxPages: Math.min(20, Math.max(1, params.maxPages ?? 8)),
    crawlDepth: Math.min(2, Math.max(0, params.crawlDepth ?? 1)),
    isDomainVerified: Boolean(params.isDomainVerified),
  });

  return job;
}

async function executeScanJob(
  job: ScanJobState,
  opts: { maxPages: number; crawlDepth: number; isDomainVerified: boolean }
) {
  const { scanId, ownerUid } = job;
  const startedAt = new Date().toISOString();

  try {
    job.status = 'running';
    updateJob(scanId, 'Validating target', 8, `Validated syntax and port constraints for ${job.targetUrl}`);

    const validated = validateTargetUrl(job.targetUrl);
    if (!validated.valid || !validated.normalizedUrl || !validated.hostname) {
      throw new Error(validated.error || 'Invalid target URL');
    }
    if (job.cancelled) return;

    // 1. DNS Check & SSRF Verification
    updateJob(scanId, 'Checking DNS', 16);
    const resolution = await resolveAndVerifyHost(validated.hostname);
    if (!resolution.safe) {
      throw new Error(resolution.error || 'Target host failed SSRF IP verification.');
    }
    const dnsSignals = await inspectDnsSignals(validated.hostname);
    updateJob(
      scanId,
      'Checking DNS',
      24,
      `Resolved ${resolution.addresses.length} public IP(s); SPF=${dnsSignals.hasSpf}, DMARC=${dnsSignals.hasDmarc}`
    );
    if (job.cancelled) return;

    // 2. TLS & HTTP -> HTTPS Redirect Check
    updateJob(scanId, 'Checking HTTPS/TLS', 32);
    const isInitialHttps = validated.protocol === 'https:';
    let httpRedirectsToHttps: boolean | null = null;
    try {
      const httpProbe = await safeFetchText(`http://${validated.hostname}/`, { timeoutMs: 4000, maxBytes: 16384 });
      httpRedirectsToHttps = httpProbe.finalUrl.startsWith('https://');
    } catch {
      httpRedirectsToHttps = null;
    }

    const tlsInfo = await inspectTlsCertificate(validated.hostname, resolution.primaryAddress);
    updateJob(
      scanId,
      'Checking HTTPS/TLS',
      42,
      tlsInfo.available
        ? `TLS ${tlsInfo.protocol || 'verified'}, issuer: ${tlsInfo.issuer || 'CA'}`
        : 'TLS certificate metadata unavailable'
    );
    if (job.cancelled) return;

    // 3. Fetch Homepage & Inspect Response Headers
    updateJob(scanId, 'Inspecting response headers', 52);
    const homeResponse = await safeFetchText(validated.normalizedUrl, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      maxBytes: MAX_BODY_BYTES,
    });

    if (!homeResponse.ok && homeResponse.statusCode === 0) {
      throw new Error(homeResponse.error || 'Unable to connect to target website.');
    }
    updateJob(
      scanId,
      'Inspecting response headers',
      60,
      `HTTP ${homeResponse.statusCode} in ${homeResponse.ttfbMs} ms TTFB (${homeResponse.redirectCount} redirects)`
    );
    if (job.cancelled) return;

    // 4. Analyze Homepage + Auxiliary Files (robots.txt, security.txt, sitemap.xml)
    updateJob(scanId, 'Analysing homepage', 68);
    const origin = new URL(homeResponse.finalUrl).origin;
    const [robotsRes, secTxtRes, sitemapRes] = await Promise.all([
      safeFetchText(`${origin}/robots.txt`, { timeoutMs: 4000, maxBytes: 65536 }),
      safeFetchText(`${origin}/.well-known/security.txt`, { timeoutMs: 4000, maxBytes: 65536 }),
      safeFetchText(`${origin}/sitemap.xml`, { timeoutMs: 4000, maxBytes: 131072 }),
    ]);

    const hasRobotsTxt = robotsRes.ok && robotsRes.statusCode === 200;
    const disallowedPaths = hasRobotsTxt ? parseDisallowedRobots(robotsRes.body) : [];
    const hasSecurityTxt =
      secTxtRes.ok &&
      secTxtRes.statusCode === 200 &&
      secTxtRes.body.toLowerCase().includes('contact:');
    const hasSitemapXml = sitemapRes.ok && sitemapRes.statusCode === 200;

    // 5. Inspect Linked Same-Origin Pages (Polite Bounded Crawl)
    updateJob(scanId, 'Inspecting linked pages', 76);
    const $home = cheerio.load(homeResponse.body || '');
    const mixedContentUrls: string[] = [];
    if (homeResponse.finalUrl.startsWith('https://')) {
      $home('script[src], link[href], img[src], iframe[src]').each((_, el) => {
        const src = $home(el).attr('src') || $home(el).attr('href') || '';
        if (src.trim().toLowerCase().startsWith('http://')) {
          mixedContentUrls.push(src.trim());
        }
      });
    }

    const internalCandidates = new Set<string>();
    if (opts.crawlDepth > 0 && opts.maxPages > 1) {
      $home('a[href]').each((_, el) => {
        const href = $home(el).attr('href')?.trim();
        if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) {
          return;
        }
        try {
          const resolvedUrl = new URL(href, homeResponse.finalUrl);
          if (resolvedUrl.origin === origin && resolvedUrl.toString() !== homeResponse.finalUrl) {
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
    const brokenInternalLinks: Array<{ url: string; status: number | string }> = [];
    const candidateList = Array.from(internalCandidates).slice(0, Math.max(0, opts.maxPages - 1));

    // Polite concurrency (batch of 3)
    for (let i = 0; i < candidateList.length; i += 3) {
      if (job.cancelled) return;
      const batch = candidateList.slice(i, i + 3);
      const batchResults = await Promise.all(
        batch.map(async (linkUrl) => {
          const res = await safeFetchText(linkUrl, { timeoutMs: 5000, maxBytes: 512 * 1024 });
          return { linkUrl, res };
        })
      );
      for (const { linkUrl, res } of batchResults) {
        pagesScanned++;
        if (!res.ok || res.statusCode >= 400) {
          brokenInternalLinks.push({ url: linkUrl, status: res.statusCode || res.error || 'error' });
        }
      }
    }
    updateJob(
      scanId,
      'Inspecting linked pages',
      84,
      `Inspected ${pagesScanned} same-origin page(s); ${brokenInternalLinks.length} broken link(s) detected`
    );
    if (job.cancelled) return;

    // 6. Frontend Structure & Performance Analysis
    updateJob(scanId, 'Analysing performance', 90);
    const lighthouse = await fetchPageSpeedInsights(homeResponse.finalUrl);
    updateJob(
      scanId,
      'Evaluating content quality',
      94,
      lighthouse.available
        ? `PageSpeed Insights Performance ${lighthouse.performanceScore}/100`
        : 'Static HTML performance & content signals evaluated'
    );

    const coverage: ScanCoverage = {
      pagesScanned,
      maxPages: opts.maxPages,
      crawlDepth: opts.crawlDepth,
      httpsVerified: homeResponse.finalUrl.startsWith('https://'),
      dnsVerified: dnsSignals.resolved,
      tlsVerified: tlsInfo.available,
      lighthouseVerified: lighthouse.available,
      apiVerified: opts.isDomainVerified,
      databaseVerified: false,
      hostingVerified: false,
      backupVerified: false,
    };

    // 7. Preparing Findings & Generating Report
    updateJob(scanId, 'Preparing findings', 97);
    const analysis = analyzeAllCategories(
      {
        scanId,
        ownerUid,
        targetUrl: job.targetUrl,
        finalUrl: homeResponse.finalUrl,
        isHttps: homeResponse.finalUrl.startsWith('https://'),
        httpRedirectsToHttps,
        headers: homeResponse.headers,
        setCookieHeaders: homeResponse.setCookieHeaders,
        tls: tlsInfo,
        dns: dnsSignals,
        mixedContentUrls,
        hasSecurityTxt,
        hasRobotsTxt,
        hasSitemapXml,
      },
      {
        scanId,
        ownerUid,
        targetUrl: job.targetUrl,
        finalUrl: homeResponse.finalUrl,
        html: homeResponse.body,
        htmlSizeBytes: Buffer.byteLength(homeResponse.body || '', 'utf8'),
        ttfbMs: homeResponse.ttfbMs,
        totalResponseTimeMs: homeResponse.totalMs,
        statusCode: homeResponse.statusCode,
        redirectCount: homeResponse.redirectCount,
        headers: homeResponse.headers,
        brokenInternalLinks,
        brokenImages: [],
        lighthouse,
      },
      coverage
    );

    const completedAt = new Date().toISOString();
    const partial = !homeResponse.ok || (!tlsInfo.available && isInitialHttps);
    const finalStatus: ScanStatus = partial && homeResponse.statusCode >= 500 ? 'partially_completed' : 'completed';

    const summary = buildExecutiveSummary(job.normalizedDomain, analysis.scores, analysis.findings, coverage);

    const metrics: ScanMetrics = {
      ttfbMs: homeResponse.ttfbMs,
      totalResponseTimeMs: homeResponse.totalMs,
      statusCode: homeResponse.statusCode,
      redirectCount: homeResponse.redirectCount,
      finalUrl: homeResponse.finalUrl,
      htmlSizeBytes: Buffer.byteLength(homeResponse.body || '', 'utf8'),
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
      compression: homeResponse.headers['content-encoding'] || null,
      serverBanner: homeResponse.headers['server'] || null,
      tls: tlsInfo,
      dns: dnsSignals,
      lighthouse,
    };

    updateJob(scanId, 'Generating report', 100, 'Audit report compiled from verified evidence.');

    const finalScan: WebsiteScan = {
      scanId,
      ownerUid,
      targetUrl: job.targetUrl,
      normalizedDomain: job.normalizedDomain,
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
