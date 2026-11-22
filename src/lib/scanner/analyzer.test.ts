import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import {
  analyzeAllCategories,
  buildExecutiveSummary,
  calculateCategoryScores,
  redactCookieHeader,
} from './analyzer';
import { compareTwoScans } from './profiles';
import { runScanJobAndWait } from './engine';
import { createApiApp } from '../server/app';
import { buildScanHistoryCsvContent } from '../export/exporters';
import { buildWebsiteScoreTrends } from './trends';
import { extractGroundingSources } from '../server/gemini';
import { verifyFirebaseJwtWithCerts } from '../server/auth';
import type { ScanCoverage, WebsiteScan } from '../../types/audit';

function makeCoverage(): ScanCoverage {
  return {
    pagesScanned: 1,
    maxPages: 8,
    crawlDepth: 1,
    scanProfile: 'standard',
    httpsVerified: true,
    dnsVerified: true,
    tlsVerified: true,
    lighthouseVerified: false,
    apiVerified: false,
    databaseVerified: false,
    hostingVerified: false,
    backupVerified: false,
  };
}

test('redactCookieHeader strips secret values and inspects flags', () => {
  const res = redactCookieHeader('session_id=super_secret_token_12345; Path=/; HttpOnly; SameSite=Lax');
  assert.equal(res.name, 'session_id');
  assert.equal(res.hasHttpOnly, true);
  assert.equal(res.hasSecure, false);
  assert.equal(res.sameSite, 'Lax');
  assert.equal(res.sanitizedSummary.includes('super_secret_token_12345'), false);
  assert.equal(res.sanitizedSummary.includes('[REDACTED]'), true);
});

test('analyzeAllCategories computes deterministic findings and never assigns passing scores to untested categories', () => {
  const coverage = makeCoverage();

  const result = analyzeAllCategories(
    {
      scanId: 'scan_test_1',
      ownerUid: 'user_1',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      isHttps: true,
      httpRedirectsToHttps: true,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        'content-encoding': 'gzip',
        'cache-control': 'public, max-age=300',
      },
      setCookieHeaders: ['sid=secret123; Path=/; Secure; HttpOnly; SameSite=Strict'],
      tls: {
        available: true,
        authorized: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'DigiCert',
        subject: 'example.com',
        validFrom: '2026-01-01T00:00:00Z',
        validTo: '2027-01-01T00:00:00Z',
        daysRemaining: 120,
        hostnameMatch: true,
      },
      dns: {
        resolved: true,
        aRecords: ['93.184.216.34'],
        aaaaRecords: [],
        mxRecords: ['mail.example.com'],
        txtRecords: ['v=spf1 -all'],
        caaRecords: [],
        hasSpf: true,
        hasDmarc: false,
      },
      mixedContentUrls: [],
      hasSecurityTxt: false,
      hasRobotsTxt: true,
      hasSitemapXml: true,
    },
    {
      scanId: 'scan_test_1',
      ownerUid: 'user_1',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      html: '<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body><main><h1>Example</h1><a href="/start">Get started</a></main></body></html>',
      htmlSizeBytes: 220,
      ttfbMs: 180,
      warmTtfbMs: 170,
      totalResponseTimeMs: 240,
      statusCode: 200,
      redirectCount: 0,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        'content-encoding': 'gzip',
        'cache-control': 'public, max-age=300',
      },
      brokenInternalLinks: [],
      brokenImages: [],
      lighthouse: {
        available: false,
        source: 'not_configured',
        strategy: 'mobile',
        dataType: 'none',
      },
    },
    coverage
  );

  assert.ok(result.findings.some((f) => f.title.includes('Missing Content-Security-Policy')));
  assert.ok(result.findings.some((f) => f.title === 'Database Security Not Assessed from Public URL' && f.status === 'not_assessed'));
  assert.ok(result.findings.some((f) => f.title === 'Backup Status Unavailable' && f.status === 'not_assessed'));
  assert.ok(result.scores.security !== null && result.scores.security < 100);
  assert.ok(result.scores.backend !== null && result.scores.backend >= 90);
  // Without PageSpeed / browser contrast verification, performance and accessibility must not claim 100/100
  assert.ok(result.scores.performance != null && result.scores.performance <= 85);
  assert.ok(result.scores.accessibility != null && result.scores.accessibility <= 88);
  assert.ok(typeof result.postureFingerprint === 'string' && result.postureFingerprint.length >= 8);

  const summary = buildExecutiveSummary('example.com', result.scores, result.findings, coverage);
  assert.ok(summary.includes('example.com'));
  assert.ok(summary.includes('Database, hosting, and backup configurations remain unverified'));

  // Confirm zero-assessed-check categories return null
  const emptyScores = calculateCategoryScores([]);
  assert.equal(emptyScores.security, null);
  assert.equal(emptyScores.overall, null);
});

test('analyzeAllCategories produces identical scores, findings, and postureFingerprint regardless of DNS/cookie order or minor warm TTFB jitter', () => {
  const coverage = makeCoverage();
  const baseHtml = '<!doctype html><html lang="en"><head><title>OriginSec Deterministic Test</title><meta name="description" content="A thorough deterministic website security and performance test page for verification."><link rel="canonical" href="https://example.com/"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body><main><h1>Welcome</h1><a href="/contact">Contact us</a></main></body></html>';

  const run1 = analyzeAllCategories(
    {
      scanId: 'scan_a',
      ownerUid: 'desktop_user',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      isHttps: true,
      httpRedirectsToHttps: null, // Port 80 timeout shouldn't flip scores inconsistently vs true
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'x-content-type-options': 'nosniff',
        'content-encoding': 'br',
        'cache-control': 'public, max-age=600',
      },
      setCookieHeaders: [
        'b_cookie=val2; HttpOnly; SameSite=Lax',
        'a_cookie=val1; Secure; HttpOnly',
      ],
      tls: {
        available: true,
        authorized: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'Let\'s Encrypt',
        subject: 'example.com',
        validFrom: '2026-01-01T00:00:00Z',
        validTo: '2027-01-01T00:00:00Z',
        daysRemaining: 80,
        hostnameMatch: true,
      },
      dns: {
        resolved: true,
        aRecords: ['93.184.216.34', '1.1.1.1'],
        aaaaRecords: ['2606:2800:220:1::1'],
        mxRecords: ['mx2.example.com', 'mx1.example.com'],
        txtRecords: ['v=spf1 -all'],
        caaRecords: ['issue "letsencrypt.org"'],
        hasSpf: true,
        hasDmarc: true,
      },
      mixedContentUrls: ['http://cdn.example.com/b.js', 'http://cdn.example.com/a.js'],
      hasSecurityTxt: true,
      hasRobotsTxt: true,
      hasSitemapXml: true,
    },
    {
      scanId: 'scan_a',
      ownerUid: 'desktop_user',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      html: baseHtml,
      htmlSizeBytes: baseHtml.length,
      ttfbMs: 210,
      warmTtfbMs: 180,
      totalResponseTimeMs: 310,
      statusCode: 200,
      redirectCount: 0,
      headers: { 'content-encoding': 'br', 'cache-control': 'public, max-age=600' },
      brokenInternalLinks: [],
      brokenImages: [],
      lighthouse: { available: false, source: 'not_configured', strategy: 'mobile', dataType: 'none' },
    },
    coverage
  );

  // Run 2 simulates reversed DNS arrays, reversed cookies, reversed mixedContentUrls, and slight sub-1s TTFB variance
  const run2 = analyzeAllCategories(
    {
      scanId: 'scan_b',
      ownerUid: 'mobile_user',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      isHttps: true,
      httpRedirectsToHttps: null,
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'x-content-type-options': 'nosniff',
        'content-encoding': 'br',
        'cache-control': 'public, max-age=600',
      },
      setCookieHeaders: [
        'a_cookie=different_secret_999; Secure; HttpOnly',
        'b_cookie=different_secret_888; HttpOnly; SameSite=Lax',
      ],
      tls: {
        available: true,
        authorized: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'Let\'s Encrypt',
        subject: 'example.com',
        validFrom: '2026-01-01T00:00:00Z',
        validTo: '2027-01-01T00:00:00Z',
        daysRemaining: 80,
        hostnameMatch: true,
      },
      dns: {
        resolved: true,
        aRecords: ['1.1.1.1', '93.184.216.34'],
        aaaaRecords: ['2606:2800:220:1::1'],
        mxRecords: ['mx1.example.com', 'mx2.example.com'],
        txtRecords: ['v=spf1 -all'],
        caaRecords: ['issue "letsencrypt.org"'],
        hasSpf: true,
        hasDmarc: true,
      },
      mixedContentUrls: ['http://cdn.example.com/a.js', 'http://cdn.example.com/b.js'],
      hasSecurityTxt: true,
      hasRobotsTxt: true,
      hasSitemapXml: true,
    },
    {
      scanId: 'scan_b',
      ownerUid: 'mobile_user',
      targetUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      html: baseHtml,
      htmlSizeBytes: baseHtml.length,
      ttfbMs: 390,
      warmTtfbMs: 240,
      totalResponseTimeMs: 490,
      statusCode: 200,
      redirectCount: 0,
      headers: { 'content-encoding': 'br', 'cache-control': 'public, max-age=600' },
      brokenInternalLinks: [],
      brokenImages: [],
      lighthouse: { available: false, source: 'not_configured', strategy: 'mobile', dataType: 'none' },
    },
    coverage
  );

  assert.deepEqual(run1.scores, run2.scores);
  assert.equal(run1.postureFingerprint, run2.postureFingerprint);
  assert.equal(run1.findings.length, run2.findings.length);
  assert.deepEqual(
    run1.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      evidence: f.ruleId === 'BE_TTFB' ? '[live-measured-ttfb]' : f.evidence,
    })),
    run2.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      evidence: f.ruleId === 'BE_TTFB' ? '[live-measured-ttfb]' : f.evidence,
    }))
  );

  // compareTwoScans should confirm identical posture
  const scanStub1 = {
    scanId: 's1',
    normalizedDomain: 'example.com',
    postureFingerprint: run1.postureFingerprint,
    scores: run1.scores,
    findings: run1.findings,
    metrics: { domNodeCount: run1.domStats.domNodeCount, scriptCount: run1.domStats.scriptCount, ttfbMs: 210 },
  } as unknown as WebsiteScan;
  const scanStub2 = {
    scanId: 's2',
    normalizedDomain: 'example.com',
    postureFingerprint: run2.postureFingerprint,
    scores: run2.scores,
    findings: run2.findings,
    metrics: { domNodeCount: run2.domStats.domNodeCount, scriptCount: run2.domStats.scriptCount, ttfbMs: 240 },
  } as unknown as WebsiteScan;

  const diff = compareTwoScans(scanStub1, scanStub2);
  assert.equal(diff.identicalPosture, true);
  assert.equal(diff.newlyDiscovered.length, 0);
  assert.equal(diff.resolvedFindings.length, 0);
});

test('runScanJobAndWait rejects private IP targets cleanly via SSRF policy', async () => {
  const job = await runScanJobAndWait({
    ownerUid: 'guest_test',
    targetUrl: 'http://127.0.0.1/',
    serverlessBudgetMs: 4000,
  });
  assert.equal(job.status, 'failed');
  assert.ok(job.error && job.error.length > 0);
});

test('createApiApp enforces SSRF rejection, protected admin/cron/remediation gates, and COOP popup header', async () => {
  const app = createApiApp();
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    // SSRF target rejected
    const ssrfRes = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'http://127.0.0.1/', authorizedConfirmed: true, sync: true }),
    });
    assert.equal(ssrfRes.status, 400);
    assert.equal(ssrfRes.headers.get('cross-origin-opener-policy'), 'same-origin-allow-popups');

    // Admin overview strictly blocked for unauthenticated / non-founder requests
    const adminRes = await fetch(`${baseUrl}/api/admin/overview`);
    assert.equal(adminRes.status, 403);

    // Cron monitoring strictly returns 401 without CRON_SECRET
    const cronRes = await fetch(`${baseUrl}/api/cron/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: ['https://example.com'] }),
    });
    assert.equal(cronRes.status, 401);

    // Remediation verify requires auth
    const remRes = await fetch(`${baseUrl}/api/remediation/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'https://example.com', title: 'Missing CSP' }),
    });
    assert.equal(remRes.status, 401);

    // Authenticated-looking Bearer token must not crash Express handler even if invalid
    const authedScanRes = await fetch(`${baseUrl}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer invalid.jwt.token' },
      body: JSON.stringify({ targetUrl: 'http://127.0.0.1/', authorizedConfirmed: true, sync: true }),
    });
    assert.equal(authedScanRes.status, 400);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('buildScanHistoryCsvContent formats multi-row scan history with escaped CSV cells', () => {
  const sample = [
    {
      scanId: 'scan_1',
      normalizedDomain: 'example.com',
      targetUrl: 'https://example.com/',
      scanProfile: 'standard',
      status: 'completed',
      postureFingerprint: 'abcd1234',
      scores: { security: 65, frontend: 82, backend: 90, engagement: 74, overall: 78, seo: 75, accessibility: 84, performance: 85 },
      findingsCount: { critical: 0, high: 2, medium: 3, low: 4, informational: 2, passed: 5 },
      coverage: { pagesScanned: 4 },
      metrics: { ttfbMs: 145 },
      startedAt: '2026-11-20T10:00:00.000Z',
      completedAt: '2026-11-20T10:00:04.000Z',
    },
  ] as unknown as WebsiteScan[];

  const csv = buildScanHistoryCsvContent(sample);
  const lines = csv.split('\r\n');
  assert.equal(lines.length, 2);
  assert.ok(lines[0].includes('"Scan ID","Domain","Target URL"'));
  assert.ok(lines[1].includes('"scan_1","example.com","https://example.com/"'));
  assert.ok(lines[1].includes('"78","65","82","90","74"'));
});

test('buildWebsiteScoreTrends returns last 5 scans chronologically for selected website with security delta', () => {
  const makeStub = (id: string, domain: string, sec: number, overall: number, iso: string) =>
    ({
      scanId: id,
      normalizedDomain: domain,
      status: 'completed',
      startedAt: iso,
      scores: { security: sec, frontend: 80, backend: 80, engagement: 80, overall },
    }) as unknown as WebsiteScan;

  const scans = [
    makeStub('s7', 'other.dev', 95, 92, '2026-11-22T07:00:00Z'),
    makeStub('s6', 'example.com', 84, 86, '2026-11-22T06:00:00Z'),
    makeStub('s5', 'example.com', 78, 82, '2026-11-22T05:00:00Z'),
    makeStub('s4', 'example.com', 72, 76, '2026-11-22T04:00:00Z'),
    makeStub('s3', 'example.com', 66, 70, '2026-11-22T03:00:00Z'),
    makeStub('s2', 'example.com', 60, 68, '2026-11-22T02:00:00Z'),
    makeStub('s1', 'example.com', 50, 60, '2026-11-22T01:00:00Z'),
  ];

  const trend = buildWebsiteScoreTrends(scans, 'example.com', 5);
  assert.equal(trend.points.length, 5);
  assert.deepEqual(
    trend.points.map((p) => p.scanId),
    ['s2', 's3', 's4', 's5', 's6']
  );
  assert.equal(trend.latestSecurity, 84);
  assert.equal(trend.securityDelta, 6);
  assert.equal(trend.overallDelta, 4);
});

test('extractGroundingSources deduplicates verified HTTP/HTTPS links and filters unsafe URIs', () => {
  const sources = extractGroundingSources([
    { web: { uri: 'https://owasp.org/www-project-secure-headers/', title: 'OWASP Secure Headers' } },
    { web: { uri: 'https://owasp.org/www-project-secure-headers/', title: 'Duplicate' } },
    { web: { uri: 'javascript:alert(1)', title: 'Bad URI' } },
    { web: { uri: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP', title: 'MDN CSP Guide' } },
  ]);
  assert.equal(sources.length, 2);
  assert.equal(sources[0].title, 'OWASP Secure Headers');
  assert.equal(sources[1].uri, 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP');
});

test('verifyFirebaseJwtWithCerts validates RS256 Firebase JWT claims without jwks-rsa/jose', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const signJwt = (payload: Record<string, unknown>, kid = 'test-key-1') => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(`${header}.${body}`);
    signer.end();
    const signature = signer.sign(privateKey).toString('base64url');
    return `${header}.${body}.${signature}`;
  };

  const now = 1_800_000_000;
  const projectId = 'cool-proposal-1c62s';
  const certs = { 'test-key-1': publicKey };

  const validToken = signJwt({
    aud: projectId,
    iss: `https://securetoken.google.com/${projectId}`,
    sub: 'uid_abc_123',
    email: 'adityaair1.2029@gmail.com',
    email_verified: true,
    iat: now - 60,
    auth_time: now - 60,
    exp: now + 3600,
  });

  const verified = verifyFirebaseJwtWithCerts(validToken, projectId, certs, now);
  assert.deepEqual(verified, {
    uid: 'uid_abc_123',
    email: 'adityaair1.2029@gmail.com',
    emailVerified: true,
  });

  const expiredToken = signJwt({
    aud: projectId,
    iss: `https://securetoken.google.com/${projectId}`,
    sub: 'uid_abc_123',
    iat: now - 7200,
    auth_time: now - 7200,
    exp: now - 10,
  });
  assert.equal(verifyFirebaseJwtWithCerts(expiredToken, projectId, certs, now), null);

  const wrongAudToken = signJwt({
    aud: 'other-project',
    iss: 'https://securetoken.google.com/other-project',
    sub: 'uid_abc_123',
    iat: now - 60,
    auth_time: now - 60,
    exp: now + 3600,
  });
  assert.equal(verifyFirebaseJwtWithCerts(wrongAudToken, projectId, certs, now), null);

  const tamperedToken = `${validToken.slice(0, -4)}AAAA`;
  assert.equal(verifyFirebaseJwtWithCerts(tamperedToken, projectId, certs, now), null);
});

test('analyzeAllCategories detects exposed dotfiles via SEC_EXPOSED_SENSITIVE_PATHS and passes when blocked', () => {
  const coverage = makeCoverage();
  const baseFetch = {
    scanId: 'scan_sec_1',
    ownerUid: 'user_1',
    targetUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    html: '<!doctype html><html lang="en"><head><title>Sec Test</title></head><body><h1>Hello</h1></body></html>',
    htmlSizeBytes: 95,
    ttfbMs: 120,
    warmTtfbMs: 110,
    totalResponseTimeMs: 180,
    statusCode: 200,
    redirectCount: 0,
    headers: { 'content-type': 'text/html' },
    brokenInternalLinks: [],
    brokenImages: [],
    lighthouse: { available: false, source: 'not_configured' as const, strategy: 'mobile' as const, dataType: 'none' as const },
  };

  const makeSecInput = (sensitivePathsExposed: string[]) => ({
    scanId: 'scan_sec_1',
    ownerUid: 'user_1',
    targetUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    isHttps: true,
    httpRedirectsToHttps: true,
    headers: { 'content-type': 'text/html' },
    setCookieHeaders: [],
    tls: {
      available: true,
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      issuer: 'DigiCert',
      subject: 'example.com',
      validFrom: '2026-01-01T00:00:00Z',
      validTo: '2027-01-01T00:00:00Z',
      hostnameMatch: true,
      daysRemaining: 90,
    },
    dns: { resolved: true, aRecords: ['93.184.216.34'], aaaaRecords: [], mxRecords: [], txtRecords: [], caaRecords: [], hasSpf: true, hasDmarc: true },
    mixedContentUrls: [],
    hasSecurityTxt: true,
    hasRobotsTxt: true,
    hasSitemapXml: true,
    sensitivePathsExposed,
  });

  const exposed = analyzeAllCategories(makeSecInput(['/.env']), baseFetch, coverage);
  const exposedFinding = exposed.findings.find((f) => f.ruleId === 'SEC_EXPOSED_SENSITIVE_PATHS');
  assert.ok(exposedFinding);
  assert.equal(exposedFinding.severity, 'critical');
  assert.equal(exposedFinding.status, 'open');

  const clean = analyzeAllCategories(makeSecInput([]), baseFetch, coverage);
  const cleanFinding = clean.findings.find((f) => f.ruleId === 'SEC_EXPOSED_SENSITIVE_PATHS');
  assert.ok(cleanFinding);
  assert.equal(cleanFinding.severity, 'passed');
  assert.equal(cleanFinding.status, 'passed');
});

test('POST /api/scans/screenshot blocks private loopback targets via SSRF policy', async () => {
  const app = createApiApp();
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  try {
    const res = await fetch(`${baseUrl}/api/scans/screenshot`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'http://127.0.0.1/' }),
    });
    assert.equal(res.status, 400);
    const body = (await res.json()) as { available?: boolean; error?: string };
    assert.equal(body.available, false);
    assert.ok(typeof body.error === 'string' && body.error.length > 0);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});


