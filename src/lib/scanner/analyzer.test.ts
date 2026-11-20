import test from 'node:test';
import assert from 'node:assert/strict';
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
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
