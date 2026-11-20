import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeAllCategories,
  buildExecutiveSummary,
  calculateCategoryScores,
  redactCookieHeader,
} from './analyzer';
import type { ScanCoverage } from '../../types/audit';

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
  const coverage: ScanCoverage = {
    pagesScanned: 1,
    maxPages: 20,
    crawlDepth: 2,
    httpsVerified: true,
    dnsVerified: true,
    tlsVerified: true,
    lighthouseVerified: false,
    apiVerified: false,
    databaseVerified: false,
    hostingVerified: false,
    backupVerified: false,
  };

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

  const summary = buildExecutiveSummary('example.com', result.scores, result.findings, coverage);
  assert.ok(summary.includes('example.com'));
  assert.ok(summary.includes('Database, hosting, and backup configurations remain unverified'));

  // Confirm zero-assessed-check categories return null
  const emptyScores = calculateCategoryScores([]);
  assert.equal(emptyScores.security, null);
  assert.equal(emptyScores.overall, null);
});
