import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import type {
  CategoryScores,
  DnsSignals,
  ExtendedFrontendMetrics,
  FindingCategory,
  FindingsCount,
  LighthouseMetrics,
  PriorityGroup,
  ScanCoverage,
  ScanFinding,
  SeverityLevel,
  TlsCertificateInfo,
} from '../../types/audit';

export interface SecurityAnalysisInput {
  scanId: string;
  ownerUid: string;
  targetUrl: string;
  finalUrl: string;
  isHttps: boolean;
  httpRedirectsToHttps: boolean | null;
  headers: Record<string, string>;
  setCookieHeaders: string[];
  tls: TlsCertificateInfo;
  dns: DnsSignals;
  mixedContentUrls: string[];
  hasSecurityTxt: boolean;
  hasRobotsTxt: boolean;
  hasSitemapXml: boolean;
}

export interface FrontendAnalysisInput {
  scanId: string;
  ownerUid: string;
  targetUrl: string;
  finalUrl: string;
  html: string;
  htmlSizeBytes: number;
  ttfbMs: number;
  warmTtfbMs?: number;
  totalResponseTimeMs: number;
  statusCode: number;
  redirectCount: number;
  headers: Record<string, string>;
  brokenInternalLinks: Array<{ url: string; status: number | string }>;
  brokenImages: Array<{ url: string; status: number | string }>;
  lighthouse: LighthouseMetrics;
  hasRobotsTxt?: boolean;
  hasSitemapXml?: boolean;
  hasSecurityTxt?: boolean;
  crawledPagesMissingTitle?: string[];
  crawledPagesCount?: number;
}

function makeFinding(
  scanId: string,
  ownerUid: string,
  index: number,
  partial: Omit<ScanFinding, 'findingId' | 'scanId' | 'ownerUid' | 'createdAt'>
): ScanFinding {
  return {
    findingId: `${scanId}_f_${index}`,
    scanId,
    ownerUid,
    createdAt: new Date().toISOString(),
    ...partial,
  };
}

/**
 * Redacts cookie values while preserving attribute flags for security auditing.
 */
export function redactCookieHeader(rawCookie: string): {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite: string | null;
  hasExpiresOrMaxAge: boolean;
  sanitizedSummary: string;
} {
  const parts = rawCookie.split(';').map((p) => p.trim());
  const firstPair = parts[0] || '';
  const eqIdx = firstPair.indexOf('=');
  const name = eqIdx > 0 ? firstPair.slice(0, eqIdx).trim() : 'unnamed_cookie';
  const attrs = parts.slice(1).map((a) => a.toLowerCase());
  const hasSecure = attrs.includes('secure');
  const hasHttpOnly = attrs.includes('httponly');
  const sameSiteAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('samesite='));
  const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1]?.trim() || null : null;
  const hasExpiresOrMaxAge = attrs.some((a) => a.startsWith('expires=') || a.startsWith('max-age='));

  const flagList = [
    hasSecure ? 'Secure' : 'Missing Secure',
    hasHttpOnly ? 'HttpOnly' : 'Missing HttpOnly',
    sameSite ? `SameSite=${sameSite}` : 'Missing SameSite',
  ];

  return {
    name,
    hasSecure,
    hasHttpOnly,
    sameSite,
    hasExpiresOrMaxAge,
    sanitizedSummary: `${name}=[REDACTED]; ${flagList.join('; ')}`,
  };
}

export function computePostureFingerprint(findings: ScanFinding[], scores: CategoryScores): string {
  const canonical = findings
    .map((f) => `${f.category}|${f.ruleId || f.title}|${f.severity}|${f.status}|${f.observedValue}`)
    .sort()
    .join('\n');
  const payload = `${scores.security ?? 'n'}|${scores.frontend ?? 'n'}|${scores.backend ?? 'n'}|${scores.engagement ?? 'n'}\n${canonical}`;
  return crypto.createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

export function analyzeAllCategories(
  secInput: SecurityAnalysisInput,
  feInput: FrontendAnalysisInput,
  coverage: ScanCoverage
): {
  findings: ScanFinding[];
  scores: CategoryScores;
  findingsCount: FindingsCount;
  postureFingerprint: string;
  domStats: {
    domNodeCount: number;
    scriptCount: number;
    stylesheetCount: number;
    renderBlockingScripts: number;
    imageCount: number;
    imagesWithoutAlt: number;
    imagesWithoutDimensions: number;
    linkCount: number;
    headingCount: { h1: number; h2: number; h3: number };
    frontendDetails: ExtendedFrontendMetrics;
  };
} {
  const findings: ScanFinding[] = [];
  let idx = 1;
  const push = (partial: Omit<ScanFinding, 'findingId' | 'scanId' | 'ownerUid' | 'createdAt'>) => {
    findings.push(makeFinding(secInput.scanId, secInput.ownerUid, idx++, partial));
  };

  const h = secInput.headers;
  const getHeader = (name: string) => h[name.toLowerCase()];

  // Deterministic sorted DNS arrays
  const sortedA = [...(secInput.dns.aRecords || [])].sort();
  const sortedAAAA = [...(secInput.dns.aaaaRecords || [])].sort();
  const sortedCaa = [...(secInput.dns.caaRecords || [])].sort();
  const sortedMixed = [...(secInput.mixedContentUrls || [])].sort();
  const sortedBrokenLinks = [...(feInput.brokenInternalLinks || [])].sort((a, b) => a.url.localeCompare(b.url));

  // =========================================================================
  // 1. CYBERSECURITY & HARDENING
  // =========================================================================

  // 1a. HTTPS & Redirect Check
  if (!secInput.isHttps) {
    push({
      ruleId: 'SEC_HTTPS_ACTIVE',
      subCategory: 'tls',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Site Served Without HTTPS Encryption',
      severity: 'critical',
      priorityGroup: 'fix_immediately',
      description: 'The final destination URL is served over unencrypted HTTP instead of HTTPS.',
      evidence: `Final URL observed: ${secInput.finalUrl}`,
      affectedUrl: secInput.finalUrl,
      observedValue: 'http:// (unencrypted)',
      impact: 'All traffic between visitors and the origin server is exposed to eavesdropping and tampering on untrusted networks.',
      recommendation: 'Provision a TLS certificate and enforce HTTPS across all endpoints.',
      remediation: 'Redirect all port 80 HTTP requests to https:// with HTTP 301 and enable Strict-Transport-Security.',
      verification: 'Request http:// and confirm an immediate 301/308 redirect to https:// with a valid certificate.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEC_HTTPS_ACTIVE',
      subCategory: 'tls',
      confidence: 'verified_direct',
      category: 'security',
      title: 'HTTPS Transport Active',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'The target site serves its primary response over encrypted HTTPS.',
      evidence: `Final URL observed: ${secInput.finalUrl}`,
      affectedUrl: secInput.finalUrl,
      observedValue: 'https:// active',
      impact: 'Transport encryption protects confidentiality and integrity in transit.',
      recommendation: 'Maintain automated certificate renewal and monitor expiry.',
      remediation: 'No action required for basic HTTPS availability.',
      verification: 'Verify HTTPS remains the canonical protocol.',
      status: 'passed',
    });
  }

  if (secInput.httpRedirectsToHttps === false) {
    const host = new URL(secInput.finalUrl).hostname;
    push({
      ruleId: 'SEC_HTTP_REDIRECT',
      subCategory: 'tls',
      confidence: 'verified_direct',
      category: 'security',
      title: 'HTTP Does Not Redirect to HTTPS',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: 'Probing the plain HTTP version of the domain responded without redirecting to HTTPS.',
      evidence: `HTTP probe to http://${host} did not return a redirect to https://.`,
      affectedUrl: `http://${host}`,
      observedValue: 'No HTTPS redirect observed',
      impact: 'Users typing the bare domain or following http:// links may communicate over unencrypted connections.',
      recommendation: 'Configure a permanent 301 or 308 redirect from HTTP (port 80) to HTTPS (port 443).',
      remediation: 'Nginx: return 301 https://$host$request_uri; | Vercel/Cloudflare: Enable "Always Use HTTPS".',
      verification: 'Run curl -I http://yourdomain.com and confirm Location: https://... with 301/308.',
      status: 'open',
    });
  } else if (secInput.httpRedirectsToHttps === true) {
    const host = new URL(secInput.finalUrl).hostname;
    push({
      ruleId: 'SEC_HTTP_REDIRECT',
      subCategory: 'tls',
      confidence: 'verified_direct',
      category: 'security',
      title: 'HTTP Redirects to HTTPS',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'Requests to plain HTTP (port 80) redirect cleanly to encrypted HTTPS.',
      evidence: `http://${host} returned an HTTPS redirect.`,
      affectedUrl: `http://${host}`,
      observedValue: 'Redirects to https://',
      impact: 'Protects visitors entering bare domain names over plain HTTP.',
      recommendation: 'Keep permanent 301/308 HTTPS redirects enabled.',
      remediation: 'No action required.',
      verification: 'Verified via port 80 redirect probe.',
      status: 'passed',
    });
  }

  // 1b. TLS Certificate Analysis
  if (secInput.isHttps) {
    if (!secInput.tls.available) {
      push({
        ruleId: 'SEC_TLS_CERT',
        subCategory: 'tls',
        confidence: 'not_assessed',
        category: 'security',
        title: 'TLS Handshake Inspection Unavailable',
        severity: 'informational',
        priorityGroup: 'best_practice',
        description: 'Direct TLS socket certificate metadata could not be retrieved from the runtime environment.',
        evidence: secInput.tls.error || 'TLS socket check did not return certificate metadata.',
        affectedUrl: secInput.finalUrl,
        observedValue: 'Unavailable',
        impact: 'Certificate expiry and cipher details could not be independently verified during this scan.',
        recommendation: 'Verify certificate expiration and chain validity using your hosting provider or openssl s_client.',
        remediation: 'openssl s_client -connect domain:443 -servername domain',
        verification: 'Confirm certificate chain and expiry date directly.',
        status: 'not_assessed',
      });
    } else {
      if (!secInput.tls.authorized || secInput.tls.hostnameMatch === false) {
        push({
          ruleId: 'SEC_TLS_CERT',
          subCategory: 'tls',
          confidence: 'verified_direct',
          category: 'security',
          title: 'TLS Certificate Validation Failure',
          severity: 'critical',
          priorityGroup: 'fix_immediately',
          description: 'The server TLS certificate failed trust chain or hostname verification.',
          evidence: `Authorized: ${secInput.tls.authorized}, Hostname match: ${secInput.tls.hostnameMatch}, Issuer: ${secInput.tls.issuer || 'Unknown'}`,
          affectedUrl: secInput.finalUrl,
          observedValue: `authorized=${String(secInput.tls.authorized)}`,
          impact: 'Modern browsers will block visitors with security warnings and expose users to MITM risk.',
          recommendation: 'Install a valid, trusted certificate covering the exact domain and intermediate chain.',
          remediation: 'Renew or reissue certificate via Let\'s Encrypt, Cloudflare, or your hosting provider.',
          verification: 'Confirm TLS handshake passes without certificate errors.',
          status: 'open',
        });
      } else if (secInput.tls.daysRemaining !== null && secInput.tls.daysRemaining <= 14) {
        push({
          ruleId: 'SEC_TLS_CERT',
          subCategory: 'tls',
          confidence: 'verified_direct',
          category: 'security',
          title: 'TLS Certificate Expiring Soon',
          severity: secInput.tls.daysRemaining <= 0 ? 'critical' : 'high',
          priorityGroup: 'fix_immediately',
          description: `The TLS certificate expires in ${secInput.tls.daysRemaining} days.`,
          evidence: `Valid To: ${secInput.tls.validTo}, Issuer: ${secInput.tls.issuer}`,
          affectedUrl: secInput.finalUrl,
          observedValue: `${secInput.tls.daysRemaining} days remaining`,
          impact: 'An expired certificate causes immediate downtime and browser security blocks.',
          recommendation: 'Renew the TLS certificate immediately and verify automated ACME renewal.',
          remediation: 'Check certbot/hosting TLS auto-renewal configuration.',
          verification: 'Re-run scan and verify validTo extends at least 60+ days.',
          status: 'open',
        });
      } else {
        push({
          ruleId: 'SEC_TLS_CERT',
          subCategory: 'tls',
          confidence: 'verified_direct',
          category: 'security',
          title: 'Valid TLS Certificate & Protocol',
          severity: 'passed',
          priorityGroup: 'best_practice',
          description: `TLS handshake succeeded with ${secInput.tls.protocol || 'TLS'} and a valid certificate issued by ${secInput.tls.issuer || 'trusted CA'}.`,
          evidence: `Protocol: ${secInput.tls.protocol}, Valid To: ${secInput.tls.validTo || 'N/A'}`,
          affectedUrl: secInput.finalUrl,
          observedValue: `${secInput.tls.protocol || 'TLS'} · Valid`,
          impact: 'Visitors receive verified transport encryption.',
          recommendation: 'Keep automated renewal active.',
          remediation: 'No action required.',
          verification: 'Monitor certificate expiry.',
          status: 'passed',
        });
      }
    }
  }

  // 1c. Mixed Content
  if (secInput.isHttps && sortedMixed.length > 0) {
    push({
      ruleId: 'SEC_MIXED_CONTENT',
      subCategory: 'headers',
      confidence: 'static_html',
      category: 'security',
      title: 'Mixed Content References Detected',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: `Found ${sortedMixed.length} insecure http:// asset or script reference(s) inside an HTTPS page.`,
      evidence: `Examples: ${sortedMixed.slice(0, 3).join(', ')}`,
      affectedUrl: secInput.finalUrl,
      observedValue: `${sortedMixed.length} http:// asset URLs`,
      impact: 'Browsers block active mixed content (scripts/styles) and warn on passive mixed content, degrading security and functionality.',
      recommendation: 'Update all subresource URLs to https:// or protocol-neutral paths.',
      remediation: 'Replace http:// asset URLs in HTML templates and optionally add upgrade-insecure-requests to CSP.',
      verification: 'Re-scan HTML and verify zero http:// asset URLs remain.',
      status: 'open',
    });
  }

  // 1d. HTTP Security Headers
  const hsts = getHeader('strict-transport-security');
  if (secInput.isHttps) {
    if (!hsts) {
      push({
        ruleId: 'SEC_HSTS',
        subCategory: 'headers',
        confidence: 'verified_direct',
        category: 'security',
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        severity: 'medium',
        priorityGroup: 'fix_soon',
        description: 'The HTTPS response does not include a Strict-Transport-Security header.',
        evidence: 'Strict-Transport-Security: Not present in observed response headers.',
        affectedUrl: secInput.finalUrl,
        observedValue: 'Not present',
        impact: 'Without HSTS, first-time or returning requests over HTTP could be downgraded before a redirect occurs.',
        recommendation: 'Add Strict-Transport-Security once all subdomains support HTTPS reliably.',
        remediation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        verification: 'Inspect HTTPS response headers and confirm max-age >= 31536000.',
        status: 'open',
      });
    } else {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
      if (maxAgeSec > 0 && maxAgeSec < 15552000) {
        push({
          ruleId: 'SEC_HSTS',
          subCategory: 'headers',
          confidence: 'verified_direct',
          category: 'security',
          title: 'Strict-Transport-Security (HSTS) max-age Under 180 Days',
          severity: 'low',
          priorityGroup: 'best_practice',
          description: `HSTS is present, but max-age=${maxAgeSec} seconds is below the recommended 1-year (31536000) duration.`,
          evidence: `Strict-Transport-Security: ${hsts}`,
          affectedUrl: secInput.finalUrl,
          observedValue: hsts,
          impact: 'Short HSTS lifetimes shorten HTTPS downgrade protection.',
          recommendation: 'Increase HSTS max-age to at least 31536000 (1 year) once HTTPS stability is confirmed.',
          remediation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
          verification: 'Inspect Strict-Transport-Security header.',
          status: 'open',
        });
      } else {
        push({
          ruleId: 'SEC_HSTS',
          subCategory: 'headers',
          confidence: 'verified_direct',
          category: 'security',
          title: 'Strict-Transport-Security (HSTS) Configured',
          severity: 'passed',
          priorityGroup: 'best_practice',
          description: 'The site instructs browsers to enforce HTTPS connections via HSTS.',
          evidence: `Strict-Transport-Security: ${hsts}`,
          affectedUrl: secInput.finalUrl,
          observedValue: hsts,
          impact: 'Protects against protocol downgrade attacks on repeat visits.',
          recommendation: 'Keep HSTS active with a max-age of at least one year.',
          remediation: 'No action required.',
          verification: 'Header verified in response.',
          status: 'passed',
        });
      }
    }
  }

  const csp = getHeader('content-security-policy');
  if (!csp) {
    push({
      ruleId: 'SEC_CSP',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Missing Content-Security-Policy (CSP)',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: 'The scanned HTTP response did not include a Content-Security-Policy header.',
      evidence: 'Content-Security-Policy: Not present in the observed response.',
      affectedUrl: secInput.finalUrl,
      observedValue: 'Not present',
      impact: 'A suitable Content Security Policy helps reduce the impact of cross-site scripting (XSS) and unauthorized script injection.',
      recommendation: 'Design and deploy a CSP tailored to the application\'s required script, style, and image origins. Start in Report-Only mode before enforcing.',
      remediation: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
      verification: 'Repeat the header assessment and confirm Content-Security-Policy is returned without breaking legitimate assets.',
      status: 'open',
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes('*')) {
    push({
      ruleId: 'SEC_CSP',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Permissive Content-Security-Policy Directives',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'Content-Security-Policy is present, but includes permissive directives such as unsafe-inline or wildcard origins.',
      evidence: `Content-Security-Policy: ${csp.slice(0, 260)}`,
      affectedUrl: secInput.finalUrl,
      observedValue: 'Permissive CSP',
      impact: 'Allowing unsafe-inline or broad wildcards weakens protection against inline script injection.',
      recommendation: 'Replace unsafe-inline scripts with nonces or cryptographic hashes and scope allowlisted domains.',
      remediation: "Use script-src 'self' 'nonce-<random>' and avoid wildcard script sources.",
      verification: 'Re-inspect the CSP header and test application scripts with browser DevTools.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEC_CSP',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Content-Security-Policy (CSP) Configured',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'A Content-Security-Policy header is present without broad unsafe-inline or wildcard script rules.',
      evidence: `Content-Security-Policy: ${csp.slice(0, 260)}`,
      affectedUrl: secInput.finalUrl,
      observedValue: 'Hardened CSP',
      impact: 'Helps mitigate XSS and unauthorized resource execution.',
      recommendation: 'Review CSP violation reports periodically when adding third-party integrations.',
      remediation: 'No action required.',
      verification: 'Header verified in response.',
      status: 'passed',
    });
  }

  const xfo = getHeader('x-frame-options');
  const hasFrameAncestors = Boolean(csp && csp.toLowerCase().includes('frame-ancestors'));
  if (!xfo && !hasFrameAncestors) {
    push({
      ruleId: 'SEC_CLICKJACKING',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: 'Neither X-Frame-Options nor a CSP frame-ancestors directive was observed in the response.',
      evidence: 'X-Frame-Options: Not present; CSP frame-ancestors: Not present.',
      affectedUrl: secInput.finalUrl,
      observedValue: 'Not present',
      impact: 'The page could be embedded inside a third-party iframe, increasing clickjacking risk for sensitive user actions.',
      recommendation: 'Restrict framing using X-Frame-Options and CSP frame-ancestors.',
      remediation: "X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors 'none'",
      verification: 'Inspect response headers and confirm framing protection is returned.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEC_CLICKJACKING',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Clickjacking Protection Active',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'Framing restrictions are configured via X-Frame-Options or CSP frame-ancestors.',
      evidence: `X-Frame-Options: ${xfo || 'via CSP frame-ancestors'}`,
      affectedUrl: secInput.finalUrl,
      observedValue: xfo || 'CSP frame-ancestors',
      impact: 'Prevents unauthorized iframe embedding.',
      recommendation: 'Keep framing restrictions consistent across authenticated routes.',
      remediation: 'No action required.',
      verification: 'Header verified.',
      status: 'passed',
    });
  }

  const xcto = getHeader('x-content-type-options');
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    push({
      ruleId: 'SEC_XCTO',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Missing X-Content-Type-Options: nosniff',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'The X-Content-Type-Options header is absent or not set to nosniff.',
      evidence: `X-Content-Type-Options: ${xcto || 'Not present'}`,
      affectedUrl: secInput.finalUrl,
      observedValue: xcto || 'Not present',
      impact: 'Browsers may attempt MIME-type sniffing on uploaded or mislabeled assets.',
      recommendation: 'Set X-Content-Type-Options: nosniff on all HTTP responses.',
      remediation: 'X-Content-Type-Options: nosniff',
      verification: 'Confirm X-Content-Type-Options: nosniff in response headers.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEC_XCTO',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'X-Content-Type-Options Enforced',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'MIME-sniffing protection is enabled with X-Content-Type-Options: nosniff.',
      evidence: `X-Content-Type-Options: ${xcto}`,
      affectedUrl: secInput.finalUrl,
      observedValue: xcto,
      impact: 'Prevents browsers from interpreting non-executable MIME types as scripts.',
      recommendation: 'Maintain nosniff across static assets and API routes.',
      remediation: 'No action required.',
      verification: 'Header verified.',
      status: 'passed',
    });
  }

  const refPolicy = getHeader('referrer-policy');
  if (!refPolicy) {
    push({
      ruleId: 'SEC_REFERRER',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Missing Referrer-Policy Header',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'No Referrer-Policy header was returned, leaving referrer leakage to browser defaults.',
      evidence: 'Referrer-Policy: Not present in observed response headers.',
      affectedUrl: secInput.finalUrl,
      observedValue: 'Not present',
      impact: 'URL paths or query parameters may be sent in the Referer header when users follow external links.',
      recommendation: 'Add a privacy-preserving Referrer-Policy header.',
      remediation: 'Referrer-Policy: strict-origin-when-cross-origin',
      verification: 'Inspect response headers for Referrer-Policy.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEC_REFERRER',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Referrer-Policy Configured',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'Referrer-Policy is explicitly configured on the response.',
      evidence: `Referrer-Policy: ${refPolicy}`,
      affectedUrl: secInput.finalUrl,
      observedValue: refPolicy,
      impact: 'Controls what URL information is shared during cross-origin navigation.',
      recommendation: 'Ensure strict-origin-when-cross-origin or no-referrer is used on sensitive pages.',
      remediation: 'No action required.',
      verification: 'Header verified.',
      status: 'passed',
    });
  }

  const permPolicy = getHeader('permissions-policy') || getHeader('feature-policy');
  if (!permPolicy) {
    push({
      ruleId: 'SEC_PERMISSIONS',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Missing Permissions-Policy Header',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: 'The response does not define a Permissions-Policy header to restrict browser APIs.',
      evidence: 'Permissions-Policy: Not present in observed response headers.',
      affectedUrl: secInput.finalUrl,
      observedValue: 'Not present',
      impact: 'Embedded frames or third-party scripts are not explicitly restricted from accessing camera, microphone, or geolocation APIs.',
      recommendation: 'Define a Permissions-Policy disabling unused browser capabilities.',
      remediation: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
      verification: 'Verify Permissions-Policy is returned in response headers.',
      status: 'open',
    });
  }

  const coop = getHeader('cross-origin-opener-policy');
  const corp = getHeader('cross-origin-resource-policy');
  const coep = getHeader('cross-origin-embedder-policy');
  if (!coop || !corp) {
    push({
      ruleId: 'SEC_COOP_CORP',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Cross-Origin Isolation Headers Incomplete',
      severity: 'low',
      priorityGroup: 'long_term',
      description: 'One or more cross-origin isolation headers (COOP / CORP / COEP) are not configured.',
      evidence: `COOP: ${coop || 'Absent'} | CORP: ${corp || 'Absent'} | COEP: ${coep || 'Absent'}`,
      affectedUrl: secInput.finalUrl,
      observedValue: `COOP=${coop ? 'yes' : 'no'}, CORP=${corp ? 'yes' : 'no'}`,
      impact: 'Cross-origin isolation headers strengthen process isolation against speculative execution side-channels and cross-origin window access.',
      recommendation: 'Evaluate adding Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin where compatible with third-party embeds.',
      remediation: 'Cross-Origin-Opener-Policy: same-origin-allow-popups',
      verification: 'Confirm headers after verifying OAuth popups and third-party widgets still function.',
      status: 'open',
    });
  }

  // 1e. Cookie Security (Values Redacted & Sorted Deterministically)
  if (secInput.setCookieHeaders.length > 0) {
    const parsedCookies = secInput.setCookieHeaders
      .map(redactCookieHeader)
      .sort((a, b) => a.name.localeCompare(b.name));
    // Deduplicate by cookie name in case edge sends duplicate Set-Cookie headers
    const uniqueCookies = Array.from(new Map(parsedCookies.map((c) => [c.name, c])).values());
    const weakCookies = uniqueCookies.filter((c) => !c.hasSecure || !c.hasHttpOnly || !c.sameSite);
    if (weakCookies.length > 0) {
      push({
        ruleId: 'SEC_COOKIES',
        subCategory: 'headers',
        confidence: 'verified_direct',
        category: 'security',
        title: 'Cookies Missing Hardened Security Flags',
        severity: 'medium',
        priorityGroup: 'fix_soon',
        description: `${weakCookies.length} Set-Cookie header(s) lack one or more recommended flags (Secure, HttpOnly, SameSite).`,
        evidence: weakCookies.map((c) => c.sanitizedSummary).join(' | '),
        affectedUrl: secInput.finalUrl,
        observedValue: `${weakCookies.length} cookie(s) missing flags`,
        impact: 'Cookies without HttpOnly can be read by client scripts; cookies without Secure may travel over HTTP; missing SameSite increases CSRF exposure.',
        recommendation: 'Apply Secure, HttpOnly (for non-JS cookies), and SameSite=Lax or Strict to session and sensitive cookies.',
        remediation: 'Set-Cookie: session=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax',
        verification: 'Inspect Set-Cookie response attributes with values redacted.',
        status: 'open',
      });
    } else {
      push({
        ruleId: 'SEC_COOKIES',
        subCategory: 'headers',
        confidence: 'verified_direct',
        category: 'security',
        title: 'Cookie Security Flags Configured',
        severity: 'passed',
        priorityGroup: 'best_practice',
        description: `All ${uniqueCookies.length} observed Set-Cookie header(s) include Secure, HttpOnly, and SameSite attributes.`,
        evidence: uniqueCookies.map((c) => c.sanitizedSummary).join(' | '),
        affectedUrl: secInput.finalUrl,
        observedValue: `${uniqueCookies.length} hardened cookie(s)`,
        impact: 'Protects cookies against script access and cross-site request leakage.',
        recommendation: 'Keep security flags enforced on all authentication cookies.',
        remediation: 'No action required.',
        verification: 'Attributes verified.',
        status: 'passed',
      });
    }
  }

  // 1f. Server Banner / Version Disclosure
  const serverHdr = getHeader('server');
  const poweredBy = getHeader('x-powered-by');
  const aspNet = getHeader('x-aspnet-version');
  const exposedBanners = [
    serverHdr ? `Server: ${serverHdr}` : null,
    poweredBy ? `X-Powered-By: ${poweredBy}` : null,
    aspNet ? `X-AspNet-Version: ${aspNet}` : null,
  ].filter(Boolean) as string[];

  if (exposedBanners.length > 0 && (poweredBy || aspNet || /\d+\.\d+/.test(serverHdr || ''))) {
    push({
      ruleId: 'SEC_SERVER_BANNER',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Server Version or Framework Banner Exposed',
      severity: 'low',
      priorityGroup: 'optimization',
      description: 'Response headers expose server software, runtime framework, or specific version numbers.',
      evidence: exposedBanners.join(' | '),
      affectedUrl: secInput.finalUrl,
      observedValue: exposedBanners.join('; '),
      impact: 'Revealing exact software versions helps automated scanners target known framework vulnerabilities.',
      recommendation: 'Suppress X-Powered-By and strip detailed version numbers from the Server header.',
      remediation: 'Express: app.disable("x-powered-by"); | Nginx: server_tokens off;',
      verification: 'Re-fetch headers and verify X-Powered-By and version numbers are omitted.',
      status: 'open',
    });
  } else if (serverHdr) {
    push({
      ruleId: 'SEC_SERVER_BANNER',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'Infrastructure Server Banner Observed',
      severity: 'informational',
      priorityGroup: 'best_practice',
      description: `The edge/server header identifies "${serverHdr}" without exposing granular runtime version strings.`,
      evidence: `Server: ${serverHdr}`,
      affectedUrl: secInput.finalUrl,
      observedValue: serverHdr,
      impact: 'CDN or reverse-proxy edge banners are common and low-risk when versions are omitted.',
      recommendation: 'Avoid adding X-Powered-By or backend stack version headers.',
      remediation: 'Optional: strip Server header at edge proxy if policy requires.',
      verification: 'Verify headers on origin responses.',
      status: 'passed',
    });
  }

  // 1g. DNS Security Signals (SPF, DMARC, CAA - sorted for determinism)
  if (secInput.dns.resolved) {
    if (!secInput.dns.hasSpf || !secInput.dns.hasDmarc) {
      push({
        ruleId: 'SEC_DNS_EMAIL',
        subCategory: 'dns',
        confidence: 'verified_direct',
        category: 'security',
        title: 'Email Authentication DNS Records Incomplete (SPF / DMARC)',
        severity: 'low',
        priorityGroup: 'best_practice',
        description: `DNS TXT inspection observed SPF=${secInput.dns.hasSpf ? 'present' : 'not observed'} and DMARC=${secInput.dns.hasDmarc ? 'present' : 'not observed'}. Note: DNS observations do not inspect private mail server signing (DKIM).`,
        evidence: `A: ${sortedA.join(', ') || 'none'} | AAAA: ${sortedAAAA.join(', ') || 'none'} | SPF: ${secInput.dns.hasSpf} | DMARC: ${secInput.dns.hasDmarc}`,
        affectedUrl: secInput.finalUrl,
        observedValue: `SPF:${secInput.dns.hasSpf ? 'Yes' : 'No'} DMARC:${secInput.dns.hasDmarc ? 'Yes' : 'No'}`,
        impact: 'Missing SPF or DMARC policies make it easier for third parties to spoof emails appearing to come from your domain.',
        recommendation: 'Publish an SPF TXT record and a _dmarc TXT policy (starting with p=none for monitoring).',
        remediation: '_dmarc.yourdomain.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"',
        verification: 'Query TXT records for the apex domain and _dmarc subdomain.',
        status: 'open',
      });
    } else {
      push({
        ruleId: 'SEC_DNS_EMAIL',
        subCategory: 'dns',
        confidence: 'verified_direct',
        category: 'security',
        title: 'DNS SPF & DMARC Records Observed',
        severity: 'passed',
        priorityGroup: 'best_practice',
        description: 'Both SPF and DMARC TXT records were observed in public DNS.',
        evidence: `DMARC: ${secInput.dns.dmarcRecord || 'Present'} | CAA records: ${sortedCaa.length}`,
        affectedUrl: secInput.finalUrl,
        observedValue: 'SPF + DMARC present',
        impact: 'Helps receiving mail providers verify domain email authenticity.',
        recommendation: 'Periodically review DMARC aggregate reports.',
        remediation: 'No action required.',
        verification: 'DNS TXT verified.',
        status: 'passed',
      });
    }

    if (sortedCaa.length === 0) {
      push({
        ruleId: 'SEC_DNS_CAA',
        subCategory: 'dns',
        confidence: 'verified_direct',
        category: 'security',
        title: 'No DNS CAA Certificate Authority Restriction Observed',
        severity: 'informational',
        priorityGroup: 'long_term',
        description: 'No Certification Authority Authorization (CAA) DNS record was observed for this domain.',
        evidence: 'DNS CAA lookup returned 0 records.',
        affectedUrl: secInput.finalUrl,
        observedValue: 'CAA absent',
        impact: 'Without CAA records, any publicly trusted CA could theoretically issue certificates if domain validation is compromised.',
        recommendation: 'Publish a CAA DNS record restricting certificate issuance to your chosen CA (e.g., letsencrypt.org or pki.goog).',
        remediation: 'yourdomain.com. IN CAA 0 issue "letsencrypt.org"',
        verification: 'Query DNS CAA records for your domain.',
        status: 'open',
      });
    }
  }

  // 1h. security.txt
  if (!secInput.hasSecurityTxt) {
    push({
      ruleId: 'SEC_SECURITY_TXT',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'security',
      title: 'No /.well-known/security.txt Found',
      severity: 'informational',
      priorityGroup: 'best_practice',
      description: 'No public security.txt policy file was found at /.well-known/security.txt.',
      evidence: 'GET /.well-known/security.txt did not return HTTP 200 text content with a Contact field.',
      affectedUrl: `${new URL(secInput.finalUrl).origin}/.well-known/security.txt`,
      observedValue: 'Not found',
      impact: 'Security researchers lack a standardized vulnerability disclosure contact channel.',
      recommendation: 'Publish a RFC 9116 security.txt file listing a security contact email and policy.',
      remediation: 'Contact: mailto:security@yourdomain.com\nExpires: 2027-12-31T23:59:00.000Z',
      verification: 'Verify /.well-known/security.txt returns HTTP 200.',
      status: 'open',
    });
  }

  // =========================================================================
  // 2. FRONT-END, ACCESSIBILITY (WCAG) & UI/UX
  // =========================================================================
  const $ = cheerio.load(feInput.html || '');
  const domNodeCount = $('*').length;
  const scriptCount = $('script').length;
  const inlineScriptsWithoutNonce = $('script:not([src])').filter((_, el) => {
    const type = ($(el).attr('type') || '').toLowerCase();
    if (type === 'application/ld+json' || type === 'application/json') return false;
    return !$(el).attr('nonce') && $(el).text().trim().length > 0;
  }).length;
  const inlineEventHandlers = $('[onclick], [onload], [onerror], [onmouseover]').length;
  if ((!csp || csp.includes("'unsafe-inline'")) && (inlineScriptsWithoutNonce > 0 || inlineEventHandlers > 0)) {
    push({
      ruleId: 'SEC_INLINE_SCRIPT',
      subCategory: 'headers',
      confidence: 'static_html',
      category: 'security',
      title: 'Unprotected Inline Scripts or Event Handlers Without Strict CSP',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: `Detected ${inlineScriptsWithoutNonce} inline <script> block(s) and ${inlineEventHandlers} inline DOM event handler(s) without a nonce-hardened Content-Security-Policy.`,
      evidence: `Inline scripts: ${inlineScriptsWithoutNonce}, inline handlers: ${inlineEventHandlers}`,
      affectedUrl: secInput.finalUrl,
      observedValue: `${inlineScriptsWithoutNonce + inlineEventHandlers} inline execution point(s)`,
      impact: 'Inline scripts complicate strict CSP deployment and expand XSS execution surface.',
      recommendation: 'Move inline logic into external bundled scripts or attach cryptographic CSP nonces.',
      remediation: 'Externalize scripts or use script-src \'self\' \'nonce-<random>\'.',
      verification: 'Inspect HTML for inline <script> tags and onclick/onload attributes.',
      status: 'open',
    });
  }

  const stylesheetCount = $('link[rel="stylesheet"]').length;
  const renderBlockingScripts = $('head script:not([async]):not([defer]):not([type="module"])').length;
  const images = $('img');
  const imageCount = images.length;
  let imagesWithoutAlt = 0;
  let imagesWithoutDimensions = 0;
  let imagesWithoutLazyLoading = 0;
  images.each((i, el) => {
    const alt = $(el).attr('alt');
    if (alt === undefined) imagesWithoutAlt++;
    if (!$(el).attr('width') || !$(el).attr('height')) imagesWithoutDimensions++;
    if (i > 1 && !$(el).attr('loading')) imagesWithoutLazyLoading++;
  });

  const links = $('a');
  const linkCount = links.length;
  let emptyLinks = 0;
  links.each((_, el) => {
    const text = $(el).text().trim();
    const aria = $(el).attr('aria-label') || $(el).attr('title') || $(el).find('img[alt]').attr('alt');
    if (!text && !aria) emptyLinks++;
  });

  const buttons = $('button');
  let buttonsWithoutText = 0;
  buttons.each((_, el) => {
    const text = $(el).text().trim();
    const aria = $(el).attr('aria-label') || $(el).attr('title');
    if (!text && !aria) buttonsWithoutText++;
  });

  const forms = $('form');
  const formCount = forms.length;
  const labelForIds = new Set<string>();
  $('label[for]').each((_, el) => {
    const forVal = $(el).attr('for')?.trim();
    if (forVal) labelForIds.add(forVal);
  });
  let inputsWithoutLabel = 0;
  $('input, select, textarea').each((_, el) => {
    const tag = el.tagName?.toLowerCase();
    const type = ($(el).attr('type') || 'text').toLowerCase();
    if (tag === 'input' && ['hidden', 'submit', 'button', 'reset', 'image'].includes(type)) return;
    const id = $(el).attr('id')?.trim();
    const aria = $(el).attr('aria-label') || $(el).attr('aria-labelledby');
    const wrappedByLabel = $(el).closest('label').length > 0;
    const hasForLabel = Boolean(id && labelForIds.has(id));
    if (!aria && !wrappedByLabel && !hasForLabel) inputsWithoutLabel++;
  });

  const h1Count = $('h1').length;
  const h2Count = $('h2').length;
  const h3Count = $('h3').length;
  let headingOrderIssues = 0;
  let prevLevel = 0;
  $('h1, h2, h3, h4, h5, h6').each((_, el) => {
    const level = Number(el.tagName.slice(1));
    if (prevLevel > 0 && level > prevLevel + 1) {
      headingOrderIssues++;
    }
    prevLevel = level;
  });

  const title = $('title').first().text().trim();
  const metaDesc = $('meta[name="description"]').attr('content')?.trim() || '';
  const viewport = $('meta[name="viewport"]').attr('content')?.trim() || '';
  const htmlLang = $('html').attr('lang')?.trim() || '';
  const canonical = $('link[rel="canonical"]').attr('href')?.trim() || '';
  const ogTitle = $('meta[property="og:title"]').attr('content')?.trim() || '';
  const ogDesc = $('meta[property="og:description"]').attr('content')?.trim() || '';
  const twitterCard = $('meta[name="twitter:card"]').attr('content')?.trim() || '';

  const hasRobotsTxt = feInput.hasRobotsTxt ?? secInput.hasRobotsTxt;
  const hasSitemapXml = feInput.hasSitemapXml ?? secInput.hasSitemapXml;
  const hasSecurityTxt = feInput.hasSecurityTxt ?? secInput.hasSecurityTxt;

  const frontendDetails: ExtendedFrontendMetrics = {
    formCount,
    inputsWithoutLabel,
    buttonsWithoutText,
    emptyLinks,
    imagesWithoutLazyLoading,
    headingOrderIssues,
    hasCanonical: Boolean(canonical),
    canonicalUrl: canonical || null,
    hasMetaDescription: Boolean(metaDesc),
    metaDescriptionLength: metaDesc.length,
    hasOpenGraph: Boolean(ogTitle || ogDesc),
    hasTwitterCard: Boolean(twitterCard),
    hasRobotsTxt,
    hasSitemapXml,
    hasSecurityTxt,
    htmlLang: htmlLang || null,
    pageTitle: title || null,
  };

  // Viewport meta
  if (!viewport) {
    push({
      ruleId: 'FE_VIEWPORT',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing Viewport Meta Tag',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: 'Static HTML lacks a <meta name="viewport"> tag.',
      evidence: 'No <meta name="viewport"> element found in <head>.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Missing',
      impact: 'Mobile browsers will render a zoomed-out desktop layout, degrading mobile usability.',
      recommendation: 'Add a responsive viewport meta tag in the document head.',
      remediation: '<meta name="viewport" content="width=device-width, initial-scale=1.0" />',
      verification: 'Inspect HTML <head> and test on mobile viewport.',
      status: 'open',
    });
  } else {
    const lowerVp = viewport.toLowerCase();
    if (lowerVp.includes('user-scalable=no') || /maximum-scale\s*=\s*1(\.0)?\b/.test(lowerVp)) {
      push({
        ruleId: 'A11Y_VIEWPORT_LOCK',
        subCategory: 'accessibility',
        confidence: 'static_html',
        category: 'frontend',
        title: 'Viewport Disables Pinch-to-Zoom',
        severity: 'medium',
        priorityGroup: 'fix_soon',
        description: 'The viewport meta tag restricts user scaling (user-scalable=no or maximum-scale=1), violating WCAG 1.4.4.',
        evidence: `<meta name="viewport" content="${viewport}">`,
        affectedUrl: feInput.finalUrl,
        observedValue: viewport,
        impact: 'Low-vision mobile users cannot zoom text and controls.',
        recommendation: 'Remove user-scalable=no and allow maximum-scale >= 2.',
        remediation: '<meta name="viewport" content="width=device-width, initial-scale=1.0" />',
        verification: 'Verify pinch-to-zoom works on mobile.',
        status: 'open',
      });
    }
    push({
      ruleId: 'FE_VIEWPORT',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Viewport Meta Tag Present',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'The viewport meta tag is present in static HTML, supporting responsive mobile scaling.',
      evidence: `<meta name="viewport" content="${viewport}">`,
      affectedUrl: feInput.finalUrl,
      observedValue: viewport,
      impact: 'Enables proper responsive layout rendering across mobile viewports.',
      recommendation: 'Keep user scaling enabled (avoid user-scalable=no).',
      remediation: 'No action required.',
      verification: 'Meta tag verified in HTML.',
      status: 'passed',
    });
  }

  const hasFavicon = $('link[rel*="icon"]').length > 0;
  if (!hasFavicon) {
    push({
      ruleId: 'FE_FAVICON',
      subCategory: 'content',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing Explicit Favicon Link in HTML Head',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: 'No <link rel="icon"> or apple-touch-icon tag was found in the static HTML <head>.',
      evidence: 'link[rel*="icon"]: Not present in initial HTML head',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Missing favicon tag',
      impact: 'Browsers fall back to /favicon.ico guesses and bookmarks lack brand icons.',
      recommendation: 'Declare explicit SVG/PNG <link rel="icon"> metadata in <head>.',
      remediation: '<link rel="icon" type="image/svg+xml" href="/favicon.svg" />',
      verification: 'Check <head> for favicon links.',
      status: 'open',
    });
  }

  // Title & Meta Description (SEO)
  if (!title || title.length < 5) {
    push({
      ruleId: 'SEO_TITLE',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing or Too Short Page Title',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'The HTML <title> tag is missing or under 5 characters.',
      evidence: `Observed <title>: "${title || '(empty)'}"`,
      affectedUrl: feInput.finalUrl,
      observedValue: title || 'Empty',
      impact: 'Hurts accessibility (screen readers announce page title first), browser tab clarity, and search indexing.',
      recommendation: 'Provide a descriptive, unique 30-60 character <title>.',
      remediation: '<title>Brand Name — Clear Value Proposition</title>',
      verification: 'Inspect static HTML <title> tag.',
      status: 'open',
    });
  }

  if (!metaDesc) {
    push({
      ruleId: 'SEO_META_DESC',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing Meta Description',
      severity: 'low',
      priorityGroup: 'optimization',
      description: 'No <meta name="description"> tag was found in the static HTML head.',
      evidence: 'meta[name="description"]: Not present',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Not present',
      impact: 'Search engines and link previews fall back to arbitrary page snippets.',
      recommendation: 'Add a concise 120-160 character meta description.',
      remediation: '<meta name="description" content="Concise summary of the page." />',
      verification: 'Inspect <head> metadata.',
      status: 'open',
    });
  }

  // Accessibility checks
  if (!htmlLang) {
    push({
      ruleId: 'A11Y_HTML_LANG',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing HTML lang Attribute',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'The root <html> element does not specify a lang attribute (WCAG 3.1.1).',
      evidence: '<html> tag has no lang attribute in static HTML.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Missing lang',
      impact: 'Screen readers cannot reliably select the correct pronunciation language.',
      recommendation: 'Add lang="en" (or the page\'s primary BCP-47 language code) to <html>.',
      remediation: '<html lang="en">',
      verification: 'Inspect root <html> element.',
      status: 'open',
    });
  }

  // Render-blocking & DOM Complexity (Static HTML measurements)
  if (renderBlockingScripts > 0 || stylesheetCount > 4) {
    push({
      ruleId: 'PERF_RENDER_BLOCKING',
      subCategory: 'performance',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Render-Blocking Resources in Head',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: `Static HTML analysis detected ${renderBlockingScripts} blocking <script> tag(s) in <head> and ${stylesheetCount} external stylesheet(s). (Static HTML measurement; full browser render timing requires PageSpeed Insights.)`,
      evidence: `Head blocking scripts: ${renderBlockingScripts}, Total scripts: ${scriptCount}, Stylesheets: ${stylesheetCount}`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${renderBlockingScripts} blocking scripts, ${stylesheetCount} CSS files`,
      impact: 'Synchronous scripts in <head> pause HTML parsing and delay First Contentful Paint.',
      recommendation: 'Add defer or type="module" to non-critical scripts and inline critical CSS where practical.',
      remediation: '<script src="/app.js" defer></script>',
      verification: 'Inspect <head> scripts and measure FCP with PageSpeed Insights.',
      status: 'open',
    });
  }

  if (domNodeCount > 1500) {
    push({
      ruleId: 'PERF_DOM_SIZE',
      subCategory: 'performance',
      confidence: 'static_html',
      category: 'frontend',
      title: 'High Static DOM Node Count',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: `The initial HTML document contains ${domNodeCount} DOM nodes, exceeding the recommended 1,500-node threshold.`,
      evidence: `Cheerio static DOM count: ${domNodeCount} elements; HTML payload: ${(feInput.htmlSizeBytes / 1024).toFixed(1)} KB`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${domNodeCount} DOM nodes`,
      impact: 'Excessive DOM depth increases style recalculation time and memory usage on mobile devices.',
      recommendation: 'Simplify wrapper markup and paginate or virtualize large lists.',
      remediation: 'Prune redundant wrapper <div> nodes and lazy-render offscreen sections.',
      verification: 'Re-measure DOM count after template optimization.',
      status: 'open',
    });
  } else if (domNodeCount > 0) {
    push({
      ruleId: 'PERF_DOM_SIZE',
      subCategory: 'performance',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Lightweight Static DOM Structure',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Static HTML contains ${domNodeCount} DOM elements (${(feInput.htmlSizeBytes / 1024).toFixed(1)} KB), keeping initial parse overhead low. Note: Client-rendered SPA hydration may add nodes at runtime.`,
      evidence: `Static DOM nodes: ${domNodeCount}, HTML size: ${feInput.htmlSizeBytes} bytes`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${domNodeCount} static nodes`,
      impact: 'Lean initial DOM enables fast HTML parsing.',
      recommendation: 'Keep initial document size compact.',
      remediation: 'No action required.',
      verification: 'Verified via static HTML parse.',
      status: 'passed',
    });
  }

  // Accessibility: Image alt, empty links, unlabeled buttons, form labels, heading jumps
  if (imagesWithoutAlt > 0) {
    push({
      ruleId: 'A11Y_IMG_ALT',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Images Missing Alt Attributes',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: `${imagesWithoutAlt} of ${imageCount} <img> element(s) lack an alt attribute (WCAG 1.1.1).`,
      evidence: `${imagesWithoutAlt} missing alt; ${imagesWithoutDimensions} missing explicit width/height.`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${imagesWithoutAlt}/${imageCount} missing alt`,
      impact: 'Screen-reader users receive no description of informational images; missing dimensions can also cause layout shifts (CLS).',
      recommendation: 'Add descriptive alt text for meaningful images or alt="" for purely decorative images, and set width/height attributes.',
      remediation: '<img src="..." alt="Descriptive caption" width="600" height="400" loading="lazy" />',
      verification: 'Audit all <img> tags in rendered templates.',
      status: 'open',
    });
  }

  if (imageCount > 0 && imagesWithoutDimensions > 0) {
    push({
      ruleId: 'PERF_IMG_DIMENSIONS',
      subCategory: 'performance',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Images Missing Explicit Width & Height Attributes',
      severity: 'low',
      priorityGroup: 'optimization',
      description: `${imagesWithoutDimensions} of ${imageCount} <img> element(s) omit explicit width/height attributes.`,
      evidence: `${imagesWithoutDimensions}/${imageCount} images lack width or height attributes`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${imagesWithoutDimensions} unsized image(s)`,
      impact: 'Without intrinsic aspect-ratio dimensions, browsers may shift layout (CLS) as images load.',
      recommendation: 'Specify width and height attributes or CSS aspect-ratio on all <img> tags.',
      remediation: '<img src="..." width="800" height="450" alt="..." />',
      verification: 'Inspect <img> tags and CLS in DevTools.',
      status: 'open',
    });
  }

  if (emptyLinks > 0) {
    push({
      ruleId: 'A11Y_EMPTY_LINKS',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Links Without Accessible Text',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: `${emptyLinks} anchor <a> element(s) contain no visible text and no aria-label (WCAG 2.4.4).`,
      evidence: `Empty links found: ${emptyLinks} of ${linkCount} total links`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${emptyLinks} unlabeled links`,
      impact: 'Icon-only links without aria-label are announced as unlabelled links by assistive technologies.',
      recommendation: 'Add concise aria-label attributes or visually hidden text inside icon-only links.',
      remediation: '<a href="/profile" aria-label="Open profile"><svg ... /></a>',
      verification: 'Run accessibility audit or inspect all <a> elements.',
      status: 'open',
    });
  }

  if (buttonsWithoutText > 0) {
    push({
      ruleId: 'A11Y_BUTTON_TEXT',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Buttons Missing Accessible Labels',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: `${buttonsWithoutText} <button> element(s) lack visible text or an aria-label attribute (WCAG 4.1.2).`,
      evidence: `Buttons without accessible name: ${buttonsWithoutText} of ${buttons.length} total <button> tags`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${buttonsWithoutText} unlabeled button(s)`,
      impact: 'Screen readers announce icon-only buttons ambiguously as "button" with no purpose.',
      recommendation: 'Add an explicit aria-label or descriptive text inside every interactive <button>.',
      remediation: '<button type="button" aria-label="Close navigation"><svg ... /></button>',
      verification: 'Inspect accessible names in browser Accessibility tree.',
      status: 'open',
    });
  }

  if (inputsWithoutLabel > 0) {
    push({
      ruleId: 'A11Y_FORM_LABELS',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Form Controls Missing Associated Labels',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: `${inputsWithoutLabel} form field(s) lack a matching <label for="...">, wrapping <label>, or aria-label (WCAG 1.3.1 / 3.3.2).`,
      evidence: `Unlabeled form inputs: ${inputsWithoutLabel} across ${formCount} form(s)`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${inputsWithoutLabel} unlabeled field(s)`,
      impact: 'Assistive technology users cannot identify the expected input for unlabeled fields.',
      recommendation: 'Associate every <input>, <select>, and <textarea> with a visible <label for="..."> or aria-label.',
      remediation: '<label for="email">Email</label><input id="email" type="email" />',
      verification: 'Verify accessible labels in browser DevTools.',
      status: 'open',
    });
  }

  if (headingOrderIssues > 0) {
    push({
      ruleId: 'A11Y_HEADING_ORDER',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Skipped Heading Hierarchy Levels Detected',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: `Detected ${headingOrderIssues} heading level jump(s) (e.g., jumping from <h1> directly to <h3> without an intervening <h2>).`,
      evidence: `Heading hierarchy skips: ${headingOrderIssues} (H1: ${h1Count}, H2: ${h2Count}, H3: ${h3Count})`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${headingOrderIssues} hierarchy skip(s)`,
      impact: 'Screen reader landmark navigation relies on sequential heading tiers.',
      recommendation: 'Maintain sequential heading order (h1 -> h2 -> h3) and style visual sizes via CSS classes.',
      remediation: 'Replace skipped heading levels with sequential tags while retaining typography styles.',
      verification: 'Check document outline hierarchy.',
      status: 'open',
    });
  }

  // Broken links / images observed during bounded crawl
  if (sortedBrokenLinks.length > 0) {
    push({
      ruleId: 'FE_BROKEN_LINKS',
      subCategory: 'content',
      confidence: 'verified_direct',
      category: 'frontend',
      title: 'Broken Internal Links Observed',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: `${sortedBrokenLinks.length} sampled internal link(s) returned 4xx/5xx or connection errors.`,
      evidence: sortedBrokenLinks.slice(0, 4).map((b) => `${b.url} (${b.status})`).join('; '),
      affectedUrl: sortedBrokenLinks[0].url,
      observedValue: `${sortedBrokenLinks.length} broken link(s)`,
      impact: 'Broken navigation links frustrate visitors and harm search crawlability.',
      recommendation: 'Update or redirect broken internal URLs to valid destinations.',
      remediation: 'Fix href targets or configure 301 redirects for moved pages.',
      verification: 'Re-run site scan and confirm HTTP 200 responses.',
      status: 'open',
    });
  }

  const crawledMissingTitle = [...(feInput.crawledPagesMissingTitle || [])].sort();
  if (crawledMissingTitle.length > 0) {
    push({
      ruleId: 'FE_CRAWL_MISSING_TITLES',
      subCategory: 'seo',
      confidence: 'verified_direct',
      category: 'frontend',
      title: 'Crawled Sub-Pages Missing <title> Metadata',
      severity: 'low',
      priorityGroup: 'optimization',
      description: `${crawledMissingTitle.length} crawled same-origin page(s) lacked a non-empty <title> tag.`,
      evidence: `Examples: ${crawledMissingTitle.slice(0, 3).join(', ')}`,
      affectedUrl: crawledMissingTitle[0],
      observedValue: `${crawledMissingTitle.length} page(s)`,
      impact: 'Secondary pages without unique titles hurt usability and search indexing.',
      recommendation: 'Ensure every route renders a descriptive, unique <title> element.',
      remediation: '<title>Page Section — Brand</title>',
      verification: 'Inspect crawled sub-page <head> tags.',
      status: 'open',
    });
  }

  // Optional Lighthouse / PageSpeed Insights result
  if (feInput.lighthouse.available && feInput.lighthouse.performanceScore !== undefined) {
    const perf = feInput.lighthouse.performanceScore;
    push({
      ruleId: 'PERF_PAGESPEED',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'frontend',
      title: 'Google PageSpeed Insights Lighthouse Measurements',
      severity: perf < 50 ? 'high' : perf < 80 ? 'medium' : 'passed',
      priorityGroup: perf < 80 ? 'optimization' : 'best_practice',
      description: `Real Google PageSpeed Insights (${feInput.lighthouse.dataType === 'field_and_lab' ? 'Field CrUX + Lab Lighthouse' : 'Lab Lighthouse'}) reported Performance ${perf}/100, Accessibility ${feInput.lighthouse.accessibilityScore ?? 'N/A'}/100, SEO ${feInput.lighthouse.seoScore ?? 'N/A'}/100.`,
      evidence: `LCP: ${feInput.lighthouse.lcpMs ?? 'N/A'}ms | CLS: ${feInput.lighthouse.cls ?? 'N/A'} | FCP: ${feInput.lighthouse.fcpMs ?? 'N/A'}ms | TBT: ${feInput.lighthouse.tbtMs ?? 'N/A'}ms`,
      affectedUrl: feInput.finalUrl,
      observedValue: `Perf ${perf}/100`,
      impact: 'Core Web Vitals directly influence user retention and search ranking.',
      recommendation: 'Optimize Largest Contentful Paint assets and minimize main-thread blocking scripts.',
      remediation: 'Preload hero media, compress images to WebP/AVIF, and code-split large JS bundles.',
      verification: 'Re-run PageSpeed Insights after deployment.',
      status: perf < 80 ? 'open' : 'passed',
    });
  }

  // Transparent WCAG manual review notice (non-penalizing informational guidance)
  push({
    ruleId: 'A11Y_MANUAL_NOTE',
    subCategory: 'accessibility',
    confidence: 'not_assessed',
    manualReviewRequired: true,
    category: 'frontend',
    title: 'Manual Accessibility Review Recommended (Contrast & Keyboard Traps)',
    severity: 'informational',
    priorityGroup: 'best_practice',
    description: 'Static HTML inspection checks alt attributes, form labels, landmarks, button labels, and heading order, but computed visual color contrast, focus visibility, and full keyboard trap behavior require live browser inspection.',
    evidence: 'Static HTML parser does not compute CSS visual contrast ratios or JavaScript keyboard event loops.',
    affectedUrl: feInput.finalUrl,
    observedValue: 'Manual review required',
    impact: 'Verifying contrast >= 4.5:1 and visible keyboard focus prevents WCAG 2.1 AA barriers.',
    recommendation: 'Test interactive tabs, modals, and keyboard navigation using Chrome DevTools or axe DevTools.',
    remediation: 'Ensure focus-visible outlines and WCAG AA contrast ratios across light and dark modes.',
    verification: 'Complete keyboard-only Tab traversal audit.',
    status: 'not_assessed',
  });

  // =========================================================================
  // 3. BACK-END & ARCHITECTURE (Jitter-Resistant Deterministic Latency)
  // =========================================================================
  const effectiveTtfb = feInput.warmTtfbMs ?? feInput.ttfbMs;
  if (effectiveTtfb > 1800) {
    push({
      ruleId: 'BE_TTFB',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'High Time-to-First-Byte (TTFB)',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: `Measured representative TTFB is ${effectiveTtfb} ms (initial: ${feInput.ttfbMs} ms), exceeding 1,800 ms for responsive origin delivery.`,
      evidence: `Representative TTFB: ${effectiveTtfb} ms | Total response time: ${feInput.totalResponseTimeMs} ms | Status: ${feInput.statusCode}`,
      affectedUrl: feInput.finalUrl,
      observedValue: '> 1800 ms sustained',
      impact: 'Slow initial server response delays every downstream asset download and page render.',
      recommendation: 'Profile server-side database queries, enable edge caching/CDN, and avoid cold-start heavy initialization.',
      remediation: 'Add CDN edge caching headers (Cache-Control: public, s-maxage=300, stale-while-revalidate=60) for cacheable pages.',
      verification: 'Measure TTFB across multiple requests and verify < 500 ms.',
      status: 'open',
    });
  } else if (effectiveTtfb > 1000) {
    push({
      ruleId: 'BE_TTFB',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Moderate Time-to-First-Byte (TTFB)',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: `Measured representative TTFB is ${effectiveTtfb} ms (initial: ${feInput.ttfbMs} ms). Sub-500 ms response times are recommended.`,
      evidence: `Representative TTFB: ${effectiveTtfb} ms | Total response time: ${feInput.totalResponseTimeMs} ms`,
      affectedUrl: feInput.finalUrl,
      observedValue: '1000–1800 ms',
      impact: 'Elevated latency increases perceived wait time on slower networks.',
      recommendation: 'Cache expensive server computations or distribute static pages via a global edge network.',
      remediation: 'Configure edge caching or optimize backend route latency.',
      verification: 'Re-measure TTFB after optimization.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'BE_TTFB',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Responsive Server Time-to-First-Byte (TTFB)',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Origin responded within responsive latency bounds (representative TTFB ${effectiveTtfb} ms; HTTP ${feInput.statusCode}).`,
      evidence: `Representative TTFB: ${effectiveTtfb} ms | Initial TTFB: ${feInput.ttfbMs} ms | Status: ${feInput.statusCode}`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'Healthy (< 1000 ms)',
      impact: 'Low origin latency supports fast First Contentful Paint.',
      recommendation: 'Maintain edge caching and response time monitoring.',
      remediation: 'No action required.',
      verification: 'Verified via live HTTP timing.',
      status: 'passed',
    });
  }

  const cacheControl = getHeader('cache-control');
  if (!cacheControl) {
    push({
      ruleId: 'BE_CACHE_CONTROL',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Missing Cache-Control Header',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: 'The primary response did not include an explicit Cache-Control directive.',
      evidence: 'Cache-Control: Not present in observed response.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Not present',
      impact: 'Without explicit caching directives, proxies and browsers rely on heuristic caching or re-fetch unnecessarily.',
      recommendation: 'Specify Cache-Control explicitly for HTML documents and immutable static assets.',
      remediation: 'HTML: Cache-Control: public, max-age=0, must-revalidate | Assets: Cache-Control: public, max-age=31536000, immutable',
      verification: 'Check Cache-Control header in HTTP response.',
      status: 'open',
    });
  } else if (cacheControl.toLowerCase().includes('no-store') || cacheControl.toLowerCase().includes('no-cache')) {
    push({
      ruleId: 'BE_CACHE_CONTROL',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Cache-Control Restricts Public Caching',
      severity: 'informational',
      priorityGroup: 'optimization',
      description: `Cache-Control is set to "${cacheControl}", preventing edge/shared caching of the landing document.`,
      evidence: `Cache-Control: ${cacheControl}`,
      affectedUrl: feInput.finalUrl,
      observedValue: cacheControl,
      impact: 'Appropriate for authenticated/private responses, but reduces CDN cache hit rates on public marketing pages.',
      recommendation: 'Confirm whether public pages can use s-maxage or stale-while-revalidate.',
      remediation: 'Cache-Control: public, max-age=0, s-maxage=300, stale-while-revalidate=60',
      verification: 'Verify cache hit ratio at your CDN/proxy.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'BE_CACHE_CONTROL',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Cache-Control Policy Configured',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Response includes explicit caching directives: "${cacheControl}".`,
      evidence: `Cache-Control: ${cacheControl}`,
      affectedUrl: feInput.finalUrl,
      observedValue: cacheControl,
      impact: 'Enables predictable browser and CDN caching behavior.',
      recommendation: 'Ensure authenticated endpoints remain marked private, no-store.',
      remediation: 'No action required.',
      verification: 'Header verified.',
      status: 'passed',
    });
  }

  const contentEncoding = getHeader('content-encoding');
  if (!contentEncoding && feInput.htmlSizeBytes > 2048) {
    push({
      ruleId: 'BE_COMPRESSION',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'HTTP Response Compression Not Observed',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: 'The HTML response did not advertise gzip or Brotli compression (Content-Encoding).',
      evidence: `Content-Encoding: Absent | Raw HTML size: ${(feInput.htmlSizeBytes / 1024).toFixed(1)} KB`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'Uncompressed',
      impact: 'Uncompressed text payloads consume significantly more bandwidth and slow page loads.',
      recommendation: 'Enable Brotli (br) or gzip compression on your web server or CDN.',
      remediation: 'Nginx: gzip on; gzip_types text/html application/javascript text/css;',
      verification: 'Send Accept-Encoding: br, gzip and confirm Content-Encoding in response.',
      status: 'open',
    });
  } else if (contentEncoding) {
    push({
      ruleId: 'BE_COMPRESSION',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: `Response Compression Active (${contentEncoding})`,
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Payload transfer uses ${contentEncoding} compression.`,
      evidence: `Content-Encoding: ${contentEncoding}`,
      affectedUrl: feInput.finalUrl,
      observedValue: contentEncoding,
      impact: 'Reduces payload transfer size and improves load speed.',
      recommendation: 'Keep Brotli prioritized over gzip where supported.',
      remediation: 'No action required.',
      verification: 'Header verified.',
      status: 'passed',
    });
  }

  const corsOrigin = getHeader('access-control-allow-origin');
  const corsCreds = getHeader('access-control-allow-credentials');
  if (corsOrigin === '*' && corsCreds === 'true') {
    push({
      ruleId: 'BE_CORS_WILDCARD',
      subCategory: 'headers',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Unsafe CORS Wildcard Combined With Credentials',
      severity: 'high',
      priorityGroup: 'fix_immediately',
      description: 'Access-Control-Allow-Origin: * is paired with Access-Control-Allow-Credentials: true.',
      evidence: `Access-Control-Allow-Origin: ${corsOrigin} | Access-Control-Allow-Credentials: ${corsCreds}`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'ACAO=* with ACAC=true',
      impact: 'Indicates misconfigured cross-origin trust policy.',
      recommendation: 'Allowlist explicit trusted origins rather than using wildcard CORS on credentialed responses.',
      remediation: 'Validate Origin header against an explicit allowlist before echoing it.',
      verification: 'Test CORS headers with an untrusted Origin request header.',
      status: 'open',
    });
  }

  if (feInput.redirectCount > 2) {
    push({
      ruleId: 'BE_REDIRECT_CHAIN',
      subCategory: 'performance',
      confidence: 'verified_direct',
      category: 'backend',
      title: 'Excessive Redirect Chain',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: `Target required ${feInput.redirectCount} HTTP redirects before reaching ${feInput.finalUrl}.`,
      evidence: `Redirect hops: ${feInput.redirectCount}`,
      affectedUrl: feInput.targetUrl,
      observedValue: `${feInput.redirectCount} redirects`,
      impact: 'Each redirect hop adds a full network round trip before HTML loading starts.',
      recommendation: 'Collapse multi-hop redirects (e.g., http -> https -> www) into a single hop.',
      remediation: 'Redirect directly to the canonical HTTPS host in one rule.',
      verification: 'Trace redirects and confirm <= 1 hop.',
      status: 'open',
    });
  }

  // =========================================================================
  // 4. PRODUCT, SEO & ENGAGEMENT
  // =========================================================================
  const ctaCandidates = $('a, button').filter((_, el) => {
    const txt = $(el).text().trim().toLowerCase();
    return /(get started|sign up|start|try|book|contact|buy|analyze|subscribe|demo|learn more|join|download|request)/.test(txt);
  }).length;
  const hasForms = formCount > 0;
  const navLinks = $('nav a').length;
  const hasSemanticMain = $('main').length > 0;
  const hasSemanticFooter = $('footer').length > 0;
  const bodyWords = $('body').text().replace(/\s+/g, ' ').trim().split(' ').filter(Boolean).length;

  if (h1Count === 0) {
    push({
      ruleId: 'ENG_H1',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'engagement',
      title: 'No Primary H1 Headline Found in Static HTML',
      severity: 'medium',
      priorityGroup: 'fix_soon',
      description: 'Static HTML does not contain an <h1> heading element. (Note: client-rendered SPAs may inject headings after JavaScript execution.)',
      evidence: `Static heading counts — H1: ${h1Count}, H2: ${h2Count}, H3: ${h3Count}`,
      affectedUrl: feInput.finalUrl,
      observedValue: '0 <h1> elements in static HTML',
      impact: 'Visitors and search crawlers rely on a clear primary <h1> headline to immediately understand the page offering.',
      recommendation: 'Include a single, clear <h1> headline in server-rendered or initial HTML.',
      remediation: '<h1>Clear value proposition for your visitors</h1>',
      verification: 'Inspect initial HTML for a single semantic <h1>.',
      status: 'open',
    });
  } else if (h1Count > 1) {
    push({
      ruleId: 'ENG_H1',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Multiple H1 Headlines Present',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: `Found ${h1Count} <h1> elements on the page; a single primary <h1> improves hierarchy.`,
      evidence: `H1 count: ${h1Count}, H2 count: ${h2Count}`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${h1Count} H1 tags`,
      impact: 'Multiple top-level headings dilute visual and semantic hierarchy.',
      recommendation: 'Keep one primary <h1> per page and use <h2>–<h3> for subsections.',
      remediation: 'Convert secondary <h1> elements to <h2>.',
      verification: 'Verify document heading outline.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'ENG_H1',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Clear Heading Hierarchy (Single H1)',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Page establishes clear visual hierarchy with 1 primary <h1> and ${h2Count} <h2> section headings.`,
      evidence: `H1: 1, H2: ${h2Count}, H3: ${h3Count}`,
      affectedUrl: feInput.finalUrl,
      observedValue: `1 H1 · ${h2Count} H2`,
      impact: 'Supports rapid scanning and assistive navigation.',
      recommendation: 'Maintain sequential heading levels without skipping tiers.',
      remediation: 'No action required.',
      verification: 'Heading structure verified.',
      status: 'passed',
    });
  }

  if (ctaCandidates === 0 && !hasForms && bodyWords > 20) {
    push({
      ruleId: 'ENG_CTA',
      subCategory: 'content',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Low Call-to-Action (CTA) Visibility in Static HTML',
      severity: 'medium',
      priorityGroup: 'optimization',
      description: 'No clear action-oriented CTA buttons or forms were detected in the initial HTML.',
      evidence: `Action CTA links/buttons detected: ${ctaCandidates}, Forms: ${formCount}, Word count: ${bodyWords}`,
      affectedUrl: feInput.finalUrl,
      observedValue: '0 primary CTAs detected',
      impact: 'Visitors without a clear next step convert at lower rates.',
      recommendation: 'Place one prominent primary CTA above the fold with clear action language.',
      remediation: '<a href="/start" class="cta-primary">Start Free Audit</a>',
      verification: 'Review hero section for a single clear primary action.',
      status: 'open',
    });
  } else if (ctaCandidates > 0 || hasForms) {
    push({
      ruleId: 'ENG_CTA',
      subCategory: 'content',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Call-to-Action Elements Present',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: `Detected ${ctaCandidates} action-oriented CTA control(s) and ${formCount} interactive form(s).`,
      evidence: `CTA controls: ${ctaCandidates} | Forms: ${formCount}`,
      affectedUrl: feInput.finalUrl,
      observedValue: `${ctaCandidates} CTAs`,
      impact: 'Provides clear conversion pathways for visitors.',
      recommendation: 'Keep one dominant primary CTA per viewport section to avoid decision fatigue.',
      remediation: 'No action required.',
      verification: 'CTA elements verified.',
      status: 'passed',
    });
  }

  if (!hasSemanticMain && bodyWords > 20) {
    push({
      ruleId: 'A11Y_LANDMARK_MAIN',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'frontend',
      title: 'Missing Semantic <main> Landmark Element',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: 'Static HTML lacks a <main> landmark region for primary page content (WCAG 1.3.1 / 2.4.1).',
      evidence: `<main> count: 0, <nav> links: ${navLinks}, <footer>: ${hasSemanticFooter}`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'No <main> landmark',
      impact: 'Screen-reader users cannot jump straight to primary content via landmark navigation.',
      recommendation: 'Wrap the primary page body content inside a single <main> element.',
      remediation: '<header><nav>...</nav></header><main>...</main><footer>...</footer>',
      verification: 'Inspect landmark outline in browser accessibility tree.',
      status: 'open',
    });
  }

  if (navLinks === 0 && !hasSemanticMain && bodyWords > 20) {
    push({
      ruleId: 'ENG_LANDMARKS',
      subCategory: 'accessibility',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Semantic Landmarks & Navigation Signals Limited',
      severity: 'low',
      priorityGroup: 'best_practice',
      description: 'Static HTML lacks semantic <nav> links or a <main> landmark.',
      evidence: `<nav> links: ${navLinks}, <main>: ${hasSemanticMain}, <footer>: ${hasSemanticFooter}`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'Missing <nav>/<main>',
      impact: 'Semantic landmarks improve keyboard skip-navigation and structural clarity.',
      recommendation: 'Wrap primary navigation in <nav> and primary content in <main>.',
      remediation: '<header><nav>...</nav></header><main>...</main><footer>...</footer>',
      verification: 'Inspect landmark structure in HTML.',
      status: 'open',
    });
  }

  if (!ogTitle || !canonical) {
    push({
      ruleId: 'SEO_OG_CANONICAL',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Social Share (Open Graph) or Canonical Metadata Incomplete',
      severity: 'low',
      priorityGroup: 'optimization',
      description: `Observed og:title=${ogTitle ? 'present' : 'missing'}, canonical=${canonical ? 'present' : 'missing'}.`,
      evidence: `og:title: ${ogTitle || 'Missing'} | rel=canonical: ${canonical || 'Missing'}`,
      affectedUrl: feInput.finalUrl,
      observedValue: `OG:${ogTitle ? 'Yes' : 'No'} Canonical:${canonical ? 'Yes' : 'No'}`,
      impact: 'Missing Open Graph tags reduce link-share clarity; missing canonical links can dilute duplicate URL indexing.',
      recommendation: 'Add og:title, og:description, og:image, and <link rel="canonical">.',
      remediation: '<link rel="canonical" href="https://example.com/" />\n<meta property="og:title" content="..." />',
      verification: 'Check document <head> tags.',
      status: 'open',
    });
  } else {
    push({
      ruleId: 'SEO_OG_CANONICAL',
      subCategory: 'seo',
      confidence: 'static_html',
      category: 'engagement',
      title: 'Open Graph & Canonical Metadata Present',
      severity: 'passed',
      priorityGroup: 'best_practice',
      description: 'Canonical URL and Open Graph sharing metadata are declared in the HTML document head.',
      evidence: `og:title: ${ogTitle.slice(0, 80)} | canonical: ${canonical}`,
      affectedUrl: feInput.finalUrl,
      observedValue: 'OG + Canonical present',
      impact: 'Improves social preview clarity and search engine URL canonicalization.',
      recommendation: 'Keep canonical URLs aligned across paginated and localized routes.',
      remediation: 'No action required.',
      verification: 'Head tags verified.',
      status: 'passed',
    });
  }

  if (!hasRobotsTxt || !hasSitemapXml) {
    push({
      ruleId: 'SEO_CRAWL_FILES',
      subCategory: 'seo',
      confidence: 'verified_direct',
      category: 'engagement',
      title: 'Crawler Guidance Files Incomplete (robots.txt / sitemap.xml)',
      severity: 'informational',
      priorityGroup: 'optimization',
      description: `Observed robots.txt=${hasRobotsTxt ? 'HTTP 200' : 'absent'}, sitemap.xml=${hasSitemapXml ? 'HTTP 200' : 'absent'}.`,
      evidence: `robots.txt: ${hasRobotsTxt ? 'Found' : 'Not found'} | sitemap.xml: ${hasSitemapXml ? 'Found' : 'Not found'}`,
      affectedUrl: `${new URL(secInput.finalUrl).origin}/robots.txt`,
      observedValue: `robots:${hasRobotsTxt ? 'Yes' : 'No'} sitemap:${hasSitemapXml ? 'Yes' : 'No'}`,
      impact: 'XML sitemaps and robots.txt guide search engine indexing efficiently.',
      recommendation: 'Publish robots.txt and a valid sitemap.xml referencing canonical public pages.',
      remediation: 'User-agent: *\nAllow: /\nSitemap: https://yourdomain.com/sitemap.xml',
      verification: 'Fetch /robots.txt and /sitemap.xml and confirm HTTP 200.',
      status: 'open',
    });
  }

  // =========================================================================
  // 5. TRANSPARENT UNVERIFIED / INTEGRATION-REQUIRED OBSERVATIONS
  // =========================================================================
  if (!coverage.databaseVerified) {
    push({
      ruleId: 'EXT_DB_NOT_ASSESSED',
      subCategory: 'infrastructure',
      confidence: 'not_assessed',
      category: 'database',
      title: 'Database Security Not Assessed from Public URL',
      severity: 'informational',
      priorityGroup: 'long_term',
      description: 'A public website URL does not expose private database configuration, access policies, or encryption state.',
      evidence: 'No authorized Firebase, Supabase, or read-only PostgreSQL integration is connected for this target.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Not assessed (Integration required)',
      impact: 'Database permission rules, public exposure, and backup policies cannot be verified externally.',
      recommendation: 'Connect an authorized read-only database integration in the Integrations Center.',
      remediation: 'Navigate to Integrations -> Database Providers to authorize read-only inspection.',
      verification: 'Connect integration and run an owner-authorized database check.',
      status: 'not_assessed',
    });
  }

  if (!coverage.hostingVerified) {
    push({
      ruleId: 'EXT_HOSTING_NOT_ASSESSED',
      subCategory: 'infrastructure',
      confidence: 'not_assessed',
      category: 'hosting',
      title: 'Hosting Configuration Cannot Be Fully Verified Publicly',
      severity: 'informational',
      priorityGroup: 'long_term',
      description: 'Hosting configuration cannot be fully verified from a public website URL without a connected cloud/platform account.',
      evidence: 'No Vercel, Netlify, Cloudflare, AWS, or GCP read-only integration connected.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Not assessed (Integration required)',
      impact: 'Deployment settings, environment metadata, and edge firewall policies remain unverified.',
      recommendation: 'Connect an authorized read-only hosting provider integration to audit platform settings.',
      remediation: 'Connect Vercel, Cloudflare, or Netlify in Integrations.',
      verification: 'Re-run infrastructure audit after authorizing provider access.',
      status: 'not_assessed',
    });
  }

  if (!coverage.backupVerified) {
    push({
      ruleId: 'EXT_BACKUP_NOT_ASSESSED',
      subCategory: 'infrastructure',
      confidence: 'not_assessed',
      category: 'backup',
      title: 'Backup Status Unavailable',
      severity: 'informational',
      priorityGroup: 'long_term',
      description: 'Backup status unavailable — connect an authorized backup provider.',
      evidence: 'No authorized backup integration connected; OriginSec never fabricates backup verification.',
      affectedUrl: feInput.finalUrl,
      observedValue: 'Unavailable',
      impact: 'Recovery point objective (RPO) and backup encryption status cannot be confirmed.',
      recommendation: 'Connect an authorized backup provider in Backup & Recovery.',
      remediation: 'Authorize read-only backup status inspection.',
      verification: 'Verify last successful backup timestamp and restore-test evidence.',
      status: 'not_assessed',
    });
  }

  const scores = calculateCategoryScores(findings, coverage, feInput.lighthouse);
  const findingsCount = countSeverities(findings);
  const postureFingerprint = computePostureFingerprint(findings, scores);

  return {
    findings,
    scores,
    findingsCount,
    postureFingerprint,
    domStats: {
      domNodeCount,
      scriptCount,
      stylesheetCount,
      renderBlockingScripts,
      imageCount,
      imagesWithoutAlt,
      imagesWithoutDimensions,
      linkCount,
      headingCount: { h1: h1Count, h2: h2Count, h3: h3Count },
      frontendDetails,
    },
  };
}

export function countSeverities(findings: ScanFinding[]): FindingsCount {
  const counts: FindingsCount = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    passed: 0,
  };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

const SEVERITY_PENALTIES: Record<SeverityLevel, number> = {
  critical: 24,
  high: 14,
  medium: 7,
  low: 3,
  informational: 0,
  passed: 0,
};

/**
 * Computes deterministic category scores (0-100) from actual assessed checks.
 * Never assigns 100/100 to unmeasured categories or partial static-only sub-scores
 * when Lighthouse / visual contrast verification is absent.
 */
export function calculateCategoryScores(
  findings: ScanFinding[],
  coverage?: ScanCoverage,
  lighthouse?: LighthouseMetrics
): CategoryScores {
  const scoreForCategory = (cat: FindingCategory): number | null => {
    const assessed = findings.filter((f) => f.category === cat && f.status !== 'not_assessed');
    if (assessed.length === 0) return null;

    let score = 100;
    for (const f of assessed) {
      score -= SEVERITY_PENALTIES[f.severity] ?? 0;
    }
    return Math.max(0, Math.min(100, Math.round(score)));
  };

  const scoreForSubCategory = (sub: ScanFinding['subCategory']): number | null => {
    const assessed = findings.filter((f) => f.subCategory === sub && f.status !== 'not_assessed');
    if (assessed.length === 0) return null;
    let score = 100;
    for (const f of assessed) {
      score -= SEVERITY_PENALTIES[f.severity] ?? 0;
    }
    return Math.max(0, Math.min(100, Math.round(score)));
  };

  let security = scoreForCategory('security');
  const frontend = scoreForCategory('frontend');
  let backend = scoreForCategory('backend');
  let engagement = scoreForCategory('engagement');
  let seo = scoreForSubCategory('seo');

  if (security !== null && coverage && coverage.httpsVerified && !coverage.tlsVerified) {
    security = Math.min(85, security);
  }

  if (backend !== null && coverage && !coverage.apiVerified && !coverage.databaseVerified && !coverage.hostingVerified) {
    // External HTTP checks alone cannot verify private backend code, databases, or API auth posture
    backend = Math.min(92, backend);
  }

  if (engagement !== null && coverage && !lighthouse?.available) {
    engagement = Math.min(92, engagement);
  }

  if (seo !== null && coverage && !lighthouse?.available) {
    seo = Math.min(92, seo);
  }

  let performance = scoreForSubCategory('performance');
  if (performance !== null) {
    if (lighthouse?.available && lighthouse.performanceScore !== undefined) {
      performance = Math.max(0, Math.min(100, Math.round(lighthouse.performanceScore * 0.7 + performance * 0.3)));
    } else {
      // Without real browser Core Web Vitals (LCP/CLS/INP), static HTTP timing cannot claim 100/100
      performance = Math.min(85, performance);
    }
  }

  let accessibility = scoreForSubCategory('accessibility');
  if (accessibility !== null) {
    if (lighthouse?.available && lighthouse.accessibilityScore !== undefined) {
      accessibility = Math.max(0, Math.min(100, Math.round(lighthouse.accessibilityScore * 0.65 + accessibility * 0.35)));
    } else {
      // Static HTML checks cannot verify color contrast or keyboard focus traps
      accessibility = Math.min(88, accessibility);
    }
  }

  const valid = [security, frontend, backend, engagement].filter((s): s is number => s !== null);
  const overall = valid.length > 0 ? Math.round(valid.reduce((a, b) => a + b, 0) / valid.length) : null;

  return {
    security,
    frontend,
    backend,
    engagement,
    overall,
    seo,
    accessibility,
    performance,
  };
}

export function buildExecutiveSummary(
  domain: string,
  scores: CategoryScores,
  findings: ScanFinding[],
  coverage: ScanCoverage
): string {
  const openActionable = findings.filter(
    (f) => f.status === 'open' && (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium' || f.severity === 'low')
  );
  const criticalOrHigh = openActionable.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const passedCount = findings.filter((f) => f.severity === 'passed').length;

  const parts: string[] = [];

  if (scores.overall !== null) {
    if (scores.overall >= 85) {
      parts.push(`${domain} demonstrates a strong externally observable posture (${scores.overall}/100 overall across ${coverage.pagesScanned} scanned page${coverage.pagesScanned === 1 ? '' : 's'}), with ${passedCount} verified passing checks.`);
    } else if (scores.overall >= 65) {
      parts.push(`The external assessment of ${domain} (${scores.overall}/100 overall) identified ${openActionable.length} actionable improvement${openActionable.length === 1 ? '' : 's'} alongside ${passedCount} passing checks.`);
    } else {
      parts.push(`The external assessment of ${domain} (${scores.overall}/100 overall) flagged ${criticalOrHigh.length} high/critical priority issue${criticalOrHigh.length === 1 ? '' : 's'} requiring prompt attention.`);
    }
  } else {
    parts.push(`Assessment of ${domain} completed with limited external signals.`);
  }

  if (criticalOrHigh.length > 0) {
    const topTitles = criticalOrHigh.slice(0, 2).map((f) => f.title).join(' and ');
    parts.push(`Key priorities include resolving ${topTitles}.`);
  }

  if (!coverage.databaseVerified || !coverage.hostingVerified || !coverage.backupVerified) {
    parts.push('Database, hosting, and backup configurations remain unverified because no owner integration is connected.');
  }

  return parts.join(' ');
}
