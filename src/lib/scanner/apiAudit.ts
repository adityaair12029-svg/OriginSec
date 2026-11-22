import type { ApiProbeResult } from '../../types/audit';
import { safeFetchText } from './engine.js';
import { resolveAndVerifyHost, validateTargetUrl } from './ssrf.js';

export interface ApiAuditRequest {
  mode: 'public' | 'verified_owner';
  baseUrl: string;
  endpoints: string[];
  openApiSpecText?: string;
}

/**
 * Extracts safe, non-destructive GET/HEAD endpoints from an uploaded OpenAPI 3.x / Swagger 2.0 JSON document.
 */
export function extractEndpointsFromOpenApi(specText: string): {
  endpoints: Array<{ method: string; path: string; requiresAuth: boolean }>;
  error?: string;
} {
  try {
    const parsed = JSON.parse(specText) as Record<string, any>;
    const paths = parsed.paths;
    if (!paths || typeof paths !== 'object') {
      return { endpoints: [], error: 'OpenAPI document does not contain a valid "paths" object.' };
    }

    const globalSecurity = Array.isArray(parsed.security) && parsed.security.length > 0;
    const extracted: Array<{ method: string; path: string; requiresAuth: boolean }> = [];

    for (const [pathStr, rawPathItem] of Object.entries(paths)) {
      if (!rawPathItem || typeof rawPathItem !== 'object') continue;
      const pathItem = rawPathItem as Record<string, any>;
      for (const method of ['get', 'head', 'options']) {
        if (pathItem[method]) {
          const op = pathItem[method] as Record<string, any>;
          const opSec = Array.isArray(op.security) ? op.security.length > 0 : globalSecurity;
          extracted.push({
            method: method.toUpperCase(),
            path: pathStr,
            requiresAuth: opSec,
          });
        }
      }
      if (extracted.length >= 15) break;
    }

    return { endpoints: extracted };
  } catch {
    return { endpoints: [], error: 'Failed to parse OpenAPI JSON. Please provide valid JSON OpenAPI/Swagger specification.' };
  }
}

/**
 * Performs safe, non-destructive API endpoint probing with strict SSRF protection.
 * Mode A ('public') only checks user-supplied public URLs (max 5).
 * Mode B ('verified_owner') supports up to 15 explicitly documented endpoints.
 */
export async function runApiAudit(req: ApiAuditRequest): Promise<ApiProbeResult[]> {
  const validatedBase = validateTargetUrl(req.baseUrl);
  if (!validatedBase.valid || !validatedBase.normalizedUrl || !validatedBase.hostname) {
    return [
      {
        endpoint: req.baseUrl,
        method: 'GET',
        statusCode: null,
        responseTimeMs: 0,
        contentType: null,
        corsHeader: null,
        cacheControl: null,
        timestamp: new Date().toISOString(),
        evidence: validatedBase.error || 'Invalid base URL',
        severity: 'high',
        description: 'Base API URL failed validation or SSRF safety policy.',
        recommendation: 'Provide a valid public http:// or https:// API base URL.',
        verificationStatus: 'blocked_ssrf',
      },
    ];
  }

  const resolved = await resolveAndVerifyHost(validatedBase.hostname);
  if (!resolved.safe) {
    return [
      {
        endpoint: validatedBase.normalizedUrl,
        method: 'GET',
        statusCode: null,
        responseTimeMs: 0,
        contentType: null,
        corsHeader: null,
        cacheControl: null,
        timestamp: new Date().toISOString(),
        evidence: resolved.error || 'Blocked by SSRF policy',
        severity: 'high',
        description: 'API host resolved to a private or reserved network destination.',
        recommendation: 'Only public API endpoints can be probed.',
        verificationStatus: 'blocked_ssrf',
      },
    ];
  }

  const maxCount = req.mode === 'verified_owner' ? 15 : 5;
  const endpointList = (req.endpoints.length > 0 ? req.endpoints : ['/']).slice(0, maxCount);
  const results: ApiProbeResult[] = [];

  for (const rawPath of endpointList) {
    const cleanPath = rawPath.trim();
    if (!cleanPath) continue;

    let fullUrl: string;
    try {
      const target = new URL(cleanPath, validatedBase.normalizedUrl);
      if (target.origin !== new URL(validatedBase.normalizedUrl).origin) {
        results.push({
          endpoint: cleanPath,
          method: 'GET',
          statusCode: null,
          responseTimeMs: 0,
          contentType: null,
          corsHeader: null,
          cacheControl: null,
          timestamp: new Date().toISOString(),
          evidence: 'Cross-origin endpoint skipped; endpoints must match the base URL origin.',
          severity: 'informational',
          description: 'Endpoint origin differs from the target API base URL.',
          recommendation: 'Provide relative paths or same-origin endpoints.',
          verificationStatus: 'blocked_ssrf',
        });
        continue;
      }
      fullUrl = target.toString();
    } catch {
      continue;
    }

    const res = await safeFetchText(fullUrl, { timeoutMs: 6000, maxBytes: 256 * 1024 });
    const ct = res.headers['content-type'] || null;
    const cors = res.headers['access-control-allow-origin'] || null;
    const cc = res.headers['cache-control'] || null;
    const statusCode = res.statusCode || null;

    let severity: ApiProbeResult['severity'] = 'passed';
    let description = `Endpoint responded with HTTP ${statusCode ?? 'error'} in ${res.ttfbMs} ms.`;
    let recommendation = 'Maintain current response headers and latency budgets.';

    if (!res.ok || statusCode === null) {
      severity = 'high';
      description = `Endpoint failed to respond cleanly: ${res.error || 'Network failure'}.`;
      recommendation = 'Verify endpoint routing, TLS configuration, and origin health.';
    } else if (statusCode >= 500) {
      severity = 'high';
      description = `Endpoint returned server error HTTP ${statusCode} on a standard GET request.`;
      recommendation = 'Inspect backend logs and ensure graceful error handling without stack traces.';
    } else if (cors === '*' && res.headers['access-control-allow-credentials'] === 'true') {
      severity = 'high';
      description = 'Endpoint combines Access-Control-Allow-Origin: * with Allow-Credentials: true.';
      recommendation = 'Restrict Access-Control-Allow-Origin to explicit trusted origins.';
    } else if (!res.headers['x-content-type-options']) {
      severity = 'low';
      description = `HTTP ${statusCode} response lacks X-Content-Type-Options: nosniff.`;
      recommendation = 'Return X-Content-Type-Options: nosniff on API responses.';
    } else if (statusCode === 401 || statusCode === 403) {
      severity = 'passed';
      description = `Endpoint properly requires authentication/authorization (HTTP ${statusCode}).`;
      recommendation = 'Authentication enforcement verified without sending credentials.';
    }

    results.push({
      endpoint: fullUrl,
      method: 'GET',
      statusCode,
      responseTimeMs: res.ttfbMs,
      contentType: ct,
      corsHeader: cors,
      cacheControl: cc,
      timestamp: new Date().toISOString(),
      evidence: `Status: ${statusCode ?? 'N/A'} | Content-Type: ${ct || 'absent'} | CORS: ${cors || 'absent'} | Cache-Control: ${cc || 'absent'}`,
      severity,
      description,
      recommendation,
      verificationStatus: req.mode === 'verified_owner' ? 'verified_owner' : 'public_observed',
    });
  }

  return results;
}
