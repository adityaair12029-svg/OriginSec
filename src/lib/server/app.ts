import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { extractEndpointsFromOpenApi, runApiAudit } from '../scanner/apiAudit';
import {
  cancelJob,
  getJobState,
  inspectTlsCertificate,
  runScanJobAndWait,
  safeFetchText,
  startScanJob,
} from '../scanner/engine';
import { generateVerificationChallenge, verifyDomainOwnership } from '../scanner/ownership';
import { resolveAndVerifyHost, validateTargetUrl } from '../scanner/ssrf';
import { verifyRequestAuth } from './auth';
import { explainScanFindingsWithGemini, isGeminiConfigured } from './gemini';

const isProduction = process.env.NODE_ENV === 'production';
const isVercelRuntime = Boolean(process.env.VERCEL);

const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (bucket.count >= maxRequests) {
    return false;
  }
  bucket.count++;
  return true;
}

const StartScanSchema = z.object({
  targetUrl: z.string().min(3).max(2048),
  authorizedConfirmed: z.literal(true, {
    error: 'You must confirm that you own the website or have permission to assess it.',
  }),
  maxPages: z.number().int().min(1).max(20).optional(),
  crawlDepth: z.number().int().min(0).max(2).optional(),
  isDomainVerified: z.boolean().optional(),
  sync: z.boolean().optional(),
});

const ChallengeSchema = z.object({
  domain: z.string().min(3).max(255),
});

const VerifyOwnershipSchema = z.object({
  domain: z.string().min(3).max(255),
  method: z.enum(['dns_txt', 'html_meta', 'well_known']),
  challengeToken: z.string().min(8).max(128),
});

const ApiAuditSchema = z.object({
  mode: z.enum(['public', 'verified_owner']),
  baseUrl: z.string().min(4).max(2048),
  endpoints: z.array(z.string().max(500)).max(20).default([]),
  openApiSpecText: z.string().max(500_000).optional(),
});

const MonitoringCheckSchema = z.object({
  targetUrl: z.string().min(4).max(2048),
});

const AiExplainSchema = z.object({
  audience: z.enum(['owner', 'developer']),
  scan: z.object({
    normalizedDomain: z.string().max(255),
    targetUrl: z.string().max(2048),
    scores: z.any(),
    coverage: z.any(),
    metrics: z.any(),
    findings: z.array(z.any()).max(100),
  }),
});

export function createApiApp() {
  const app = express();
  app.disable('x-powered-by');

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    if (isProduction) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'OriginSec',
      runtime: isVercelRuntime ? 'serverless' : 'node',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/integrations/status', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const hasFirebaseCfg =
      Boolean(process.env.FIREBASE_PROJECT_ID || process.env.VITE_FIREBASE_PROJECT_ID) ||
      fs.existsSync(path.resolve(process.cwd(), 'firebase-applet-config.json'));
    const hasPageSpeed = Boolean(process.env.PAGESPEED_API_KEY && process.env.PAGESPEED_API_KEY.trim().length > 5);
    const hasGemini = isGeminiConfigured();

    res.json({
      authenticated: Boolean(user),
      providers: {
        firebase_auth: { connected: hasFirebaseCfg, label: hasFirebaseCfg ? 'Configured' : 'Not configured' },
        firebase_firestore: { connected: hasFirebaseCfg, label: hasFirebaseCfg ? 'Configured' : 'Not configured' },
        pagespeed_insights: {
          connected: hasPageSpeed,
          label: hasPageSpeed ? 'API key configured on server' : 'Not configured (PAGESPEED_API_KEY optional)',
        },
        gemini_ai: {
          connected: hasGemini,
          label: hasGemini ? 'Server-side Gemini API active' : 'Not configured (GEMINI_API_KEY optional)',
        },
      },
    });
  });

  // Start Website Scan (automatically awaits completion on serverless runtimes like Vercel)
  app.post('/api/scans', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `scan:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, user ? 25 : 10, 10 * 60 * 1000)) {
      res.status(429).json({ error: 'Scan rate limit reached. Please wait a few minutes before starting another scan.' });
      return;
    }

    const parsed = StartScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid scan request.' });
      return;
    }

    const validated = validateTargetUrl(parsed.data.targetUrl);
    if (!validated.valid || !validated.normalizedUrl) {
      res.status(400).json({ error: validated.error || 'Invalid target URL.' });
      return;
    }

    const ownerUid = user?.uid || `guest_${req.ip || 'anonymous'}`;
    const shouldRunSync = isVercelRuntime || Boolean(parsed.data.sync);

    if (shouldRunSync) {
      const completedJob = await runScanJobAndWait({
        ownerUid,
        targetUrl: validated.normalizedUrl,
        maxPages: Math.min(8, parsed.data.maxPages ?? 8),
        crawlDepth: parsed.data.crawlDepth ?? 1,
        isDomainVerified: parsed.data.isDomainVerified,
        serverlessBudgetMs: 18000,
      });

      if (completedJob.status === 'failed') {
        res.status(422).json({
          scanId: completedJob.scanId,
          status: completedJob.status,
          currentStage: completedJob.currentStage,
          progressPercent: completedJob.progressPercent,
          stagesLog: completedJob.stagesLog,
          error: completedJob.error || 'Website scan could not be completed.',
        });
        return;
      }

      res.status(200).json({
        scanId: completedJob.scanId,
        status: completedJob.status,
        currentStage: completedJob.currentStage,
        progressPercent: completedJob.progressPercent,
        targetUrl: completedJob.targetUrl,
        normalizedDomain: completedJob.normalizedDomain,
        stagesLog: completedJob.stagesLog,
        error: completedJob.error,
        result: completedJob.result,
      });
      return;
    }

    const job = startScanJob({
      ownerUid,
      targetUrl: validated.normalizedUrl,
      maxPages: parsed.data.maxPages,
      crawlDepth: parsed.data.crawlDepth,
      isDomainVerified: parsed.data.isDomainVerified,
    });

    res.status(202).json({
      scanId: job.scanId,
      status: job.status,
      currentStage: job.currentStage,
      progressPercent: job.progressPercent,
      targetUrl: job.targetUrl,
      normalizedDomain: job.normalizedDomain,
    });
  });

  app.get('/api/scans/:scanId/progress', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const job = getJobState(req.params.scanId);
    if (!job) {
      res.status(404).json({ error: 'Active scan job not found or expired. Saved scans are available in Scan History.' });
      return;
    }

    if (!job.ownerUid.startsWith('guest_') && (!user || user.uid !== job.ownerUid)) {
      res.status(403).json({ error: 'Unauthorized to access this scan job.' });
      return;
    }

    res.json({
      scanId: job.scanId,
      status: job.status,
      currentStage: job.currentStage,
      progressPercent: job.progressPercent,
      stagesLog: job.stagesLog,
      error: job.error,
      result: job.result,
    });
  });

  app.post('/api/scans/:scanId/cancel', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const job = getJobState(req.params.scanId);
    if (!job) {
      res.status(404).json({ error: 'Active scan job not found.' });
      return;
    }

    const callerUid = user?.uid || job.ownerUid;
    if (!job.ownerUid.startsWith('guest_') && (!user || user.uid !== job.ownerUid)) {
      res.status(403).json({ error: 'Unauthorized to cancel this scan.' });
      return;
    }

    const cancelled = cancelJob(req.params.scanId, callerUid);
    res.json({ cancelled, status: job.status });
  });

  app.post('/api/ownership/challenge', async (req, res) => {
    const user = await verifyRequestAuth(req);
    if (!user) {
      res.status(401).json({ error: 'Sign in with Google to verify domain ownership.' });
      return;
    }

    const parsed = ChallengeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid domain parameter.' });
      return;
    }

    const validated = validateTargetUrl(parsed.data.domain);
    if (!validated.valid || !validated.hostname) {
      res.status(400).json({ error: validated.error || 'Invalid domain name.' });
      return;
    }

    const challenge = generateVerificationChallenge(validated.hostname);
    res.json(challenge);
  });

  app.post('/api/ownership/verify', async (req, res) => {
    const user = await verifyRequestAuth(req);
    if (!user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const parsed = VerifyOwnershipSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid ownership verification request.' });
      return;
    }

    const result = await verifyDomainOwnership(parsed.data);
    res.json(result);
  });

  app.post('/api/api-audit', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `apiaudit:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, 20, 10 * 60 * 1000)) {
      res.status(429).json({ error: 'API audit rate limit reached. Try again shortly.' });
      return;
    }

    const parsed = ApiAuditSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid API audit payload.' });
      return;
    }

    if (parsed.data.mode === 'verified_owner' && !user) {
      res.status(401).json({ error: 'Sign in with Google and verify domain ownership to run Verified Owner API Audits.' });
      return;
    }

    let endpoints = parsed.data.endpoints;
    let parsedOpenApiMeta: Array<{ method: string; path: string; requiresAuth: boolean }> = [];
    if (parsed.data.openApiSpecText) {
      const extracted = extractEndpointsFromOpenApi(parsed.data.openApiSpecText);
      if (extracted.error) {
        res.status(400).json({ error: extracted.error });
        return;
      }
      parsedOpenApiMeta = extracted.endpoints;
      endpoints = [...endpoints, ...extracted.endpoints.map((e) => e.path)];
    }

    const results = await runApiAudit({
      mode: parsed.data.mode,
      baseUrl: parsed.data.baseUrl,
      endpoints: Array.from(new Set(endpoints)),
      openApiSpecText: parsed.data.openApiSpecText,
    });

    res.json({ results, parsedOpenApiEndpoints: parsedOpenApiMeta });
  });

  app.post('/api/monitoring/check', async (req, res) => {
    const user = await verifyRequestAuth(req);
    if (!user) {
      res.status(401).json({ error: 'Sign in with Google to run monitoring checks.' });
      return;
    }

    if (!checkRateLimit(`monitor:${user.uid}`, 40, 10 * 60 * 1000)) {
      res.status(429).json({ error: 'Monitoring check rate limit reached.' });
      return;
    }

    const parsed = MonitoringCheckSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid monitoring URL.' });
      return;
    }

    const validated = validateTargetUrl(parsed.data.targetUrl);
    if (!validated.valid || !validated.normalizedUrl || !validated.hostname) {
      res.status(400).json({ error: validated.error || 'Invalid URL.' });
      return;
    }

    const resolved = await resolveAndVerifyHost(validated.hostname);
    if (!resolved.safe) {
      res.status(400).json({ error: resolved.error || 'Target blocked by SSRF policy.' });
      return;
    }

    const [httpRes, tlsInfo] = await Promise.all([
      safeFetchText(validated.normalizedUrl, { timeoutMs: 7000, maxBytes: 65536 }),
      validated.protocol === 'https:' ? inspectTlsCertificate(validated.hostname, resolved.primaryAddress) : Promise.resolve(null),
    ]);

    const status =
      !httpRes.ok || httpRes.statusCode >= 500 || httpRes.statusCode === 0
        ? 'down'
        : httpRes.statusCode >= 400 || httpRes.ttfbMs > 1500
          ? 'degraded'
          : 'up';

    res.json({
      status,
      httpStatus: httpRes.statusCode || null,
      responseTimeMs: httpRes.ttfbMs,
      sslExpiryDays: tlsInfo?.daysRemaining ?? null,
      details: httpRes.ok
        ? `HTTP ${httpRes.statusCode} in ${httpRes.ttfbMs} ms${tlsInfo?.daysRemaining !== null && tlsInfo?.daysRemaining !== undefined ? ` · TLS valid ${tlsInfo.daysRemaining}d` : ''}`
        : httpRes.error || 'Target unreachable',
      checkedAt: new Date().toISOString(),
    });
  });

  app.post('/api/ai/explain', async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `ai:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, 15, 10 * 60 * 1000)) {
      res.status(429).json({ error: 'AI explanation rate limit reached. Please wait briefly.' });
      return;
    }

    const parsed = AiExplainSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid AI explanation request payload.' });
      return;
    }

    const result = await explainScanFindingsWithGemini({
      scan: parsed.data.scan,
      audience: parsed.data.audience,
    });

    if (!result.available) {
      res.status(503).json({ error: result.error });
      return;
    }
    if (result.error) {
      res.status(502).json({ error: result.error });
      return;
    }

    res.json({ explanation: result.explanation, generatedAt: new Date().toISOString() });
  });

  return app;
}
