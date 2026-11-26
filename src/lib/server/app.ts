import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { extractEndpointsFromOpenApi, runApiAudit } from '../scanner/apiAudit.js';
import {
  cancelJob,
  findInFlightJob,
  getJobState,
  inspectTlsCertificate,
  runScanJobAndWait,
  safeFetchText,
  startScanJob,
  verifySpecificRemediation,
} from '../scanner/engine.js';
import { generateVerificationChallenge, verifyDomainOwnership } from '../scanner/ownership.js';
import { resolveAndVerifyHost, validateTargetUrl } from '../scanner/ssrf.js';
import { verifyRequestAuth } from './auth.js';
import { askAiAboutScanWithGemini, explainScanFindingsWithGemini, isGeminiConfigured } from './gemini.js';

const isProduction = process.env.NODE_ENV === 'production';
const isVercelRuntime = Boolean(process.env.VERCEL);
const ADMIN_EMAIL = 'adityaair1.2029@gmail.com';

const asyncHandler =
  (fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<void>) =>
  (req: express.Request, res: express.Response, next: express.NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

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
  scanProfile: z
    .enum(['quick', 'standard', 'comprehensive', 'verified_owner', 'performance', 'frontend_quality'])
    .optional(),
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

const RemediationVerifySchema = z.object({
  targetUrl: z.string().min(4).max(2048),
  ruleId: z.string().max(80).optional(),
  title: z.string().min(2).max(240),
});

const AiExplainSchema = z.object({
  audience: z.enum(['owner', 'developer']),
  scan: z.object({
    normalizedDomain: z.string().max(255),
    targetUrl: z.string().max(2048),
    scores: z.any(),
    coverage: z.any(),
    metrics: z.any(),
    findings: z.array(z.any()).max(120),
  }),
});

const AiAskSchema = z.object({
  question: z.string().min(3).max(600),
  scan: z.object({
    normalizedDomain: z.string().max(255),
    targetUrl: z.string().max(2048),
    scores: z.any(),
    coverage: z.any(),
    metrics: z.any(),
    findings: z.array(z.any()).max(120),
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
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (isProduction || isVercelRuntime) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' https://apis.google.com https://accounts.google.com https://www.gstatic.com https://pagead2.googlesyndication.com https://partner.googleadservices.com https://tpc.googlesyndication.com https://adservice.google.com https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google https://fundingchoicesmessages.google.com https://www.googletagservices.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self' https://firestore.googleapis.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com https://apis.google.com https://accounts.google.com https://firebase.googleapis.com https://firebaseinstallations.googleapis.com https://cool-proposal-1c62s.firebaseapp.com https://api.microlink.io https://iad.microlink.io https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google https://fundingchoicesmessages.google.com https://csi.gstatic.com https://adservice.google.com; frame-src 'self' https://cool-proposal-1c62s.firebaseapp.com https://accounts.google.com https://googleads.g.doubleclick.net https://tpc.googlesyndication.com https://ep1.adtrafficquality.google https://ep2.adtrafficquality.google https://www.google.com https://fundingchoicesmessages.google.com; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
      );
    }
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.get('/ads.txt', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send('google.com, pub-8553738834266214, DIRECT, f08c47fec0942fa0\n');
  });

  app.get('/.well-known/security.txt', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(
      [
        'Contact: mailto:adityaair1.2029@gmail.com',
        'Expires: 2027-12-31T23:59:00.000Z',
        'Preferred-Languages: en, hi',
        'Canonical: https://originsec.vercel.app/.well-known/security.txt',
        'Policy: https://originsec.vercel.app/',
        '',
      ].join('\n')
    );
  });

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'OriginSec',
      version: '2.0.0',
      runtime: isVercelRuntime ? 'serverless' : 'node',
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/integrations/status', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    const hasFirebaseCfg =
      Boolean(process.env.FIREBASE_PROJECT_ID || process.env.VITE_FIREBASE_PROJECT_ID) ||
      fs.existsSync(path.resolve(process.cwd(), 'firebase-applet-config.json'));
    const hasPageSpeed = Boolean(process.env.PAGESPEED_API_KEY && process.env.PAGESPEED_API_KEY.trim().length > 5);
    const hasGemini = isGeminiConfigured();
    const hasCronSecret = Boolean(process.env.CRON_SECRET && process.env.CRON_SECRET.trim().length >= 8);
    const hasEmailProvider = Boolean(process.env.RESEND_API_KEY || process.env.SMTP_HOST);

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
        scheduled_cron: {
          connected: hasCronSecret,
          label: hasCronSecret ? 'CRON_SECRET configured' : 'Requires CRON_SECRET for unattended Vercel Cron',
        },
        email_alerts: {
          connected: hasEmailProvider,
          label: hasEmailProvider ? 'Email transport configured' : 'Requires RESEND_API_KEY or SMTP configuration',
        },
      },
    });
  }));

  // Protected Admin Overview (strictly restricted to verified founder email)
  app.get('/api/admin/overview', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    if (!user || !user.emailVerified || user.email?.toLowerCase() !== ADMIN_EMAIL) {
      res.status(403).json({ error: 'Forbidden: Admin access requires verified founder credentials.' });
      return;
    }

    res.json({
      service: 'OriginSec 2.0',
      adminEmail: user.email,
      runtime: isVercelRuntime ? 'vercel-serverless' : 'node-express',
      nodeVersion: process.version,
      uptimeSeconds: Math.round(process.uptime()),
      capabilities: {
        geminiConfigured: isGeminiConfigured(),
        pageSpeedConfigured: Boolean(process.env.PAGESPEED_API_KEY),
        cronSecretConfigured: Boolean(process.env.CRON_SECRET),
        emailProviderConfigured: Boolean(process.env.RESEND_API_KEY || process.env.SMTP_HOST),
      },
      checkedAt: new Date().toISOString(),
    });
  }));

  // Vercel Cron / Scheduled Monitoring Webhook (protected by CRON_SECRET)
  app.post('/api/cron/monitoring', asyncHandler(async (req, res) => {
    const cronSecret = process.env.CRON_SECRET;
    const authHeader = req.headers.authorization || '';
    const xCron = req.headers['x-cron-secret'];
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : String(xCron || '');

    if (!cronSecret || token !== cronSecret) {
      res.status(401).json({ error: 'Unauthorized cron trigger.' });
      return;
    }

    const targets = Array.isArray(req.body?.targets) ? req.body.targets.slice(0, 10) : [];
    const results: Array<{ targetUrl: string; status: string; httpStatus: number | null; responseTimeMs: number }> = [];
    for (const rawUrl of targets) {
      if (typeof rawUrl !== 'string') continue;
      const validated = validateTargetUrl(rawUrl);
      if (!validated.valid || !validated.normalizedUrl || !validated.hostname) continue;
      const resolved = await resolveAndVerifyHost(validated.hostname);
      if (!resolved.safe) continue;
      const r = await safeFetchText(validated.normalizedUrl, { timeoutMs: 6000, maxBytes: 16384, method: 'HEAD' });
      results.push({
        targetUrl: validated.normalizedUrl,
        status: !r.ok || r.statusCode >= 500 || r.statusCode === 0 ? 'down' : r.statusCode >= 400 ? 'degraded' : 'up',
        httpStatus: r.statusCode || null,
        responseTimeMs: r.ttfbMs,
      });
    }

    res.json({ ok: true, checkedCount: results.length, results, timestamp: new Date().toISOString() });
  }));

  // Start Website Scan (automatically awaits completion on serverless runtimes like Vercel)
  app.post('/api/scans', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `scan:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, user ? 30 : 12, 10 * 60 * 1000)) {
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
        scanProfile: parsed.data.scanProfile,
        maxPages: parsed.data.maxPages !== undefined ? Math.min(8, parsed.data.maxPages) : undefined,
        crawlDepth: parsed.data.crawlDepth,
        isDomainVerified: parsed.data.isDomainVerified,
        serverlessBudgetMs: isVercelRuntime ? 8200 : 16000,
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

    // Idempotency guard for duplicate clicks on async Node scans
    const existingInFlight = findInFlightJob(ownerUid, validated.normalizedUrl);
    if (existingInFlight) {
      res.status(202).json({
        scanId: existingInFlight.scanId,
        status: existingInFlight.status,
        currentStage: existingInFlight.currentStage,
        progressPercent: existingInFlight.progressPercent,
        targetUrl: existingInFlight.targetUrl,
        normalizedDomain: existingInFlight.normalizedDomain,
        deduplicated: true,
      });
      return;
    }

    const job = startScanJob({
      ownerUid,
      targetUrl: validated.normalizedUrl,
      scanProfile: parsed.data.scanProfile,
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
  }));

  // Dedicated SSRF-verified live browser screenshot capture (separate serverless call to prevent timeouts)
  app.post('/api/scans/screenshot', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `shot:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, user ? 30 : 12, 10 * 60 * 1000)) {
      res.json({ available: false, source: 'unavailable', error: 'Screenshot rate limit reached.' });
      return;
    }

    const rawUrl = typeof req.body?.targetUrl === 'string' ? req.body.targetUrl.trim() : '';
    const validated = validateTargetUrl(rawUrl);
    if (!validated.valid || !validated.normalizedUrl || !validated.hostname) {
      res.status(400).json({ available: false, source: 'unavailable', error: validated.error || 'Invalid target URL.' });
      return;
    }

    const resolved = await resolveAndVerifyHost(validated.hostname);
    if (!resolved.safe) {
      res.status(400).json({ available: false, source: 'unavailable', error: resolved.error || 'SSRF policy blocked screenshot target.' });
      return;
    }

    try {
      const apiUrl = new URL('https://api.microlink.io/');
      apiUrl.searchParams.set('url', validated.normalizedUrl);
      apiUrl.searchParams.set('screenshot', 'true');
      apiUrl.searchParams.set('meta', 'false');
      apiUrl.searchParams.set('viewport.width', '1280');
      apiUrl.searchParams.set('viewport.height', '800');
      apiUrl.searchParams.set('waitUntil', 'networkidle2');

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 14500);
      const mlRes = await fetch(apiUrl.toString(), {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      clearTimeout(timer);

      if (!mlRes.ok) {
        res.json({
          available: false,
          source: 'unavailable',
          error: `Live capture service returned HTTP ${mlRes.status}.`,
        });
        return;
      }

      const payload = (await mlRes.json()) as {
        status?: string;
        data?: {
          url?: string;
          screenshot?: { url?: string; width?: number; height?: number };
        };
      };

      const shotUrl = payload?.data?.screenshot?.url;
      if (payload?.status === 'success' && typeof shotUrl === 'string' && shotUrl.startsWith('https://')) {
        res.json({
          available: true,
          source: 'microlink',
          imageUrl: shotUrl,
          width: payload.data?.screenshot?.width ?? 1280,
          height: payload.data?.screenshot?.height ?? 800,
          finalUrl: payload.data?.url || validated.normalizedUrl,
          capturedAt: new Date().toISOString(),
        });
        return;
      }

      res.json({
        available: false,
        source: 'unavailable',
        error: 'Target page prevented automated browser capture.',
      });
    } catch (err) {
      res.json({
        available: false,
        source: 'unavailable',
        error: err instanceof Error && err.name === 'AbortError'
          ? 'Live browser screenshot timed out.'
          : 'Live screenshot service temporarily unreachable.',
      });
    }
  }));

  app.get('/api/scans/:scanId/progress', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/scans/:scanId/cancel', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/remediation/verify', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    if (!user) {
      res.status(401).json({ error: 'Sign in with Google to run live remediation verification.' });
      return;
    }

    const parsed = RemediationVerifySchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid remediation verification payload.' });
      return;
    }

    const result = await verifySpecificRemediation(parsed.data);
    res.json(result);
  }));

  app.post('/api/ownership/challenge', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/ownership/verify', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/api-audit', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/monitoring/check', asyncHandler(async (req, res) => {
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
  }));

  app.post('/api/ai/explain', asyncHandler(async (req, res) => {
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

    res.json({
      explanation: result.explanation,
      sources: result.sources || [],
      generatedAt: new Date().toISOString(),
    });
  }));

  app.post('/api/ai/ask', asyncHandler(async (req, res) => {
    const user = await verifyRequestAuth(req);
    const rateKey = `ai:${user?.uid || req.ip || 'anon'}`;
    if (!checkRateLimit(rateKey, 20, 10 * 60 * 1000)) {
      res.status(429).json({ error: 'AI Q&A rate limit reached. Please wait briefly.' });
      return;
    }

    const parsed = AiAskSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Please enter a valid question (3-600 characters).' });
      return;
    }

    const result = await askAiAboutScanWithGemini({
      scan: parsed.data.scan,
      question: parsed.data.question,
    });

    if (!result.available) {
      res.status(503).json({ error: result.error });
      return;
    }
    if (result.error) {
      res.status(502).json({ error: result.error });
      return;
    }

    res.json({
      answer: result.answer,
      sources: result.sources || [],
      answeredAt: new Date().toISOString(),
    });
  }));

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const message = err instanceof Error ? err.message : 'Internal server error.';
    console.error('OriginSec API unhandled route error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: message });
    }
  });

  return app;
}
