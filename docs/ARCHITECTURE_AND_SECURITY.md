# OriginSec 2.0 Architecture, Security, API & Deployment Guide

**Founded by Aditya Choudhary | A DopTails Company**

## 1. Architecture Overview
- **SPA Frontend (`src/`)**: React 19 + Tailwind CSS v4. State persistence is isolated per authenticated Firebase UID across `users`, `scans`, `scanFindings`, `websites`, `remediationTasks`, `notifications`, `verifiedDomains`, `monitoringTargets`, `monitoringEvents`, `integrations`, and `backupStatus`.
- **Express API (`src/lib/server/app.ts`)**: Shared cleanly between local `server.ts` (Vite dev middleware) and `api/index.ts` (Vercel serverless function). Zero Vite imports exist inside `src/lib/server/` or `api/index.ts`.
- **Deterministic Scanner Engine (`src/lib/scanner/`)**:
  - `ssrf.ts`: Blocks private IPv4/IPv6 ranges, localhost, loopback, link-local, CGNAT, and cloud metadata IPs (`169.254.169.254`) on initial resolution and every redirect hop (`redirect: 'manual'`). Strips tracking query parameters (`utm_*`, `fbclid`, `gclid`, etc.) and sorts remaining parameters canonically.
  - `engine.ts`: Uses uniform `OriginSec-Auditor/2.0` request headers regardless of client device, sorts DNS and internal crawl candidates lexicographically before slicing, differentiates port-80 timeouts (`null`) from true unencrypted non-redirects (`false`), retries transient socket timeouts once, and captures cold vs. warm TTFB + timing waterfall.
  - `analyzer.ts`: Evaluates deterministic rules (`ruleId`), sorts multi-value evidence records (`Set-Cookie`, DNS, mixed content, broken links), applies jitter-tolerant warm-TTFB thresholds, and computes a SHA-256 `postureFingerprint`.

## 2. REST API Endpoints
- `GET /api/health`: Service & runtime status (`version: '2.0.0'`).
- `GET /api/integrations/status`: Honest readiness flags for Firebase, Gemini AI, PageSpeed Insights, `CRON_SECRET`, and Email providers.
- `POST /api/scans`: Runs live audit (`scanProfile`: `quick | standard | comprehensive | verified_owner | performance | frontend_quality`, `sync`: true on Vercel serverless, in-flight job deduplication on Node).
- `GET /api/scans/:scanId/progress` & `POST /api/scans/:scanId/cancel`: Progress tracking and cancellation for async Node scans.
- `POST /api/remediation/verify`: Authenticated live single-rule re-verification against a target URL.
- `POST /api/ownership/challenge` & `POST /api/ownership/verify`: Domain ownership challenge & DNS TXT / HTML meta / `.well-known` verification.
- `POST /api/api-audit`: Mode A (public) & Mode B (verified owner OpenAPI) non-destructive API probing.
- `POST /api/monitoring/check`: Authenticated uptime + latency + TLS days-remaining probe.
- `POST /api/cron/monitoring`: Protected webhook (`Authorization: Bearer $CRON_SECRET`) for Vercel Cron unattended target checks.
- `POST /api/ai/explain` & `POST /api/ai/ask`: Optional server-side Gemini analyst briefs & grounded Q&A.
- `GET /api/admin/overview`: Strictly restricted to verified founder email (`adityaair1.2029@gmail.com`).

## 3. Security & Zero-Trust Guarantees
- **Firestore Rules (`firestore.rules`)**: Verified email enforcement (`request.auth.token.email_verified == true`), strict field allowlists (`hasOnly`) and type validators on all 11 collections, and privilege escalation prevention (`users.role` immutable to `user`).
- **Cookie & Secret Redaction**: `Set-Cookie` headers have cookie values immediately replaced with `[REDACTED]`; only security attribute flags (`Secure`, `HttpOnly`, `SameSite`) are inspected or stored.
- **No AI/LLM Keys in Browser**: `GEMINI_API_KEY`, `PAGESPEED_API_KEY`, `CRON_SECRET`, and email keys stay strictly on the server.

## 4. Vercel Deployment Checklist
1. Push repository to GitHub (`.github/workflows/ci.yml` verifies `lint`, `npm test`, `eslint firestore.rules`, `firestore.rules.test.ts`, and `npm run build`).
2. Import in Vercel and configure environment variables from `.env.example`.
3. Add your Vercel production hostname (`originsec.vercel.app`) to **Firebase Console → Authentication → Settings → Authorized domains**.
4. Deploy Firestore rules & indexes: `firebase deploy --only firestore:rules,firestore:indexes`.
