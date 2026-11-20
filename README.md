# OriginSec 2.0 — Autonomous Website Audit & Security Intelligence Platform

**Founded by Aditya Choudhary | A DopTails Company**

OriginSec 2.0 is a deterministic, real-time website security, front-end quality, SEO, accessibility, performance, API posture, and infrastructure auditing platform. It visits live publicly accessible targets using SSRF-hardened server-side scanners and produces evidence-backed, reproducible findings, posture fingerprints, and live remediation verification.

---

## 1. Key Capabilities

- **Reproducible Live Audits**: Canonical URL normalization (`utm_*`, `fbclid`, `gclid`, query sorting), uniform `OriginSec-Auditor/2.0` probe headers, sorted DNS/cookie/candidate ordering, warm TTFB verification, and a deterministic `postureFingerprint` ensure repeated scans from desktop or mobile devices return identical findings unless the live site itself changes.
- **Scan Profiles**: Choose between **Quick Audit (1 page)**, **Standard Audit (8 pages)**, **Comprehensive External (15 pages)**, **Verified Owner Deep (20 pages)**, **Performance Lab**, and **Frontend Quality**.
- **9 Audit Domains**:
  1. **Cybersecurity & Hardening**: HTTPS/TLS certificate inspection, HTTP-to-HTTPS redirect verification, security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP/CORP/COEP`), redacted `Set-Cookie` flags, DNS (`A`, `AAAA`, `MX`, `TXT`, `SPF`, `DMARC`, `CAA`), `security.txt`, and mixed content.
  2. **Frontend Intelligence & WCAG Accessibility**: DOM complexity, render-blocking scripts, image dimensions & lazy hints, `html lang`, missing alt/form labels/button text, and heading hierarchy checks (with honest Manual Review flags for color contrast & keyboard navigation).
  3. **SEO & Content Quality**: Title, meta description length, canonical URL, Open Graph, Twitter Card, `robots.txt`, `sitemap.xml`, and broken internal links.
  4. **Performance Lab & Backend Assessment**: DNS/TLS/TTFB/warm-TTFB waterfall, compression, caching, and optional Google PageSpeed Insights / Core Web Vitals.
  5. **API Posture**: Non-destructive Mode A (Public) & Mode B (Verified Owner OpenAPI) endpoint probing.
  6. **Infrastructure, Database & Backup Transparency**: Explicitly labeled **Not assessed** unless authorized read-only integrations are connected.
- **Remediation Workspace & Live Verification**: Track findings through `open → acknowledged → in_progress → ready_for_verification → resolved / accepted_risk`, store notes/due dates in Firestore, and click **Verify Fix Now** (`POST /api/remediation/verify`) to re-probe live production.
- **Scan Comparison Engine**: Compare two historical scans side-by-side (`Newly Discovered`, `Resolved`, `Header Diffs`, `Telemetry Deltas`, and `Identical Posture` badge).
- **Exports & Grounded AI Analyst**: PDF, CSV, JSON exports plus optional Gemini AI briefs & interactive Q&A (`POST /api/ai/ask`) strictly grounded in sanitized findings.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS v4 (Dark/Light modes), Lucide Icons, jsPDF
- **Backend**: Node.js, Express 4, Zod validation, Cheerio HTML parser, native `node:tls` & `node:dns`
- **Database & Auth**: Firebase Authentication (Google Sign-In) & Cloud Firestore with Zero-Trust ABAC Security Rules
- **Deployment Target**: GitHub + Vercel (`vercel.json` & `api/index.ts`)

---

## 3. Running Locally & Testing

```bash
npm install
cp .env.example .env
npm test
npm run lint
npm run dev
```

For full architecture, SSRF defenses, API documentation, scanner methodology, and Vercel deployment steps, see [docs/ARCHITECTURE_AND_SECURITY.md](./docs/ARCHITECTURE_AND_SECURITY.md).
