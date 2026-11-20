# OriginSec — Autonomous Website Audit & Security Intelligence Platform

**Founded by Aditya Choudhary | A DopTails Company**

OriginSec is a real-time website security, front-end quality, back-end posture, and infrastructure auditing platform. It inspects live publicly accessible targets using SSRF-hardened server-side scanners and generates evidence-backed findings, deterministic scores, and practical remediation guidance.

---

## 1. What OriginSec Does

- **Cybersecurity & Hardening Audit**: Inspects HTTPS availability, HTTP-to-HTTPS redirects, TLS certificate issuer/validity/expiry/protocol, mixed content, HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP/CORP/COEP`), redacted `Set-Cookie` security flags, DNS records (`A`, `AAAA`, `MX`, `TXT`, `SPF`, `DMARC`, `CAA`), `robots.txt`, and `/.well-known/security.txt`.
- **Front-End & UI/UX Audit**: Evaluates static HTML metadata, viewport configuration, heading hierarchy, DOM node count, image `alt` attributes & dimensions, unlabeled links, render-blocking scripts/stylesheets, broken internal links, and optional Google PageSpeed Insights Lighthouse metrics.
- **Back-End & API Posture**: Measures Time-to-First-Byte (TTFB), total response latency, compression (`br`/`gzip`), `Cache-Control`, redirect chains, and non-destructive Mode A (Public) & Mode B (Verified Owner OpenAPI) endpoint probing.
- **Product & Engagement**: Evaluates CTA visibility, semantic landmarks, Open Graph shareability, canonical links, and readability signals.
- **Transparent Scope**: Unconnected database, hosting, and backup categories are explicitly marked **Not assessed** or **Unavailable** — OriginSec never invents scores or fabricated statuses.
- **Exports & AI Briefs**: Export full reports in **PDF**, **CSV**, or **JSON**, and optionally summarize verified findings via server-side **Gemini AI**.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS v4 (Dual Dark/Light theme), Lucide Icons, jsPDF
- **Backend**: Node.js, Express 4, Zod validation, Cheerio HTML parser, native `node:tls` & `node:dns`
- **Database & Auth**: Firebase Authentication (Google Sign-In) & Cloud Firestore with ABAC Security Rules
- **Optional Integrations**: Google Gemini API (`@google/genai`), Google PageSpeed Insights API v5
- **Deployment Target**: GitHub + Vercel (`vercel.json` & `api/index.ts`)

---

## 3. Project Folder Structure

```text
├── api/index.ts                  # Vercel serverless entry point
├── server.ts                     # Express backend + Vite middleware
├── vercel.json                   # Vercel build & rewrite configuration
├── firebase-blueprint.json       # Firestore entity & collection schema IR
├── firestore.rules               # Hardened Firestore security rules
├── firestore.indexes.json        # Firestore composite query indexes
├── src/
│   ├── App.tsx                   # Root SPA orchestrator & auth/theme state
│   ├── index.css                 # Tailwind v4 + Dark/Light CSS variables
│   ├── types/audit.ts            # TypeScript domain models
│   ├── components/               # Modular UI views (Landing, Report, History, Monitoring, etc.)
│   └── lib/
│       ├── export/exporters.ts   # PDF, CSV, JSON report generators
│       ├── firebase/             # Firebase SDK init & Firestore CRUD service
│       ├── scanner/              # SSRF guard, engine, deterministic analyzer, API audit, ownership
│       └── server/               # Firebase ID token verifier & Gemini AI service
```

---

## 4. Installation & Running Locally (Windows & macOS/Linux)

1. **Prerequisites**: Install Node.js 20+ (`node -v`) and Git.
2. **Clone and install**:
   ```powershell
   git clone https://github.com/<your-username>/originsec.git
   cd originsec
   npm install
   ```
3. **Create `.env` from `.env.example`**:
   ```powershell
   copy .env.example .env
   ```
4. **Run automated tests**:
   ```powershell
   npm test
   ```
5. **Start the local development server** (runs on port 3000):
   ```powershell
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

---

## 5. Firebase Project, Google Sign-In & Firestore Setup

1. Go to the [Firebase Console](https://console.firebase.google.com/) and create or select a project.
2. **Enable Google Authentication**:
   - Open **Authentication → Sign-in method → Google → Enable**.
   - Add your local (`localhost`) and production (`your-app.vercel.app`) domains under **Authentication → Settings → Authorized domains**.
3. **Create Firestore Database**:
   - Open **Firestore Database → Create database** in Production mode.
   - Deploy `firestore.rules` and `firestore.indexes.json` using the Firebase CLI:
     ```powershell
     npm install -g firebase-tools
     firebase login
     firebase deploy --only firestore:rules,firestore:indexes
     ```
4. Copy your Web App credentials into `.env` (or `firebase-applet-config.json`).

---

## 6. Environment Variables

| Variable | Where Used | Required | Source |
| :--- | :--- | :--- | :--- |
| `VITE_FIREBASE_API_KEY` | Browser | Yes | Firebase Web App Config |
| `VITE_FIREBASE_AUTH_DOMAIN` | Browser | Yes | Firebase Web App Config |
| `VITE_FIREBASE_PROJECT_ID` | Browser | Yes | Firebase Web App Config |
| `VITE_FIREBASE_APP_ID` | Browser | Yes | Firebase Web App Config |
| `VITE_FIREBASE_DATABASE_ID` | Browser | Optional | Firestore database ID (if non-default) |
| `FIREBASE_PROJECT_ID` | Server | Yes | Firebase Project Settings |
| `GEMINI_API_KEY` | Server | Optional | Google AI Studio Secrets / API Keys |
| `PAGESPEED_API_KEY` | Server | Optional | Google Cloud PageSpeed Insights API |
| `APP_BASE_URL` | Server | Optional | Your production Vercel URL |

> **Security Rule**: Never place `GEMINI_API_KEY`, `PAGESPEED_API_KEY`, or private keys under `VITE_` or `NEXT_PUBLIC_` variables.

---

## 7. GitHub Upload & Vercel Deployment

1. **Push to GitHub**:
   ```powershell
   git init
   git add .
   git commit -m "Initial OriginSec production build"
   git branch -M main
   git remote add origin https://github.com/<your-username>/originsec.git
   git push -u origin main
   ```
2. **Deploy to Vercel**:
   - Log in to [Vercel](https://vercel.com/) and click **Add New → Project**.
   - Import your `originsec` GitHub repository.
   - Add all environment variables from Section 6 under **Settings → Environment Variables**.
   - Click **Deploy**.
3. **Authorize Production Domain in Firebase**:
   - Copy your deployed Vercel domain (e.g., `originsec.vercel.app`) and add it under **Firebase Console → Authentication → Settings → Authorized domains**.

---

## 8. Troubleshooting & Production Checklist

- **Google Sign-In popup fails on Vercel**: Verify your Vercel domain is listed in Firebase Authorized Domains.
- **Firestore permission denied**: Ensure `firestore.rules` is deployed and the user is signed in with a verified Google email.
- **PageSpeed Insights shows "Not configured"**: Add `PAGESPEED_API_KEY` on the server (or Vercel Environment Variables).
- **SSRF Error on Scan**: OriginSec intentionally blocks `localhost`, `127.0.0.0/8`, private RFC 1918 ranges, IPv6 ULA/link-local, and cloud metadata IPs (`169.254.169.254`).

**Production Readiness Checklist**:
- [ ] `npm test` passes (SSRF, deterministic analyzer, and Firestore rule invariants)
- [ ] `npm run lint` passes with zero TypeScript errors
- [ ] `npm run build` succeeds cleanly
- [ ] `.env` is excluded from GitHub (`.gitignore` verified)
- [ ] `firestore.rules` deployed and audited
- [ ] Vercel environment variables configured & Firebase Authorized Domains updated
