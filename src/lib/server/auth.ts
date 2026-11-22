import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request } from 'express';

const GOOGLE_SECURE_TOKEN_CERTS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const FALLBACK_FIREBASE_PROJECT_ID = 'cool-proposal-1c62s';

let projectIdCache: string | null = null;
let cachedCerts: { keys: Record<string, string>; expiresAt: number } | null = null;

function resolveCurrentDir(): string | null {
  try {
    if (
      typeof import.meta !== 'undefined' &&
      typeof import.meta.url === 'string' &&
      import.meta.url.startsWith('file:')
    ) {
      return path.dirname(fileURLToPath(import.meta.url));
    }
  } catch {
    // Ignore when bundled into CommonJS (e.g., @vercel/node)
  }
  return typeof __dirname === 'string' ? __dirname : null;
}

export function getFirebaseProjectId(): string | null {
  if (projectIdCache) return projectIdCache;

  const envId =
    process.env.FIREBASE_PROJECT_ID ||
    process.env.VITE_FIREBASE_PROJECT_ID ||
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID;
  if (envId && envId !== 'remixed-project-id') {
    projectIdCache = envId;
    return projectIdCache;
  }

  const candidatePaths: string[] = [path.resolve(process.cwd(), 'firebase-applet-config.json')];
  const currentDir = resolveCurrentDir();
  if (currentDir) {
    candidatePaths.push(path.resolve(currentDir, '../../../firebase-applet-config.json'));
    candidatePaths.push(path.resolve(currentDir, '../firebase-applet-config.json'));
  }

  for (const cfgPath of candidatePaths) {
    try {
      if (fs.existsSync(cfgPath)) {
        const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { projectId?: string };
        if (parsed.projectId && parsed.projectId !== 'remixed-project-id') {
          projectIdCache = parsed.projectId;
          return projectIdCache;
        }
      }
    } catch {
      // Try next candidate
    }
  }

  projectIdCache = FALLBACK_FIREBASE_PROJECT_ID;
  return projectIdCache;
}

function decodeBase64Url(input: string): Buffer {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64');
}

async function fetchGooglePublicCerts(forceRefresh = false): Promise<Record<string, string>> {
  const now = Date.now();
  if (!forceRefresh && cachedCerts && cachedCerts.expiresAt > now) {
    return cachedCerts.keys;
  }

  const response = await fetch(GOOGLE_SECURE_TOKEN_CERTS_URL, {
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch Firebase public keys (HTTP ${response.status}).`);
  }

  const keys = (await response.json()) as Record<string, string>;
  const cacheControl = response.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const ttlMs = maxAgeMatch ? Math.max(60, Number(maxAgeMatch[1])) * 1000 : 3600_000;

  cachedCerts = {
    keys,
    expiresAt: now + ttlMs,
  };
  return keys;
}

export interface VerifiedUser {
  uid: string;
  email: string | null;
  emailVerified: boolean;
}

/**
 * Cryptographically verifies a Firebase Auth ID token against a provided PEM map using Node built-in RSA-SHA256.
 * Zero dependency on firebase-admin / jwks-rsa / jose — 100% compatible with Vercel ESM & CJS runtimes.
 */
export function verifyFirebaseJwtWithCerts(
  token: string,
  projectId: string,
  certs: Record<string, string>,
  nowSec = Math.floor(Date.now() / 1000)
): VerifiedUser | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, sigB64] = parts;
  if (!headerB64 || !payloadB64 || !sigB64) return null;

  let header: { alg?: unknown; kid?: unknown };
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(decodeBase64Url(headerB64).toString('utf8'));
    payload = JSON.parse(decodeBase64Url(payloadB64).toString('utf8'));
  } catch {
    return null;
  }

  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) {
    return null;
  }

  const certPem = certs[header.kid];
  if (!certPem || typeof certPem !== 'string') {
    return null;
  }

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const signatureValid = verifier.verify(certPem, decodeBase64Url(sigB64));
    if (!signatureValid) return null;
  } catch {
    return null;
  }

  const expectedIssuer = `https://securetoken.google.com/${projectId}`;
  const exp = typeof payload.exp === 'number' ? payload.exp : 0;
  const iat = typeof payload.iat === 'number' ? payload.iat : Infinity;
  const authTime = typeof payload.auth_time === 'number' ? payload.auth_time : Infinity;
  const sub = typeof payload.sub === 'string' ? payload.sub : '';

  if (payload.aud !== projectId) return null;
  if (payload.iss !== expectedIssuer) return null;
  if (exp <= nowSec) return null;
  if (iat > nowSec + 300) return null;
  if (authTime > nowSec + 300) return null;
  if (!sub || sub.length > 128) return null;

  return {
    uid: sub,
    email: typeof payload.email === 'string' ? payload.email : null,
    emailVerified: Boolean(payload.email_verified),
  };
}

/**
 * Verifies a Firebase ID token passed via Authorization: Bearer <token>.
 */
export async function verifyRequestAuth(req: Request): Promise<VerifiedUser | null> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    const token = authHeader.slice(7).trim();
    if (!token || token.length > 4096) {
      return null;
    }

    const projectId = getFirebaseProjectId();
    if (!projectId) {
      return null;
    }

    const headerPart = token.split('.')[0];
    let kid: string | undefined;
    try {
      const parsedHeader = JSON.parse(decodeBase64Url(headerPart).toString('utf8')) as { kid?: string };
      kid = parsedHeader.kid;
    } catch {
      return null;
    }

    let certs = await fetchGooglePublicCerts(false);
    if (kid && !certs[kid]) {
      certs = await fetchGooglePublicCerts(true);
    }

    return verifyFirebaseJwtWithCerts(token, projectId, certs);
  } catch {
    return null;
  }
}
