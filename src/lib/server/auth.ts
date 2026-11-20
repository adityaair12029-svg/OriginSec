import { getApp, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request } from 'express';

let projectIdCache: string | null = null;

function getFirebaseProjectId(): string | null {
  if (projectIdCache) return projectIdCache;

  const envId =
    process.env.FIREBASE_PROJECT_ID ||
    process.env.VITE_FIREBASE_PROJECT_ID ||
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID;
  if (envId && envId !== 'remixed-project-id') {
    projectIdCache = envId;
    return projectIdCache;
  }

  const candidatePaths = [
    path.resolve(process.cwd(), 'firebase-applet-config.json'),
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../firebase-applet-config.json'),
  ];

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

  return null;
}

export interface VerifiedUser {
  uid: string;
  email: string | null;
  emailVerified: boolean;
}

/**
 * Verifies a Firebase ID token passed via Authorization: Bearer <token>.
 * Uses verifyIdToken(token) which requires no IAM role and works on Starter Tier & Vercel.
 */
export async function verifyRequestAuth(req: Request): Promise<VerifiedUser | null> {
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

  try {
    const app = getApps().length ? getApp() : initializeApp({ projectId });
    const decoded = await getAuth(app).verifyIdToken(token);
    return {
      uid: decoded.uid,
      email: decoded.email ?? null,
      emailVerified: Boolean(decoded.email_verified),
    };
  } catch {
    return null;
  }
}
