import { initializeApp, getApps, getApp, type FirebaseApp } from 'firebase/app';
import {
  browserLocalPersistence,
  getAuth,
  getRedirectResult,
  GoogleAuthProvider,
  indexedDBLocalPersistence,
  setPersistence,
  signInWithPopup,
  signInWithRedirect,
  signOut,
  type Auth,
} from 'firebase/auth';
import { doc, getDocFromServer, getFirestore, type Firestore } from 'firebase/firestore';
import firebaseAppletConfig from '../../../firebase-applet-config.json';

const config = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || firebaseAppletConfig.apiKey,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || firebaseAppletConfig.authDomain,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || firebaseAppletConfig.projectId,
  appId: import.meta.env.VITE_FIREBASE_APP_ID || firebaseAppletConfig.appId,
  storageBucket: firebaseAppletConfig.storageBucket,
  messagingSenderId: firebaseAppletConfig.messagingSenderId,
  firestoreDatabaseId: import.meta.env.VITE_FIREBASE_DATABASE_ID || firebaseAppletConfig.firestoreDatabaseId,
};

export const isFirebaseConfigured = Boolean(
  config.apiKey && config.projectId && config.projectId !== 'remixed-project-id'
);

let app: FirebaseApp | null = null;
let dbInstance: Firestore | null = null;
let authInstance: Auth | null = null;
let persistenceReady: Promise<void> = Promise.resolve();

if (isFirebaseConfigured) {
  app = getApps().length ? getApp() : initializeApp(config);
  dbInstance = getFirestore(app, config.firestoreDatabaseId);
  authInstance = getAuth(app);
  persistenceReady = setPersistence(authInstance, indexedDBLocalPersistence).catch(() =>
    authInstance ? setPersistence(authInstance, browserLocalPersistence).catch(() => {}) : undefined
  );
}

export const db = dbInstance as Firestore;
export const auth = authInstance as Auth;
export const googleProvider = new GoogleAuthProvider();

export async function testConnection(): Promise<{ online: boolean; message?: string }> {
  if (!dbInstance) {
    return { online: false, message: 'Firebase configuration missing.' };
  }
  try {
    await getDocFromServer(doc(dbInstance, 'test', 'connection'));
    return { online: true };
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration (client is offline).');
      return { online: false, message: 'Firestore client is offline. Check Firebase configuration.' };
    }
    // Permission denied / not-found from server confirms connectivity is online
    return { online: true };
  }
}

void testConnection();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: Array<{
      providerId?: string | null;
      email?: string | null;
    }>;
  };
}

export function logFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): FirestoreErrorInfo {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: authInstance?.currentUser?.uid ?? null,
      email: authInstance?.currentUser?.email ?? null,
      emailVerified: authInstance?.currentUser?.emailVerified ?? null,
      isAnonymous: authInstance?.currentUser?.isAnonymous ?? null,
      tenantId: authInstance?.currentUser?.tenantId ?? null,
      providerInfo:
        authInstance?.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  return errInfo;
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo = logFirestoreError(error, operationType, path);
  throw new Error(JSON.stringify(errInfo));
}

function formatAuthError(error: unknown): Error {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: string }).code) : '';
  const hostname = typeof window !== 'undefined' ? window.location.hostname : 'this domain';
  const projectId = config.projectId || 'cool-proposal-1c62s';

  if (code === 'auth/unauthorized-domain') {
    return new Error(
      `Domain "${hostname}" is not authorized for Google Sign-In yet. Add "${hostname}" in Firebase Console -> Project "${projectId}" -> Authentication -> Settings -> Authorized domains.`
    );
  }
  if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
    return new Error('Google Sign-In popup was closed before finishing.');
  }
  if (code === 'auth/operation-not-allowed') {
    return new Error(`Google Sign-In provider is not enabled in Firebase Authentication for project "${projectId}".`);
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error('Google Sign-In failed.');
}

export async function completeRedirectSignIn() {
  if (!authInstance) return null;
  await persistenceReady;
  try {
    return await getRedirectResult(authInstance);
  } catch (error) {
    throw formatAuthError(error);
  }
}

export async function signInWithGoogle() {
  if (!authInstance) {
    throw new Error('Firebase Authentication is not configured.');
  }
  await persistenceReady;
  try {
    return await signInWithPopup(authInstance, googleProvider);
  } catch (error) {
    const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: string }).code) : '';
    if (code === 'auth/popup-blocked') {
      await signInWithRedirect(authInstance, googleProvider);
      return null;
    }
    throw formatAuthError(error);
  }
}

export async function signOutUser() {
  if (!authInstance) return;
  return signOut(authInstance);
}
