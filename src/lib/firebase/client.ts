import { initializeApp, getApps, getApp, type FirebaseApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut, type Auth } from 'firebase/auth';
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

if (isFirebaseConfigured) {
  app = getApps().length ? getApp() : initializeApp(config);
  dbInstance = getFirestore(app, config.firestoreDatabaseId);
  authInstance = getAuth(app);
}

export const db = dbInstance as Firestore;
export const auth = authInstance as Auth;
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: 'select_account' });

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

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
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
  throw new Error(JSON.stringify(errInfo));
}

export async function signInWithGoogle() {
  if (!authInstance) {
    throw new Error('Firebase Authentication is not configured.');
  }
  return signInWithPopup(authInstance, googleProvider);
}

export async function signOutUser() {
  if (!authInstance) return;
  return signOut(authInstance);
}
