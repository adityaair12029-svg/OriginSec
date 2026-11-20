import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
  updateDoc,
  where,
  writeBatch,
  type Unsubscribe,
} from 'firebase/firestore';
import type { User } from 'firebase/auth';
import { auth, db, handleFirestoreError, isFirebaseConfigured, logFirestoreError, OperationType } from './client';
import type {
  BackupStatusRecord,
  IntegrationRecord,
  MonitoringEvent,
  MonitoringTarget,
  NotificationItem,
  RemediationTask,
  ScanFinding,
  ScanProfileId,
  ThemeMode,
  UserProfile,
  VerifiedDomain,
  WebsiteRecord,
  WebsiteScan,
} from '../../types/audit';

function clampStr(val: string | undefined | null, max: number): string {
  if (!val) return '';
  return String(val).slice(0, max);
}

function toIsoString(val: unknown): string {
  if (!val) return new Date().toISOString();
  if (val instanceof Timestamp) return val.toDate().toISOString();
  if (typeof val === 'string') return val;
  if (typeof val === 'object' && val !== null && 'seconds' in val) {
    return new Date((val as { seconds: number }).seconds * 1000).toISOString();
  }
  return new Date().toISOString();
}

export async function ensureUserProfile(user: User, preferredTheme: ThemeMode): Promise<UserProfile> {
  if (!isFirebaseConfigured) {
    throw new Error('Firebase is not configured.');
  }

  const path = `users/${user.uid}`;
  try {
    const userRef = doc(db, 'users', user.uid);
    const snap = await getDoc(userRef);

    if (!snap.exists()) {
      const payload = {
        uid: user.uid,
        displayName: clampStr(user.displayName || 'OriginSec User', 120),
        email: clampStr(user.email || '', 254),
        photoURL: clampStr(user.photoURL || '', 1000),
        role: 'user' as const,
        theme: preferredTheme,
        defaultCrawlLimit: 8,
        defaultCrawlDepth: 1,
        emailAlerts: true,
        webhookAlerts: false,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };
      await setDoc(userRef, payload);
      return {
        ...payload,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    }

    const d = snap.data();
    return {
      uid: d.uid,
      displayName: d.displayName || user.displayName || 'OriginSec User',
      email: d.email || user.email || '',
      photoURL: d.photoURL || user.photoURL || '',
      role: d.role === 'owner' ? 'owner' : 'user',
      theme: d.theme === 'light' ? 'light' : 'dark',
      defaultCrawlLimit: Number(d.defaultCrawlLimit || 8),
      defaultCrawlDepth: Number(d.defaultCrawlDepth ?? 1),
      emailAlerts: Boolean(d.emailAlerts ?? true),
      webhookAlerts: Boolean(d.webhookAlerts ?? false),
      createdAt: toIsoString(d.createdAt),
      updatedAt: toIsoString(d.updatedAt),
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function updateUserPreferences(
  uid: string,
  updates: Partial<Pick<UserProfile, 'theme' | 'defaultCrawlLimit' | 'defaultCrawlDepth' | 'emailAlerts' | 'webhookAlerts' | 'displayName'>>
) {
  if (!isFirebaseConfigured) return;
  const path = `users/${uid}`;
  try {
    const clean: Record<string, unknown> = { updatedAt: serverTimestamp() };
    if (updates.theme) clean.theme = updates.theme;
    if (updates.defaultCrawlLimit !== undefined) clean.defaultCrawlLimit = Math.min(25, Math.max(1, updates.defaultCrawlLimit));
    if (updates.defaultCrawlDepth !== undefined) clean.defaultCrawlDepth = Math.min(3, Math.max(0, updates.defaultCrawlDepth));
    if (updates.emailAlerts !== undefined) clean.emailAlerts = updates.emailAlerts;
    if (updates.webhookAlerts !== undefined) clean.webhookAlerts = updates.webhookAlerts;
    if (updates.displayName !== undefined) clean.displayName = clampStr(updates.displayName, 120);
    await updateDoc(doc(db, 'users', uid), clean);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function saveScanToFirestore(scan: WebsiteScan, ownerUid: string): Promise<void> {
  if (!isFirebaseConfigured || !auth.currentUser) return;

  const scanPath = `scans/${scan.scanId}`;
  try {
    const scanDocRef = doc(db, 'scans', scan.scanId);
    await setDoc(scanDocRef, {
      scanId: clampStr(scan.scanId, 128),
      ownerUid,
      targetUrl: clampStr(scan.targetUrl, 2048),
      normalizedDomain: clampStr(scan.normalizedDomain, 255),
      ...(scan.scanProfile ? { scanProfile: scan.scanProfile } : {}),
      ...(scan.postureFingerprint ? { postureFingerprint: clampStr(scan.postureFingerprint, 64) } : {}),
      status: scan.status,
      currentStage: clampStr(scan.currentStage, 120),
      progressPercent: Math.min(100, Math.max(0, Math.round(scan.progressPercent))),
      authorizedConfirmed: true,
      coverage: scan.coverage,
      scores: scan.scores,
      summary: clampStr(scan.summary, 4000),
      ...(scan.aiExplanation ? { aiExplanation: clampStr(scan.aiExplanation, 8000) } : {}),
      metrics: scan.metrics,
      findingsCount: scan.findingsCount,
      scannerVersion: clampStr(scan.scannerVersion, 40),
      startedAt: serverTimestamp(),
      completedAt: scan.completedAt ? serverTimestamp() : null,
      updatedAt: serverTimestamp(),
    });

    const findings = scan.findings || [];
    if (findings.length > 0) {
      const batch = writeBatch(db);
      for (const f of findings) {
        const safeFindingId = f.findingId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
        const fRef = doc(db, 'scanFindings', safeFindingId);
        batch.set(fRef, {
          findingId: safeFindingId,
          ...(f.ruleId ? { ruleId: clampStr(f.ruleId, 80) } : {}),
          scanId: clampStr(scan.scanId, 128),
          ownerUid,
          category: f.category,
          ...(f.subCategory ? { subCategory: clampStr(f.subCategory, 40) } : {}),
          title: clampStr(f.title, 200),
          severity: f.severity,
          priorityGroup: f.priorityGroup,
          description: clampStr(f.description, 2000),
          evidence: clampStr(f.evidence, 2000),
          affectedUrl: clampStr(f.affectedUrl, 2048),
          observedValue: clampStr(f.observedValue, 1000),
          impact: clampStr(f.impact, 1500),
          recommendation: clampStr(f.recommendation, 2000),
          remediation: clampStr(f.remediation, 2500),
          verification: clampStr(f.verification, 1500),
          status: f.status,
          ...(f.confidence ? { confidence: clampStr(f.confidence, 40) } : {}),
          ...(f.manualReviewRequired !== undefined ? { manualReviewRequired: Boolean(f.manualReviewRequired) } : {}),
          createdAt: serverTimestamp(),
        });
      }
      await batch.commit();
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, scanPath);
  }
}

export async function attachAiExplanationToScan(scanId: string, aiExplanation: string): Promise<void> {
  if (!isFirebaseConfigured || !auth.currentUser) return;
  const path = `scans/${scanId}`;
  try {
    await updateDoc(doc(db, 'scans', scanId), {
      aiExplanation: clampStr(aiExplanation, 8000),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export function subscribeUserScans(
  ownerUid: string,
  onData: (scans: WebsiteScan[]) => void
): Unsubscribe {
  const path = 'scans';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snapshot) => {
      const items: WebsiteScan[] = snapshot.docs.map((d) => {
        const data = d.data();
        return {
          scanId: data.scanId,
          ownerUid: data.ownerUid,
          targetUrl: data.targetUrl,
          normalizedDomain: data.normalizedDomain,
          scanProfile: data.scanProfile,
          postureFingerprint: data.postureFingerprint,
          status: data.status,
          currentStage: data.currentStage || 'Completed',
          progressPercent: data.progressPercent ?? 100,
          authorizedConfirmed: Boolean(data.authorizedConfirmed),
          coverage: data.coverage,
          scores: data.scores,
          summary: data.summary || '',
          aiExplanation: data.aiExplanation,
          metrics: data.metrics,
          findingsCount: data.findingsCount,
          scannerVersion: data.scannerVersion || 'originsec-engine-2.0',
          startedAt: toIsoString(data.startedAt),
          completedAt: data.completedAt ? toIsoString(data.completedAt) : null,
          updatedAt: toIsoString(data.updatedAt),
        };
      });
      items.sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
      onData(items);
    },
    (error) => {
      logFirestoreError(error, OperationType.LIST, path);
    }
  );
}

export async function getScanFindings(scanId: string, ownerUid: string): Promise<ScanFinding[]> {
  const path = 'scanFindings';
  try {
    const q = query(
      collection(db, path),
      where('ownerUid', '==', ownerUid),
      where('scanId', '==', scanId)
    );
    const snap = await getDocs(q);
    return snap.docs.map((d) => {
      const data = d.data();
      return {
        findingId: data.findingId,
        ruleId: data.ruleId,
        scanId: data.scanId,
        ownerUid: data.ownerUid,
        category: data.category,
        subCategory: data.subCategory,
        title: data.title,
        severity: data.severity,
        priorityGroup: data.priorityGroup || 'best_practice',
        description: data.description,
        evidence: data.evidence,
        affectedUrl: data.affectedUrl || '',
        observedValue: data.observedValue || '',
        impact: data.impact,
        recommendation: data.recommendation,
        remediation: data.remediation || '',
        verification: data.verification,
        status: data.status,
        confidence: data.confidence,
        manualReviewRequired: data.manualReviewRequired,
        remediationNote: data.remediationNote,
        dueDate: data.dueDate ?? null,
        resolvedAt: data.resolvedAt ?? null,
        createdAt: toIsoString(data.createdAt),
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function updateFindingStatusInFirestore(
  findingId: string,
  updates: Partial<Pick<ScanFinding, 'status' | 'remediationNote' | 'dueDate' | 'resolvedAt'>>
) {
  if (!isFirebaseConfigured || !auth.currentUser) return;
  const path = `scanFindings/${findingId}`;
  try {
    const clean: Record<string, unknown> = {};
    if (updates.status !== undefined) clean.status = updates.status;
    if (updates.remediationNote !== undefined) clean.remediationNote = clampStr(updates.remediationNote, 2000);
    if (updates.dueDate !== undefined) clean.dueDate = updates.dueDate ? clampStr(updates.dueDate, 40) : null;
    if (updates.resolvedAt !== undefined) clean.resolvedAt = updates.resolvedAt ? clampStr(updates.resolvedAt, 40) : null;
    await updateDoc(doc(db, 'scanFindings', findingId), clean);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function deleteScanAndFindings(scanId: string, ownerUid: string): Promise<void> {
  const path = `scans/${scanId}`;
  try {
    const findings = await getScanFindings(scanId, ownerUid);
    const batch = writeBatch(db);
    for (const f of findings) {
      batch.delete(doc(db, 'scanFindings', f.findingId));
    }
    batch.delete(doc(db, 'scans', scanId));
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function deleteAllUserScanHistory(ownerUid: string): Promise<void> {
  const path = 'scans';
  try {
    const qScans = query(collection(db, 'scans'), where('ownerUid', '==', ownerUid));
    const qFindings = query(collection(db, 'scanFindings'), where('ownerUid', '==', ownerUid));
    const [scansSnap, findingsSnap] = await Promise.all([getDocs(qScans), getDocs(qFindings)]);
    const batch = writeBatch(db);
    findingsSnap.docs.forEach((d) => batch.delete(d.ref));
    scansSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

// --- Managed Websites (Phase 2) ---
export function subscribeWebsites(ownerUid: string, onData: (items: WebsiteRecord[]) => void): Unsubscribe {
  const path = 'websites';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => {
        const v = d.data();
        return {
          websiteId: v.websiteId,
          ownerUid: v.ownerUid,
          name: v.name,
          targetUrl: v.targetUrl,
          normalizedDomain: v.normalizedDomain,
          verificationStatus: v.verificationStatus || 'unverified',
          defaultProfile: (v.defaultProfile || 'standard') as ScanProfileId,
          monitoringPaused: Boolean(v.monitoringPaused),
          latestScanId: v.latestScanId ?? null,
          latestOverallScore: v.latestOverallScore ?? null,
          lastScannedAt: v.lastScannedAt ?? null,
          createdAt: toIsoString(v.createdAt),
          updatedAt: toIsoString(v.updatedAt),
        } as WebsiteRecord;
      });
      items.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
      onData(items);
    },
    (err) => logFirestoreError(err, OperationType.LIST, path)
  );
}

export async function createWebsiteRecord(record: {
  websiteId: string;
  ownerUid: string;
  name: string;
  targetUrl: string;
  normalizedDomain: string;
  verificationStatus?: WebsiteRecord['verificationStatus'];
  defaultProfile?: ScanProfileId;
  latestScanId?: string | null;
  latestOverallScore?: number | null;
  lastScannedAt?: string | null;
}) {
  const path = `websites/${record.websiteId}`;
  try {
    await setDoc(doc(db, 'websites', record.websiteId), {
      websiteId: clampStr(record.websiteId, 128),
      ownerUid: record.ownerUid,
      name: clampStr(record.name, 150),
      targetUrl: clampStr(record.targetUrl, 2048),
      normalizedDomain: clampStr(record.normalizedDomain, 255),
      verificationStatus: record.verificationStatus || 'unverified',
      defaultProfile: record.defaultProfile || 'standard',
      monitoringPaused: false,
      ...(record.latestScanId ? { latestScanId: clampStr(record.latestScanId, 128) } : {}),
      ...(record.latestOverallScore !== undefined && record.latestOverallScore !== null
        ? { latestOverallScore: Math.round(record.latestOverallScore) }
        : {}),
      ...(record.lastScannedAt ? { lastScannedAt: clampStr(record.lastScannedAt, 40) } : {}),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function updateWebsiteRecord(
  websiteId: string,
  updates: Partial<
    Pick<
      WebsiteRecord,
      'name' | 'targetUrl' | 'verificationStatus' | 'defaultProfile' | 'monitoringPaused' | 'latestScanId' | 'latestOverallScore' | 'lastScannedAt'
    >
  >
) {
  const path = `websites/${websiteId}`;
  try {
    const clean: Record<string, unknown> = { updatedAt: serverTimestamp() };
    if (updates.name !== undefined) clean.name = clampStr(updates.name, 150);
    if (updates.targetUrl !== undefined) clean.targetUrl = clampStr(updates.targetUrl, 2048);
    if (updates.verificationStatus !== undefined) clean.verificationStatus = updates.verificationStatus;
    if (updates.defaultProfile !== undefined) clean.defaultProfile = updates.defaultProfile;
    if (updates.monitoringPaused !== undefined) clean.monitoringPaused = updates.monitoringPaused;
    if (updates.latestScanId !== undefined) clean.latestScanId = updates.latestScanId ? clampStr(updates.latestScanId, 128) : null;
    if (updates.latestOverallScore !== undefined) clean.latestOverallScore = updates.latestOverallScore !== null ? Math.round(updates.latestOverallScore) : null;
    if (updates.lastScannedAt !== undefined) clean.lastScannedAt = updates.lastScannedAt ? clampStr(updates.lastScannedAt, 40) : null;
    await updateDoc(doc(db, 'websites', websiteId), clean);
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function deleteWebsiteRecord(websiteId: string) {
  const path = `websites/${websiteId}`;
  try {
    await deleteDoc(doc(db, 'websites', websiteId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

// --- Remediation Workspace (Phase 17) ---
export function subscribeRemediationTasks(ownerUid: string, onData: (items: RemediationTask[]) => void): Unsubscribe {
  const path = 'remediationTasks';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => {
        const v = d.data();
        return {
          taskId: v.taskId,
          ownerUid: v.ownerUid,
          scanId: v.scanId,
          findingId: v.findingId,
          ruleId: v.ruleId,
          domain: v.domain,
          targetUrl: v.targetUrl,
          title: v.title,
          category: v.category,
          severity: v.severity,
          status: v.status,
          priority: v.priority,
          notes: v.notes || '',
          dueDate: v.dueDate ?? null,
          lastVerifiedAt: v.lastVerifiedAt ?? null,
          verificationResult: v.verificationResult,
          createdAt: toIsoString(v.createdAt),
          updatedAt: toIsoString(v.updatedAt),
        } as RemediationTask;
      });
      items.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
      onData(items);
    },
    (err) => logFirestoreError(err, OperationType.LIST, path)
  );
}

export async function createRemediationTask(task: {
  taskId: string;
  ownerUid: string;
  scanId: string;
  findingId: string;
  ruleId?: string;
  domain: string;
  targetUrl: string;
  title: string;
  category: RemediationTask['category'];
  severity: RemediationTask['severity'];
  priority: RemediationTask['priority'];
  notes?: string;
  dueDate?: string | null;
}) {
  const path = `remediationTasks/${task.taskId}`;
  try {
    await setDoc(doc(db, 'remediationTasks', task.taskId), {
      taskId: clampStr(task.taskId, 128),
      ownerUid: task.ownerUid,
      scanId: clampStr(task.scanId, 128),
      findingId: clampStr(task.findingId, 128),
      ...(task.ruleId ? { ruleId: clampStr(task.ruleId, 80) } : {}),
      domain: clampStr(task.domain, 255),
      targetUrl: clampStr(task.targetUrl, 2048),
      title: clampStr(task.title, 200),
      category: task.category,
      severity: task.severity,
      status: 'open',
      priority: task.priority,
      notes: clampStr(task.notes || '', 2000),
      dueDate: task.dueDate ? clampStr(task.dueDate, 40) : null,
      lastVerifiedAt: null,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function updateRemediationTask(
  taskId: string,
  updates: Partial<
    Pick<RemediationTask, 'status' | 'priority' | 'notes' | 'dueDate' | 'lastVerifiedAt' | 'verificationResult'>
  >
) {
  const path = `remediationTasks/${taskId}`;
  try {
    const clean: Record<string, unknown> = { updatedAt: serverTimestamp() };
    if (updates.status !== undefined) clean.status = updates.status;
    if (updates.priority !== undefined) clean.priority = updates.priority;
    if (updates.notes !== undefined) clean.notes = clampStr(updates.notes, 2000);
    if (updates.dueDate !== undefined) clean.dueDate = updates.dueDate ? clampStr(updates.dueDate, 40) : null;
    if (updates.lastVerifiedAt !== undefined) clean.lastVerifiedAt = updates.lastVerifiedAt ? clampStr(updates.lastVerifiedAt, 40) : null;
    if (updates.verificationResult !== undefined) clean.verificationResult = clampStr(updates.verificationResult, 1000);
    await updateDoc(doc(db, 'remediationTasks', taskId), clean);
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function deleteRemediationTask(taskId: string) {
  const path = `remediationTasks/${taskId}`;
  try {
    await deleteDoc(doc(db, 'remediationTasks', taskId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

// --- Notification Centre (Phase 20) ---
export function subscribeNotifications(ownerUid: string, onData: (items: NotificationItem[]) => void): Unsubscribe {
  const path = 'notifications';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => {
        const v = d.data();
        return {
          notificationId: v.notificationId,
          ownerUid: v.ownerUid,
          type: v.type,
          title: v.title,
          message: v.message,
          domain: v.domain,
          relatedId: v.relatedId,
          read: Boolean(v.read),
          createdAt: toIsoString(v.createdAt),
        } as NotificationItem;
      });
      items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      onData(items.slice(0, 60));
    },
    (err) => logFirestoreError(err, OperationType.LIST, path)
  );
}

export async function createNotificationItem(item: {
  notificationId: string;
  ownerUid: string;
  type: NotificationItem['type'];
  title: string;
  message: string;
  domain?: string;
  relatedId?: string;
}) {
  if (!isFirebaseConfigured || !auth.currentUser) return;
  const path = `notifications/${item.notificationId}`;
  try {
    await setDoc(doc(db, 'notifications', item.notificationId), {
      notificationId: clampStr(item.notificationId, 128),
      ownerUid: item.ownerUid,
      type: item.type,
      title: clampStr(item.title, 200),
      message: clampStr(item.message, 1000),
      ...(item.domain ? { domain: clampStr(item.domain, 255) } : {}),
      ...(item.relatedId ? { relatedId: clampStr(item.relatedId, 128) } : {}),
      read: false,
      createdAt: serverTimestamp(),
    });
  } catch (err) {
    logFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function markNotificationRead(notificationId: string, read = true) {
  const path = `notifications/${notificationId}`;
  try {
    await updateDoc(doc(db, 'notifications', notificationId), { read });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function markAllNotificationsRead(notifications: NotificationItem[]) {
  const unread = notifications.filter((n) => !n.read);
  if (unread.length === 0) return;
  try {
    const batch = writeBatch(db);
    for (const n of unread) {
      batch.update(doc(db, 'notifications', n.notificationId), { read: true });
    }
    await batch.commit();
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, 'notifications');
  }
}

export async function deleteNotificationItem(notificationId: string) {
  const path = `notifications/${notificationId}`;
  try {
    await deleteDoc(doc(db, 'notifications', notificationId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

// --- Verified Domains ---
export function subscribeVerifiedDomains(ownerUid: string, onData: (domains: VerifiedDomain[]) => void): Unsubscribe {
  const path = 'verifiedDomains';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      onData(
        snap.docs.map((d) => {
          const v = d.data();
          return {
            domainId: v.domainId,
            ownerUid: v.ownerUid,
            domain: v.domain,
            method: v.method,
            challengeToken: v.challengeToken,
            verified: Boolean(v.verified),
            verifiedAt: v.verifiedAt ? toIsoString(v.verifiedAt) : null,
            createdAt: toIsoString(v.createdAt),
            updatedAt: toIsoString(v.updatedAt),
          };
        })
      );
    },
    (err) => {
      logFirestoreError(err, OperationType.LIST, path);
    }
  );
}

export async function saveVerifiedDomain(record: {
  domainId: string;
  ownerUid: string;
  domain: string;
  method: 'dns_txt' | 'html_meta' | 'well_known';
  challengeToken: string;
  verified: boolean;
}) {
  const path = `verifiedDomains/${record.domainId}`;
  try {
    const ref = doc(db, 'verifiedDomains', record.domainId);
    const existing = await getDoc(ref);
    if (!existing.exists()) {
      await setDoc(ref, {
        ...record,
        verifiedAt: record.verified ? serverTimestamp() : null,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        method: record.method,
        challengeToken: record.challengeToken,
        verified: record.verified,
        verifiedAt: record.verified ? serverTimestamp() : null,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, path);
  }
}

// --- Monitoring Targets & Events ---
export function subscribeMonitoringTargets(ownerUid: string, onData: (targets: MonitoringTarget[]) => void): Unsubscribe {
  const path = 'monitoringTargets';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      onData(
        snap.docs.map((d) => {
          const v = d.data();
          return {
            targetId: v.targetId,
            ownerUid: v.ownerUid,
            domain: v.domain,
            targetUrl: v.targetUrl,
            frequencyMinutes: Number(v.frequencyMinutes || 15),
            enabled: Boolean(v.enabled),
            lastStatus: v.lastStatus || 'pending',
            lastHttpStatus: v.lastHttpStatus ?? null,
            lastResponseTimeMs: v.lastResponseTimeMs ?? null,
            sslExpiryDays: v.sslExpiryDays ?? null,
            alertEmailEnabled: Boolean(v.alertEmailEnabled ?? true),
            webhookUrl: v.webhookUrl || '',
            lastCheckAt: v.lastCheckAt ? toIsoString(v.lastCheckAt) : null,
            createdAt: toIsoString(v.createdAt),
            updatedAt: toIsoString(v.updatedAt),
          };
        })
      );
    },
    (err) => {
      logFirestoreError(err, OperationType.LIST, path);
    }
  );
}

export function subscribeMonitoringEvents(ownerUid: string, onData: (events: MonitoringEvent[]) => void): Unsubscribe {
  const path = 'monitoringEvents';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      const items = snap.docs.map((d) => {
        const v = d.data();
        return {
          eventId: v.eventId,
          ownerUid: v.ownerUid,
          targetId: v.targetId,
          status: v.status,
          httpStatus: v.httpStatus ?? null,
          responseTimeMs: Number(v.responseTimeMs || 0),
          details: v.details || '',
          timestamp: toIsoString(v.timestamp),
        } as MonitoringEvent;
      });
      items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      onData(items.slice(0, 50));
    },
    (err) => {
      logFirestoreError(err, OperationType.LIST, path);
    }
  );
}

export async function createMonitoringTarget(target: {
  targetId: string;
  ownerUid: string;
  domain: string;
  targetUrl: string;
  frequencyMinutes: number;
  alertEmailEnabled: boolean;
  webhookUrl?: string;
}) {
  const path = `monitoringTargets/${target.targetId}`;
  try {
    await setDoc(doc(db, 'monitoringTargets', target.targetId), {
      targetId: clampStr(target.targetId, 128),
      ownerUid: target.ownerUid,
      domain: clampStr(target.domain, 255),
      targetUrl: clampStr(target.targetUrl, 2048),
      frequencyMinutes: Math.min(1440, Math.max(5, Math.round(target.frequencyMinutes))),
      enabled: true,
      lastStatus: 'pending',
      lastHttpStatus: null,
      lastResponseTimeMs: null,
      sslExpiryDays: null,
      alertEmailEnabled: target.alertEmailEnabled,
      webhookUrl: clampStr(target.webhookUrl || '', 1000),
      lastCheckAt: null,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.CREATE, path);
  }
}

export async function recordMonitoringCheckResult(params: {
  targetId: string;
  ownerUid: string;
  status: 'up' | 'degraded' | 'down';
  httpStatus: number | null;
  responseTimeMs: number;
  sslExpiryDays: number | null;
  details: string;
}) {
  const targetPath = `monitoringTargets/${params.targetId}`;
  const eventId = `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  try {
    await updateDoc(doc(db, 'monitoringTargets', params.targetId), {
      lastStatus: params.status,
      lastHttpStatus: params.httpStatus,
      lastResponseTimeMs: Math.round(params.responseTimeMs),
      sslExpiryDays: params.sslExpiryDays,
      lastCheckAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });

    await setDoc(doc(db, 'monitoringEvents', eventId), {
      eventId,
      ownerUid: params.ownerUid,
      targetId: params.targetId,
      status: params.status,
      httpStatus: params.httpStatus,
      responseTimeMs: Math.min(120000, Math.max(0, Math.round(params.responseTimeMs))),
      details: clampStr(params.details, 1000),
      timestamp: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, targetPath);
  }
}

export async function toggleMonitoringTarget(targetId: string, enabled: boolean) {
  const path = `monitoringTargets/${targetId}`;
  try {
    await updateDoc(doc(db, 'monitoringTargets', targetId), {
      enabled,
      updatedAt: serverTimestamp(),
    });
  } catch (err) {
    handleFirestoreError(err, OperationType.UPDATE, path);
  }
}

export async function deleteMonitoringTarget(targetId: string) {
  const path = `monitoringTargets/${targetId}`;
  try {
    await deleteDoc(doc(db, 'monitoringTargets', targetId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

// --- Integrations & Backup Status ---
export function subscribeIntegrations(ownerUid: string, onData: (items: IntegrationRecord[]) => void): Unsubscribe {
  const path = 'integrations';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      onData(
        snap.docs.map((d) => {
          const v = d.data();
          return {
            integrationId: v.integrationId,
            ownerUid: v.ownerUid,
            provider: v.provider,
            category: v.category || 'hosting',
            connectionStatus: v.connectionStatus,
            permissions: v.permissions,
            accountLabel: v.accountLabel,
            configMeta: v.configMeta,
            lastSyncAt: v.lastSyncAt ? toIsoString(v.lastSyncAt) : null,
            createdAt: toIsoString(v.createdAt),
            updatedAt: toIsoString(v.updatedAt),
          };
        })
      );
    },
    (err) => {
      logFirestoreError(err, OperationType.LIST, path);
    }
  );
}

export async function saveIntegrationRecord(record: {
  integrationId: string;
  ownerUid: string;
  provider: string;
  category: IntegrationRecord['category'];
  connectionStatus: IntegrationRecord['connectionStatus'];
  permissions: string;
  accountLabel?: string;
}) {
  const path = `integrations/${record.integrationId}`;
  try {
    const ref = doc(db, 'integrations', record.integrationId);
    const snap = await getDoc(ref);
    if (!snap.exists()) {
      await setDoc(ref, {
        integrationId: clampStr(record.integrationId, 128),
        ownerUid: record.ownerUid,
        provider: clampStr(record.provider, 64),
        category: clampStr(record.category, 64),
        connectionStatus: record.connectionStatus,
        permissions: clampStr(record.permissions, 500),
        accountLabel: clampStr(record.accountLabel || '', 150),
        lastSyncAt: record.connectionStatus === 'connected' ? serverTimestamp() : null,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await updateDoc(ref, {
        connectionStatus: record.connectionStatus,
        permissions: clampStr(record.permissions, 500),
        accountLabel: clampStr(record.accountLabel || '', 150),
        lastSyncAt: record.connectionStatus === 'connected' ? serverTimestamp() : null,
        updatedAt: serverTimestamp(),
      });
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, path);
  }
}

export async function deleteIntegrationRecord(integrationId: string) {
  const path = `integrations/${integrationId}`;
  try {
    await deleteDoc(doc(db, 'integrations', integrationId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, path);
  }
}

export function subscribeBackupStatus(ownerUid: string, onData: (items: BackupStatusRecord[]) => void): Unsubscribe {
  const path = 'backupStatus';
  const q = query(collection(db, path), where('ownerUid', '==', ownerUid));
  return onSnapshot(
    q,
    (snap) => {
      onData(
        snap.docs.map((d) => {
          const v = d.data();
          return {
            recordId: v.recordId,
            ownerUid: v.ownerUid,
            provider: v.provider,
            verifiedStatus: v.verifiedStatus,
            lastBackupAt: v.lastBackupAt ? toIsoString(v.lastBackupAt) : null,
            frequency: v.frequency,
            retentionPolicy: v.retentionPolicy,
            encrypted: v.encrypted ?? null,
            storageLocation: v.storageLocation,
            evidence: v.evidence,
            lastCheckedAt: toIsoString(v.lastCheckedAt),
            createdAt: toIsoString(v.createdAt),
          };
        })
      );
    },
    (err) => {
      logFirestoreError(err, OperationType.LIST, path);
    }
  );
}
