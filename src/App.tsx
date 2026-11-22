import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { onAuthStateChanged, type User } from 'firebase/auth';
import { Search, X } from 'lucide-react';
import {
  attachAiExplanationToScan,
  createMonitoringTarget,
  createNotificationItem,
  createRemediationTask,
  createWebsiteRecord,
  deleteAllUserScanHistory,
  deleteIntegrationRecord,
  deleteMonitoringTarget,
  deleteNotificationItem,
  deleteRemediationTask,
  deleteScanAndFindings,
  deleteWebsiteRecord,
  ensureUserProfile,
  getScanFindings,
  markAllNotificationsRead,
  markNotificationRead,
  recordMonitoringCheckResult,
  saveScanToFirestore,
  saveVerifiedDomain,
  subscribeBackupStatus,
  subscribeIntegrations,
  subscribeMonitoringEvents,
  subscribeMonitoringTargets,
  subscribeNotifications,
  subscribeRemediationTasks,
  subscribeUserScans,
  subscribeVerifiedDomains,
  subscribeWebsites,
  toggleMonitoringTarget,
  updateFindingStatusInFirestore,
  updateRemediationTask,
  updateUserPreferences,
  updateWebsiteRecord,
} from './lib/firebase/firestoreService';
import {
  auth,
  completeRedirectSignIn,
  isFirebaseConfigured,
  signInWithGoogle,
  signOutUser,
} from './lib/firebase/client';
import { ORDERED_PROGRESS_STAGES, SCAN_PROFILES } from './lib/scanner/profiles';
import type {
  BackupStatusRecord,
  GroundingSource,
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
} from './types/audit';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Header, type AppRoute } from './components/Header';
import { Footer } from './components/Footer';
import { OriginSecMark } from './components/OriginSecMark';
import { LandingHome } from './components/LandingHome';
import { LoginView } from './components/LoginView';
import { ScanProgressView, type ActiveScanProgress } from './components/ScanProgressView';
import { AuditReportView } from './components/AuditReportView';
import { DashboardShell } from './components/DashboardShell';
import { OverviewView } from './components/OverviewView';
import { ScanHistoryView } from './components/ScanHistoryView';
import { ApiAuditView } from './components/ApiAuditView';
import {
  BackupRecoveryView,
  DatabaseAuditView,
  InfrastructureView,
  SecurityReportsView,
} from './components/InfraSectionsView';
import { MonitoringView } from './components/MonitoringView';
import { IntegrationsView } from './components/IntegrationsView';
import { AboutView, SettingsView } from './components/SettingsAndAboutView';
import { MyWebsitesView } from './components/MyWebsitesView';
import {
  AccessibilityView,
  BackendAssessmentView,
  FrontendIntelligenceView,
  PerformanceLabView,
  SeoContentView,
} from './components/IntelligenceViews';
import { RemediationWorkspaceView } from './components/RemediationWorkspaceView';
import { AdminOverviewView, NotificationsView } from './components/NotificationsAndAdminView';

const THEME_STORAGE_KEY = 'originsec-theme';
const ADMIN_EMAIL = 'adityaair1.2029@gmail.com';

function getInitialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Ignore storage access errors
  }
  return 'light';
}

async function parseJsonSafe<T = Record<string, any>>(res: Response): Promise<{ data: T | null; rawText: string }> {
  const rawText = await res.text();
  if (!rawText) return { data: null, rawText: '' };
  try {
    return { data: JSON.parse(rawText) as T, rawText };
  } catch {
    return { data: null, rawText };
  }
}

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [route, setRoute] = useState<AppRoute>('home');
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [profile, setProfile] = useState<UserProfile | null>(null);

  const [firestoreScans, setFirestoreScans] = useState<WebsiteScan[]>([]);
  const [sessionScans, setSessionScans] = useState<WebsiteScan[]>([]);
  const [websites, setWebsites] = useState<WebsiteRecord[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [verifiedDomains, setVerifiedDomains] = useState<VerifiedDomain[]>([]);
  const [monitoringTargets, setMonitoringTargets] = useState<MonitoringTarget[]>([]);
  const [monitoringEvents, setMonitoringEvents] = useState<MonitoringEvent[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationRecord[]>([]);
  const [backupRecords, setBackupRecords] = useState<BackupStatusRecord[]>([]);

  const [selectedReport, setSelectedReport] = useState<WebsiteScan | null>(null);
  const [activeProgress, setActiveProgress] = useState<ActiveScanProgress | null>(null);
  const [scanSubmitError, setScanSubmitError] = useState<string | null>(null);
  const [isSubmittingScan, setIsSubmittingScan] = useState(false);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const [searchOpen, setSearchOpen] = useState(false);
  const [universalQuery, setUniversalQuery] = useState('');

  const pollTimerRef = useRef<number | null>(null);

  // Sync theme class on <html>
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore
    }
  }, [theme]);

  // Global keyboard shortcut Cmd/Ctrl + K for Universal Search
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setSearchOpen((v) => !v);
      } else if (e.key === 'Escape') {
        setSearchOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleToggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: ThemeMode = prev === 'dark' ? 'light' : 'dark';
      if (user) {
        void updateUserPreferences(user.uid, { theme: next }).catch(() => {});
      }
      return next;
    });
  }, [user]);

  // Firebase Auth listener + redirect sign-in completion
  useEffect(() => {
    if (!isFirebaseConfigured || !auth) {
      setAuthReady(true);
      return;
    }

    void completeRedirectSignIn().catch((err) => {
      setAuthNotice(err instanceof Error ? err.message : 'Google Sign-In failed.');
    });

    const unsub = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      setAuthReady(true);
      if (firebaseUser) {
        try {
          const userProf = await ensureUserProfile(firebaseUser, theme);
          setProfile(userProf);
        } catch (err) {
          console.error('Failed to initialize user profile:', err);
        }
      } else {
        setProfile(null);
        setFirestoreScans([]);
        setWebsites([]);
        setRemediationTasks([]);
        setNotifications([]);
        setVerifiedDomains([]);
        setMonitoringTargets([]);
        setMonitoringEvents([]);
        setIntegrations([]);
        setBackupRecords([]);
      }
    });

    return () => unsub();
  }, []);

  // Firestore real-time subscriptions (only when authenticated)
  useEffect(() => {
    if (!authReady || !user || !isFirebaseConfigured) return;

    const unsubs = [
      subscribeUserScans(user.uid, setFirestoreScans),
      subscribeWebsites(user.uid, setWebsites),
      subscribeRemediationTasks(user.uid, setRemediationTasks),
      subscribeNotifications(user.uid, setNotifications),
      subscribeVerifiedDomains(user.uid, setVerifiedDomains),
      subscribeMonitoringTargets(user.uid, setMonitoringTargets),
      subscribeMonitoringEvents(user.uid, setMonitoringEvents),
      subscribeIntegrations(user.uid, setIntegrations),
      subscribeBackupStatus(user.uid, setBackupRecords),
    ];

    return () => {
      unsubs.forEach((u) => u());
    };
  }, [authReady, user]);

  // Cleanup active scan poll timer on unmount
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) window.clearTimeout(pollTimerRef.current);
    };
  }, []);

  // Automatically navigate to scanner home once authenticated from login screen
  useEffect(() => {
    if (user && route === 'login') {
      setAuthNotice(null);
      setRoute('home');
    }
  }, [user, route]);

  const getAuthToken = useCallback(async (): Promise<string | null> => {
    const activeUser = user || auth?.currentUser;
    if (!activeUser) return null;
    try {
      return await activeUser.getIdToken();
    } catch {
      return null;
    }
  }, [user]);

  const handleSignIn = async () => {
    setAuthNotice(null);
    if (!isFirebaseConfigured) {
      setAuthNotice('Firebase Authentication is not configured in this environment.');
      return;
    }
    setAuthLoading(true);
    try {
      await signInWithGoogle();
    } catch (err) {
      setAuthNotice(err instanceof Error ? err.message : 'Google Sign-In was cancelled or failed.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleSignOut = async () => {
    await signOutUser();
    setSelectedReport(null);
    setActiveProgress(null);
    setRoute(isFirebaseConfigured ? 'login' : 'home');
  };

  const allScans = user ? firestoreScans : sessionScans;
  const isAdmin = Boolean(user?.email && user.email.toLowerCase() === ADMIN_EMAIL);
  const unreadNotificationsCount = notifications.filter((n) => !n.read).length;
  const openRemediationCount = remediationTasks.filter((t) => t.status !== 'resolved' && t.status !== 'accepted_risk').length;

  const stopPolling = () => {
    if (pollTimerRef.current) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const handlePostScanPersistence = useCallback(
    async (finalReport: WebsiteScan, currentUser: User | null) => {
      if (!currentUser) {
        setSessionScans((prev) => [finalReport, ...prev]);
        return;
      }

      try {
        await saveScanToFirestore(finalReport, currentUser.uid);

        // Update matching registered website with latest score
        const matchingSite = websites.find((w) => w.normalizedDomain === finalReport.normalizedDomain);
        if (matchingSite) {
          await updateWebsiteRecord(matchingSite.websiteId, {
            latestScanId: finalReport.scanId,
            latestOverallScore: finalReport.scores?.overall ?? null,
            lastScannedAt: finalReport.completedAt || finalReport.startedAt,
          }).catch(() => {});
        }

        // Create concise notifications (scan completed + critical finding or TLS expiry if triggered)
        await createNotificationItem({
          notificationId: `notif_${finalReport.scanId}_done`,
          ownerUid: currentUser.uid,
          type: 'scan_completed',
          title: `Audit completed: ${finalReport.normalizedDomain}`,
          message: `Score ${finalReport.scores?.overall ?? 'N/A'}/100 · ${finalReport.findingsCount?.critical ?? 0} critical, ${finalReport.findingsCount?.high ?? 0} high issue(s).`,
          domain: finalReport.normalizedDomain,
          relatedId: finalReport.scanId,
        });

        const critCount = (finalReport.findingsCount?.critical ?? 0) + (finalReport.findingsCount?.high ?? 0);
        if (critCount > 0) {
          await createNotificationItem({
            notificationId: `notif_${finalReport.scanId}_crit`,
            ownerUid: currentUser.uid,
            type: 'critical_finding',
            title: `${critCount} High/Critical issue(s) on ${finalReport.normalizedDomain}`,
            message: `Inspect Security & Architecture findings and track fixes inside Remediation Workspace.`,
            domain: finalReport.normalizedDomain,
            relatedId: finalReport.scanId,
          });
        }

        const tlsDays = finalReport.metrics?.tls?.daysRemaining;
        if (tlsDays !== null && tlsDays !== undefined && tlsDays <= 30) {
          await createNotificationItem({
            notificationId: `notif_${finalReport.scanId}_tls`,
            ownerUid: currentUser.uid,
            type: 'tls_expiry',
            title: `TLS certificate expiring soon (${tlsDays}d)`,
            message: `${finalReport.normalizedDomain} SSL/TLS certificate has ${tlsDays} day(s) remaining.`,
            domain: finalReport.normalizedDomain,
            relatedId: finalReport.scanId,
          });
        }
      } catch (saveErr) {
        console.error('Could not persist scan to Firestore:', saveErr);
        setSessionScans((prev) => [finalReport, ...prev]);
      }
    },
    [websites]
  );

  const handleStartScan = async (params: {
    targetUrl: string;
    authorizedConfirmed: boolean;
    scanProfile?: ScanProfileId;
    maxPages?: number;
    crawlDepth?: number;
  }) => {
    stopPolling();
    setScanSubmitError(null);
    setAiError(null);
    setIsSubmittingScan(true);

    const chosenProfile: ScanProfileId = params.scanProfile || 'standard';
    const profileDef = SCAN_PROFILES[chosenProfile] || SCAN_PROFILES.standard;
    const maxPages = params.maxPages ?? profileDef.maxPages;
    const crawlDepth = params.crawlDepth ?? profileDef.crawlDepth;

    let targetHostname = '';
    try {
      const normalizedAttempt = /^https?:\/\//i.test(params.targetUrl.trim())
        ? params.targetUrl.trim()
        : `https://${params.targetUrl.trim()}`;
      targetHostname = new URL(normalizedAttempt).hostname.toLowerCase();
    } catch {
      targetHostname = '';
    }

    const isVercelClient =
      typeof window !== 'undefined' && window.location.hostname.endsWith('.vercel.app');

    let syncTicker: number | null = null;
    const clearSyncTicker = () => {
      if (syncTicker) {
        window.clearInterval(syncTicker);
        syncTicker = null;
      }
    };

    if (isVercelClient) {
      let idx = 0;
      setActiveProgress({
        scanId: 'pending',
        targetUrl: params.targetUrl,
        normalizedDomain: targetHostname || params.targetUrl,
        status: 'running',
        currentStage: ORDERED_PROGRESS_STAGES[0],
        progressPercent: 10,
        stagesLog: [],
      });
      setRoute('scan');
      syncTicker = window.setInterval(() => {
        idx = Math.min(ORDERED_PROGRESS_STAGES.length - 2, idx + 1);
        setActiveProgress((prev) =>
          prev
            ? {
                ...prev,
                currentStage: ORDERED_PROGRESS_STAGES[idx],
                progressPercent: Math.min(92, Math.round(((idx + 1) / ORDERED_PROGRESS_STAGES.length) * 95)),
              }
            : prev
        );
      }, 950);
    }

    try {
      const token = await getAuthToken();
      const isDomainVerified = verifiedDomains.some((d) => d.verified && d.domain === targetHostname);

      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          targetUrl: params.targetUrl,
          authorizedConfirmed: params.authorizedConfirmed,
          scanProfile: chosenProfile,
          maxPages,
          crawlDepth,
          isDomainVerified,
          ...(isVercelClient ? { sync: true } : {}),
        }),
      });

      clearSyncTicker();
      const { data, rawText } = await parseJsonSafe<any>(res);
      if (!res.ok) {
        const errMsg =
          data?.error ||
          (res.status === 504
            ? 'The target website took too long to respond on serverless timeout. Try Quick Audit profile.'
            : rawText && !rawText.trim().startsWith('<')
              ? rawText.slice(0, 200)
              : `Could not complete website scan (HTTP ${res.status}).`);
        setScanSubmitError(errMsg);
        setActiveProgress(null);
        setRoute('home');
        setIsSubmittingScan(false);
        return;
      }

      if (!data) {
        setScanSubmitError('Server returned an empty or unexpected response. Please try again.');
        setActiveProgress(null);
        setRoute('home');
        setIsSubmittingScan(false);
        return;
      }

      const activeUser = user || auth?.currentUser || null;

      // Synchronous completion path (Vercel Serverless or ?sync=true)
      if ((data.status === 'completed' || data.status === 'partially_completed') && data.result) {
        const finalReport: WebsiteScan = data.result;
        await handlePostScanPersistence(finalReport, activeUser);
        setSelectedReport(finalReport);
        setActiveProgress(null);
        setRoute('report');
        setIsSubmittingScan(false);
        return;
      }

      setActiveProgress({
        scanId: data.scanId,
        targetUrl: data.targetUrl,
        normalizedDomain: data.normalizedDomain,
        status: data.status,
        currentStage: data.currentStage,
        progressPercent: data.progressPercent,
        stagesLog: data.stagesLog || [],
      });
      setRoute('scan');
      setIsSubmittingScan(false);

      let notFoundCount = 0;
      const pollProgress = async () => {
        try {
          const authTok = await getAuthToken();
          const pRes = await fetch(`/api/scans/${data.scanId}/progress`, {
            headers: authTok ? { Authorization: `Bearer ${authTok}` } : undefined,
          });
          if (!pRes.ok) {
            if (pRes.status === 404) {
              notFoundCount++;
              if (notFoundCount >= 3) {
                setActiveProgress((prev) =>
                  prev
                    ? {
                        ...prev,
                        status: 'failed',
                        currentStage: 'Failed',
                        error: 'Scan session expired or moved across serverless instances. Please retry the scan.',
                      }
                    : null
                );
                return;
              }
            }
            pollTimerRef.current = window.setTimeout(pollProgress, 900);
            return;
          }
          notFoundCount = 0;
          const { data: pData } = await parseJsonSafe<any>(pRes);
          if (!pData) {
            pollTimerRef.current = window.setTimeout(pollProgress, 900);
            return;
          }

          setActiveProgress({
            scanId: pData.scanId,
            targetUrl: data.targetUrl,
            normalizedDomain: data.normalizedDomain,
            status: pData.status,
            currentStage: pData.currentStage,
            progressPercent: pData.progressPercent,
            stagesLog: pData.stagesLog || [],
            error: pData.error,
          });

          if (pData.status === 'completed' || pData.status === 'partially_completed') {
            const finalReport: WebsiteScan = pData.result;
            const currentUser = user || auth?.currentUser || null;
            await handlePostScanPersistence(finalReport, currentUser);
            setSelectedReport(finalReport);
            setActiveProgress(null);
            setRoute('report');
            return;
          }

          if (pData.status === 'failed' || pData.status === 'cancelled') {
            return;
          }

          pollTimerRef.current = window.setTimeout(pollProgress, 550);
        } catch {
          pollTimerRef.current = window.setTimeout(pollProgress, 1000);
        }
      };

      pollTimerRef.current = window.setTimeout(pollProgress, 450);
    } catch (err) {
      clearSyncTicker();
      setActiveProgress(null);
      setRoute('home');
      setScanSubmitError(err instanceof Error ? err.message : 'Network error starting scan.');
      setIsSubmittingScan(false);
    }
  };

  const handleCancelActiveScan = async () => {
    if (!activeProgress) return;
    stopPolling();
    const token = await getAuthToken();
    await fetch(`/api/scans/${activeProgress.scanId}/cancel`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    }).catch(() => {});
    setActiveProgress((prev) => (prev ? { ...prev, status: 'cancelled', currentStage: 'Cancelled' } : null));
  };

  const handleOpenReport = async (scan: WebsiteScan) => {
    setAiError(null);
    if ((!scan.findings || scan.findings.length === 0) && user) {
      const findings = await getScanFindings(scan.scanId, user.uid);
      setSelectedReport({ ...scan, findings });
    } else {
      setSelectedReport(scan);
    }
    setRoute('report');
  };

  const handleRescan = (url: string, scanProfile: ScanProfileId = 'standard') => {
    void handleStartScan({
      targetUrl: url,
      authorizedConfirmed: true,
      scanProfile,
    });
  };

  const handleDeleteScan = async (scanId: string) => {
    if (user) {
      await deleteScanAndFindings(scanId, user.uid);
    } else {
      setSessionScans((prev) => prev.filter((s) => s.scanId !== scanId));
    }
    if (selectedReport?.scanId === scanId) {
      setSelectedReport(null);
      setRoute('history');
    }
  };

  const handleAddToMonitoring = async (scan: WebsiteScan) => {
    if (!user) {
      await handleSignIn();
      return;
    }
    const targetId = `mon_${scan.normalizedDomain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    await createMonitoringTarget({
      targetId,
      ownerUid: user.uid,
      domain: scan.normalizedDomain,
      targetUrl: scan.targetUrl,
      frequencyMinutes: 15,
      alertEmailEnabled: true,
    });
    setRoute('monitoring');
  };

  const handleTrackFindingInRemediation = async (finding: ScanFinding, scan: WebsiteScan) => {
    if (!user) {
      await handleSignIn();
      return;
    }
    const taskId = `rem_${finding.findingId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 90)}`;
    const priorityMap: Record<string, RemediationTask['priority']> = {
      critical: 'p1_critical',
      high: 'p2_high',
      medium: 'p3_medium',
      low: 'p4_low',
    };
    await createRemediationTask({
      taskId,
      ownerUid: user.uid,
      scanId: scan.scanId,
      findingId: finding.findingId,
      ruleId: finding.ruleId,
      domain: scan.normalizedDomain,
      targetUrl: scan.targetUrl,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      priority: priorityMap[finding.severity] || 'p3_medium',
      notes: '',
      dueDate: null,
    });
  };

  const handleGenerateAiBrief = async (
    scan: WebsiteScan,
    audience: 'owner' | 'developer'
  ): Promise<{ text: string; sources?: GroundingSource[] } | null> => {
    setIsGeneratingAi(true);
    setAiError(null);
    try {
      const token = await getAuthToken();
      const res = await fetch('/api/ai/explain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ audience, scan }),
      });
      const { data } = await parseJsonSafe<any>(res);
      if (!res.ok || !data) {
        setAiError(data?.error || `Could not generate AI brief (HTTP ${res.status}).`);
        return null;
      }
      const sources: GroundingSource[] = Array.isArray(data.sources) ? data.sources : [];
      if (user && data.explanation) {
        await attachAiExplanationToScan(scan.scanId, data.explanation).catch(() => {});
      }
      setSelectedReport((prev) =>
        prev ? { ...prev, aiExplanation: data.explanation, aiSources: sources } : prev
      );
      return { text: data.explanation as string, sources };
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'Network error calling AI service.');
      return null;
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleAskAiQuestion = async (
    scan: WebsiteScan,
    question: string
  ): Promise<{ text: string; sources?: GroundingSource[] } | null> => {
    setAiError(null);
    try {
      const token = await getAuthToken();
      const res = await fetch('/api/ai/ask', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ scan, question }),
      });
      const { data } = await parseJsonSafe<any>(res);
      if (!res.ok || !data) {
        setAiError(data?.error || `AI Q&A unavailable (HTTP ${res.status}).`);
        return null;
      }
      const sources: GroundingSource[] = Array.isArray(data.sources) ? data.sources : [];
      return { text: data.answer as string, sources };
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'Network error calling AI Q&A.');
      return null;
    }
  };

  const handleRunMonitoringCheck = async (target: MonitoringTarget) => {
    if (!user) return;
    const token = await getAuthToken();
    const res = await fetch('/api/monitoring/check', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ targetUrl: target.targetUrl }),
    });
    const { data } = await parseJsonSafe<any>(res);
    if (res.ok && data) {
      await recordMonitoringCheckResult({
        targetId: target.targetId,
        ownerUid: user.uid,
        status: data.status,
        httpStatus: data.httpStatus,
        responseTimeMs: data.responseTimeMs,
        sslExpiryDays: data.sslExpiryDays,
        details: data.details,
      });

      if (data.status === 'down' || data.status === 'degraded') {
        await createNotificationItem({
          notificationId: `notif_mon_${Date.now()}`,
          ownerUid: user.uid,
          type: 'monitoring_incident',
          title: `Monitor ${data.status.toUpperCase()}: ${target.domain}`,
          message: data.details || `HTTP ${data.httpStatus ?? 'N/A'}`,
          domain: target.domain,
          relatedId: target.targetId,
        });
      }
    }
  };

  // Universal Search Matches
  const searchResults = useMemo(() => {
    const q = universalQuery.trim().toLowerCase();
    if (!q) {
      return {
        scans: allScans.slice(0, 4),
        websites: websites.slice(0, 3),
        tasks: remediationTasks.slice(0, 3),
      };
    }
    return {
      scans: allScans.filter((s) => s.normalizedDomain.toLowerCase().includes(q) || s.targetUrl.toLowerCase().includes(q)).slice(0, 6),
      websites: websites.filter((w) => w.name.toLowerCase().includes(q) || w.normalizedDomain.toLowerCase().includes(q)).slice(0, 5),
      tasks: remediationTasks.filter((t) => t.title.toLowerCase().includes(q) || t.domain.toLowerCase().includes(q)).slice(0, 5),
    };
  }, [universalQuery, allScans, websites, remediationTasks]);

  const mustGateOnLogin = isFirebaseConfigured && authReady && !user;

  const isDashboardWorkspaceRoute =
    !mustGateOnLogin &&
    authReady &&
    route !== 'home' &&
    route !== 'login' &&
    route !== 'scan' &&
    route !== 'report';

  return (
    <ErrorBoundary>
      <div className="min-h-screen flex flex-col bg-[#FFFFFF] dark:bg-[#070708] text-[#0A0A0C] dark:text-white transition-colors duration-200">
        <Header
          theme={theme}
          onToggleTheme={handleToggleTheme}
          user={user}
          onSignIn={handleSignIn}
          onSignOut={handleSignOut}
          activeRoute={mustGateOnLogin && route !== 'about' ? 'login' : route}
          onNavigate={(r) => {
            setAuthNotice(null);
            if (mustGateOnLogin && r !== 'about') {
              setRoute('login');
              return;
            }
            setRoute(r);
          }}
          authLoading={authLoading}
          authReady={authReady}
          unreadNotificationsCount={unreadNotificationsCount}
          onOpenSearch={() => setSearchOpen(true)}
        />

        {authNotice && route !== 'login' && !mustGateOnLogin && (
          <div className="max-w-4xl mx-auto mt-4 px-4 w-full">
            <div className="rounded-xl border border-amber-400/50 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-800 dark:text-amber-300 flex items-center justify-between gap-2">
              <span>{authNotice}</span>
              <button type="button" onClick={() => setAuthNotice(null)} className="underline cursor-pointer">
                Dismiss
              </button>
            </div>
          </div>
        )}

        {!authReady && (
          <main className="flex-1 flex flex-col items-center justify-center px-4 py-20">
            <OriginSecMark theme={theme} className="w-12 h-12 mb-4 animate-pulse" />
            <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">Checking session...</p>
          </main>
        )}

        {mustGateOnLogin && route !== 'about' && (
          <LoginView
            theme={theme}
            authLoading={authLoading}
            authNotice={authNotice}
            onGoogleSignIn={handleSignIn}
            requireAuthGate={true}
          />
        )}

        {mustGateOnLogin && route === 'about' && (
          <main className="max-w-4xl mx-auto w-full px-4 sm:px-6 py-10 space-y-6">
            <div>
              <button
                type="button"
                onClick={() => setRoute('login')}
                className="text-sm font-medium text-[#2F75C3] dark:text-[#2F71E3] hover:underline cursor-pointer"
              >
                &larr; Back to Sign in
              </button>
            </div>
            <AboutView />
          </main>
        )}

        {authReady && !mustGateOnLogin && route === 'home' && (
          <LandingHome
            theme={theme}
            onStartScan={handleStartScan}
            isSubmitting={isSubmittingScan}
            errorMessage={scanSubmitError}
          />
        )}

        {authReady && !mustGateOnLogin && route === 'login' && (
          <LoginView
            theme={theme}
            authLoading={authLoading}
            authNotice={authNotice}
            onGoogleSignIn={handleSignIn}
            requireAuthGate={false}
            onContinueAsGuest={() => {
              setAuthNotice(null);
              setRoute('home');
            }}
          />
        )}

        {authReady && !mustGateOnLogin && route === 'scan' && activeProgress && (
          <ScanProgressView
            progress={activeProgress}
            onCancel={handleCancelActiveScan}
            onBackHome={() => {
              stopPolling();
              setActiveProgress(null);
              setRoute('home');
            }}
          />
        )}

        {authReady && !mustGateOnLogin && route === 'report' && selectedReport && (
          <AuditReportView
            scan={selectedReport}
            onRescan={(url) => handleRescan(url, selectedReport.scanProfile || 'standard')}
            onAddToMonitoring={handleAddToMonitoring}
            onTrackFindingInRemediation={handleTrackFindingInRemediation}
            onGenerateAiBrief={handleGenerateAiBrief}
            onAskAiQuestion={handleAskAiQuestion}
            isGeneratingAi={isGeneratingAi}
            aiError={aiError}
          />
        )}

        {isDashboardWorkspaceRoute && (
          <DashboardShell
            activeRoute={route}
            onNavigate={setRoute}
            isAdmin={isAdmin}
            unreadNotificationsCount={unreadNotificationsCount}
            openRemediationCount={openRemediationCount}
            onOpenSearch={() => setSearchOpen(true)}
          >
            {route === 'dashboard' && (
              <OverviewView
                scans={allScans}
                websites={websites}
                monitoringTargets={monitoringTargets}
                remediationTasks={remediationTasks}
                onOpenReport={handleOpenReport}
                onNavigate={setRoute}
                userEmail={user?.email}
              />
            )}

            {route === 'websites' && (
              <MyWebsitesView
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                websites={websites}
                scans={allScans}
                verifiedDomains={verifiedDomains}
                getAuthToken={getAuthToken}
                onCreateWebsite={async (rec) => {
                  if (!user) return;
                  await createWebsiteRecord({ ...rec, ownerUid: user.uid });
                }}
                onUpdateWebsite={updateWebsiteRecord}
                onDeleteWebsite={deleteWebsiteRecord}
                onSaveVerifiedDomain={async (rec) => {
                  if (!user) return;
                  await saveVerifiedDomain({ ...rec, ownerUid: user.uid });
                }}
                onRunScan={(url, prof) => handleRescan(url, prof)}
                onOpenReport={handleOpenReport}
              />
            )}

            {route === 'history' && (
              <ScanHistoryView
                scans={allScans}
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                onOpenReport={handleOpenReport}
                onRescan={(url) => handleRescan(url)}
                onDeleteScan={handleDeleteScan}
                onStartNewScan={() => setRoute('home')}
              />
            )}

            {route === 'security-reports' && (
              <SecurityReportsView
                scans={allScans}
                onOpenReport={handleOpenReport}
                onNavigate={setRoute}
              />
            )}

            {route === 'frontend-intel' && (
              <FrontendIntelligenceView scans={allScans} onNavigate={setRoute} onOpenReport={handleOpenReport} />
            )}

            {route === 'seo-quality' && (
              <SeoContentView scans={allScans} onNavigate={setRoute} onOpenReport={handleOpenReport} />
            )}

            {route === 'performance-lab' && (
              <PerformanceLabView scans={allScans} onNavigate={setRoute} onOpenReport={handleOpenReport} />
            )}

            {route === 'accessibility' && (
              <AccessibilityView scans={allScans} onNavigate={setRoute} onOpenReport={handleOpenReport} />
            )}

            {route === 'backend-assessment' && (
              <BackendAssessmentView
                scans={allScans}
                integrations={integrations}
                onNavigate={setRoute}
                onOpenReport={handleOpenReport}
              />
            )}

            {route === 'remediation' && (
              <RemediationWorkspaceView
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                tasks={remediationTasks}
                getAuthToken={getAuthToken}
                onUpdateTask={updateRemediationTask}
                onUpdateFindingStatus={updateFindingStatusInFirestore}
                onDeleteTask={deleteRemediationTask}
                onNotificationTrigger={async (msg, domain, taskId) => {
                  if (!user) return;
                  await createNotificationItem({
                    notificationId: `notif_ver_${Date.now()}`,
                    ownerUid: user.uid,
                    type: 'verification_success',
                    title: `Fix verified on ${domain}`,
                    message: msg,
                    domain,
                    relatedId: taskId,
                  });
                }}
              />
            )}

            {route === 'notifications' && (
              <NotificationsView
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                notifications={notifications}
                onMarkRead={markNotificationRead}
                onMarkAllRead={() => markAllNotificationsRead(notifications)}
                onDelete={deleteNotificationItem}
              />
            )}

            {route === 'api-audits' && (
              <ApiAuditView
                isAuthenticated={Boolean(user)}
                getAuthToken={getAuthToken}
                verifiedDomains={verifiedDomains}
                onSaveVerifiedDomain={async (rec) => {
                  if (!user) return;
                  await saveVerifiedDomain({ ...rec, ownerUid: user.uid });
                }}
                onSignIn={handleSignIn}
              />
            )}

            {route === 'database-audits' && (
              <DatabaseAuditView integrations={integrations} onNavigate={setRoute} />
            )}

            {route === 'infrastructure' && (
              <InfrastructureView integrations={integrations} onNavigate={setRoute} />
            )}

            {route === 'backups' && (
              <BackupRecoveryView backupRecords={backupRecords} onNavigate={setRoute} />
            )}

            {route === 'monitoring' && (
              <MonitoringView
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                targets={monitoringTargets}
                events={monitoringEvents}
                onCreateTarget={async (p) => {
                  if (!user) return;
                  const domain = new URL(p.targetUrl).hostname;
                  await createMonitoringTarget({
                    targetId: `mon_${domain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`,
                    ownerUid: user.uid,
                    domain,
                    targetUrl: p.targetUrl,
                    frequencyMinutes: p.frequencyMinutes,
                    alertEmailEnabled: p.alertEmailEnabled,
                    webhookUrl: p.webhookUrl,
                  });
                }}
                onRunCheckNow={handleRunMonitoringCheck}
                onToggleTarget={toggleMonitoringTarget}
                onDeleteTarget={deleteMonitoringTarget}
              />
            )}

            {route === 'integrations' && (
              <IntegrationsView
                isAuthenticated={Boolean(user)}
                userIntegrations={integrations}
                onDisconnectIntegration={deleteIntegrationRecord}
              />
            )}

            {route === 'settings' && (
              <SettingsView
                user={user}
                profile={profile}
                theme={theme}
                onToggleTheme={handleToggleTheme}
                onSignIn={handleSignIn}
                onSignOut={handleSignOut}
                onUpdatePreferences={async (updates) => {
                  if (!user) return;
                  await updateUserPreferences(user.uid, updates);
                }}
                onDeleteAllHistory={async () => {
                  if (!user) return;
                  await deleteAllUserScanHistory(user.uid);
                }}
              />
            )}

            {route === 'about' && <AboutView />}

            {route === 'admin' && isAdmin && (
              <AdminOverviewView user={user} getAuthToken={getAuthToken} />
            )}
          </DashboardShell>
        )}

        {/* Universal Search Modal */}
        {searchOpen && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Universal Search"
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-start justify-center pt-20 px-4"
            onClick={() => setSearchOpen(false)}
          >
            <div
              className="max-w-xl w-full rounded-2xl border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] shadow-2xl overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[#E5E7EB] dark:border-white/[0.08]">
                <Search className="w-4 h-4 text-[#5A606E] dark:text-[#9499A6]" />
                <input
                  type="text"
                  autoFocus
                  value={universalQuery}
                  onChange={(e) => setUniversalQuery(e.target.value)}
                  placeholder="Search websites, scan domains, or remediation findings..."
                  className="flex-1 bg-transparent text-sm text-[#0A0A0C] dark:text-white focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setSearchOpen(false)}
                  aria-label="Close search"
                  className="p-1 text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="max-h-80 overflow-y-auto p-3 space-y-4 text-xs">
                {searchResults.scans.length > 0 && (
                  <div className="space-y-1">
                    <p className="px-2 font-semibold uppercase tracking-wider text-[10px] text-[#5A606E] dark:text-[#9499A6]">Audited Scans</p>
                    {searchResults.scans.map((s) => (
                      <button
                        key={s.scanId}
                        type="button"
                        onClick={() => {
                          setSearchOpen(false);
                          void handleOpenReport(s);
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-[#F7F8FA] dark:hover:bg-white/[0.05] flex items-center justify-between cursor-pointer"
                      >
                        <span className="font-medium text-[#0A0A0C] dark:text-white">{s.normalizedDomain}</span>
                        <span className="font-mono text-[#5A606E] dark:text-[#9499A6]">{s.scores?.overall ?? 'N/A'}/100</span>
                      </button>
                    ))}
                  </div>
                )}

                {searchResults.websites.length > 0 && (
                  <div className="space-y-1">
                    <p className="px-2 font-semibold uppercase tracking-wider text-[10px] text-[#5A606E] dark:text-[#9499A6]">My Websites</p>
                    {searchResults.websites.map((w) => (
                      <button
                        key={w.websiteId}
                        type="button"
                        onClick={() => {
                          setSearchOpen(false);
                          setRoute('websites');
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-[#F7F8FA] dark:hover:bg-white/[0.05] flex items-center justify-between cursor-pointer"
                      >
                        <span className="font-medium text-[#0A0A0C] dark:text-white">{w.name}</span>
                        <span className="font-mono text-[#5A606E] dark:text-[#9499A6]">{w.normalizedDomain}</span>
                      </button>
                    ))}
                  </div>
                )}

                {searchResults.tasks.length > 0 && (
                  <div className="space-y-1">
                    <p className="px-2 font-semibold uppercase tracking-wider text-[10px] text-[#5A606E] dark:text-[#9499A6]">Remediation Tasks</p>
                    {searchResults.tasks.map((t) => (
                      <button
                        key={t.taskId}
                        type="button"
                        onClick={() => {
                          setSearchOpen(false);
                          setRoute('remediation');
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-[#F7F8FA] dark:hover:bg-white/[0.05] flex items-center justify-between cursor-pointer"
                      >
                        <span className="font-medium text-[#0A0A0C] dark:text-white truncate pr-2">{t.title}</span>
                        <span className="font-mono text-[#5A606E] dark:text-[#9499A6] uppercase">{t.status}</span>
                      </button>
                    ))}
                  </div>
                )}

                {searchResults.scans.length === 0 &&
                  searchResults.websites.length === 0 &&
                  searchResults.tasks.length === 0 && (
                    <p className="text-center py-6 text-[#5A606E] dark:text-[#9499A6]">No matching scans, websites, or findings.</p>
                  )}
              </div>
            </div>
          </div>
        )}

        <Footer theme={theme} onNavigate={setRoute} />
      </div>
    </ErrorBoundary>
  );
}
