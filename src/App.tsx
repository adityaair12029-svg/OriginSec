import { useCallback, useEffect, useRef, useState } from 'react';
import { onAuthStateChanged, type User } from 'firebase/auth';
import {
  attachAiExplanationToScan,
  createMonitoringTarget,
  deleteAllUserScanHistory,
  deleteIntegrationRecord,
  deleteMonitoringTarget,
  deleteScanAndFindings,
  ensureUserProfile,
  getScanFindings,
  recordMonitoringCheckResult,
  saveIntegrationRecord,
  saveScanToFirestore,
  saveVerifiedDomain,
  subscribeBackupStatus,
  subscribeIntegrations,
  subscribeMonitoringEvents,
  subscribeMonitoringTargets,
  subscribeUserScans,
  subscribeVerifiedDomains,
  toggleMonitoringTarget,
  updateUserPreferences,
} from './lib/firebase/firestoreService';
import { auth, isFirebaseConfigured, signInWithGoogle, signOutUser } from './lib/firebase/client';
import type {
  BackupStatusRecord,
  IntegrationRecord,
  MonitoringEvent,
  MonitoringTarget,
  ThemeMode,
  UserProfile,
  VerifiedDomain,
  WebsiteScan,
} from './types/audit';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Header, type AppRoute } from './components/Header';
import { Footer } from './components/Footer';
import { LandingHome } from './components/LandingHome';
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

const THEME_STORAGE_KEY = 'originsec-theme';

function getInitialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Ignore storage access errors
  }
  return 'dark';
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

  const handleToggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: ThemeMode = prev === 'dark' ? 'light' : 'dark';
      if (user) {
        void updateUserPreferences(user.uid, { theme: next }).catch(() => {});
      }
      return next;
    });
  }, [user]);

  // Firebase Auth listener
  useEffect(() => {
    if (!isFirebaseConfigured || !auth) {
      setAuthReady(true);
      return;
    }

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

  const getAuthToken = useCallback(async (): Promise<string | null> => {
    if (!user) return null;
    try {
      return await user.getIdToken();
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
    if (route === 'dashboard' || route === 'settings') {
      setRoute('home');
    }
  };

  const allScans = user ? firestoreScans : sessionScans;

  const stopPolling = () => {
    if (pollTimerRef.current) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const handleStartScan = async (params: {
    targetUrl: string;
    authorizedConfirmed: boolean;
    maxPages: number;
    crawlDepth: number;
  }) => {
    stopPolling();
    setScanSubmitError(null);
    setAiError(null);
    setIsSubmittingScan(true);

    try {
      const token = await getAuthToken();
      let targetHostname = '';
      try {
        targetHostname = new URL(params.targetUrl).hostname.toLowerCase();
      } catch {
        targetHostname = '';
      }
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
          maxPages: params.maxPages || profile?.defaultCrawlLimit || 8,
          crawlDepth: params.crawlDepth ?? profile?.defaultCrawlDepth ?? 1,
          isDomainVerified,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setScanSubmitError(data.error || 'Could not start website scan.');
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
        stagesLog: [],
      });
      setRoute('scan');
      setIsSubmittingScan(false);

      const pollProgress = async () => {
        try {
          const authTok = await getAuthToken();
          const pRes = await fetch(`/api/scans/${data.scanId}/progress`, {
            headers: authTok ? { Authorization: `Bearer ${authTok}` } : undefined,
          });
          if (!pRes.ok) {
            pollTimerRef.current = window.setTimeout(pollProgress, 900);
            return;
          }
          const pData = await pRes.json();

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
            if (user) {
              await saveScanToFirestore(finalReport, user.uid);
            } else {
              setSessionScans((prev) => [finalReport, ...prev]);
            }
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

  const handleRescan = (url: string) => {
    void handleStartScan({
      targetUrl: url,
      authorizedConfirmed: true,
      maxPages: profile?.defaultCrawlLimit ?? 8,
      crawlDepth: profile?.defaultCrawlDepth ?? 1,
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

  const handleGenerateAiBrief = async (scan: WebsiteScan, audience: 'owner' | 'developer') => {
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
      const data = await res.json();
      if (!res.ok) {
        setAiError(data.error || 'Could not generate AI brief.');
        return null;
      }
      if (user && data.explanation) {
        await attachAiExplanationToScan(scan.scanId, data.explanation).catch(() => {});
      }
      setSelectedReport((prev) => (prev ? { ...prev, aiExplanation: data.explanation } : prev));
      return data.explanation as string;
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'Network error calling AI service.');
      return null;
    } finally {
      setIsGeneratingAi(false);
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
    const data = await res.json();
    if (res.ok) {
      await recordMonitoringCheckResult({
        targetId: target.targetId,
        ownerUid: user.uid,
        status: data.status,
        httpStatus: data.httpStatus,
        responseTimeMs: data.responseTimeMs,
        sslExpiryDays: data.sslExpiryDays,
        details: data.details,
      });
    }
  };

  const isDashboardWorkspaceRoute =
    route !== 'home' && route !== 'scan' && route !== 'report';

  return (
    <ErrorBoundary>
      <div className="min-h-screen flex flex-col bg-[#F7F5EF] dark:bg-[#050505] text-[#151515] dark:text-white">
        <Header
          theme={theme}
          onToggleTheme={handleToggleTheme}
          user={user}
          onSignIn={handleSignIn}
          onSignOut={handleSignOut}
          activeRoute={route}
          onNavigate={(r) => {
            setAuthNotice(null);
            setRoute(r);
          }}
          authLoading={authLoading}
        />

        {authNotice && (
          <div className="max-w-4xl mx-auto mt-4 px-4 w-full">
            <div className="rounded-xl border border-amber-400/50 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-800 dark:text-amber-300 flex items-center justify-between gap-2">
              <span>{authNotice}</span>
              <button type="button" onClick={() => setAuthNotice(null)} className="underline cursor-pointer">
                Dismiss
              </button>
            </div>
          </div>
        )}

        {route === 'home' && (
          <LandingHome
            onStartScan={handleStartScan}
            isSubmitting={isSubmittingScan}
            errorMessage={scanSubmitError}
          />
        )}

        {route === 'scan' && activeProgress && (
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

        {route === 'report' && selectedReport && (
          <AuditReportView
            scan={selectedReport}
            onRescan={handleRescan}
            onAddToMonitoring={handleAddToMonitoring}
            onGenerateAiBrief={handleGenerateAiBrief}
            isGeneratingAi={isGeneratingAi}
            aiError={aiError}
          />
        )}

        {isDashboardWorkspaceRoute && (
          <DashboardShell activeRoute={route} onNavigate={setRoute}>
            {route === 'dashboard' && (
              <OverviewView
                scans={allScans}
                monitoringTargets={monitoringTargets}
                onOpenReport={handleOpenReport}
                onNavigate={setRoute}
                userEmail={user?.email}
              />
            )}

            {route === 'history' && (
              <ScanHistoryView
                scans={allScans}
                isAuthenticated={Boolean(user)}
                onSignIn={handleSignIn}
                onOpenReport={handleOpenReport}
                onRescan={handleRescan}
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
          </DashboardShell>
        )}

        <Footer onNavigate={setRoute} />
      </div>
    </ErrorBoundary>
  );
}
