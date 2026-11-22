import React, { useState } from 'react';
import { Activity, Pause, Play, RefreshCw, Trash2, AlertCircle } from 'lucide-react';
import type { MonitoringEvent, MonitoringTarget } from '../types/audit';
import { EmptyWorkspaceState } from './DashboardShell';

interface MonitoringViewProps {
  isAuthenticated: boolean;
  onSignIn: () => void;
  targets: MonitoringTarget[];
  events: MonitoringEvent[];
  onCreateTarget: (params: {
    targetUrl: string;
    frequencyMinutes: number;
    alertEmailEnabled: boolean;
    webhookUrl?: string;
  }) => Promise<void>;
  onRunCheckNow: (target: MonitoringTarget) => Promise<void>;
  onToggleTarget: (targetId: string, enabled: boolean) => Promise<void>;
  onDeleteTarget: (targetId: string) => Promise<void>;
}

export const MonitoringView: React.FC<MonitoringViewProps> = ({
  isAuthenticated,
  onSignIn,
  targets,
  events,
  onCreateTarget,
  onRunCheckNow,
  onToggleTarget,
  onDeleteTarget,
}) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [frequencyMinutes, setFrequencyMinutes] = useState(15);
  const [alertEmail, setAlertEmail] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!isAuthenticated) {
      onSignIn();
      return;
    }

    let candidate = targetUrl.trim();
    if (!candidate) {
      setError('Enter a target URL to monitor.');
      return;
    }
    if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`;

    try {
      const parsed = new URL(candidate);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setError('Only http:// and https:// targets are supported.');
        return;
      }
    } catch {
      setError('Invalid URL format.');
      return;
    }

    setSubmitting(true);
    try {
      await onCreateTarget({
        targetUrl: candidate,
        frequencyMinutes,
        alertEmailEnabled: alertEmail,
        webhookUrl: webhookUrl.trim() || undefined,
      });
      setTargetUrl('');
      setWebhookUrl('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create monitoring target.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCheck = async (target: MonitoringTarget) => {
    setCheckingId(target.targetId);
    try {
      await onRunCheckNow(target);
    } finally {
      setCheckingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#0A0A0C] dark:text-white">Continuous Monitoring</h1>
        <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">
          Track live HTTP availability, response time, and SSL/TLS certificate expiry. Scheduled execution runs via server cron integration, plus on-demand live checks below.
        </p>
      </div>

      {!isAuthenticated && (
        <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">
            Sign in with Google to persist monitoring targets and view incident history.
          </p>
          <button
            type="button"
            onClick={onSignIn}
            className="px-4 py-2 rounded-full text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white cursor-pointer whitespace-nowrap"
          >
            Sign in with Google
          </button>
        </div>
      )}

      {/* Add Monitoring Target Form */}
      <form
        onSubmit={handleAdd}
        className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4"
      >
        <h2 className="text-sm font-bold text-[#0A0A0C] dark:text-white">Configure Monitoring Target</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2 space-y-1">
            <label htmlFor="monitor-url" className="block text-xs font-medium text-[#5A606E] dark:text-[#9499A6]">
              Website URL
            </label>
            <input
              id="monitor-url"
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-4 py-2.5 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="monitor-freq" className="block text-xs font-medium text-[#5A606E] dark:text-[#9499A6]">
              Check Interval
            </label>
            <select
              id="monitor-freq"
              value={frequencyMinutes}
              onChange={(e) => setFrequencyMinutes(Number(e.target.value))}
              className="w-full px-3 py-2.5 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white"
            >
              <option value={5}>Every 5 minutes</option>
              <option value={15}>Every 15 minutes</option>
              <option value={60}>Every 1 hour</option>
              <option value={360}>Every 6 hours</option>
              <option value={1440}>Daily</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
          <div className="space-y-1">
            <label htmlFor="monitor-webhook" className="block text-xs font-medium text-[#5A606E] dark:text-[#9499A6]">
              Alert Webhook URL (optional)
            </label>
            <input
              id="monitor-webhook"
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.example.com/..."
              className="w-full px-4 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white"
            />
          </div>
          <label className="inline-flex items-center gap-2 text-xs text-[#5A606E] dark:text-[#9499A6] pt-4 cursor-pointer">
            <input
              type="checkbox"
              checked={alertEmail}
              onChange={(e) => setAlertEmail(e.target.checked)}
              className="w-4 h-4 accent-[#2F75C3] dark:accent-[#2F71E3]"
            />
            <span>Send email alert notifications on downtime or TLS expiry &lt; 14 days</span>
          </label>
        </div>

        {error && (
          <div role="alert" className="flex items-center gap-2 text-xs text-red-600 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="px-5 py-2.5 rounded-full text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-95 disabled:opacity-50 cursor-pointer"
        >
          {submitting ? 'Saving target...' : 'Add Monitoring Target'}
        </button>
      </form>

      {/* Targets List */}
      {targets.length === 0 ? (
        <EmptyWorkspaceState
          title="No monitoring targets configured"
          description="Add a verified website above to start tracking uptime, TTFB response times, and TLS certificate expiry."
        />
      ) : (
        <div className="space-y-4">
          {targets.map((t) => (
            <div
              key={t.targetId}
              className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <Activity
                    className={`w-4 h-4 ${
                      t.lastStatus === 'up'
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : t.lastStatus === 'down'
                          ? 'text-red-500'
                          : 'text-amber-500'
                    }`}
                  />
                  <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">{t.domain}</h3>
                  <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded border border-[#E5E7EB] dark:border-white/[0.1]">
                    {t.enabled ? t.lastStatus : 'paused'}
                  </span>
                </div>
                <p className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6]">
                  {t.targetUrl} · Every {t.frequencyMinutes}m · HTTP {t.lastHttpStatus ?? '—'} ·{' '}
                  {t.lastResponseTimeMs !== null ? `${t.lastResponseTimeMs} ms` : 'Not checked yet'} · TLS{' '}
                  {t.sslExpiryDays !== null ? `${t.sslExpiryDays}d` : '—'}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => handleCheck(t)}
                  disabled={checkingId === t.targetId}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${checkingId === t.targetId ? 'animate-spin' : ''}`} />
                  {checkingId === t.targetId ? 'Checking...' : 'Run Check'}
                </button>
                <button
                  type="button"
                  onClick={() => onToggleTarget(t.targetId, !t.enabled)}
                  aria-label={t.enabled ? `Pause ${t.domain}` : `Resume ${t.domain}`}
                  className="p-2 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
                >
                  {t.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => onDeleteTarget(t.targetId)}
                  aria-label={`Delete ${t.domain}`}
                  className="p-2 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6] hover:text-red-500 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Event History */}
      {events.length > 0 && (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#E5E7EB] dark:border-white/[0.08]">
            <h2 className="text-sm font-bold text-[#0A0A0C] dark:text-white">Check &amp; Incident History</h2>
          </div>
          <div className="divide-y divide-[#E5E7EB] dark:divide-white/[0.06]">
            {events.slice(0, 15).map((ev) => (
              <div key={ev.eventId} className="px-6 py-3 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-3">
                  <span className="font-mono uppercase font-bold">{ev.status}</span>
                  <span className="text-[#5A606E] dark:text-[#9499A6]">{ev.details}</span>
                </div>
                <span className="font-mono tabular-nums text-[#5A606E] dark:text-[#9499A6]">
                  {ev.responseTimeMs} ms · {new Date(ev.timestamp).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
};
