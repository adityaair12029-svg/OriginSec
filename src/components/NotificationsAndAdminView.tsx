import React, { useEffect, useState } from 'react';
import { Bell, CheckCheck, Shield, Trash2 } from 'lucide-react';
import type { User } from 'firebase/auth';
import type { NotificationItem } from '../types/audit';
import { EmptyWorkspaceState } from './DashboardShell';

export const NotificationsView: React.FC<{
  isAuthenticated: boolean;
  onSignIn: () => void;
  notifications: NotificationItem[];
  onMarkRead: (id: string, read: boolean) => Promise<void>;
  onMarkAllRead: () => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}> = ({ isAuthenticated, onSignIn, notifications, onMarkRead, onMarkAllRead, onDelete }) => {
  const [filter, setFilter] = useState<'all' | 'unread'>('all');
  const [deliveryStatus, setDeliveryStatus] = useState<{ emailConfigured: boolean; cronConfigured: boolean } | null>(null);

  useEffect(() => {
    let active = true;
    fetch('/api/integrations/status')
      .then((r) => r.json())
      .then((d) => {
        if (!active || !d?.providers) return;
        setDeliveryStatus({
          emailConfigured: Boolean(d.providers.email_alerts?.connected),
          cronConfigured: Boolean(d.providers.scheduled_cron?.connected),
        });
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  if (!isAuthenticated) {
    return (
      <EmptyWorkspaceState
        title="Sign in to view notifications"
        description="Receive persistent alerts when critical findings are detected, TLS certificates approach expiration, or remediation verification completes."
        actionLabel="Sign in with Google"
        onAction={onSignIn}
      />
    );
  }

  const displayed = filter === 'unread' ? notifications.filter((n) => !n.read) : notifications;
  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#0A0A0C] dark:text-white">Notification Centre</h1>
          <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] mt-1">
            Real-time audit alerts, certificate warnings, and monitoring incidents.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setFilter(filter === 'all' ? 'unread' : 'all')}
            className="px-3.5 py-2 rounded-xl text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] cursor-pointer"
          >
            {filter === 'all' ? `Unread (${unreadCount})` : 'Show All'}
          </button>
          {unreadCount > 0 && (
            <button
              type="button"
              onClick={() => void onMarkAllRead()}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#0A0A0C] text-white dark:bg-white dark:text-[#070708] cursor-pointer"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              Mark All Read
            </button>
          )}
        </div>
      </div>

      {/* Honest Delivery Channel Status */}
      {deliveryStatus && (
        <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] px-5 py-3 text-xs text-[#5A606E] dark:text-[#9499A6] flex flex-wrap items-center justify-between gap-2">
          <span>
            Email Alerts: <strong className="text-[#0A0A0C] dark:text-white">{deliveryStatus.emailConfigured ? 'Active' : 'Requires RESEND_API_KEY / SMTP on server'}</strong>
          </span>
          <span>
            Unattended Cron: <strong className="text-[#0A0A0C] dark:text-white">{deliveryStatus.cronConfigured ? 'Configured' : 'Requires CRON_SECRET on Vercel'}</strong>
          </span>
        </div>
      )}

      {displayed.length === 0 ? (
        <EmptyWorkspaceState
          title="No notifications to display"
          description="Alerts will appear here automatically after audits or monitoring checks trigger findings."
        />
      ) : (
        <div className="space-y-3">
          {displayed.map((n) => (
            <div
              key={n.notificationId}
              className={`rounded-2xl border p-5 flex items-start justify-between gap-4 transition-colors ${
                n.read
                  ? 'border-[#E5E7EB] dark:border-white/[0.06] bg-white/70 dark:bg-[#101115]/70 opacity-80'
                  : 'border-[#2F75C3]/45 dark:border-[#2F71E3]/45 bg-white dark:bg-[#101115]'
              }`}
            >
              <div className="flex items-start gap-3 min-w-0">
                <Bell className={`w-4 h-4 shrink-0 mt-1 ${n.read ? 'text-[#5A606E]' : 'text-[#2F75C3] dark:text-[#2F71E3]'}`} />
                <div className="space-y-1 min-w-0">
                  <p className="text-sm font-bold text-[#0A0A0C] dark:text-white">{n.title}</p>
                  <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">{n.message}</p>
                  <p className="text-[11px] font-mono text-[#5A606E] dark:text-[#9499A6]">
                    {n.domain ? `${n.domain} · ` : ''}
                    {new Date(n.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => void onMarkRead(n.notificationId, !n.read)}
                  className="px-3 py-1.5 rounded-lg text-[11px] font-medium border border-[#E5E7EB] dark:border-white/[0.08] cursor-pointer"
                >
                  {n.read ? 'Mark Unread' : 'Mark Read'}
                </button>
                <button
                  type="button"
                  onClick={() => void onDelete(n.notificationId)}
                  aria-label="Delete notification"
                  className="p-1.5 rounded-lg border border-[#E5E7EB] dark:border-white/[0.08] text-[#5A606E] hover:text-red-500 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const AdminOverviewView: React.FC<{
  user: User | null;
  getAuthToken: () => Promise<string | null>;
}> = ({ user, getAuthToken }) => {
  const [adminData, setAdminData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      const token = await getAuthToken();
      if (!token) {
        if (mounted) setError('Authenticated founder session required.');
        return;
      }
      const res = await fetch('/api/admin/overview', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!mounted) return;
      if (!res.ok) {
        setError(data.error || 'Access denied.');
      } else {
        setAdminData(data);
      }
    })();
    return () => {
      mounted = false;
    };
  }, [user, getAuthToken]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2.5">
        <Shield className="w-5 h-5 text-[#2F75C3] dark:text-[#2F71E3]" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#0A0A0C] dark:text-white">OriginSec Founder &amp; Platform Overview</h1>
          <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">
            Protected runtime telemetry restricted to verified admin account (adityaair1.2029@gmail.com).
          </p>
        </div>
      </div>

      {error ? (
        <div className="rounded-2xl border border-red-400/50 bg-red-500/10 p-6 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      ) : !adminData ? (
        <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 text-xs text-[#5A606E] dark:text-[#9499A6]">
          Verifying admin credentials...
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-5">
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Runtime Environment</p>
            <p className="text-lg font-bold font-mono mt-1">{adminData.runtime} ({adminData.nodeVersion})</p>
          </div>
          <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-5">
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Process Uptime</p>
            <p className="text-lg font-bold font-mono mt-1">{adminData.uptimeSeconds}s</p>
          </div>
          <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-5">
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Verified Operator</p>
            <p className="text-sm font-bold font-mono mt-1">{adminData.adminEmail}</p>
          </div>
          <div className="sm:col-span-2 lg:col-span-3 rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-2 text-xs font-mono">
            <p className="font-bold text-sm font-sans text-[#0A0A0C] dark:text-white mb-2">Server Capability Flags (No Secrets Exposed)</p>
            <p>Gemini Server AI: {adminData.capabilities?.geminiConfigured ? 'Configured' : 'Not configured'}</p>
            <p>PageSpeed Insights Key: {adminData.capabilities?.pageSpeedConfigured ? 'Configured' : 'Not configured'}</p>
            <p>Cron Secret Guard: {adminData.capabilities?.cronSecretConfigured ? 'Configured' : 'Not configured'}</p>
            <p>Email Provider: {adminData.capabilities?.emailProviderConfigured ? 'Configured' : 'Not configured'}</p>
          </div>
        </div>
      )}
    </div>
  );
};
