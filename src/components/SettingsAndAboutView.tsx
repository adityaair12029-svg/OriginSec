import React, { useState } from 'react';
import { Trash2, Shield, LogOut } from 'lucide-react';
import type { User } from 'firebase/auth';
import type { ThemeMode, UserProfile } from '../types/audit';

interface SettingsViewProps {
  user: User | null;
  profile: UserProfile | null;
  theme: ThemeMode;
  onToggleTheme: () => void;
  onSignIn: () => void;
  onSignOut: () => void;
  onUpdatePreferences: (updates: Partial<UserProfile>) => Promise<void>;
  onDeleteAllHistory: () => Promise<void>;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  user,
  profile,
  theme,
  onToggleTheme,
  onSignIn,
  onSignOut,
  onUpdatePreferences,
  onDeleteAllHistory,
}) => {
  const [crawlLimit, setCrawlLimit] = useState(profile?.defaultCrawlLimit ?? 8);
  const [crawlDepth, setCrawlDepth] = useState(profile?.defaultCrawlDepth ?? 1);
  const [emailAlerts, setEmailAlerts] = useState(profile?.emailAlerts ?? true);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const handleSave = async () => {
    if (!user) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      await onUpdatePreferences({
        defaultCrawlLimit: crawlLimit,
        defaultCrawlDepth: crawlDepth,
        emailAlerts,
        theme,
      });
      setStatusMsg('Preferences saved to your account.');
    } catch (err) {
      setStatusMsg(err instanceof Error ? err.message : 'Could not save preferences.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-[#0A0A0C] dark:text-white">Account &amp; Platform Settings</h1>
        <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">
          Manage your profile, appearance, scan budgets, notifications, and stored history.
        </p>
      </div>

      {/* Profile & Account */}
      <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
        <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white">Profile &amp; Authentication</h2>
        {user ? (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              {user.photoURL ? (
                <img
                  src={user.photoURL}
                  alt={user.displayName || 'User'}
                  referrerPolicy="no-referrer"
                  className="w-12 h-12 rounded-full border border-[#E5E7EB] dark:border-white/[0.08]"
                />
              ) : (
                <div className="w-12 h-12 rounded-full bg-[#F7F8FA] dark:bg-[#13151B]" />
              )}
              <div>
                <p className="text-sm font-bold text-[#0A0A0C] dark:text-white">
                  {user.displayName || 'Authenticated User'}
                </p>
                <p className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6]">{user.email}</p>
                <p className="text-[11px] text-emerald-600 dark:text-emerald-400">
                  Verified Google Session · Role: {profile?.role || 'user'}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={onSignOut}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold border border-[#E5E7EB] dark:border-white/[0.08] text-[#0A0A0C] dark:text-white hover:border-red-400 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">
              Not signed in. Sign in with Google to save scan history, monitor targets, and verify domain ownership.
            </p>
            <button
              type="button"
              onClick={onSignIn}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#0A0A0C] text-white dark:bg-white dark:text-[#070708] cursor-pointer whitespace-nowrap"
            >
              Sign in with Google
            </button>
          </div>
        )}
      </section>

      {/* Appearance */}
      <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 flex items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white">Appearance</h2>
          <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">
            Current theme: <strong className="capitalize">{theme} Mode</strong> (persisted automatically).
          </p>
        </div>
        <button
          type="button"
          onClick={onToggleTheme}
          className="px-4 py-2 rounded-full text-xs font-semibold uppercase tracking-wider border border-[#E5E7EB] dark:border-white/[0.08] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors cursor-pointer"
        >
          Switch to {theme === 'dark' ? 'Light' : 'Dark'} Mode
        </button>
      </section>

      {/* Scan & Notification Preferences */}
      {user && (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
          <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white">Scan &amp; Notification Preferences</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <label htmlFor="pref-crawl-limit" className="block text-xs font-medium text-[#5A606E] dark:text-[#9499A6]">
                Default Max Pages per Scan (1–20)
              </label>
              <input
                id="pref-crawl-limit"
                type="number"
                min={1}
                max={20}
                value={crawlLimit}
                onChange={(e) => setCrawlLimit(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="pref-crawl-depth" className="block text-xs font-medium text-[#5A606E] dark:text-[#9499A6]">
                Default Crawl Depth (0–2)
              </label>
              <input
                id="pref-crawl-depth"
                type="number"
                min={0}
                max={2}
                value={crawlDepth}
                onChange={(e) => setCrawlDepth(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
              />
            </div>
          </div>

          <label className="inline-flex items-center gap-2 text-xs text-[#5A606E] dark:text-[#9499A6] cursor-pointer">
            <input
              type="checkbox"
              checked={emailAlerts}
              onChange={(e) => setEmailAlerts(e.target.checked)}
              className="w-4 h-4 accent-[#2F75C3] dark:accent-[#2F71E3]"
            />
            <span>Enable monitoring alert emails when configured</span>
          </label>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-95 cursor-pointer disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Preferences'}
            </button>
            {statusMsg && <span className="text-xs text-emerald-600 dark:text-emerald-400">{statusMsg}</span>}
          </div>
        </section>
      )}

      {/* Privacy & Data Management */}
      {user && (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
            <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white">Privacy &amp; Data Management</h2>
          </div>
          <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">
            All scans and monitoring targets are strictly isolated to your authenticated UID via Firestore Security Rules. Session cookie values and credentials are always redacted before storage.
          </p>

          {!confirmDelete ? (
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold border border-red-400/50 text-red-600 dark:text-red-400 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Delete Saved Scan History
            </button>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-xs font-semibold text-red-600 dark:text-red-400">
                Permanently delete all your saved scans and findings?
              </span>
              <button
                type="button"
                onClick={async () => {
                  await onDeleteAllHistory();
                  setConfirmDelete(false);
                  setStatusMsg('All saved scan history deleted.');
                }}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-red-600 text-white cursor-pointer"
              >
                Confirm Delete All
              </button>
              <button
                type="button"
                onClick={() => setConfirmDelete(false)}
                className="px-3.5 py-1.5 rounded-lg text-xs border border-[#E5E7EB] dark:border-white/[0.08] cursor-pointer"
              >
                Cancel
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  );
};

export const AboutView: React.FC = () => (
  <div className="space-y-6 max-w-4xl">
    <div>
      <p className="text-xs font-semibold uppercase tracking-widest text-[#2F75C3] dark:text-[#2F71E3]">
        About OriginSec
      </p>
      <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#0A0A0C] dark:text-white mt-1">
        Real-time diagnostics, no fluff.
      </h1>
    </div>

    <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-7 space-y-5 text-[15px] leading-[1.65] text-[#5A606E] dark:text-[#9499A6]">
      <p className="text-[#0A0A0C] dark:text-white font-medium text-base">
        OriginSec is built to make website security, quality analysis, and infrastructure visibility easier to understand and act upon. Our goal is to help website owners discover weaknesses, understand their impact, and improve their digital infrastructure using real evidence.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-3 border-t border-[#E5E7EB] dark:border-white/[0.08]">
        <div>
          <p className="text-xs uppercase tracking-wider">Product</p>
          <p className="text-base font-bold text-[#0A0A0C] dark:text-white mt-0.5">OriginSec</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wider">Founder</p>
          <p className="text-base font-bold text-[#0A0A0C] dark:text-white mt-0.5">Aditya Choudhary</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wider">Parent Company</p>
          <p className="text-base font-bold text-[#0A0A0C] dark:text-white mt-0.5">DopTails</p>
        </div>
      </div>
    </section>

    <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-7 space-y-4">
      <h2 className="text-lg font-bold text-[#0A0A0C] dark:text-white">
        Scoring Methodology &amp; Transparent Limitations
      </h2>
      <ul className="list-disc pl-5 space-y-2.5 text-[15px] leading-[1.6] text-[#5A606E] dark:text-[#9499A6]">
        <li>
          Every finding is backed by an observed HTTP header, TLS certificate handshake, DNS record, or HTML DOM measurement.
        </li>
        <li>
          OriginSec never assigns passing scores to untested categories. Database security, hosting platform configuration, and backup statuses remain explicitly marked <strong>Not assessed</strong> or <strong>Unavailable</strong> unless an authorized integration is connected.
        </li>
        <li>
          Static HTML analysis inspects the initial server response; client-side hydrated SPAs may add runtime DOM nodes not visible without a full browser run (available via optional Google PageSpeed Insights integration).
        </li>
        <li>
          OriginSec is a defensive auditing platform protected against SSRF (blocking private IPs, localhost, and cloud metadata on every redirect hop) and never conducts destructive or intrusive attacks.
        </li>
      </ul>
    </section>
  </div>
);
