import React from 'react';
import { Database, HardDrive, Server, ShieldAlert, ShieldCheck, ArrowUpRight } from 'lucide-react';
import type { BackupStatusRecord, IntegrationRecord, WebsiteScan } from '../types/audit';
import type { AppRoute } from './Header';

export const SecurityReportsView: React.FC<{
  scans: WebsiteScan[];
  onOpenReport: (scan: WebsiteScan) => void;
  onNavigate: (route: AppRoute) => void;
}> = ({ scans, onOpenReport, onNavigate }) => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Security Reports</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          External cybersecurity posture assessments across HTTPS/TLS, security headers, cookies, and DNS.
        </p>
      </div>

      {scans.length === 0 ? (
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-8 text-center space-y-3">
          <p className="text-sm text-[#777267] dark:text-[#929292]">No security reports recorded yet.</p>
          <button
            type="button"
            onClick={() => onNavigate('home')}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
          >
            Run Security Audit
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scans.map((s) => (
            <div
              key={s.scanId}
              className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5 space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h2 className="text-base font-bold text-[#151515] dark:text-white">{s.normalizedDomain}</h2>
                  <p className="text-xs font-mono text-[#777267] dark:text-[#929292]">
                    {new Date(s.startedAt).toLocaleString()}
                  </p>
                </div>
                <span className="text-lg font-bold font-mono tabular-nums text-[#151515] dark:text-white">
                  {s.scores?.security ?? 'N/A'}/100
                </span>
              </div>
              <div className="flex flex-wrap gap-3 text-xs font-mono text-[#777267] dark:text-[#929292]">
                <span>Critical: {s.findingsCount?.critical ?? 0}</span>
                <span>High: {s.findingsCount?.high ?? 0}</span>
                <span>Medium: {s.findingsCount?.medium ?? 0}</span>
                <span>Passed: {s.findingsCount?.passed ?? 0}</span>
              </div>
              <button
                type="button"
                onClick={() => onOpenReport(s)}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#008C55] dark:text-[#00E69A] hover:underline cursor-pointer"
              >
                Inspect Security Findings
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export const DatabaseAuditView: React.FC<{
  integrations: IntegrationRecord[];
  onNavigate: (route: AppRoute) => void;
}> = ({ integrations, onNavigate }) => {
  const dbIntegrations = integrations.filter((i) => i.category === 'database' && i.connectionStatus === 'connected');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Database Security Audits</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          Read-only owner-authorized database posture verification. OriginSec never guesses or probes private databases from a public URL.
        </p>
      </div>

      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
        <div className="flex items-start gap-3">
          <Database className="w-5 h-5 text-[#777267] dark:text-[#929292] shrink-0 mt-0.5" />
          <div className="space-y-2">
            <h2 className="text-base font-bold text-[#151515] dark:text-white">
              {dbIntegrations.length > 0 ? 'Connected Database Providers' : 'Database Configuration Not Assessed'}
            </h2>
            <p className="text-sm text-[#777267] dark:text-[#929292]">
              {dbIntegrations.length > 0
                ? `${dbIntegrations.length} read-only database integration(s) authorized.`
                : 'A public website URL does not grant access to your database rules, connection TLS policy, or public exposure state. Connect an authorized read-only integration (Firebase, Supabase, or PostgreSQL) to assess database posture.'}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {[
            { name: 'Firebase / Firestore', scope: 'Security rules review, PII isolation & project configuration' },
            { name: 'Supabase', scope: 'Row-Level Security (RLS) audit & public schema exposure check' },
            { name: 'PostgreSQL (Read-Only)', scope: 'TLS connection enforcement, role privileges & public access check' },
          ].map((dbItem) => (
            <div
              key={dbItem.name}
              className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-4 space-y-2"
            >
              <p className="text-sm font-semibold text-[#151515] dark:text-white">{dbItem.name}</p>
              <p className="text-xs text-[#777267] dark:text-[#929292]">{dbItem.scope}</p>
              <p className="text-[11px] font-mono text-[#777267] dark:text-[#777]">Status: Integration required</p>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={() => onNavigate('integrations')}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
        >
          Manage Database Integrations
        </button>
      </section>
    </div>
  );
};

export const InfrastructureView: React.FC<{
  integrations: IntegrationRecord[];
  onNavigate: (route: AppRoute) => void;
}> = ({ integrations, onNavigate }) => {
  const hostIntegrations = integrations.filter((i) => i.category === 'hosting' && i.connectionStatus === 'connected');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Hosting &amp; Infrastructure</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          Read-only cloud platform inspection for HTTPS enforcement, domain bindings, deployment status, and edge security.
        </p>
      </div>

      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
        <div className="flex items-start gap-3">
          <Server className="w-5 h-5 text-[#777267] dark:text-[#929292] shrink-0 mt-0.5" />
          <div className="space-y-1.5">
            <h2 className="text-base font-bold text-[#151515] dark:text-white">
              {hostIntegrations.length > 0
                ? 'Authorized Hosting Providers Connected'
                : 'Hosting configuration cannot be fully verified from a public website URL.'}
            </h2>
            <p className="text-sm text-[#777267] dark:text-[#929292]">
              Connect a read-only hosting provider integration (Vercel, Netlify, Cloudflare, AWS, or Google Cloud) to audit deployment metadata, domain HTTPS policies, and edge access controls without exposing environment-variable values.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 pt-2">
          {['Vercel', 'Netlify', 'Cloudflare', 'AWS', 'Google Cloud'].map((provider) => (
            <div
              key={provider}
              className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-4 space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-[#151515] dark:text-white">{provider}</span>
                <span className="text-[11px] font-mono text-[#777267] dark:text-[#929292]">Not connected</span>
              </div>
              <p className="text-xs text-[#777267] dark:text-[#929292]">
                Read-only check: HTTPS settings, domain DNS, deployment history &amp; edge security.
              </p>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={() => onNavigate('integrations')}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
        >
          Configure Hosting Integrations
        </button>
      </section>
    </div>
  );
};

export const BackupRecoveryView: React.FC<{
  backupRecords: BackupStatusRecord[];
  onNavigate: (route: AppRoute) => void;
}> = ({ backupRecords, onNavigate }) => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Backup &amp; Disaster Recovery</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          Verified backup telemetry from authorized storage and database providers. OriginSec never displays fabricated backup checks.
        </p>
      </div>

      {backupRecords.length === 0 ? (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
          <div className="flex items-start gap-3">
            <HardDrive className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <h2 className="text-base font-bold text-[#151515] dark:text-white">
                Backup status unavailable — connect an authorized backup provider.
              </h2>
              <p className="text-sm text-[#777267] dark:text-[#929292]">
                A public URL scan cannot observe private snapshot schedules, retention policies, encryption keys, or restore tests. Connect an authorized read-only backup provider to populate verified recovery metrics.
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs text-amber-800 dark:text-amber-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0" />
            <span>Warning: No verified backup evidence is currently connected for this account.</span>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('integrations')}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
          >
            Connect Backup Provider
          </button>
        </section>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {backupRecords.map((b) => (
            <div
              key={b.recordId}
              className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5 space-y-2 text-xs"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-[#151515] dark:text-white">{b.provider}</span>
                <span className="inline-flex items-center gap-1 font-mono uppercase font-semibold">
                  {b.verifiedStatus === 'verified' && <ShieldCheck className="w-3.5 h-3.5 text-[#008C55] dark:text-[#00E69A]" />}
                  {b.verifiedStatus}
                </span>
              </div>
              <p className="text-[#777267] dark:text-[#929292]">{b.evidence}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
