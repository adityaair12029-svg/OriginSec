import React, { useEffect, useState } from 'react';
import { CheckCircle2, Cloud, Database, Cpu, Gauge, Shield, PlugZap } from 'lucide-react';
import type { IntegrationRecord } from '../types/audit';

interface ServerIntegrationStatus {
  providers: {
    firebase_auth: { connected: boolean; label: string };
    firebase_firestore: { connected: boolean; label: string };
    pagespeed_insights: { connected: boolean; label: string };
    gemini_ai: { connected: boolean; label: string };
  };
}

interface IntegrationsViewProps {
  isAuthenticated: boolean;
  userIntegrations: IntegrationRecord[];
  onDisconnectIntegration: (integrationId: string) => Promise<void>;
}

const FUTURE_PROVIDERS: Array<{
  provider: string;
  name: string;
  category: IntegrationRecord['category'];
  purpose: string;
  permissions: string;
}> = [
  {
    provider: 'vercel',
    name: 'Vercel',
    category: 'hosting',
    purpose: 'Inspect deployment status, HTTPS domains, and edge security headers (no secret values exposed).',
    permissions: 'Read-only Vercel Project & Domain API scope',
  },
  {
    provider: 'netlify',
    name: 'Netlify',
    category: 'hosting',
    purpose: 'Audit DNS zones, TLS certificate status, and deployment headers.',
    permissions: 'Read-only Netlify Site Metadata scope',
  },
  {
    provider: 'cloudflare',
    name: 'Cloudflare',
    category: 'hosting',
    purpose: 'Review WAF rules, SSL/TLS encryption mode, HSTS edge settings, and DNSSEC status.',
    permissions: 'Read-only Zone Settings & DNS Read token',
  },
  {
    provider: 'aws',
    name: 'AWS',
    category: 'hosting',
    purpose: 'Inspect CloudFront TLS policy, S3 public-access blocks, and backup vault status.',
    permissions: 'Read-only IAM SecurityAudit Role ARN',
  },
  {
    provider: 'gcp',
    name: 'Google Cloud',
    category: 'hosting',
    purpose: 'Audit Cloud Run / Load Balancer HTTPS posture and Cloud Armor configuration.',
    permissions: 'Read-only GCP Security Viewer role',
  },
  {
    provider: 'supabase',
    name: 'Supabase',
    category: 'database',
    purpose: 'Check Row-Level Security (RLS) policy coverage and public schema exposure.',
    permissions: 'Read-only Project Metadata & Postgres schema inspection',
  },
  {
    provider: 'postgresql',
    name: 'PostgreSQL',
    category: 'database',
    purpose: 'Verify SSL/TLS connection requirement, role least-privilege, and backup metadata.',
    permissions: 'Read-only restricted monitoring role',
  },
  {
    provider: 'backup_provider',
    name: 'Backup & Snapshot Provider',
    category: 'backup',
    purpose: 'Verify last successful backup timestamp, retention policy, and encryption status.',
    permissions: 'Read-only snapshot metadata (never deletes or overwrites backups)',
  },
];

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({
  userIntegrations,
  onDisconnectIntegration,
}) => {
  const [serverStatus, setServerStatus] = useState<ServerIntegrationStatus | null>(null);
  const [setupNote, setSetupNote] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/integrations/status')
      .then((r) => r.json())
      .then((d) => setServerStatus(d))
      .catch(() => setServerStatus(null));
  }, []);

  const coreProviders = [
    {
      id: 'firebase_auth',
      name: 'Firebase Authentication',
      purpose: 'Google Sign-In authentication and server-verified identity tokens.',
      permissions: 'Email, display name, and profile avatar (read-only)',
      connected: serverStatus?.providers.firebase_auth.connected ?? false,
      statusText: serverStatus?.providers.firebase_auth.label || 'Checking...',
      icon: Shield,
    },
    {
      id: 'firebase_firestore',
      name: 'Firebase Firestore',
      purpose: 'User-isolated scan reports, findings, monitoring targets, and preferences.',
      permissions: 'Owner-scoped Firestore collections enforced by security rules',
      connected: serverStatus?.providers.firebase_firestore.connected ?? false,
      statusText: serverStatus?.providers.firebase_firestore.label || 'Checking...',
      icon: Database,
    },
    {
      id: 'pagespeed_insights',
      name: 'Google PageSpeed Insights',
      purpose: 'Real Lighthouse Lab & CrUX Field Core Web Vitals (LCP, CLS, INP, FCP).',
      permissions: 'Server-side PAGESPEED_API_KEY environment variable',
      connected: serverStatus?.providers.pagespeed_insights.connected ?? false,
      statusText: serverStatus?.providers.pagespeed_insights.label || 'Checking...',
      icon: Gauge,
    },
    {
      id: 'gemini_ai',
      name: 'Gemini AI Explanation Engine',
      purpose: 'Translates verified deterministic scan findings into owner & developer briefs.',
      permissions: 'Server-side GEMINI_API_KEY (receives sanitized findings only)',
      connected: serverStatus?.providers.gemini_ai.connected ?? false,
      statusText: serverStatus?.providers.gemini_ai.label || 'Checking...',
      icon: Cpu,
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Integration Center</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          Real connection status for core OriginSec services and authorized read-only infrastructure adapters. Integrations are never shown as connected without verified server credentials.
        </p>
      </div>

      {/* Core Platform Integrations */}
      <section className="space-y-3">
        <h2 className="text-sm font-bold uppercase tracking-wider text-[#777267] dark:text-[#929292]">
          Core Platform Services
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {coreProviders.map((p) => {
            const Icon = p.icon;
            return (
              <div
                key={p.id}
                className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5 space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-5 h-5 text-[#151515] dark:text-white shrink-0" />
                    <h3 className="text-base font-bold text-[#151515] dark:text-white">{p.name}</h3>
                  </div>
                  <span
                    className={`inline-flex items-center gap-1 text-[11px] font-mono font-semibold px-2.5 py-1 rounded-md border ${
                      p.connected
                        ? 'border-[#008C55]/40 dark:border-[#00E69A]/40 text-[#008C55] dark:text-[#00E69A]'
                        : 'border-[#E7E0D3] dark:border-[#252525] text-[#777267] dark:text-[#929292]'
                    }`}
                  >
                    {p.connected && <CheckCircle2 className="w-3 h-3" />}
                    {p.connected ? 'Connected' : 'Not configured'}
                  </span>
                </div>
                <p className="text-xs text-[#777267] dark:text-[#929292] leading-relaxed">{p.purpose}</p>
                <div className="text-[11px] text-[#777267] dark:text-[#888] border-t border-[#EFECE4] dark:border-[#1A1A1A] pt-2.5 space-y-1">
                  <p>
                    <strong>Scope:</strong> {p.permissions}
                  </p>
                  <p className="font-mono">{p.statusText}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Authorized Infrastructure & Database Provider Modules */}
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-[#777267] dark:text-[#929292]">
            Infrastructure, Database &amp; Backup Adapters
          </h2>
        </div>

        {setupNote && (
          <div className="rounded-xl border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] p-4 text-xs text-[#151515] dark:text-[#E5E5E5] flex items-start gap-2.5">
            <PlugZap className="w-4 h-4 text-[#008C55] dark:text-[#00E69A] shrink-0 mt-0.5" />
            <span>{setupNote}</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {FUTURE_PROVIDERS.map((fp) => {
            const linked = userIntegrations.find((u) => u.provider === fp.provider && u.connectionStatus === 'connected');
            return (
              <div
                key={fp.provider}
                className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5 space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <Cloud className="w-4 h-4 text-[#777267] dark:text-[#929292]" />
                    <h3 className="text-sm font-bold text-[#151515] dark:text-white">{fp.name}</h3>
                  </div>
                  <span className="text-[11px] font-mono text-[#777267] dark:text-[#929292]">
                    {linked ? 'Connected' : 'Integration required'}
                  </span>
                </div>
                <p className="text-xs text-[#777267] dark:text-[#929292]">{fp.purpose}</p>
                <p className="text-[11px] text-[#777267] dark:text-[#888]">
                  <strong>Permissions:</strong> {fp.permissions}
                </p>
                <div className="pt-1 flex items-center justify-between">
                  {linked ? (
                    <button
                      type="button"
                      onClick={() => onDisconnectIntegration(linked.integrationId)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium border border-red-400/50 text-red-600 dark:text-red-400 cursor-pointer"
                    >
                      Disconnect
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() =>
                        setSetupNote(
                          `${fp.name} read-only connector requires server-side OAuth/API credentials configured in your Vercel Environment Variables (see README.md). OriginSec never simulates unverified provider connections.`
                        )
                      }
                      className="px-3 py-1.5 rounded-lg text-xs font-medium border border-[#E7E0D3] dark:border-[#252525] text-[#151515] dark:text-white hover:border-[#008C55] dark:hover:border-[#00E69A] cursor-pointer"
                    >
                      View Setup Requirements
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
