import React, { useMemo, useState } from 'react';
import {
  Activity,
  ChevronDown,
  ChevronUp,
  Download,
  ExternalLink,
  FileJson,
  FileSpreadsheet,
  FileText,
  RefreshCw,
  ShieldAlert,
  Sparkles,
} from 'lucide-react';
import type { FindingCategory, PriorityGroup, ScanFinding, SeverityLevel, WebsiteScan } from '../types/audit';
import { CircularGauge } from './CircularGauge';
import { exportScanAsCsv, exportScanAsJson, exportScanAsPdf } from '../lib/export/exporters';

interface AuditReportViewProps {
  scan: WebsiteScan;
  onRescan: (url: string) => void;
  onAddToMonitoring?: (scan: WebsiteScan) => void;
  onGenerateAiBrief?: (scan: WebsiteScan, audience: 'owner' | 'developer') => Promise<string | null>;
  isGeneratingAi?: boolean;
  aiError?: string | null;
}

const SEVERITY_BADGE_STYLES: Record<SeverityLevel, string> = {
  critical: 'border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-400',
  high: 'border-red-400/50 bg-red-500/10 text-red-700 dark:text-red-300',
  medium: 'border-amber-500/50 bg-amber-500/10 text-amber-800 dark:text-amber-300',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  informational: 'border-[#CFC8B8] dark:border-[#3A3A3A] bg-transparent text-[#777267] dark:text-[#929292]',
  passed: 'border-[#008C55]/45 dark:border-[#00E69A]/40 bg-[#008C55]/10 dark:bg-[#00E69A]/10 text-[#008C55] dark:text-[#00E69A]',
};

const CATEGORY_TITLES: Record<FindingCategory, string> = {
  security: 'Cybersecurity & Hardening',
  frontend: 'Front-End & UI/UX',
  backend: 'Back-End & Architecture',
  engagement: 'Product & Engagement',
  api: 'API Posture',
  database: 'Database Security',
  hosting: 'Hosting & Infrastructure',
  backup: 'Backup & Recovery',
  monitoring: 'Monitoring & Alerts',
};

const PRIORITY_LABELS: Record<PriorityGroup, string> = {
  fix_immediately: 'Fix immediately',
  fix_soon: 'Fix soon',
  optimization: 'Optimization opportunities',
  best_practice: 'Best practices',
  long_term: 'Long-term improvements',
};

const FindingCard: React.FC<{ finding: ScanFinding }> = ({ finding }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <article className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-6 space-y-3.5 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <h4 className="text-base font-semibold text-[#151515] dark:text-white leading-snug">
          {finding.title}
        </h4>
        <span
          className={`px-2.5 py-0.5 rounded-md border text-[11px] font-bold tracking-wider uppercase whitespace-nowrap shrink-0 ${
            SEVERITY_BADGE_STYLES[finding.severity]
          }`}
        >
          {finding.status === 'not_assessed' ? 'NOT ASSESSED' : finding.severity.toUpperCase()}
        </span>
      </div>

      <p className="text-[15px] leading-[1.6] text-[#777267] dark:text-[#929292]">
        {finding.description}
      </p>

      <div className="border-t border-[#E7E0D3] dark:border-[#202020] pt-3.5 space-y-2.5 text-[15px]">
        <p className="text-[#151515] dark:text-[#E5E5E5] leading-[1.6]">
          <span className="font-semibold">Fix:</span> {finding.recommendation}
          {finding.remediation && (
            <code className="block mt-2 px-3 py-2 rounded-lg bg-[#EFECE4] dark:bg-[#070707] border border-[#E7E0D3] dark:border-[#222] text-[13px] font-mono text-[#151515] dark:text-[#D4D4D4] break-all whitespace-pre-wrap">
              {finding.remediation}
            </code>
          )}
        </p>

        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="inline-flex items-center gap-1.5 text-[13px] font-medium text-[#777267] dark:text-[#929292] hover:text-[#151515] dark:hover:text-white cursor-pointer pt-1 transition-colors"
        >
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          {expanded ? 'Hide evidence & verification' : 'Inspect evidence, impact & verification'}
        </button>

        {expanded && (
          <div className="pt-2.5 space-y-2 text-[13px] text-[#777267] dark:text-[#929292] border-t border-dashed border-[#E7E0D3] dark:border-[#222]">
            <div>
              <span className="font-semibold text-[#151515] dark:text-white">Evidence: </span>
              <span className="font-mono break-all">{finding.evidence}</span>
            </div>
            <div>
              <span className="font-semibold text-[#151515] dark:text-white">Observed Value: </span>
              <span className="font-mono">{finding.observedValue}</span>
            </div>
            <div>
              <span className="font-semibold text-[#151515] dark:text-white">Affected URL: </span>
              <span className="font-mono break-all">{finding.affectedUrl}</span>
            </div>
            <div>
              <span className="font-semibold text-[#151515] dark:text-white">Impact: </span>
              <span>{finding.impact}</span>
            </div>
            <div>
              <span className="font-semibold text-[#151515] dark:text-white">Verification: </span>
              <span>{finding.verification}</span>
            </div>
          </div>
        )}
      </div>
    </article>
  );
};

export const AuditReportView: React.FC<AuditReportViewProps> = ({
  scan,
  onRescan,
  onAddToMonitoring,
  onGenerateAiBrief,
  isGeneratingAi,
  aiError,
}) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'recommendations' | 'telemetry' | 'ai'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [audience, setAudience] = useState<'owner' | 'developer'>('owner');
  const [localAiText, setLocalAiText] = useState<string | null>(scan.aiExplanation || null);

  const findings = scan.findings || [];

  const filteredFindings = useMemo(() => {
    if (severityFilter === 'all') return findings;
    return findings.filter((f) => f.severity === severityFilter);
  }, [findings, severityFilter]);

  const primaryCategories: FindingCategory[] = ['security', 'frontend', 'backend', 'engagement'];
  const extendedCategories: FindingCategory[] = ['database', 'hosting', 'backup'];

  const priorityOrder: PriorityGroup[] = [
    'fix_immediately',
    'fix_soon',
    'optimization',
    'best_practice',
    'long_term',
  ];

  const sevCounts = scan.findingsCount || {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    informational: findings.filter((f) => f.severity === 'informational').length,
    passed: findings.filter((f) => f.severity === 'passed').length,
  };

  const maxSevVal = Math.max(1, sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low, sevCounts.passed);

  const handleAiTrigger = async () => {
    if (!onGenerateAiBrief) return;
    const result = await onGenerateAiBrief(scan, audience);
    if (result) setLocalAiText(result);
  };

  return (
    <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8 animate-fade-up">
      {/* Top Report Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E] pb-6">
        <div className="space-y-1.5 min-w-0">
          <h1 className="text-2xl sm:text-[34px] font-bold tracking-tight text-[#151515] dark:text-white break-words">
            Audit report — {scan.normalizedDomain}
          </h1>
          <p className="text-[15px] text-[#777267] dark:text-[#929292] break-all">
            {scan.targetUrl}
          </p>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-[#777267] dark:text-[#929292] pt-1 font-mono tabular-nums">
            <span>ID: {scan.scanId}</span>
            <span aria-hidden="true">·</span>
            <span>Status: {scan.status}</span>
            <span aria-hidden="true">·</span>
            <span>{new Date(scan.completedAt || scan.startedAt).toLocaleString()}</span>
            <span aria-hidden="true">·</span>
            <span>{scan.coverage?.pagesScanned ?? 1} page(s) crawled</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <a
            href={scan.targetUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-medium border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#929292] transition-colors whitespace-nowrap"
          >
            Visit site
            <ExternalLink className="w-3.5 h-3.5" />
          </a>

          <button
            type="button"
            onClick={() => onRescan(scan.targetUrl)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-medium border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#008C55] dark:hover:border-[#00E69A] transition-colors whitespace-nowrap cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Rescan
          </button>

          {onAddToMonitoring && (
            <button
              type="button"
              onClick={() => onAddToMonitoring(scan)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-medium border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#008C55] dark:hover:border-[#00E69A] transition-colors whitespace-nowrap cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5" />
              Monitor
            </button>
          )}

          <div className="inline-flex items-center rounded-full border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-0.5">
            <button
              type="button"
              onClick={() => exportScanAsPdf(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#151515] dark:text-white hover:bg-[#F7F5EF] dark:hover:bg-[#1A1A1A] cursor-pointer"
              title="Export PDF Report"
            >
              <FileText className="w-3 h-3" />
              PDF
            </button>
            <button
              type="button"
              onClick={() => exportScanAsCsv(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#151515] dark:text-white hover:bg-[#F7F5EF] dark:hover:bg-[#1A1A1A] cursor-pointer"
              title="Export CSV Findings"
            >
              <FileSpreadsheet className="w-3 h-3" />
              CSV
            </button>
            <button
              type="button"
              onClick={() => exportScanAsJson(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#151515] dark:text-white hover:bg-[#F7F5EF] dark:hover:bg-[#1A1A1A] cursor-pointer"
              title="Export JSON Report"
            >
              <FileJson className="w-3 h-3" />
              JSON
            </button>
          </div>
        </div>
      </div>

      {/* Executive Summary Box */}
      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-7 space-y-2.5">
        <p className="text-[16px] sm:text-[17px] leading-[1.65] text-[#151515] dark:text-[#EDEDED]">
          {scan.summary}
        </p>
        <p className="text-[13px] text-[#777267] dark:text-[#929292]">
          Coverage: HTTPS {scan.coverage?.httpsVerified ? 'checked' : 'unavailable'} · TLS{' '}
          {scan.coverage?.tlsVerified ? 'verified' : 'unavailable'} · DNS{' '}
          {scan.coverage?.dnsVerified ? 'resolved' : 'unavailable'} · Lighthouse{' '}
          {scan.coverage?.lighthouseVerified ? 'verified' : 'not configured'} · DB/Hosting/Backup{' '}
          {scan.coverage?.databaseVerified || scan.coverage?.hostingVerified || scan.coverage?.backupVerified
            ? 'owner-connected'
            : 'not assessed (no integration connected)'}
        </p>
      </section>

      {/* Four Score Ring Cards matching Screenshots 3 & 4 */}
      <section aria-label="Category Scores" className="grid grid-cols-2 lg:grid-cols-4 gap-5">
        <CircularGauge score={scan.scores?.security ?? null} label="SECURITY" />
        <CircularGauge score={scan.scores?.frontend ?? null} label="FRONT-END" />
        <CircularGauge score={scan.scores?.backend ?? null} label="BACK-END" />
        <CircularGauge score={scan.scores?.engagement ?? null} label="ENGAGEMENT" />
      </section>

      {/* Report Sub-Navigation Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E] pb-3">
        <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Report Sections">
          {(
            [
              { id: 'findings', label: `Checks & Findings (${findings.length})` },
              { id: 'recommendations', label: 'Recommendation Priority' },
              { id: 'telemetry', label: 'Metrics, TLS, DNS & Charts' },
              { id: 'ai', label: 'AI Analyst Brief' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 rounded-lg text-[13px] font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                activeTab === tab.id
                  ? 'bg-[#151515] text-white dark:bg-white dark:text-[#050505]'
                  : 'text-[#777267] dark:text-[#929292] hover:text-[#151515] dark:hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'findings' && (
          <div className="flex items-center gap-2">
            <label htmlFor="severity-filter" className="text-[13px] text-[#777267] dark:text-[#929292]">
              Filter:
            </label>
            <select
              id="severity-filter"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3.5 py-2 rounded-lg text-[13px] border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white cursor-pointer"
            >
              <option value="all">All Checks ({findings.length})</option>
              <option value="critical">Critical ({sevCounts.critical})</option>
              <option value="high">High ({sevCounts.high})</option>
              <option value="medium">Medium ({sevCounts.medium})</option>
              <option value="low">Low ({sevCounts.low})</option>
              <option value="informational">Informational ({sevCounts.informational})</option>
              <option value="passed">Passed ({sevCounts.passed})</option>
            </select>
          </div>
        )}
      </div>

      {/* Category Audit Grid */}
      {activeTab === 'findings' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
            {primaryCategories.map((cat) => {
              const catFindings = filteredFindings.filter((f) => f.category === cat);
              return (
                <section
                  key={cat}
                  className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-7 space-y-5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xl font-bold text-[#151515] dark:text-white">
                      {CATEGORY_TITLES[cat]}
                    </h3>
                    <span className="text-[13px] font-mono tabular-nums text-[#777267] dark:text-[#929292]">
                      {catFindings.length} check{catFindings.length === 1 ? '' : 's'}
                    </span>
                  </div>

                  {catFindings.length === 0 ? (
                    <p className="text-sm text-[#777267] dark:text-[#929292] py-4">
                      No findings match the selected severity filter in this category.
                    </p>
                  ) : (
                    <div className="space-y-4">
                      {catFindings.map((f) => (
                        <FindingCard key={f.findingId} finding={f} />
                      ))}
                    </div>
                  )}
                </section>
              );
            })}
          </div>

          {/* Extended Infrastructure / Database / Backup Transparency Cards */}
          <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h3 className="text-lg font-bold text-[#151515] dark:text-white">
                Extended Infrastructure Scope (Database, Hosting &amp; Backup)
              </h3>
              <span className="text-xs text-[#777267] dark:text-[#929292]">
                Requires authorized owner integration
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {extendedCategories.map((cat) => {
                const items = findings.filter((f) => f.category === cat);
                return (
                  <div key={cat} className="space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-[#777267] dark:text-[#929292]">
                      {CATEGORY_TITLES[cat]}
                    </h4>
                    {items.map((f) => (
                      <FindingCard key={f.findingId} finding={f} />
                    ))}
                  </div>
                );
              })}
            </div>
          </section>
        </div>
      )}

      {/* TAB 2: Recommendation Engine */}
      {activeTab === 'recommendations' && (
        <div className="space-y-6">
          {priorityOrder.map((group) => {
            const items = findings.filter((f) => f.priorityGroup === group);
            if (items.length === 0) return null;
            return (
              <section
                key={group}
                className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4"
              >
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-bold text-[#151515] dark:text-white">
                    {PRIORITY_LABELS[group]}
                  </h3>
                  <span className="text-xs font-mono tabular-nums text-[#777267] dark:text-[#929292]">
                    {items.length} item{items.length === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {items.map((item) => (
                    <FindingCard key={item.findingId} finding={item} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>
      )}

      {/* TAB 3: Metrics, TLS, DNS & Visual Charts */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6">
          {/* Performance & DOM Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'TTFB Latency', value: `${scan.metrics?.ttfbMs ?? 'N/A'} ms` },
              { label: 'Total Response Time', value: `${scan.metrics?.totalResponseTimeMs ?? 'N/A'} ms` },
              { label: 'HTTP Status', value: `${scan.metrics?.statusCode ?? 'N/A'}` },
              { label: 'HTML Payload', value: scan.metrics?.htmlSizeBytes ? `${(scan.metrics.htmlSizeBytes / 1024).toFixed(1)} KB` : 'N/A' },
              { label: 'Static DOM Nodes', value: `${scan.metrics?.domNodeCount ?? 'N/A'}` },
              { label: 'Scripts / CSS', value: `${scan.metrics?.scriptCount ?? 0} / ${scan.metrics?.stylesheetCount ?? 0}` },
              { label: 'Compression', value: scan.metrics?.compression || 'None observed' },
              { label: 'Redirects', value: `${scan.metrics?.redirectCount ?? 0} hop(s)` },
            ].map((m) => (
              <div
                key={m.label}
                className="rounded-xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4"
              >
                <p className="text-xs text-[#777267] dark:text-[#929292]">{m.label}</p>
                <p className="text-lg font-bold font-mono tabular-nums text-[#151515] dark:text-white mt-1 truncate">
                  {m.value}
                </p>
              </div>
            ))}
          </div>

          {/* Severity Distribution Chart (From Real Findings) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
              <h3 className="text-base font-bold text-[#151515] dark:text-white">
                Severity Distribution (Observed Checks)
              </h3>
              <div className="space-y-3">
                {(
                  [
                    { label: 'Critical', count: sevCounts.critical, color: 'bg-red-600' },
                    { label: 'High', count: sevCounts.high, color: 'bg-red-400' },
                    { label: 'Medium', count: sevCounts.medium, color: 'bg-amber-500' },
                    { label: 'Low', count: sevCounts.low, color: 'bg-sky-500' },
                    { label: 'Informational', count: sevCounts.informational, color: 'bg-neutral-400' },
                    { label: 'Passed', count: sevCounts.passed, color: 'bg-[#008C55] dark:bg-[#00E69A]' },
                  ] as const
                ).map((row) => (
                  <div key={row.label} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-[#151515] dark:text-white font-medium">{row.label}</span>
                      <span className="font-mono tabular-nums text-[#777267] dark:text-[#929292]">{row.count}</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[#EFECE4] dark:bg-[#1B1B1B] overflow-hidden">
                      <div
                        className={`h-full rounded-full ${row.color}`}
                        style={{ width: `${(row.count / maxSevVal) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* TLS & DNS Observations */}
            <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
              <h3 className="text-base font-bold text-[#151515] dark:text-white">
                TLS Certificate &amp; DNS Signals
              </h3>
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#EFECE4] dark:border-[#1B1B1B]">
                  <span className="text-[#777267] dark:text-[#929292]">TLS Protocol / Cipher</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right">
                    {scan.metrics?.tls?.available
                      ? `${scan.metrics.tls.protocol || 'TLS'} (${scan.metrics.tls.cipher || 'N/A'})`
                      : 'Unavailable'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#EFECE4] dark:border-[#1B1B1B]">
                  <span className="text-[#777267] dark:text-[#929292]">Certificate Issuer &amp; Expiry</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right">
                    {scan.metrics?.tls?.available
                      ? `${scan.metrics.tls.issuer || 'CA'} · ${scan.metrics.tls.daysRemaining ?? '?'}d remaining`
                      : 'Unavailable'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#EFECE4] dark:border-[#1B1B1B]">
                  <span className="text-[#777267] dark:text-[#929292]">DNS A / AAAA Records</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right truncate max-w-[260px]">
                    {[...(scan.metrics?.dns?.aRecords || []), ...(scan.metrics?.dns?.aaaaRecords || [])].join(', ') || 'None'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#EFECE4] dark:border-[#1B1B1B]">
                  <span className="text-[#777267] dark:text-[#929292]">Email DNS (SPF / DMARC)</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right">
                    SPF: {scan.metrics?.dns?.hasSpf ? 'Observed' : 'Not observed'} · DMARC:{' '}
                    {scan.metrics?.dns?.hasDmarc ? 'Observed' : 'Not observed'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5">
                  <span className="text-[#777267] dark:text-[#929292]">PageSpeed Insights (Lighthouse)</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right">
                    {scan.metrics?.lighthouse?.available
                      ? `Perf ${scan.metrics.lighthouse.performanceScore}/100 · LCP ${scan.metrics.lighthouse.lcpMs}ms (${scan.metrics.lighthouse.dataType})`
                      : 'Not configured on server'}
                  </span>
                </div>
              </div>
            </section>
          </div>
        </div>
      )}

      {/* TAB 4: Gemini AI Explanation */}
      {activeTab === 'ai' && (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E] pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
                <h3 className="text-base font-bold text-[#151515] dark:text-white">
                  AI-Generated Findings Brief (Optional)
                </h3>
              </div>
              <p className="text-xs text-[#777267] dark:text-[#929292]">
                Distinguishes deterministic observed facts from AI interpretation. Only sanitized findings are passed to Gemini; cookies and credentials are never sent.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <select
                value={audience}
                onChange={(e) => setAudience(e.target.value as 'owner' | 'developer')}
                aria-label="Brief Audience"
                className="px-3 py-2 rounded-lg text-xs border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
              >
                <option value="owner">Website Owner Summary</option>
                <option value="developer">Developer Remediation Brief</option>
              </select>
              <button
                type="button"
                onClick={handleAiTrigger}
                disabled={isGeneratingAi}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 disabled:opacity-50 cursor-pointer whitespace-nowrap"
              >
                {isGeneratingAi ? 'Generating...' : 'Generate AI Brief'}
              </button>
            </div>
          </div>

          {aiError && (
            <div className="rounded-xl border border-amber-400/50 bg-amber-500/10 p-4 text-xs text-amber-800 dark:text-amber-300 flex items-start gap-2.5">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{aiError}</span>
            </div>
          )}

          {localAiText ? (
            <div className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-5 space-y-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-[#008C55] dark:text-[#00E69A]">
                AI-Generated Interpretation (Grounded in Verified Scan Data)
              </p>
              <div className="text-sm leading-relaxed text-[#151515] dark:text-[#E5E5E5] whitespace-pre-wrap">
                {localAiText}
              </div>
            </div>
          ) : (
            <div className="text-center py-8 text-sm text-[#777267] dark:text-[#929292]">
              Select an audience and click <strong>Generate AI Brief</strong> to synthesize prioritized remediation steps from the verified findings above.
            </div>
          )}
        </section>
      )}
    </main>
  );
};
