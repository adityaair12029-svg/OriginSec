import React, { useMemo, useState } from 'react';
import { Activity, ArrowUpRight, Globe, PlusCircle, TrendingDown, TrendingUp, Wrench } from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { MonitoringTarget, RemediationTask, WebsiteRecord, WebsiteScan } from '../types/audit';
import type { AppRoute } from './Header';
import { EmptyWorkspaceState } from './DashboardShell';
import { buildWebsiteScoreTrends } from '../lib/scanner/trends';

interface OverviewViewProps {
  scans: WebsiteScan[];
  websites: WebsiteRecord[];
  monitoringTargets: MonitoringTarget[];
  remediationTasks: RemediationTask[];
  onOpenReport: (scan: WebsiteScan) => void;
  onNavigate: (route: AppRoute) => void;
  userEmail?: string | null;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  scans,
  websites,
  monitoringTargets,
  remediationTasks,
  onOpenReport,
  onNavigate,
  userEmail,
}) => {
  const completedScans = useMemo(
    () => scans.filter((s) => s.status === 'completed' || s.status === 'partially_completed'),
    [scans]
  );

  const uniqueDomains = useMemo(() => {
    const set = new Set<string>();
    for (const s of completedScans) {
      if (s.normalizedDomain) set.add(s.normalizedDomain);
    }
    for (const w of websites) {
      if (w.normalizedDomain) set.add(w.normalizedDomain);
    }
    return Array.from(set);
  }, [completedScans, websites]);

  const [selectedDomain, setSelectedDomain] = useState<string>('all');
  const activeDomain =
    selectedDomain !== 'all' && !uniqueDomains.includes(selectedDomain) ? 'all' : selectedDomain;

  const trendSummary = useMemo(
    () => buildWebsiteScoreTrends(scans, activeDomain, 5),
    [scans, activeDomain]
  );

  const openFindings = scans.reduce(
    (acc, s) =>
      acc + (s.findingsCount ? s.findingsCount.critical + s.findingsCount.high + s.findingsCount.medium + s.findingsCount.low : 0),
    0
  );
  const highCriticalFindings = scans.reduce(
    (acc, s) => acc + (s.findingsCount ? s.findingsCount.critical + s.findingsCount.high : 0),
    0
  );

  const latestScan = scans[0] || null;
  const activeMonitors = monitoringTargets.filter((t) => t.enabled);
  const openTasks = remediationTasks.filter((t) => t.status !== 'resolved' && t.status !== 'accepted_risk');

  const kpis = [
    { label: 'Registered Websites', value: websites.length },
    { label: 'Completed Scans', value: completedScans.length },
    { label: 'Active Monitors', value: activeMonitors.length },
    { label: 'Total Observed Issues', value: openFindings },
    { label: 'High / Critical Issues', value: highCriticalFindings },
    { label: 'Open Remediation Tasks', value: openTasks.length },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-semibold text-[#0A0A0C] dark:text-white">
            Security &amp; Audit Overview
          </h1>
          <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] mt-1">
            {userEmail ? `Signed in as ${userEmail} · Real-time deterministic telemetry` : 'Real-time diagnostics summary'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full text-xs font-medium bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-90 cursor-pointer whitespace-nowrap shrink-0"
        >
          <PlusCircle className="w-4 h-4" />
          New Website Scan
        </button>
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {kpis.map((kpi) => (
          <div
            key={kpi.label}
            className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-5"
          >
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">{kpi.label}</p>
            <p className="text-2xl font-bold tabular-nums text-[#0A0A0C] dark:text-white mt-1.5">
              {kpi.value}
            </p>
          </div>
        ))}
      </div>

      {/* Recharts Visual Score Trends (Last 5 Scans per Website) */}
      <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-[#0A0A0C] dark:text-white">
              Security &amp; Quality Trends (Last 5 Scans)
            </h2>
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6] mt-0.5">
              Track improvement or regression in Security Score and Overall Score per audited website.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {trendSummary.securityDelta !== null && (
              <span
                className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono font-semibold border ${
                  trendSummary.securityDelta > 0
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                    : trendSummary.securityDelta < 0
                      ? 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400'
                      : 'border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6]'
                }`}
              >
                {trendSummary.securityDelta >= 0 ? (
                  <TrendingUp className="w-3.5 h-3.5" />
                ) : (
                  <TrendingDown className="w-3.5 h-3.5" />
                )}
                Security {trendSummary.securityDelta > 0 ? `+${trendSummary.securityDelta}` : trendSummary.securityDelta} pts
              </span>
            )}

            <label htmlFor="trend-domain-select" className="sr-only">
              Select website for score trend chart
            </label>
            <select
              id="trend-domain-select"
              value={activeDomain}
              onChange={(e) => setSelectedDomain(e.target.value)}
              className="px-3.5 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#0D0E12] text-[#0A0A0C] dark:text-white cursor-pointer"
            >
              <option value="all">All Audited Websites ({completedScans.length})</option>
              {uniqueDomains.map((dom) => (
                <option key={dom} value={dom}>
                  {dom}
                </option>
              ))}
            </select>
          </div>
        </div>

        {trendSummary.points.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[#E5E7EB] dark:border-white/[0.1] p-8 text-center text-xs text-[#5A606E] dark:text-[#9499A6]">
            Run at least one audit for the selected website to visualize score trends here.
          </div>
        ) : (
          <div className="w-full h-72 min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendSummary.points} margin={{ top: 10, right: 16, left: -12, bottom: 0 }}>
                <defs>
                  <linearGradient id="secScoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2F71E3" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#2F71E3" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="overallScoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#16A34A" stopOpacity={0.22} />
                    <stop offset="95%" stopColor="#16A34A" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,153,166,0.2)" />
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 11, fill: '#9499A6' }}
                  axisLine={{ stroke: 'rgba(148,153,166,0.25)' }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 11, fill: '#9499A6' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#101115',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: '12px',
                    color: '#FFFFFF',
                    fontSize: '12px',
                  }}
                  formatter={(value: unknown, name: unknown) => [`${value}/100`, String(name)]}
                  labelFormatter={(label, payload) => {
                    const first = payload?.[0]?.payload as { domain?: string; fullDate?: string } | undefined;
                    return first ? `${first.domain} · ${first.fullDate}` : String(label);
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
                <Area
                  type="monotone"
                  dataKey="security"
                  name="Security Score"
                  stroke="#2F71E3"
                  strokeWidth={2.5}
                  fill="url(#secScoreGrad)"
                  dot={{ r: 4, strokeWidth: 2 }}
                  activeDot={{ r: 6 }}
                />
                <Area
                  type="monotone"
                  dataKey="overall"
                  name="Overall Score"
                  stroke="#16A34A"
                  strokeWidth={2}
                  fill="url(#overallScoreGrad)"
                  dot={{ r: 3.5, strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      {/* Latest Scan Highlight */}
      {latestScan ? (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-[#2F75C3] dark:text-[#2F71E3]">
                Latest Verified Scan
              </p>
              <h2 className="text-lg font-semibold text-[#0A0A0C] dark:text-white mt-0.5">
                {latestScan.normalizedDomain}
              </h2>
              <p className="text-xs text-[#5A606E] dark:text-[#9499A6] font-mono">
                {new Date(latestScan.startedAt).toLocaleString()} · Overall Score:{' '}
                {latestScan.scores?.overall ?? 'N/A'}/100
              </p>
            </div>
            <button
              type="button"
              onClick={() => onOpenReport(latestScan)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.12] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] cursor-pointer whitespace-nowrap"
            >
              Open Full Report
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <p className="text-sm text-[#5A606E] dark:text-[#9499A6] leading-relaxed">{latestScan.summary}</p>
        </section>
      ) : (
        <EmptyWorkspaceState
          title="No audits recorded yet"
          description="Run your first live website audit to measure HTTPS/TLS posture, HTTP security headers, DOM structure, server TTFB, and engagement signals."
          actionLabel="Start First Audit"
          onAction={() => onNavigate('home')}
        />
      )}

      {/* Website Properties & Active Monitors Snapshot */}
      {(websites.length > 0 || monitoringTargets.length > 0 || openTasks.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            type="button"
            onClick={() => onNavigate('websites')}
            className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-5 text-left hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors cursor-pointer space-y-1.5"
          >
            <div className="flex items-center justify-between">
              <Globe className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
              <ArrowUpRight className="w-4 h-4 text-[#5A606E] dark:text-[#9499A6]" />
            </div>
            <p className="text-sm font-semibold text-[#0A0A0C] dark:text-white">My Websites ({websites.length})</p>
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Manage domain verification &amp; scan profiles</p>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('remediation')}
            className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-5 text-left hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors cursor-pointer space-y-1.5"
          >
            <div className="flex items-center justify-between">
              <Wrench className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
              <ArrowUpRight className="w-4 h-4 text-[#5A606E] dark:text-[#9499A6]" />
            </div>
            <p className="text-sm font-semibold text-[#0A0A0C] dark:text-white">Remediation Queue ({openTasks.length})</p>
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Track open fixes and verify live resolution</p>
          </button>

          <button
            type="button"
            onClick={() => onNavigate('monitoring')}
            className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-5 text-left hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors cursor-pointer space-y-1.5"
          >
            <div className="flex items-center justify-between">
              <Activity className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
              <ArrowUpRight className="w-4 h-4 text-[#5A606E] dark:text-[#9499A6]" />
            </div>
            <p className="text-sm font-semibold text-[#0A0A0C] dark:text-white">Uptime &amp; TLS Monitors ({activeMonitors.length})</p>
            <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">Live HTTP checks &amp; certificate expiry alerts</p>
          </button>
        </div>
      )}

      {/* Recent Scans Table */}
      {scans.length > 0 && (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#E5E7EB] dark:border-white/[0.08] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[#0A0A0C] dark:text-white">Recent Scans</h2>
            <button
              type="button"
              onClick={() => onNavigate('history')}
              className="text-xs font-medium text-[#2F75C3] dark:text-[#2F71E3] hover:underline cursor-pointer"
            >
              View all history
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-[#E5E7EB] dark:border-white/[0.08] text-xs text-[#5A606E] dark:text-[#9499A6]">
                  <th className="py-3 px-6 font-medium">Website</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium text-right">Security</th>
                  <th className="py-3 px-4 font-medium text-right">Front-End</th>
                  <th className="py-3 px-4 font-medium text-right">Back-End</th>
                  <th className="py-3 px-4 font-medium text-right">Engagement</th>
                  <th className="py-3 px-6 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 5).map((s) => (
                  <tr
                    key={s.scanId}
                    className="border-b border-[#F1F3F6] dark:border-white/[0.05] last:border-b-0 hover:bg-[#F7F8FA] dark:hover:bg-[#16181F]"
                  >
                    <td className="py-3 px-6 font-medium text-[#0A0A0C] dark:text-white">
                      {s.normalizedDomain}
                    </td>
                    <td className="py-3 px-4 text-[#5A606E] dark:text-[#9499A6] capitalize">
                      {s.status.replace('_', ' ')}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums">{s.scores?.security ?? 'N/A'}</td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums">{s.scores?.frontend ?? 'N/A'}</td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums">{s.scores?.backend ?? 'N/A'}</td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums">{s.scores?.engagement ?? 'N/A'}</td>
                    <td className="py-3 px-6 text-right">
                      <button
                        type="button"
                        onClick={() => onOpenReport(s)}
                        className="font-semibold text-[#2F75C3] dark:text-[#2F71E3] hover:underline cursor-pointer"
                      >
                        Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
