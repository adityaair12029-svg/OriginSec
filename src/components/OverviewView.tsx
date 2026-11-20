import React from 'react';
import { ArrowUpRight, PlusCircle } from 'lucide-react';
import type { MonitoringTarget, WebsiteScan } from '../types/audit';
import type { AppRoute } from './Header';
import { EmptyWorkspaceState } from './DashboardShell';

interface OverviewViewProps {
  scans: WebsiteScan[];
  monitoringTargets: MonitoringTarget[];
  onOpenReport: (scan: WebsiteScan) => void;
  onNavigate: (route: AppRoute) => void;
  userEmail?: string | null;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  scans,
  monitoringTargets,
  onOpenReport,
  onNavigate,
  userEmail,
}) => {
  const completedScans = scans.filter((s) => s.status === 'completed' || s.status === 'partially_completed');
  const openFindings = scans.reduce(
    (acc, s) => acc + (s.findingsCount ? s.findingsCount.critical + s.findingsCount.high + s.findingsCount.medium + s.findingsCount.low : 0),
    0
  );
  const highCriticalFindings = scans.reduce(
    (acc, s) => acc + (s.findingsCount ? s.findingsCount.critical + s.findingsCount.high : 0),
    0
  );

  const latestScan = scans[0] || null;
  const activeMonitors = monitoringTargets.filter((t) => t.enabled);
  const latestMonitor = monitoringTargets[0] || null;

  const kpis = [
    { label: 'Total Scans', value: scans.length },
    { label: 'Completed Scans', value: completedScans.length },
    { label: 'Websites Monitored', value: activeMonitors.length },
    { label: 'Open Findings', value: openFindings },
    { label: 'High / Critical Findings', value: highCriticalFindings },
    {
      label: 'Latest Monitoring Status',
      value: latestMonitor ? latestMonitor.lastStatus.toUpperCase() : 'None configured',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-[#151515] dark:text-white">Security &amp; Audit Overview</h1>
          <p className="text-[15px] text-[#777267] dark:text-[#929292] mt-1">
            {userEmail ? `Signed in as ${userEmail} · Real-time persisted telemetry` : 'Real-time diagnostics summary'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => onNavigate('home')}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 cursor-pointer whitespace-nowrap shrink-0"
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
            className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5"
          >
            <p className="text-xs text-[#777267] dark:text-[#929292]">{kpi.label}</p>
            <p className="text-2xl font-bold tabular-nums text-[#151515] dark:text-white mt-1.5">
              {kpi.value}
            </p>
          </div>
        ))}
      </div>

      {/* Latest Scan Highlight */}
      {latestScan ? (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-[#008C55] dark:text-[#00E69A]">
                Latest Scan
              </p>
              <h2 className="text-lg font-bold text-[#151515] dark:text-white mt-0.5">
                {latestScan.normalizedDomain}
              </h2>
              <p className="text-xs text-[#777267] dark:text-[#929292] font-mono">
                {new Date(latestScan.startedAt).toLocaleString()} · Overall Score:{' '}
                {latestScan.scores?.overall ?? 'N/A'}/100
              </p>
            </div>
            <button
              type="button"
              onClick={() => onOpenReport(latestScan)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold border border-[#E7E0D3] dark:border-[#252525] text-[#151515] dark:text-white hover:border-[#008C55] dark:hover:border-[#00E69A] cursor-pointer whitespace-nowrap"
            >
              Open Full Report
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <p className="text-sm text-[#777267] dark:text-[#929292] leading-relaxed">{latestScan.summary}</p>
        </section>
      ) : (
        <EmptyWorkspaceState
          title="No audits recorded yet"
          description="Run your first live website audit to measure HTTPS/TLS posture, HTTP security headers, DOM structure, server TTFB, and engagement signals."
          actionLabel="Start First Audit"
          onAction={() => onNavigate('home')}
        />
      )}

      {/* Recent Scans Table */}
      {scans.length > 0 && (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E] flex items-center justify-between">
            <h2 className="text-sm font-bold text-[#151515] dark:text-white">Recent Scans</h2>
            <button
              type="button"
              onClick={() => onNavigate('history')}
              className="text-xs font-medium text-[#008C55] dark:text-[#00E69A] hover:underline cursor-pointer"
            >
              View all history
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-[#E7E0D3] dark:border-[#1E1E1E] text-xs text-[#777267] dark:text-[#929292]">
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
                    className="border-b border-[#EFECE4] dark:border-[#161616] last:border-b-0 hover:bg-[#FAF9F5] dark:hover:bg-[#101010]"
                  >
                    <td className="py-3 px-6 font-medium text-[#151515] dark:text-white">
                      {s.normalizedDomain}
                    </td>
                    <td className="py-3 px-4 text-[#777267] dark:text-[#929292] capitalize">
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
                        className="font-semibold text-[#008C55] dark:text-[#00E69A] hover:underline cursor-pointer"
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
