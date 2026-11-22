import React, { useMemo, useState } from 'react';
import { ArrowLeftRight, CheckCircle2, Download, ExternalLink, RefreshCw, Search, Trash2 } from 'lucide-react';
import type { WebsiteScan } from '../types/audit';
import { compareTwoScans } from '../lib/scanner/profiles';
import { exportScanHistoryAsCsv } from '../lib/export/exporters';
import { EmptyWorkspaceState } from './DashboardShell';

interface ScanHistoryViewProps {
  scans: WebsiteScan[];
  isAuthenticated: boolean;
  onSignIn: () => void;
  onOpenReport: (scan: WebsiteScan) => void;
  onRescan: (url: string) => void;
  onDeleteScan: (scanId: string) => void;
  onStartNewScan: () => void;
}

const PAGE_SIZE = 8;

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  scans,
  isAuthenticated,
  onOpenReport,
  onRescan,
  onDeleteScan,
  onStartNewScan,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'score_desc'>('newest');
  const [page, setPage] = useState(1);
  const [compareIds, setCompareIds] = useState<string[]>([]);

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = scans.filter((s) => {
      if (statusFilter !== 'all' && s.status !== statusFilter) return false;
      if (q && !s.normalizedDomain.toLowerCase().includes(q) && !s.targetUrl.toLowerCase().includes(q)) return false;
      return true;
    });

    list.sort((a, b) => {
      if (sortBy === 'oldest') return new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime();
      if (sortBy === 'score_desc') return (b.scores?.overall ?? -1) - (a.scores?.overall ?? -1);
      return new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime();
    });
    return list;
  }, [scans, searchQuery, statusFilter, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const toggleCompare = (scanId: string) => {
    setCompareIds((prev) => {
      if (prev.includes(scanId)) return prev.filter((id) => id !== scanId);
      if (prev.length >= 2) return [prev[1], scanId];
      return [...prev, scanId];
    });
  };

  const compareData = useMemo(() => {
    if (compareIds.length !== 2) return null;
    const a = scans.find((s) => s.scanId === compareIds[0]);
    const b = scans.find((s) => s.scanId === compareIds[1]);
    if (!a || !b) return null;
    const [older, newer] =
      new Date(a.startedAt).getTime() <= new Date(b.startedAt).getTime() ? [a, b] : [b, a];
    return { older, newer, diff: compareTwoScans(older, newer) };
  }, [compareIds, scans]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-[#0A0A0C] dark:text-white">Scan History</h1>
          <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] mt-1">
            {isAuthenticated
              ? 'Your persisted website audits, posture fingerprints, and side-by-side comparison.'
              : 'Showing session scans. Sign in with Google from the top bar to persist scan history across devices.'}
          </p>
        </div>

        <button
          type="button"
          onClick={() => exportScanHistoryAsCsv(filtered)}
          disabled={filtered.length === 0}
          aria-label="Download scan history as CSV"
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-full text-xs font-semibold border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] disabled:opacity-45 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Download className="w-3.5 h-3.5 text-[#2F75C3] dark:text-[#2F71E3]" />
          Download History CSV
        </button>
      </div>

      {/* Search, Filter & Sort Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-[#5A606E] dark:text-[#9499A6] absolute left-3.5 top-1/2 -translate-y-1/2" />
          <label htmlFor="history-search" className="sr-only">
            Search domains
          </label>
          <input
            id="history-search"
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(1);
            }}
            placeholder="Filter by domain or URL..."
            className="w-full pl-10 pr-4 py-2.5 rounded-xl text-xs sm:text-sm border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(1);
          }}
          aria-label="Filter by status"
          className="px-3.5 py-2.5 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white cursor-pointer"
        >
          <option value="all">All Statuses</option>
          <option value="completed">Completed</option>
          <option value="partially_completed">Partially Completed</option>
          <option value="failed">Failed</option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as 'newest' | 'oldest' | 'score_desc')}
          aria-label="Sort scans"
          className="px-3.5 py-2.5 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white cursor-pointer"
        >
          <option value="newest">Newest First</option>
          <option value="oldest">Oldest First</option>
          <option value="score_desc">Highest Overall Score</option>
        </select>
      </div>

      {/* Side-by-Side Comparison Engine */}
      {compareData && (
        <section className="rounded-2xl border border-[#2F75C3]/40 dark:border-[#2F71E3]/40 bg-white dark:bg-[#101115] p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <ArrowLeftRight className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
              <h2 className="text-sm font-bold text-[#0A0A0C] dark:text-white">
                Comparison: {compareData.older.normalizedDomain} ({new Date(compareData.older.startedAt).toLocaleDateString()}) →{' '}
                {compareData.newer.normalizedDomain} ({new Date(compareData.newer.startedAt).toLocaleDateString()})
              </h2>
              {compareData.diff.identicalPosture && (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/15 text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 className="w-3 h-3" />
                  Identical Posture Verified
                </span>
              )}
            </div>
            <button
              type="button"
              onClick={() => setCompareIds([])}
              className="text-xs text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
            >
              Clear comparison
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            {(['overall', 'security', 'frontend', 'backend', 'engagement'] as const).map((cat) => {
              const s1 = compareData.older.scores?.[cat] ?? null;
              const s2 = compareData.newer.scores?.[cat] ?? null;
              const diff = compareData.diff.scoreDeltas[cat];
              return (
                <div key={cat} className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] p-3.5 space-y-1">
                  <p className="uppercase tracking-wider text-[10px] font-semibold text-[#5A606E] dark:text-[#9499A6]">{cat}</p>
                  <p className="font-mono text-sm font-bold tabular-nums text-[#0A0A0C] dark:text-white">
                    {s1 ?? 'N/A'} → {s2 ?? 'N/A'}
                  </p>
                  {diff !== null && (
                    <p className={`font-mono text-[11px] ${diff > 0 ? 'text-emerald-600 dark:text-emerald-400' : diff < 0 ? 'text-red-500' : 'text-[#5A606E] dark:text-[#9499A6]'}`}>
                      {diff > 0 ? `+${diff}` : diff} pts
                    </p>
                  )}
                </div>
              );
            })}
          </div>

          {/* Detailed Diff Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] p-4 space-y-2">
              <p className="font-bold text-[#0A0A0C] dark:text-white">
                Newly Discovered Issues ({compareData.diff.newlyDiscovered.length})
              </p>
              {compareData.diff.newlyDiscovered.length === 0 ? (
                <p className="text-[#5A606E] dark:text-[#9499A6]">None — no new weaknesses introduced.</p>
              ) : (
                <ul className="space-y-1 text-[#5A606E] dark:text-[#9499A6] list-disc pl-4">
                  {compareData.diff.newlyDiscovered.slice(0, 6).map((f) => (
                    <li key={f.findingId}>{f.title} ({f.severity})</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] p-4 space-y-2">
              <p className="font-bold text-[#0A0A0C] dark:text-white">
                Resolved Issues ({compareData.diff.resolvedFindings.length})
              </p>
              {compareData.diff.resolvedFindings.length === 0 ? (
                <p className="text-[#5A606E] dark:text-[#9499A6]">None resolved between selected scans.</p>
              ) : (
                <ul className="space-y-1 text-emerald-600 dark:text-emerald-400 list-disc pl-4">
                  {compareData.diff.resolvedFindings.slice(0, 6).map((f) => (
                    <li key={f.findingId}>{f.title}</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] p-4 space-y-2 font-mono">
              <p className="font-bold font-sans text-[#0A0A0C] dark:text-white">
                Headers &amp; Telemetry Diff
              </p>
              <p className="text-[#5A606E] dark:text-[#9499A6]">
                Unchanged Findings: {compareData.diff.unchangedCount}
              </p>
              <p className="text-[#5A606E] dark:text-[#9499A6]">
                DOM Delta: {compareData.diff.metricChanges.domNodesDelta ?? 0} nodes
              </p>
              <p className="text-[#5A606E] dark:text-[#9499A6]">
                TTFB Delta: {compareData.diff.metricChanges.ttfbDeltaMs ?? 0} ms
              </p>
              <p className="text-[#5A606E] dark:text-[#9499A6]">
                Header Changes: {compareData.diff.changedHeaders.length}
              </p>
            </div>
          </div>
        </section>
      )}

      {/* Table or Empty State */}
      {filtered.length === 0 ? (
        <EmptyWorkspaceState
          title={scans.length === 0 ? 'No saved scans yet' : 'No matching scans'}
          description={
            scans.length === 0
              ? 'Run a live website audit to generate your first security, frontend, backend, and engagement report.'
              : 'Try adjusting your domain search query or status filter.'
          }
          actionLabel={scans.length === 0 ? 'Analyze a Website' : undefined}
          onAction={scans.length === 0 ? onStartNewScan : undefined}
        />
      ) : (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-[#E5E7EB] dark:border-white/[0.08] text-xs text-[#5A606E] dark:text-[#9499A6]">
                  <th className="py-3 px-4 font-medium">Compare</th>
                  <th className="py-3 px-4 font-medium">Website</th>
                  <th className="py-3 px-4 font-medium">Scan Date</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-3 font-medium text-right">Sec</th>
                  <th className="py-3 px-3 font-medium text-right">FE</th>
                  <th className="py-3 px-3 font-medium text-right">BE</th>
                  <th className="py-3 px-3 font-medium text-right">Eng</th>
                  <th className="py-3 px-3 font-medium text-right">Issues</th>
                  <th className="py-3 px-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((s) => {
                  const totalFindings = s.findingsCount
                    ? s.findingsCount.critical + s.findingsCount.high + s.findingsCount.medium + s.findingsCount.low
                    : s.findings?.length ?? 0;
                  const checked = compareIds.includes(s.scanId);
                  return (
                    <tr
                      key={s.scanId}
                      className="border-b border-[#E5E7EB] dark:border-white/[0.05] last:border-b-0 hover:bg-[#F7F8FA] dark:hover:bg-white/[0.03]"
                    >
                      <td className="py-3 px-4">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleCompare(s.scanId)}
                          aria-label={`Select ${s.normalizedDomain} for comparison`}
                          className="w-4 h-4 accent-[#2F75C3] dark:accent-[#2F71E3] cursor-pointer"
                        />
                      </td>
                      <td className="py-3 px-4 font-medium text-[#0A0A0C] dark:text-white">
                        <div>{s.normalizedDomain}</div>
                        <div className="text-[11px] font-mono text-[#5A606E] dark:text-[#9499A6] truncate max-w-[200px]">
                          {s.targetUrl}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-[#5A606E] dark:text-[#9499A6] font-mono tabular-nums whitespace-nowrap">
                        {new Date(s.startedAt).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 capitalize text-[#5A606E] dark:text-[#9499A6] whitespace-nowrap">
                        {s.status.replace('_', ' ')}
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">{s.scores?.security ?? '—'}</td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">{s.scores?.frontend ?? '—'}</td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">{s.scores?.backend ?? '—'}</td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">{s.scores?.engagement ?? '—'}</td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums">{totalFindings}</td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => onOpenReport(s)}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-[11px] font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white cursor-pointer"
                          >
                            Open
                            <ExternalLink className="w-3 h-3" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onRescan(s.targetUrl)}
                            aria-label={`Rescan ${s.normalizedDomain}`}
                            title="Rescan target"
                            className="p-1.5 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
                          >
                            <RefreshCw className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => onDeleteScan(s.scanId)}
                            aria-label={`Delete scan ${s.normalizedDomain}`}
                            title="Delete scan"
                            className="p-1.5 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6] hover:text-red-600 dark:hover:text-red-400 cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="px-6 py-3 border-t border-[#E5E7EB] dark:border-white/[0.08] flex items-center justify-between text-xs">
              <span className="text-[#5A606E] dark:text-[#9499A6] font-mono tabular-nums">
                Page {page} of {totalPages}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                  className="px-3 py-1 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] disabled:opacity-40 cursor-pointer"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="px-3 py-1 rounded-lg border border-[#E5E7EB] dark:border-white/[0.1] disabled:opacity-40 cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
};
