import React, { useMemo, useState } from 'react';
import { Accessibility, AlertTriangle, CheckCircle2, Eye, Gauge, Globe, Layers, Server } from 'lucide-react';
import type { IntegrationRecord, WebsiteScan } from '../types/audit';
import type { AppRoute } from './Header';
import { EmptyWorkspaceState } from './DashboardShell';

function useTargetScanSelector(scans: WebsiteScan[]) {
  const completed = useMemo(
    () => scans.filter((s) => s.status === 'completed' || s.status === 'partially_completed'),
    [scans]
  );
  const [selectedId, setSelectedId] = useState<string>('');
  const activeScan = useMemo(() => {
    if (completed.length === 0) return null;
    return completed.find((s) => s.scanId === selectedId) || completed[0];
  }, [completed, selectedId]);

  return { completed, activeScan, selectedId, setSelectedId };
}

const ScanSelectorHeader: React.FC<{
  title: string;
  subtitle: string;
  scans: WebsiteScan[];
  activeScan: WebsiteScan;
  onSelect: (scanId: string) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ title, subtitle, scans, activeScan, onSelect, onOpenReport }) => (
  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
    <div>
      <h1 className="text-2xl sm:text-3xl font-bold text-[#151515] dark:text-white">{title}</h1>
      <p className="text-[15px] text-[#777267] dark:text-[#929292] mt-1">{subtitle}</p>
    </div>
    <div className="flex flex-wrap items-center gap-2 shrink-0">
      <select
        value={activeScan.scanId}
        onChange={(e) => onSelect(e.target.value)}
        aria-label="Select audited scan"
        className="px-3.5 py-2 rounded-xl text-xs border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white cursor-pointer"
      >
        {scans.map((s) => (
          <option key={s.scanId} value={s.scanId}>
            {s.normalizedDomain} ({new Date(s.startedAt).toLocaleDateString()})
          </option>
        ))}
      </select>
      <button
        type="button"
        onClick={() => onOpenReport(activeScan)}
        className="px-3.5 py-2 rounded-xl text-xs font-semibold border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#008C55] cursor-pointer"
      >
        Full Report
      </button>
    </div>
  </div>
);

export const FrontendIntelligenceView: React.FC<{
  scans: WebsiteScan[];
  onNavigate: (route: AppRoute) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ scans, onNavigate, onOpenReport }) => {
  const { completed, activeScan, setSelectedId } = useTargetScanSelector(scans);

  if (!activeScan) {
    return (
      <EmptyWorkspaceState
        title="No frontend telemetry yet"
        description="Run a live website audit to inspect static DOM density, render-blocking scripts, stylesheet weight, images, and crawled assets."
        actionLabel="Start New Scan"
        onAction={() => onNavigate('home')}
      />
    );
  }

  const m = activeScan.metrics;
  const fd = m?.frontendDetails;

  return (
    <div className="space-y-6">
      <ScanSelectorHeader
        title="Frontend Intelligence"
        subtitle="Static DOM complexity, render-blocking scripts, image hygiene, and verified asset footprint from live HTML."
        scans={completed}
        activeScan={activeScan}
        onSelect={setSelectedId}
        onOpenReport={onOpenReport}
      />

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Frontend Score', value: `${activeScan.scores?.frontend ?? 'N/A'}/100` },
          { label: 'Static DOM Nodes', value: `${m?.domNodeCount ?? 'N/A'}` },
          { label: 'Scripts (Blocking)', value: `${m?.scriptCount ?? 0} (${m?.renderBlockingScripts ?? 0})` },
          { label: 'Stylesheets', value: `${m?.stylesheetCount ?? 0}` },
          { label: 'Images Total', value: `${m?.imageCount ?? 0}` },
          { label: 'Missing Dimensions', value: `${m?.imagesWithoutDimensions ?? 0}` },
          { label: 'Missing Lazy Hint', value: `${fd?.imagesWithoutLazyLoading ?? 0}` },
          { label: 'HTML Weight', value: m?.htmlSizeBytes ? `${(m.htmlSizeBytes / 1024).toFixed(1)} KB` : 'N/A' },
        ].map((card) => (
          <div key={card.label} className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
            <p className="text-xs text-[#777267] dark:text-[#929292]">{card.label}</p>
            <p className="text-xl font-bold font-mono tabular-nums text-[#151515] dark:text-white mt-1">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Crawled Same-Origin Pages */}
      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
          <h2 className="text-base font-bold text-[#151515] dark:text-white">
            Crawled Pages ({m?.crawledUrls?.length ?? activeScan.coverage?.pagesScanned ?? 1})
          </h2>
        </div>
        {m?.crawledUrls && m.crawledUrls.length > 0 ? (
          <ul className="space-y-1.5 text-xs font-mono text-[#777267] dark:text-[#929292]">
            {m.crawledUrls.map((u) => (
              <li key={u} className="truncate py-1 border-b border-[#EFECE4] dark:border-[#181818] last:border-b-0">
                {u}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-[#777267] dark:text-[#929292]">
            Primary target audited: <span className="font-mono">{activeScan.targetUrl}</span>
          </p>
        )}
      </section>
    </div>
  );
};

export const SeoContentView: React.FC<{
  scans: WebsiteScan[];
  onNavigate: (route: AppRoute) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ scans, onNavigate, onOpenReport }) => {
  const { completed, activeScan, setSelectedId } = useTargetScanSelector(scans);

  if (!activeScan) {
    return (
      <EmptyWorkspaceState
        title="No SEO & content audit data yet"
        description="Analyze any website to inspect title, meta description, canonical tag, Open Graph, robots.txt, sitemap.xml, and internal links."
        actionLabel="Audit a Website"
        onAction={() => onNavigate('home')}
      />
    );
  }

  const fd = activeScan.metrics?.frontendDetails;
  const hc = activeScan.metrics?.headingCount;
  const checks = [
    { label: 'Title Tag', ok: Boolean(fd?.pageTitle), detail: fd?.pageTitle || 'Not detected' },
    {
      label: 'Meta Description',
      ok: Boolean(fd?.hasMetaDescription && (fd?.metaDescriptionLength ?? 0) >= 40),
      detail: fd?.hasMetaDescription ? `${fd.metaDescriptionLength} characters` : 'Missing meta description',
    },
    { label: 'Canonical URL', ok: Boolean(fd?.hasCanonical), detail: fd?.canonicalUrl || 'No <link rel="canonical">' },
    { label: 'Open Graph Tags', ok: Boolean(fd?.hasOpenGraph), detail: fd?.hasOpenGraph ? 'og:title / og:description detected' : 'Missing Open Graph tags' },
    { label: 'Twitter Card', ok: Boolean(fd?.hasTwitterCard), detail: fd?.hasTwitterCard ? 'twitter:card detected' : 'Not detected' },
    { label: 'robots.txt', ok: Boolean(fd?.hasRobotsTxt), detail: fd?.hasRobotsTxt ? 'HTTP 200 valid' : 'Not detected' },
    { label: 'sitemap.xml', ok: Boolean(fd?.hasSitemapXml), detail: fd?.hasSitemapXml ? 'XML sitemap reachable' : 'Not detected' },
    { label: 'Internal Link Health', ok: (activeScan.metrics?.brokenInternalLinks ?? 0) === 0, detail: `${activeScan.metrics?.brokenInternalLinks ?? 0} broken link(s) across ${activeScan.metrics?.linkCount ?? 0} links` },
  ];

  return (
    <div className="space-y-6">
      <ScanSelectorHeader
        title="SEO & Content Quality"
        subtitle="Verified search indexing metadata, structural heading distribution, and broken link evidence."
        scans={completed}
        activeScan={activeScan}
        onSelect={setSelectedId}
        onOpenReport={onOpenReport}
      />

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
          <p className="text-xs text-[#777267] dark:text-[#929292]">SEO Score</p>
          <p className="text-xl font-bold font-mono tabular-nums mt-1">{activeScan.scores?.seo ?? activeScan.scores?.engagement ?? 'N/A'}/100</p>
        </div>
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
          <p className="text-xs text-[#777267] dark:text-[#929292]">H1 / H2 / H3 Count</p>
          <p className="text-xl font-bold font-mono tabular-nums mt-1">
            {hc ? `${hc.h1} / ${hc.h2} / ${hc.h3}` : 'N/A'}
          </p>
        </div>
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
          <p className="text-xs text-[#777267] dark:text-[#929292]">Total Links</p>
          <p className="text-xl font-bold font-mono tabular-nums mt-1">{activeScan.metrics?.linkCount ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
          <p className="text-xs text-[#777267] dark:text-[#929292]">Broken Links</p>
          <p className="text-xl font-bold font-mono tabular-nums mt-1">{activeScan.metrics?.brokenInternalLinks ?? 0}</p>
        </div>
      </div>

      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {checks.map((c) => (
          <div key={c.label} className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-4 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-semibold text-[#151515] dark:text-white flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-[#008C55] dark:text-[#00E69A] shrink-0" />
                {c.label}
              </p>
              <p className="text-xs font-mono text-[#777267] dark:text-[#929292] mt-1 truncate">{c.detail}</p>
            </div>
            <span className={`px-2 py-0.5 rounded text-[11px] font-bold shrink-0 ${c.ok ? 'bg-[#008C55]/15 text-[#008C55] dark:text-[#00E69A]' : 'bg-amber-500/15 text-amber-700 dark:text-amber-300'}`}>
              {c.ok ? 'PASS' : 'CHECK'}
            </span>
          </div>
        ))}
      </section>
    </div>
  );
};

export const PerformanceLabView: React.FC<{
  scans: WebsiteScan[];
  onNavigate: (route: AppRoute) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ scans, onNavigate, onOpenReport }) => {
  const { completed, activeScan, setSelectedId } = useTargetScanSelector(scans);

  if (!activeScan) {
    return (
      <EmptyWorkspaceState
        title="No performance measurements yet"
        description="Run a Performance Lab or Standard Audit to measure DNS lookup, TLS handshake, TTFB, compression, and Lighthouse Web Vitals."
        actionLabel="Launch Performance Audit"
        onAction={() => onNavigate('home')}
      />
    );
  }

  const m = activeScan.metrics;
  const tb = m?.timingBreakdown;
  const totalTime = Math.max(1, tb?.totalResponseTimeMs || m?.totalResponseTimeMs || 1);
  const lh = m?.lighthouse;

  const domainHistory = completed
    .filter((s) => s.normalizedDomain === activeScan.normalizedDomain && s.metrics?.ttfbMs !== undefined)
    .slice(0, 10)
    .reverse();

  return (
    <div className="space-y-6">
      <ScanSelectorHeader
        title="Performance Lab"
        subtitle="Network timing waterfall, warm TTFB verification, asset compression, and Lighthouse Web Vitals."
        scans={completed}
        activeScan={activeScan}
        onSelect={setSelectedId}
        onOpenReport={onOpenReport}
      />

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Performance Score', value: `${activeScan.scores?.performance ?? activeScan.scores?.backend ?? 'N/A'}/100` },
          { label: 'Cold TTFB', value: `${tb?.ttfbMs ?? m?.ttfbMs ?? 'N/A'} ms` },
          { label: 'Warm TTFB (Re-check)', value: `${tb?.warmTtfbMs ?? m?.ttfbMs ?? 'N/A'} ms` },
          { label: 'Compression', value: m?.compression || 'None' },
        ].map((card) => (
          <div key={card.label} className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-4">
            <p className="text-xs text-[#777267] dark:text-[#929292]">{card.label}</p>
            <p className="text-xl font-bold font-mono tabular-nums mt-1">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Request Waterfall */}
      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Gauge className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
          <h2 className="text-base font-bold text-[#151515] dark:text-white">Measured Network Waterfall</h2>
        </div>
        <div className="space-y-3 text-xs">
          {[
            { label: 'DNS Resolution', ms: tb?.dnsLookupMs ?? 0, color: 'bg-sky-500' },
            { label: 'TLS Handshake', ms: tb?.tlsHandshakeMs ?? 0, color: 'bg-indigo-500' },
            { label: 'First Byte (TTFB)', ms: tb?.ttfbMs ?? m?.ttfbMs ?? 0, color: 'bg-[#008C55] dark:bg-[#00E69A]' },
            { label: 'Content Transfer', ms: tb?.contentTransferMs ?? Math.max(0, (m?.totalResponseTimeMs || 0) - (m?.ttfbMs || 0)), color: 'bg-amber-500' },
          ].map((row) => (
            <div key={row.label} className="space-y-1">
              <div className="flex justify-between font-mono">
                <span className="text-[#151515] dark:text-white">{row.label}</span>
                <span className="text-[#777267] dark:text-[#929292]">{row.ms} ms</span>
              </div>
              <div className="w-full h-2 rounded-full bg-[#EFECE4] dark:bg-[#1B1B1B] overflow-hidden">
                <div className={`h-full rounded-full ${row.color}`} style={{ width: `${Math.min(100, Math.max(2, (row.ms / totalTime) * 100))}%` }} />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Google PageSpeed / Lighthouse Section */}
      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-3">
        <h2 className="text-base font-bold text-[#151515] dark:text-white">
          Google PageSpeed Insights &amp; Core Web Vitals
        </h2>
        {lh?.available ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 rounded-xl bg-[#FAF9F5] dark:bg-[#101010] border border-[#E7E0D3] dark:border-[#222]">
              <p className="text-[#777267]">Lighthouse Perf</p>
              <p className="text-lg font-bold mt-1">{lh.performanceScore ?? '—'}/100</p>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF9F5] dark:bg-[#101010] border border-[#E7E0D3] dark:border-[#222]">
              <p className="text-[#777267]">LCP</p>
              <p className="text-lg font-bold mt-1">{lh.lcpMs ?? '—'} ms</p>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF9F5] dark:bg-[#101010] border border-[#E7E0D3] dark:border-[#222]">
              <p className="text-[#777267]">CLS</p>
              <p className="text-lg font-bold mt-1">{lh.cls ?? '—'}</p>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF9F5] dark:bg-[#101010] border border-[#E7E0D3] dark:border-[#222]">
              <p className="text-[#777267]">Data Source</p>
              <p className="text-sm font-bold mt-1">{lh.dataType}</p>
            </div>
          </div>
        ) : (
          <p className="text-xs text-[#777267] dark:text-[#929292]">
            {lh?.errorNote || 'PageSpeed Insights API key not configured on server (PAGESPEED_API_KEY optional). Timing above reflects live HTTP/TLS probes.'}
          </p>
        )}
      </section>

      {/* Historical Domain TTFB Chart */}
      {domainHistory.length > 1 && (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-3">
          <h2 className="text-base font-bold text-[#151515] dark:text-white">
            Recorded TTFB Trend — {activeScan.normalizedDomain}
          </h2>
          <div className="flex items-end gap-3 h-28 pt-2">
            {domainHistory.map((item) => {
              const maxTtfb = Math.max(...domainHistory.map((d) => d.metrics?.ttfbMs || 100), 100);
              const val = item.metrics?.ttfbMs || 0;
              const pct = Math.max(10, Math.round((val / maxTtfb) * 100));
              return (
                <div key={item.scanId} className="flex-1 flex flex-col items-center gap-1 min-w-0">
                  <span className="text-[10px] font-mono tabular-nums text-[#777267] dark:text-[#929292]">{val}ms</span>
                  <div className="w-full max-w-[36px] rounded-t-md bg-[#008C55]/80 dark:bg-[#00E69A]/80" style={{ height: `${pct}%` }} />
                  <span className="text-[10px] text-[#777267] truncate w-full text-center">
                    {new Date(item.startedAt).toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' })}
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
};

export const AccessibilityView: React.FC<{
  scans: WebsiteScan[];
  onNavigate: (route: AppRoute) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ scans, onNavigate, onOpenReport }) => {
  const { completed, activeScan, setSelectedId } = useTargetScanSelector(scans);

  if (!activeScan) {
    return (
      <EmptyWorkspaceState
        title="No accessibility scan data yet"
        description="Run a Frontend Quality or Standard Audit to measure WCAG HTML signals: alt attributes, html lang, form labels, button text, and headings."
        actionLabel="Scan Website"
        onAction={() => onNavigate('home')}
      />
    );
  }

  const m = activeScan.metrics;
  const fd = m?.frontendDetails;

  const wcagChecks = [
    { label: 'Document Language (<html lang>)', ok: Boolean(fd?.htmlLang), value: fd?.htmlLang || 'Missing' },
    { label: 'Images Missing Alt Text', ok: (m?.imagesWithoutAlt ?? 0) === 0, value: `${m?.imagesWithoutAlt ?? 0} of ${m?.imageCount ?? 0}` },
    { label: 'Form Inputs Missing Label', ok: (fd?.inputsWithoutLabel ?? 0) === 0, value: `${fd?.inputsWithoutLabel ?? 0}` },
    { label: 'Buttons Missing Accessible Text', ok: (fd?.buttonsWithoutText ?? 0) === 0, value: `${fd?.buttonsWithoutText ?? 0}` },
    { label: 'Empty Links (No Label/Text)', ok: (fd?.emptyLinks ?? 0) === 0, value: `${fd?.emptyLinks ?? 0}` },
    { label: 'Heading Hierarchy Skips', ok: (fd?.headingOrderIssues ?? 0) === 0, value: `${fd?.headingOrderIssues ?? 0} skip(s)` },
  ];

  return (
    <div className="space-y-6">
      <ScanSelectorHeader
        title="Accessibility Centre (WCAG Static Signals)"
        subtitle={`Observed DOM accessibility posture for ${activeScan.normalizedDomain}.`}
        scans={completed}
        activeScan={activeScan}
        onSelect={setSelectedId}
        onOpenReport={onOpenReport}
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-5">
          <p className="text-xs text-[#777267] dark:text-[#929292] flex items-center gap-1.5">
            <Accessibility className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
            Static Accessibility Score
          </p>
          <p className="text-3xl font-bold font-mono tabular-nums mt-2">
            {activeScan.scores?.accessibility ?? activeScan.scores?.frontend ?? 'N/A'}/100
          </p>
        </div>
        <div className="md:col-span-2 rounded-2xl border border-amber-500/35 bg-amber-500/5 p-5 flex items-start gap-3">
          <Eye className="w-5 h-5 text-amber-600 dark:text-amber-300 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <p className="font-bold text-[#151515] dark:text-white">Manual Review Required for Full WCAG 2.1 AA Compliance</p>
            <p className="text-[#777267] dark:text-[#929292] leading-relaxed">
              Static HTML parsing accurately checks semantic markup, alt text, labels, and heading order, but cannot measure rendered CSS color contrast, focus visibility, or keyboard trap behavior without an interactive browser pass.
            </p>
          </div>
        </div>
      </div>

      <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
        {wcagChecks.map((item) => (
          <div key={item.label} className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-[#151515] dark:text-white">{item.label}</p>
              <p className="text-xs font-mono text-[#777267] dark:text-[#929292] mt-0.5">{item.value}</p>
            </div>
            {item.ok ? (
              <CheckCircle2 className="w-5 h-5 text-[#008C55] dark:text-[#00E69A] shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />
            )}
          </div>
        ))}
      </section>
    </div>
  );
};

export const BackendAssessmentView: React.FC<{
  scans: WebsiteScan[];
  integrations: IntegrationRecord[];
  onNavigate: (route: AppRoute) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}> = ({ scans, integrations, onNavigate, onOpenReport }) => {
  const { completed, activeScan, setSelectedId } = useTargetScanSelector(scans);
  const connectedCount = integrations.filter((i) => i.connectionStatus === 'connected').length;

  return (
    <div className="space-y-6">
      {activeScan ? (
        <ScanSelectorHeader
          title="Backend & Edge Posture Assessment"
          subtitle="Clear separation between externally observable server telemetry and private infrastructure audits."
          scans={completed}
          activeScan={activeScan}
          onSelect={setSelectedId}
          onOpenReport={onOpenReport}
        />
      ) : (
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-[#151515] dark:text-white">Backend Assessment</h1>
          <p className="text-[15px] text-[#777267] dark:text-[#929292] mt-1">
            External HTTP/TLS behavior vs. authorized private backend inspection.
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-[#151515] dark:text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
              Publicly Observed Backend Signals
            </h2>
            <span className="text-xs font-mono text-[#008C55] dark:text-[#00E69A]">Live Measured</span>
          </div>
          {activeScan ? (
            <div className="space-y-2.5 text-xs">
              {[
                { k: 'HTTP Status & Redirects', v: `HTTP ${activeScan.metrics?.statusCode} · ${activeScan.metrics?.redirectCount} redirect(s)` },
                { k: 'Cold / Warm TTFB', v: `${activeScan.metrics?.ttfbMs} ms / ${activeScan.metrics?.timingBreakdown?.warmTtfbMs ?? activeScan.metrics?.ttfbMs} ms` },
                { k: 'Server Banner', v: activeScan.metrics?.serverBanner || 'Hidden / Omitted (Good)' },
                { k: 'Compression', v: activeScan.metrics?.compression || 'None detected' },
                { k: 'TLS Protocol', v: activeScan.metrics?.tls?.available ? `${activeScan.metrics.tls.protocol} (${activeScan.metrics.tls.daysRemaining}d remaining)` : 'Unavailable' },
                { k: 'security.txt', v: activeScan.metrics?.frontendDetails?.hasSecurityTxt ? 'Present at /.well-known/security.txt' : 'Not detected' },
              ].map((row) => (
                <div key={row.k} className="flex justify-between gap-4 py-2 border-b border-[#EFECE4] dark:border-[#1B1B1B] last:border-b-0">
                  <span className="text-[#777267] dark:text-[#929292]">{row.k}</span>
                  <span className="font-mono text-[#151515] dark:text-white text-right">{row.v}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[#777267] dark:text-[#929292]">
              No scan selected yet. Run a website audit to inspect live HTTP/TLS backend headers and latency.
            </p>
          )}
        </section>

        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-[#151515] dark:text-white">Private Backend &amp; Server Scope</h2>
            <span className="text-xs font-mono text-[#777267] dark:text-[#929292]">
              {connectedCount > 0 ? `${connectedCount} connected` : 'Requires Integration'}
            </span>
          </div>
          <p className="text-xs leading-relaxed text-[#777267] dark:text-[#929292]">
            Internal server source code, database queries, IAM roles, private queues, and environment secrets cannot be inspected from an unauthenticated public URL. Connect read-only hosting, API specs, or database providers to unlock verified owner posture checks.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => onNavigate('api-audits')}
              className="px-4 py-2 rounded-xl text-xs font-semibold border border-[#E7E0D3] dark:border-[#252525] cursor-pointer"
            >
              Open API Audits
            </button>
            <button
              type="button"
              onClick={() => onNavigate('integrations')}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
            >
              Connect Integrations
            </button>
          </div>
        </section>
      </div>
    </div>
  );
};
