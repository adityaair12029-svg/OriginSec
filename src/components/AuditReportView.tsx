import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Camera,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileJson,
  FileSpreadsheet,
  FileText,
  Globe,
  RefreshCw,
  Send,
  ShieldAlert,
  Sparkles,
  Wrench,
} from 'lucide-react';
import type {
  FindingCategory,
  GroundingSource,
  PriorityGroup,
  ScanFinding,
  SeverityLevel,
  WebsiteScan,
} from '../types/audit';
import { CircularGauge } from './CircularGauge';
import { exportScanAsCsv, exportScanAsJson, exportScanAsPdf } from '../lib/export/exporters';

interface AiResponsePayload {
  text: string;
  sources?: GroundingSource[];
}

interface AuditReportViewProps {
  scan: WebsiteScan;
  onRescan: (url: string) => void;
  onAddToMonitoring?: (scan: WebsiteScan) => void;
  onTrackFindingInRemediation?: (finding: ScanFinding, scan: WebsiteScan) => Promise<void>;
  onGenerateAiBrief?: (scan: WebsiteScan, audience: 'owner' | 'developer') => Promise<AiResponsePayload | null>;
  onAskAiQuestion?: (scan: WebsiteScan, question: string) => Promise<AiResponsePayload | null>;
  isGeneratingAi?: boolean;
  aiError?: string | null;
}

const SEVERITY_BADGE_STYLES: Record<SeverityLevel, string> = {
  critical: 'border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-400',
  high: 'border-red-400/50 bg-red-500/10 text-red-700 dark:text-red-300',
  medium: 'border-amber-500/50 bg-amber-500/10 text-amber-800 dark:text-amber-300',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  informational: 'border-[#E5E7EB] dark:border-white/[0.15] bg-transparent text-[#5A606E] dark:text-[#9499A6]',
  passed: 'border-emerald-600/40 dark:border-emerald-400/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
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

const QUICK_AI_PROMPTS = [
  'How do I fix missing security headers cleanly?',
  'Which highest-risk issue should we resolve first?',
  'Summarize this posture for executive leadership.',
];

const GroundingSourcesList: React.FC<{ sources?: GroundingSource[] }> = ({ sources }) => {
  if (!sources || sources.length === 0) return null;
  return (
    <div className="pt-3 border-t border-[#E5E7EB] dark:border-white/[0.08] space-y-2">
      <p className="inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#2F75C3] dark:text-[#2F71E3]">
        <Globe className="w-3.5 h-3.5" />
        Verified Web References (Google Search Grounding)
      </p>
      <div className="flex flex-wrap gap-2">
        {sources.map((src) => (
          <a
            key={src.uri}
            href={src.uri}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#0D0E12] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors max-w-xs"
            title={src.uri}
          >
            <span className="truncate">{src.title}</span>
            <ExternalLink className="w-3 h-3 shrink-0 text-[#5A606E] dark:text-[#9499A6]" />
          </a>
        ))}
      </div>
    </div>
  );
};

const FindingCard: React.FC<{
  finding: ScanFinding;
  scan: WebsiteScan;
  onTrack?: (finding: ScanFinding, scan: WebsiteScan) => Promise<void>;
}> = ({ finding, scan, onTrack }) => {
  const [expanded, setExpanded] = useState(false);
  const [tracked, setTracked] = useState(false);
  const isActionable = finding.severity !== 'passed' && finding.status !== 'not_assessed';

  return (
    <article className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] p-6 space-y-3.5 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <h4 className="text-base font-semibold text-[#0A0A0C] dark:text-white leading-snug">
            {finding.title}
          </h4>
          {(finding.ruleId || finding.confidence) && (
            <p className="text-[11px] font-mono text-[#5A606E] dark:text-[#9499A6]">
              {finding.ruleId ? `Rule ${finding.ruleId}` : ''}
              {finding.ruleId && finding.confidence ? ' · ' : ''}
              {finding.confidence ? `Evidence: ${finding.confidence.replace('_', ' ')}` : ''}
            </p>
          )}
        </div>
        <span
          className={`px-2.5 py-0.5 rounded-md border text-[11px] font-bold tracking-wider uppercase whitespace-nowrap shrink-0 ${
            SEVERITY_BADGE_STYLES[finding.severity]
          }`}
        >
          {finding.status === 'not_assessed' ? 'NOT ASSESSED' : finding.severity.toUpperCase()}
        </span>
      </div>

      <p className="text-[15px] leading-[1.6] text-[#5A606E] dark:text-[#9499A6]">
        {finding.description}
      </p>

      <div className="border-t border-[#E5E7EB] dark:border-white/[0.08] pt-3.5 space-y-2.5 text-[15px]">
        <p className="text-[#0A0A0C] dark:text-[#E5E7EB] leading-[1.6]">
          <span className="font-semibold">Fix:</span> {finding.recommendation}
          {finding.remediation && (
            <code className="block mt-2 px-3 py-2 rounded-lg bg-[#FFFFFF] dark:bg-[#090A0D] border border-[#E5E7EB] dark:border-white/[0.08] text-[13px] font-mono text-[#0A0A0C] dark:text-[#D8DCE6] break-all whitespace-pre-wrap">
              {finding.remediation}
            </code>
          )}
        </p>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer transition-colors"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            {expanded ? 'Hide evidence & verification' : 'Inspect evidence, impact & verification'}
          </button>

          {isActionable && onTrack && (
            <button
              type="button"
              onClick={async () => {
                await onTrack(finding, scan);
                setTracked(true);
              }}
              disabled={tracked}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] disabled:opacity-60 cursor-pointer"
            >
              <Wrench className="w-3 h-3 text-[#2F75C3] dark:text-[#2F71E3]" />
              {tracked ? 'Added to Remediation' : 'Track in Remediation'}
            </button>
          )}
        </div>

        {expanded && (
          <div className="pt-2.5 space-y-2 text-[13px] text-[#5A606E] dark:text-[#9499A6] border-t border-dashed border-[#E5E7EB] dark:border-white/[0.08]">
            <div>
              <span className="font-semibold text-[#0A0A0C] dark:text-white">Evidence: </span>
              <span className="font-mono break-all">{finding.evidence}</span>
            </div>
            <div>
              <span className="font-semibold text-[#0A0A0C] dark:text-white">Observed Value: </span>
              <span className="font-mono">{finding.observedValue}</span>
            </div>
            <div>
              <span className="font-semibold text-[#0A0A0C] dark:text-white">Affected URL: </span>
              <span className="font-mono break-all">{finding.affectedUrl}</span>
            </div>
            <div>
              <span className="font-semibold text-[#0A0A0C] dark:text-white">Impact: </span>
              <span>{finding.impact}</span>
            </div>
            <div>
              <span className="font-semibold text-[#0A0A0C] dark:text-white">Verification: </span>
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
  onTrackFindingInRemediation,
  onGenerateAiBrief,
  onAskAiQuestion,
  isGeneratingAi,
  aiError,
}) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'recommendations' | 'telemetry' | 'ai'>('findings');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [audience, setAudience] = useState<'owner' | 'developer'>('owner');
  const [localAiText, setLocalAiText] = useState<string | null>(scan.aiExplanation || null);
  const [localAiSources, setLocalAiSources] = useState<GroundingSource[]>(scan.aiSources || []);
  const [askInput, setAskInput] = useState('');
  const [askAnswer, setAskAnswer] = useState<string | null>(null);
  const [askSources, setAskSources] = useState<GroundingSource[]>([]);
  const [isAskingAi, setIsAskingAi] = useState(false);

  useEffect(() => {
    setLocalAiText(scan.aiExplanation || null);
    setLocalAiSources(scan.aiSources || []);
    setAskAnswer(null);
    setAskSources([]);
  }, [scan.scanId, scan.aiExplanation, scan.aiSources]);

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
    if (result) {
      setLocalAiText(result.text);
      setLocalAiSources(result.sources || []);
    }
  };

  const submitQuestion = async (questionText: string) => {
    if (!onAskAiQuestion || questionText.trim().length < 3) return;
    setIsAskingAi(true);
    try {
      const answer = await onAskAiQuestion(scan, questionText.trim());
      if (answer) {
        setAskAnswer(answer.text);
        setAskSources(answer.sources || []);
      }
    } finally {
      setIsAskingAi(false);
    }
  };

  const handleAskSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await submitQuestion(askInput);
  };

  return (
    <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8 animate-fade-up">
      {/* Top Report Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-[#E5E7EB] dark:border-white/[0.08] pb-6">
        <div className="space-y-1.5 min-w-0">
          <h1 className="text-2xl sm:text-[36px] font-semibold tracking-tight text-[#0A0A0C] dark:text-white break-words">
            Audit report — {scan.normalizedDomain}
          </h1>
          <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] break-all">
            {scan.targetUrl}
          </p>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-[#5A606E] dark:text-[#9499A6] pt-1 font-mono tabular-nums">
            <span>ID: {scan.scanId}</span>
            <span aria-hidden="true">·</span>
            <span>Profile: {scan.scanProfile || scan.coverage?.scanProfile || 'standard'}</span>
            {scan.postureFingerprint && (
              <>
                <span aria-hidden="true">·</span>
                <span title="Deterministic Posture Fingerprint across devices">
                  Fingerprint: {scan.postureFingerprint}
                </span>
              </>
            )}
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
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors whitespace-nowrap"
          >
            Visit site
            <ExternalLink className="w-3.5 h-3.5" />
          </a>

          <button
            type="button"
            onClick={() => onRescan(scan.targetUrl)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors whitespace-nowrap cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Rescan
          </button>

          {onAddToMonitoring && (
            <button
              type="button"
              onClick={() => onAddToMonitoring(scan)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors whitespace-nowrap cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5" />
              Monitor
            </button>
          )}

          <div className="inline-flex items-center rounded-full border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] p-0.5">
            <button
              type="button"
              onClick={() => exportScanAsPdf(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#0A0A0C] dark:text-white hover:bg-[#F7F8FA] dark:hover:bg-white/[0.06] cursor-pointer"
              title="Export PDF Report"
            >
              <FileText className="w-3 h-3" />
              PDF
            </button>
            <button
              type="button"
              onClick={() => exportScanAsCsv(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#0A0A0C] dark:text-white hover:bg-[#F7F8FA] dark:hover:bg-white/[0.06] cursor-pointer"
              title="Export CSV Findings"
            >
              <FileSpreadsheet className="w-3 h-3" />
              CSV
            </button>
            <button
              type="button"
              onClick={() => exportScanAsJson(scan)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-full text-[11px] font-medium text-[#0A0A0C] dark:text-white hover:bg-[#F7F8FA] dark:hover:bg-white/[0.06] cursor-pointer"
              title="Export JSON Report"
            >
              <FileJson className="w-3 h-3" />
              JSON
            </button>
          </div>
        </div>
      </div>

      {/* Executive Summary Box */}
      <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-7 space-y-2.5">
        <p className="text-[16px] sm:text-[17px] leading-[1.65] text-[#0A0A0C] dark:text-[#EDEDED]">
          {scan.summary}
        </p>
        <p className="text-[13px] text-[#5A606E] dark:text-[#9499A6]">
          Coverage: HTTPS {scan.coverage?.httpsVerified ? 'checked' : 'unavailable'} · TLS{' '}
          {scan.coverage?.tlsVerified ? 'verified' : 'unavailable'} · DNS{' '}
          {scan.coverage?.dnsVerified ? 'resolved' : 'unavailable'} · Lighthouse{' '}
          {scan.coverage?.lighthouseVerified ? 'verified' : 'not configured'} · DB/Hosting/Backup{' '}
          {scan.coverage?.databaseVerified || scan.coverage?.hostingVerified || scan.coverage?.backupVerified
            ? 'owner-connected'
            : 'not assessed (no integration connected)'}
        </p>
      </section>

      {/* Four Score Ring Cards */}
      <section aria-label="Category Scores" className="grid grid-cols-2 lg:grid-cols-4 gap-5">
        <CircularGauge score={scan.scores?.security ?? null} label="SECURITY" />
        <CircularGauge score={scan.scores?.frontend ?? null} label="FRONT-END" />
        <CircularGauge score={scan.scores?.backend ?? null} label="BACK-END" />
        <CircularGauge score={scan.scores?.engagement ?? null} label="ENGAGEMENT" />
      </section>

      {/* Sub-Scores Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        {[
          { label: 'Overall Score', value: `${scan.scores?.overall ?? 'N/A'}/100` },
          { label: 'SEO Posture', value: `${scan.scores?.seo ?? scan.scores?.engagement ?? 'N/A'}/100` },
          { label: 'Accessibility Signals', value: `${scan.scores?.accessibility ?? scan.scores?.frontend ?? 'N/A'}/100` },
          { label: 'Performance Score', value: `${scan.scores?.performance ?? scan.scores?.backend ?? 'N/A'}/100` },
        ].map((sub) => (
          <div key={sub.label} className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] px-4 py-3 flex items-center justify-between">
            <span className="text-[#5A606E] dark:text-[#9499A6]">{sub.label}</span>
            <span className="font-mono font-bold tabular-nums text-[#0A0A0C] dark:text-white">{sub.value}</span>
          </div>
        ))}
      </div>

      {/* Live Browser Screenshot Verification */}
      {scan.metrics?.screenshot && (
        <section
          aria-label="Live Browser Screenshot"
          className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] overflow-hidden"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B]">
            <div className="flex items-center gap-2.5 min-w-0">
              <Camera className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3] shrink-0" />
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-[#0A0A0C] dark:text-white">
                  Live Browser Capture
                </h2>
                <p className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6] truncate">
                  {scan.metrics.screenshot.finalUrl || scan.metrics.finalUrl || scan.targetUrl}
                  {scan.metrics.screenshot.width && scan.metrics.screenshot.height
                    ? ` · ${scan.metrics.screenshot.width}×${scan.metrics.screenshot.height}`
                    : ''}
                </p>
              </div>
            </div>

            {scan.metrics.screenshot.available && scan.metrics.screenshot.imageUrl && (
              <a
                href={scan.metrics.screenshot.imageUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.12] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors"
              >
                Open full screenshot
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            )}
          </div>

          {scan.metrics.screenshot.available && scan.metrics.screenshot.imageUrl ? (
            <div className="p-4 sm:p-6 bg-[#F1F3F6]/60 dark:bg-[#090A0D]">
              <div className="rounded-xl overflow-hidden border border-[#E5E7EB] dark:border-white/[0.1] shadow-sm bg-white dark:bg-[#0D0E12]">
                <img
                  src={scan.metrics.screenshot.imageUrl}
                  alt={`Live screenshot of ${scan.normalizedDomain}`}
                  loading="lazy"
                  className="w-full max-h-[460px] object-cover object-top"
                />
              </div>
              {scan.metrics.screenshot.capturedAt && (
                <p className="mt-2.5 text-[11px] font-mono text-[#5A606E] dark:text-[#9499A6]">
                  Captured live at {new Date(scan.metrics.screenshot.capturedAt).toLocaleString()}
                </p>
              )}
            </div>
          ) : (
            <div className="px-6 py-5 text-xs text-[#5A606E] dark:text-[#9499A6]">
              Live screenshot unavailable for this target: {scan.metrics.screenshot.error || 'Target blocked automated browser rendering.'}
            </div>
          )}
        </section>
      )}

      {/* Report Sub-Navigation Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E5E7EB] dark:border-white/[0.08] pb-3">
        <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Report Sections">
          {(
            [
              { id: 'findings', label: `Checks & Findings (${findings.length})` },
              { id: 'recommendations', label: 'Recommendation Priority' },
              { id: 'telemetry', label: 'Metrics, TLS, DNS & Charts' },
              { id: 'ai', label: 'AI Analyst & Q&A' },
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
                  ? 'bg-[#2F75C3] dark:bg-[#2F71E3] text-white'
                  : 'text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'findings' && (
          <div className="flex items-center gap-2">
            <label htmlFor="severity-filter" className="text-[13px] text-[#5A606E] dark:text-[#9499A6]">
              Filter:
            </label>
            <select
              id="severity-filter"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3.5 py-2 rounded-lg text-[13px] border border-[#E5E7EB] dark:border-white/[0.1] bg-white dark:bg-[#101115] text-[#0A0A0C] dark:text-white cursor-pointer"
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
                  className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-7 space-y-5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xl font-bold text-[#0A0A0C] dark:text-white">
                      {CATEGORY_TITLES[cat]}
                    </h3>
                    <span className="text-[13px] font-mono tabular-nums text-[#5A606E] dark:text-[#9499A6]">
                      {catFindings.length} check{catFindings.length === 1 ? '' : 's'}
                    </span>
                  </div>

                  {catFindings.length === 0 ? (
                    <p className="text-sm text-[#5A606E] dark:text-[#9499A6] py-4">
                      No findings match the selected severity filter in this category.
                    </p>
                  ) : (
                    <div className="space-y-4">
                      {catFindings.map((f) => (
                        <FindingCard key={f.findingId} finding={f} scan={scan} onTrack={onTrackFindingInRemediation} />
                      ))}
                    </div>
                  )}
                </section>
              );
            })}
          </div>

          {/* Extended Infrastructure / Database / Backup Transparency Cards */}
          <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h3 className="text-lg font-bold text-[#0A0A0C] dark:text-white">
                Extended Infrastructure Scope (Database, Hosting &amp; Backup)
              </h3>
              <span className="text-xs text-[#5A606E] dark:text-[#9499A6]">
                Requires authorized owner integration
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {extendedCategories.map((cat) => {
                const items = findings.filter((f) => f.category === cat);
                return (
                  <div key={cat} className="space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-[#5A606E] dark:text-[#9499A6]">
                      {CATEGORY_TITLES[cat]}
                    </h4>
                    {items.map((f) => (
                      <FindingCard key={f.findingId} finding={f} scan={scan} />
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
                className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4"
              >
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">
                    {PRIORITY_LABELS[group]}
                  </h3>
                  <span className="text-xs font-mono tabular-nums text-[#5A606E] dark:text-[#9499A6]">
                    {items.length} item{items.length === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {items.map((item) => (
                    <FindingCard key={item.findingId} finding={item} scan={scan} onTrack={onTrackFindingInRemediation} />
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
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'TTFB / Warm TTFB', value: `${scan.metrics?.ttfbMs ?? 'N/A'} / ${scan.metrics?.timingBreakdown?.warmTtfbMs ?? scan.metrics?.ttfbMs ?? 'N/A'} ms` },
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
                className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-4"
              >
                <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">{m.label}</p>
                <p className="text-lg font-bold font-mono tabular-nums text-[#0A0A0C] dark:text-white mt-1 truncate">
                  {m.value}
                </p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
              <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">
                Severity Distribution (Observed Checks)
              </h3>
              <div className="space-y-3">
                {(
                  [
                    { label: 'Critical', count: sevCounts.critical, color: 'bg-red-600' },
                    { label: 'High', count: sevCounts.high, color: 'bg-red-400' },
                    { label: 'Medium', count: sevCounts.medium, color: 'bg-amber-500' },
                    { label: 'Low', count: sevCounts.low, color: 'bg-[#2F75C3] dark:bg-[#2F71E3]' },
                    { label: 'Informational', count: sevCounts.informational, color: 'bg-neutral-400' },
                    { label: 'Passed', count: sevCounts.passed, color: 'bg-emerald-600 dark:bg-emerald-400' },
                  ] as const
                ).map((row) => (
                  <div key={row.label} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-[#0A0A0C] dark:text-white font-medium">{row.label}</span>
                      <span className="font-mono tabular-nums text-[#5A606E] dark:text-[#9499A6]">{row.count}</span>
                    </div>
                    <div className="w-full h-2 rounded-full bg-[#F1F3F6] dark:bg-white/[0.08] overflow-hidden">
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
            <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
              <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">
                TLS Certificate &amp; DNS Signals
              </h3>
              <div className="space-y-2.5 text-xs">
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#E5E7EB] dark:border-white/[0.06]">
                  <span className="text-[#5A606E] dark:text-[#9499A6]">TLS Protocol / Cipher</span>
                  <span className="font-mono text-[#0A0A0C] dark:text-white text-right">
                    {scan.metrics?.tls?.available
                      ? `${scan.metrics.tls.protocol || 'TLS'} (${scan.metrics.tls.cipher || 'N/A'})`
                      : 'Unavailable'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#E5E7EB] dark:border-white/[0.06]">
                  <span className="text-[#5A606E] dark:text-[#9499A6]">Certificate Issuer &amp; Expiry</span>
                  <span className="font-mono text-[#0A0A0C] dark:text-white text-right">
                    {scan.metrics?.tls?.available
                      ? `${scan.metrics.tls.issuer || 'CA'} · ${scan.metrics.tls.daysRemaining ?? '?'}d remaining`
                      : 'Unavailable'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#E5E7EB] dark:border-white/[0.06]">
                  <span className="text-[#5A606E] dark:text-[#9499A6]">DNS A / AAAA Records</span>
                  <span className="font-mono text-[#0A0A0C] dark:text-white text-right truncate max-w-[260px]">
                    {[...(scan.metrics?.dns?.aRecords || []), ...(scan.metrics?.dns?.aaaaRecords || [])].join(', ') || 'None'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5 border-b border-[#E5E7EB] dark:border-white/[0.06]">
                  <span className="text-[#5A606E] dark:text-[#9499A6]">Email &amp; CAA DNS</span>
                  <span className="font-mono text-[#0A0A0C] dark:text-white text-right">
                    SPF: {scan.metrics?.dns?.hasSpf ? 'Yes' : 'No'} · DMARC: {scan.metrics?.dns?.hasDmarc ? 'Yes' : 'No'} · CAA:{' '}
                    {(scan.metrics?.dns?.caaRecords?.length ?? 0) > 0 ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between gap-4 py-1.5">
                  <span className="text-[#5A606E] dark:text-[#9499A6]">PageSpeed Insights (Lighthouse)</span>
                  <span className="font-mono text-[#0A0A0C] dark:text-white text-right">
                    {scan.metrics?.lighthouse?.available
                      ? `Perf ${scan.metrics.lighthouse.performanceScore}/100 · LCP ${scan.metrics.lighthouse.lcpMs}ms (${scan.metrics.lighthouse.dataType})`
                      : 'Not configured on server'}
                  </span>
                </div>
              </div>
            </section>
          </div>

          {scan.metrics?.crawledPageDetails && scan.metrics.crawledPageDetails.length > 0 && (
            <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">
                  Live Crawled Pages ({scan.metrics.crawledPageDetails.length})
                </h3>
                <span className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6]">
                  Same-origin deterministic crawl
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-[#E5E7EB] dark:border-white/[0.08] text-[#5A606E] dark:text-[#9499A6]">
                      <th className="py-2 pr-4 font-medium">Page URL</th>
                      <th className="py-2 px-3 font-medium">Page Title</th>
                      <th className="py-2 px-3 font-medium text-right">HTTP</th>
                      <th className="py-2 pl-3 font-medium text-right">TTFB</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scan.metrics.crawledPageDetails.map((pg) => (
                      <tr key={pg.url} className="border-b border-[#E5E7EB] dark:border-white/[0.05] last:border-b-0">
                        <td className="py-2 pr-4 font-mono text-[#0A0A0C] dark:text-white max-w-[280px] truncate">{pg.url}</td>
                        <td className="py-2 px-3 text-[#5A606E] dark:text-[#9499A6] max-w-[260px] truncate">{pg.title || '—'}</td>
                        <td className="py-2 px-3 font-mono text-right tabular-nums">{pg.statusCode || 'ERR'}</td>
                        <td className="py-2 pl-3 font-mono text-right tabular-nums text-[#5A606E] dark:text-[#9499A6]">{pg.ttfbMs} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>
      )}

      {/* TAB 4: AI Explanation & Google Search Grounded Q&A */}
      {activeTab === 'ai' && (
        <section className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E5E7EB] dark:border-white/[0.08] pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
                <h3 className="text-base font-bold text-[#0A0A0C] dark:text-white">
                  AI-Generated Findings Brief &amp; Grounded Q&amp;A
                </h3>
              </div>
              <p className="text-xs text-[#5A606E] dark:text-[#9499A6]">
                Combines verified deterministic scan findings with Google Search Grounding references. Credentials and cookies are never transmitted.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <select
                value={audience}
                onChange={(e) => setAudience(e.target.value as 'owner' | 'developer')}
                aria-label="Brief Audience"
                className="px-3 py-2 rounded-lg text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white"
              >
                <option value="owner">Website Owner Summary</option>
                <option value="developer">Developer Remediation Brief</option>
              </select>
              <button
                type="button"
                onClick={handleAiTrigger}
                disabled={isGeneratingAi}
                className="px-4 py-2 rounded-full text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-95 disabled:opacity-50 cursor-pointer whitespace-nowrap"
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
            <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] p-5 space-y-3">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-[#2F75C3] dark:text-[#2F71E3]">
                AI-Generated Interpretation (Grounded in Verified Scan Data)
              </p>
              <div className="text-sm leading-relaxed text-[#0A0A0C] dark:text-[#E5E7EB] whitespace-pre-wrap">
                {localAiText}
              </div>
              <GroundingSourcesList sources={localAiSources} />
            </div>
          ) : (
            <div className="text-center py-6 text-sm text-[#5A606E] dark:text-[#9499A6]">
              Select an audience and click <strong>Generate AI Brief</strong> to synthesize prioritized remediation steps from the verified findings above.
            </div>
          )}

          {/* Grounded Q&A Box */}
          {onAskAiQuestion && (
            <form onSubmit={handleAskSubmit} className="pt-4 border-t border-[#E5E7EB] dark:border-white/[0.08] space-y-3">
              <label htmlFor="ai-ask-input" className="block text-xs font-semibold text-[#0A0A0C] dark:text-white">
                Ask AI Analyst about this specific scan
              </label>

              <div className="flex flex-wrap gap-2">
                {QUICK_AI_PROMPTS.map((promptText) => (
                  <button
                    key={promptText}
                    type="button"
                    disabled={isAskingAi}
                    onClick={() => {
                      setAskInput(promptText);
                      void submitQuestion(promptText);
                    }}
                    className="px-3 py-1.5 rounded-full text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {promptText}
                  </button>
                ))}
              </div>

              <div className="flex gap-2">
                <input
                  id="ai-ask-input"
                  type="text"
                  value={askInput}
                  onChange={(e) => setAskInput(e.target.value)}
                  placeholder="e.g. How do I configure the missing Content-Security-Policy header cleanly?"
                  className="flex-1 px-3.5 py-2.5 rounded-xl text-xs sm:text-sm border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
                />
                <button
                  type="submit"
                  disabled={isAskingAi || askInput.trim().length < 3}
                  className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-full text-xs font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-95 disabled:opacity-50 cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isAskingAi ? 'Thinking...' : 'Ask'}
                </button>
              </div>
              {askAnswer && (
                <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] p-4 space-y-3 text-sm text-[#0A0A0C] dark:text-[#E5E7EB] whitespace-pre-wrap">
                  <div>{askAnswer}</div>
                  <GroundingSourcesList sources={askSources} />
                </div>
              )}
            </form>
          )}
        </section>
      )}
    </main>
  );
};
