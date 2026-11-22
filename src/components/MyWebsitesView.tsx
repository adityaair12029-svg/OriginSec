import React, { useState } from 'react';
import { CheckCircle2, Globe, PauseCircle, Play, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import type { ScanProfileId, VerifiedDomain, WebsiteRecord, WebsiteScan } from '../types/audit';
import { SCAN_PROFILES } from '../lib/scanner/profiles';
import { EmptyWorkspaceState } from './DashboardShell';

interface MyWebsitesViewProps {
  isAuthenticated: boolean;
  onSignIn: () => void;
  websites: WebsiteRecord[];
  scans: WebsiteScan[];
  verifiedDomains: VerifiedDomain[];
  getAuthToken: () => Promise<string | null>;
  onCreateWebsite: (record: {
    websiteId: string;
    name: string;
    targetUrl: string;
    normalizedDomain: string;
    defaultProfile: ScanProfileId;
  }) => Promise<void>;
  onUpdateWebsite: (
    websiteId: string,
    updates: Partial<Pick<WebsiteRecord, 'name' | 'defaultProfile' | 'monitoringPaused' | 'verificationStatus'>>
  ) => Promise<void>;
  onDeleteWebsite: (websiteId: string) => Promise<void>;
  onSaveVerifiedDomain: (rec: {
    domainId: string;
    domain: string;
    method: 'dns_txt' | 'html_meta' | 'well_known';
    challengeToken: string;
    verified: boolean;
  }) => Promise<void>;
  onRunScan: (targetUrl: string, profile: ScanProfileId) => void;
  onOpenReport: (scan: WebsiteScan) => void;
}

export const MyWebsitesView: React.FC<MyWebsitesViewProps> = ({
  isAuthenticated,
  onSignIn,
  websites,
  scans,
  verifiedDomains,
  getAuthToken,
  onCreateWebsite,
  onUpdateWebsite,
  onDeleteWebsite,
  onSaveVerifiedDomain,
  onRunScan,
  onOpenReport,
}) => {
  const [nameInput, setNameInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [defaultProfile, setDefaultProfile] = useState<ScanProfileId>('standard');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [verifyingWebsiteId, setVerifyingWebsiteId] = useState<string | null>(null);
  const [verifyMethod, setVerifyMethod] = useState<'dns_txt' | 'html_meta' | 'well_known'>('dns_txt');
  const [challengeInfo, setChallengeInfo] = useState<{
    domain: string;
    token: string;
    dnsTxtRecord: string;
    htmlMetaTag: string;
    wellKnownUrl: string;
  } | null>(null);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  const handleAddWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const trimmedUrl = urlInput.trim();
    if (!trimmedUrl) {
      setFormError('Enter a website URL (e.g. https://example.com).');
      return;
    }
    const normalized = /^https?:\/\//i.test(trimmedUrl) ? trimmedUrl : `https://${trimmedUrl}`;
    let parsed: URL;
    try {
      parsed = new URL(normalized);
      if (!parsed.hostname.includes('.')) {
        setFormError('Enter a valid public domain name.');
        return;
      }
    } catch {
      setFormError('Invalid URL format.');
      return;
    }

    const domain = parsed.hostname.toLowerCase();
    const displayName = nameInput.trim() || domain;
    const websiteId = `site_${domain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;

    setSubmitting(true);
    try {
      await onCreateWebsite({
        websiteId,
        name: displayName,
        targetUrl: parsed.toString(),
        normalizedDomain: domain,
        defaultProfile,
      });
      setNameInput('');
      setUrlInput('');
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not add website.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRequestChallenge = async (site: WebsiteRecord) => {
    setVerifyingWebsiteId(site.websiteId);
    setVerifyMessage(null);
    const token = await getAuthToken();
    const res = await fetch('/api/ownership/challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ domain: site.normalizedDomain }),
    });
    const data = await res.json();
    if (res.ok) {
      setChallengeInfo({
        domain: data.domain,
        token: data.token,
        dnsTxtRecord: data.dnsTxtRecord,
        htmlMetaTag: data.htmlMetaTag,
        wellKnownUrl: data.wellKnownUrl,
      });
      await onUpdateWebsite(site.websiteId, { verificationStatus: 'pending' });
    } else {
      setVerifyMessage(data.error || 'Could not generate ownership challenge.');
    }
  };

  const handleConfirmVerification = async (site: WebsiteRecord) => {
    if (!challengeInfo) return;
    setVerifyMessage('Checking live proof...');
    const token = await getAuthToken();
    const res = await fetch('/api/ownership/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        domain: site.normalizedDomain,
        method: verifyMethod,
        challengeToken: challengeInfo.token,
      }),
    });
    const data = await res.json();
    setVerifyMessage(data.evidence || (data.verified ? 'Verified!' : 'Proof not found yet.'));
    if (data.verified) {
      await onSaveVerifiedDomain({
        domainId: `dom_${site.normalizedDomain.replace(/[^a-zA-Z0-9]/g, '_')}`,
        domain: site.normalizedDomain,
        method: verifyMethod,
        challengeToken: challengeInfo.token,
        verified: true,
      });
      await onUpdateWebsite(site.websiteId, { verificationStatus: 'verified' });
      setChallengeInfo(null);
      setVerifyingWebsiteId(null);
    }
  };

  if (!isAuthenticated) {
    return (
      <EmptyWorkspaceState
        title="Sign in to manage Websites"
        description="Save your properties, verify domain ownership for deeper scans, set default audit profiles, and track score history per domain."
        actionLabel="Sign in with Google"
        onAction={onSignIn}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-[#0A0A0C] dark:text-white">My Websites</h1>
        <p className="text-[15px] text-[#5A606E] dark:text-[#9499A6] mt-1">
          Register properties, verify domain ownership, assign default scan profiles, and launch deterministic audits.
        </p>
      </div>

      {/* Add Website Form */}
      <form
        onSubmit={handleAddWebsite}
        className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4"
      >
        <h2 className="text-base font-bold text-[#0A0A0C] dark:text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
          Add Website Property
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <input
            type="text"
            value={nameInput}
            onChange={(e) => setNameInput(e.target.value)}
            placeholder="Label (e.g. Production App)"
            aria-label="Website name"
            className="px-3.5 py-2.5 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
          />
          <input
            type="url"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="https://yourdomain.com"
            aria-label="Website URL"
            className="md:col-span-2 px-3.5 py-2.5 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
          />
          <select
            value={defaultProfile}
            onChange={(e) => setDefaultProfile(e.target.value as ScanProfileId)}
            aria-label="Default scan profile"
            className="px-3.5 py-2.5 rounded-xl text-sm border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white focus:outline-none focus:border-[#2F75C3] dark:focus:border-[#2F71E3]"
          >
            {Object.values(SCAN_PROFILES).map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </div>
        {formError && <p className="text-xs text-red-600 dark:text-red-400">{formError}</p>}
        <button
          type="submit"
          disabled={submitting}
          className="px-5 py-2.5 rounded-xl text-xs font-semibold bg-[#0A0A0C] text-white dark:bg-white dark:text-[#070708] hover:opacity-90 cursor-pointer disabled:opacity-50"
        >
          {submitting ? 'Saving...' : 'Save Website'}
        </button>
      </form>

      {/* Websites List */}
      {websites.length === 0 ? (
        <EmptyWorkspaceState
          title="No websites registered yet"
          description="Add your first domain above to configure recurring scan profiles, ownership verification, and quick one-click re-audits."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {websites.map((site) => {
            const domainVerified =
              site.verificationStatus === 'verified' ||
              verifiedDomains.some((v) => v.verified && v.domain === site.normalizedDomain);
            const domainScans = scans.filter((s) => s.normalizedDomain === site.normalizedDomain);
            const latestSiteScan = domainScans[0] || null;
            const displayScore = site.latestOverallScore ?? latestSiteScan?.scores?.overall ?? null;

            return (
              <section
                key={site.websiteId}
                className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115] p-6 space-y-4"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <Globe className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3] shrink-0" />
                      <h3 className="text-lg font-bold text-[#0A0A0C] dark:text-white">{site.name}</h3>
                      {domainVerified ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-emerald-600/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 text-[11px] font-semibold">
                          <CheckCircle2 className="w-3 h-3" />
                          Verified Owner
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-md border border-[#E5E7EB] dark:border-white/[0.1] text-[11px] text-[#5A606E] dark:text-[#9499A6]">
                          Unverified External
                        </span>
                      )}
                      {site.monitoringPaused && (
                        <span className="px-2 py-0.5 rounded-md border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-300 text-[11px] font-medium">
                          Monitoring Paused
                        </span>
                      )}
                    </div>
                    <p className="text-xs font-mono text-[#5A606E] dark:text-[#9499A6] break-all">
                      {site.targetUrl} · {domainScans.length} recorded scan{domainScans.length === 1 ? '' : 's'}
                      {latestSiteScan ? ` · Last scanned ${new Date(latestSiteScan.startedAt).toLocaleDateString()}` : ''}
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <div className="px-3.5 py-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-xs font-mono tabular-nums">
                      Overall Score: <strong>{displayScore !== null ? `${displayScore}/100` : 'N/A'}</strong>
                    </div>

                    <select
                      value={site.defaultProfile}
                      onChange={(e) => onUpdateWebsite(site.websiteId, { defaultProfile: e.target.value as ScanProfileId })}
                      aria-label={`Default profile for ${site.name}`}
                      className="px-3 py-2 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#13151B] text-[#0A0A0C] dark:text-white cursor-pointer"
                    >
                      {Object.values(SCAN_PROFILES).map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.label}
                        </option>
                      ))}
                    </select>

                    <button
                      type="button"
                      onClick={() => onRunScan(site.targetUrl, site.defaultProfile)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#0A0A0C] text-white dark:bg-white dark:text-[#070708] hover:opacity-90 cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5" />
                      Scan Now
                    </button>

                    {latestSiteScan && (
                      <button
                        type="button"
                        onClick={() => onOpenReport(latestSiteScan)}
                        className="px-3.5 py-2 rounded-xl text-xs font-medium border border-[#E5E7EB] dark:border-white/[0.08] text-[#0A0A0C] dark:text-white cursor-pointer"
                      >
                        Latest Report
                      </button>
                    )}

                    {!domainVerified && (
                      <button
                        type="button"
                        onClick={() => handleRequestChallenge(site)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border border-[#2F75C3]/40 dark:border-[#2F71E3]/40 text-[#2F75C3] dark:text-[#2F71E3] cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Verify Ownership
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => onUpdateWebsite(site.websiteId, { monitoringPaused: !site.monitoringPaused })}
                      title={site.monitoringPaused ? 'Resume monitoring' : 'Pause monitoring'}
                      className="p-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
                    >
                      <PauseCircle className="w-4 h-4" />
                    </button>

                    <button
                      type="button"
                      onClick={() => onDeleteWebsite(site.websiteId)}
                      title="Remove website"
                      aria-label={`Remove ${site.name}`}
                      className="p-2 rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] text-[#5A606E] dark:text-[#9499A6] hover:text-red-500 cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Inline Ownership Challenge Drawer */}
                {verifyingWebsiteId === site.websiteId && challengeInfo && (
                  <div className="rounded-xl border border-[#2F75C3]/40 dark:border-[#2F71E3]/40 bg-[#F7F8FA] dark:bg-[#13151B] p-4 space-y-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-[#0A0A0C] dark:text-white">
                        Domain Verification Challenge for {challengeInfo.domain}
                      </span>
                      <select
                        value={verifyMethod}
                        onChange={(e) => setVerifyMethod(e.target.value as 'dns_txt' | 'html_meta' | 'well_known')}
                        className="px-2.5 py-1 rounded-lg border border-[#E5E7EB] dark:border-white/[0.08] bg-white dark:bg-[#101115]"
                      >
                        <option value="dns_txt">DNS TXT Record</option>
                        <option value="html_meta">HTML Meta Tag</option>
                        <option value="well_known">.well-known File</option>
                      </select>
                    </div>
                    <code className="block p-3 rounded-lg bg-white dark:bg-[#070708] border border-[#E5E7EB] dark:border-white/[0.08] font-mono break-all text-[12px]">
                      {verifyMethod === 'dns_txt'
                        ? challengeInfo.dnsTxtRecord
                        : verifyMethod === 'html_meta'
                          ? challengeInfo.htmlMetaTag
                          : `${challengeInfo.wellKnownUrl} -> ${challengeInfo.token}`}
                    </code>
                    {verifyMessage && <p className="text-[#2F75C3] dark:text-[#2F71E3] font-medium">{verifyMessage}</p>}
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleConfirmVerification(site)}
                        className="px-4 py-2 rounded-lg font-semibold bg-[#2F75C3] dark:bg-[#2F71E3] text-white cursor-pointer"
                      >
                        Check Live Verification Proof
                      </button>
                      <button
                        type="button"
                        onClick={() => setVerifyingWebsiteId(null)}
                        className="px-3 py-2 rounded-lg border border-[#E5E7EB] dark:border-white/[0.08] cursor-pointer"
                      >
                        Close
                      </button>
                    </div>
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
};
