import React, { useState } from 'react';
import { CheckCircle2, Lock, ShieldCheck, AlertCircle, Play } from 'lucide-react';
import type { ApiProbeResult, VerifiedDomain } from '../types/audit';

interface ApiAuditViewProps {
  isAuthenticated: boolean;
  getAuthToken: () => Promise<string | null>;
  verifiedDomains: VerifiedDomain[];
  onSaveVerifiedDomain: (rec: {
    domainId: string;
    domain: string;
    method: 'dns_txt' | 'html_meta' | 'well_known';
    challengeToken: string;
    verified: boolean;
  }) => Promise<void>;
  onSignIn: () => void;
}

async function parseApiJson(res: Response): Promise<Record<string, any> | null> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as Record<string, any>;
  } catch {
    return null;
  }
}

export const ApiAuditView: React.FC<ApiAuditViewProps> = ({
  isAuthenticated,
  getAuthToken,
  verifiedDomains,
  onSaveVerifiedDomain,
  onSignIn,
}) => {
  const [mode, setMode] = useState<'public' | 'verified_owner'>('public');
  const [baseUrl, setBaseUrl] = useState('');
  const [endpointsText, setEndpointsText] = useState('/\n/api/health');
  const [openApiText, setOpenApiText] = useState('');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ApiProbeResult[]>([]);

  // Ownership Verification State
  const [verifyDomainInput, setVerifyDomainInput] = useState('');
  const [verifyMethod, setVerifyMethod] = useState<'dns_txt' | 'html_meta' | 'well_known'>('dns_txt');
  const [challengeData, setChallengeData] = useState<{
    normalizedDomain: string;
    challengeToken: string;
    dnsTxtName: string;
    dnsTxtValue: string;
    htmlMetaTag: string;
    wellKnownUrl: string;
  } | null>(null);
  const [verifyStatusMsg, setVerifyStatusMsg] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const handleGenerateChallenge = async () => {
    setVerifyStatusMsg(null);
    if (!isAuthenticated) {
      onSignIn();
      return;
    }
    try {
      const token = await getAuthToken();
      const res = await fetch('/api/ownership/challenge', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ domain: verifyDomainInput }),
      });
      const data = await parseApiJson(res);
      if (!res.ok || !data) {
        setVerifyStatusMsg(data?.error || `Could not generate verification challenge (HTTP ${res.status}).`);
        return;
      }
      setChallengeData(data as typeof challengeData);
      await onSaveVerifiedDomain({
        domainId: `dom_${data.normalizedDomain.replace(/[^a-zA-Z0-9]/g, '_')}`,
        domain: data.normalizedDomain,
        method: verifyMethod,
        challengeToken: data.challengeToken,
        verified: false,
      });
    } catch (err) {
      setVerifyStatusMsg(err instanceof Error ? err.message : 'Network error generating challenge.');
    }
  };

  const handleVerifyNow = async () => {
    if (!challengeData) return;
    setVerifying(true);
    setVerifyStatusMsg(null);
    try {
      const token = await getAuthToken();
      const res = await fetch('/api/ownership/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          domain: challengeData.normalizedDomain,
          method: verifyMethod,
          challengeToken: challengeData.challengeToken,
        }),
      });
      const data = await parseApiJson(res);
      if (!data) {
        setVerifyStatusMsg(`Verification service returned HTTP ${res.status}.`);
        return;
      }
      setVerifyStatusMsg(data.evidence || data.error || 'Verification check completed.');
      if (res.ok && data.verified) {
        await onSaveVerifiedDomain({
          domainId: `dom_${challengeData.normalizedDomain.replace(/[^a-zA-Z0-9]/g, '_')}`,
          domain: challengeData.normalizedDomain,
          method: verifyMethod,
          challengeToken: challengeData.challengeToken,
          verified: true,
        });
      }
    } catch (err) {
      setVerifyStatusMsg(err instanceof Error ? err.message : 'Network error verifying ownership.');
    } finally {
      setVerifying(false);
    }
  };

  const handleRunAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResults([]);
    if (mode === 'verified_owner' && !isAuthenticated) {
      setError('Sign in with Google to run Verified Owner API Audits.');
      return;
    }

    setRunning(true);
    try {
      const token = await getAuthToken();
      const endpoints = endpointsText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);

      const res = await fetch('/api/api-audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          mode,
          baseUrl,
          endpoints,
          openApiSpecText: mode === 'verified_owner' && openApiText.trim() ? openApiText.trim() : undefined,
        }),
      });
      const data = await parseApiJson(res);
      if (!res.ok || !data) {
        setError(data?.error || `API audit failed (HTTP ${res.status}).`);
        return;
      }
      setResults(data.results || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error running API audit.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[#151515] dark:text-white">Back-End &amp; API Audits</h1>
        <p className="text-sm text-[#777267] dark:text-[#929292]">
          Non-destructive API posture testing. OriginSec never guesses private endpoints or runs brute-force / injection attacks.
        </p>
      </div>

      {/* Mode Switcher */}
      <div className="inline-flex rounded-xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-1">
        <button
          type="button"
          onClick={() => setMode('public')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
            mode === 'public'
              ? 'bg-[#151515] text-white dark:bg-white dark:text-[#050505]'
              : 'text-[#777267] dark:text-[#929292]'
          }`}
        >
          Mode A: Public External Assessment
        </button>
        <button
          type="button"
          onClick={() => setMode('verified_owner')}
          className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${
            mode === 'verified_owner'
              ? 'bg-[#151515] text-white dark:bg-white dark:text-[#050505]'
              : 'text-[#777267] dark:text-[#929292]'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          Mode B: Verified Owner Assessment
        </button>
      </div>

      {/* Ownership Verification Section (shown in Mode B) */}
      {mode === 'verified_owner' && (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
              <h2 className="text-base font-bold text-[#151515] dark:text-white">
                Domain Ownership Verification
              </h2>
            </div>
            <span className="text-xs font-mono text-[#777267] dark:text-[#929292]">
              {verifiedDomains.filter((d) => d.verified).length} verified domain(s)
            </span>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={verifyDomainInput}
              onChange={(e) => setVerifyDomainInput(e.target.value)}
              placeholder="example.com"
              className="flex-1 px-4 py-2.5 rounded-xl text-sm border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
            />
            <select
              value={verifyMethod}
              onChange={(e) => setVerifyMethod(e.target.value as 'dns_txt' | 'html_meta' | 'well_known')}
              aria-label="Verification Method"
              className="px-3 py-2.5 rounded-xl text-xs border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
            >
              <option value="dns_txt">DNS TXT Record</option>
              <option value="html_meta">HTML Meta Tag</option>
              <option value="well_known">.well-known File</option>
            </select>
            <button
              type="button"
              onClick={handleGenerateChallenge}
              className="px-4 py-2.5 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer whitespace-nowrap"
            >
              Generate Challenge
            </button>
          </div>

          {challengeData && (
            <div className="rounded-xl border border-[#E7E0D3] dark:border-[#222] bg-[#FAF9F5] dark:bg-[#101010] p-4 space-y-3 text-xs">
              {verifyMethod === 'dns_txt' && (
                <div>
                  <p className="font-semibold text-[#151515] dark:text-white">Add TXT record to {challengeData.dnsTxtName}:</p>
                  <code className="block mt-1 p-2 rounded bg-[#EFECE4] dark:bg-[#050505] font-mono break-all">
                    {challengeData.dnsTxtValue}
                  </code>
                </div>
              )}
              {verifyMethod === 'html_meta' && (
                <div>
                  <p className="font-semibold text-[#151515] dark:text-white">Add meta tag to homepage &lt;head&gt;:</p>
                  <code className="block mt-1 p-2 rounded bg-[#EFECE4] dark:bg-[#050505] font-mono break-all">
                    {challengeData.htmlMetaTag}
                  </code>
                </div>
              )}
              {verifyMethod === 'well_known' && (
                <div>
                  <p className="font-semibold text-[#151515] dark:text-white">Host token at {challengeData.wellKnownUrl}:</p>
                  <code className="block mt-1 p-2 rounded bg-[#EFECE4] dark:bg-[#050505] font-mono break-all">
                    {challengeData.challengeToken}
                  </code>
                </div>
              )}
              <button
                type="button"
                onClick={handleVerifyNow}
                disabled={verifying}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#008C55] dark:bg-[#00E69A] text-white dark:text-[#050505] cursor-pointer disabled:opacity-50"
              >
                {verifying ? 'Verifying...' : 'Verify Ownership Now'}
              </button>
            </div>
          )}

          {verifyStatusMsg && (
            <p className="text-xs font-mono text-[#777267] dark:text-[#929292]">{verifyStatusMsg}</p>
          )}

          {verifiedDomains.length > 0 && (
            <div className="flex flex-wrap gap-3 pt-1">
              {verifiedDomains.map((vd) => (
                <div
                  key={vd.domainId}
                  className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[#E7E0D3] dark:border-[#222] text-xs"
                >
                  <CheckCircle2
                    className={`w-3.5 h-3.5 ${vd.verified ? 'text-[#008C55] dark:text-[#00E69A]' : 'text-[#777267]'}`}
                  />
                  <span className="font-mono">{vd.domain}</span>
                  <span className="text-[#777267] dark:text-[#929292]">({vd.verified ? 'Verified' : 'Pending'})</span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Endpoint Probe Form */}
      <form
        onSubmit={handleRunAudit}
        className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 space-y-4"
      >
        <div className="space-y-1.5">
          <label htmlFor="api-base-url" className="block text-xs font-semibold text-[#151515] dark:text-white">
            API Base URL
          </label>
          <input
            id="api-base-url"
            type="url"
            required
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://api.example.com"
            className="w-full px-4 py-2.5 rounded-xl text-sm border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label htmlFor="api-endpoints" className="block text-xs font-semibold text-[#151515] dark:text-white">
              Supplied Endpoints (one per line, {mode === 'public' ? 'max 5' : 'max 15'})
            </label>
            <textarea
              id="api-endpoints"
              rows={4}
              value={endpointsText}
              onChange={(e) => setEndpointsText(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl text-xs font-mono border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
            />
          </div>

          {mode === 'verified_owner' && (
            <div className="space-y-1.5">
              <label htmlFor="openapi-spec" className="block text-xs font-semibold text-[#151515] dark:text-white">
                OpenAPI / Swagger JSON (optional)
              </label>
              <textarea
                id="openapi-spec"
                rows={4}
                value={openApiText}
                onChange={(e) => setOpenApiText(e.target.value)}
                placeholder='{"openapi": "3.0.0", "paths": { "/v1/health": { "get": {} } }}'
                className="w-full px-4 py-2.5 rounded-xl text-xs font-mono border border-[#E7E0D3] dark:border-[#252525] bg-[#FAF9F5] dark:bg-[#101010] text-[#151515] dark:text-white"
              />
            </div>
          )}
        </div>

        {error && (
          <div role="alert" className="flex items-center gap-2 text-xs text-red-600 dark:text-red-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={running}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 disabled:opacity-50 cursor-pointer"
        >
          <Play className="w-3.5 h-3.5" />
          {running ? 'Running Safe Probes...' : 'Run API Assessment'}
        </button>
      </form>

      {/* Results Table */}
      {results.length > 0 && (
        <section className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] overflow-hidden">
          <div className="px-6 py-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E]">
            <h2 className="text-sm font-bold text-[#151515] dark:text-white">API Assessment Results</h2>
          </div>
          <div className="divide-y divide-[#EFECE4] dark:divide-[#1A1A1A]">
            {results.map((r, i) => (
              <div key={`${r.endpoint}_${i}`} className="p-5 space-y-2 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono font-semibold text-[#151515] dark:text-white break-all">
                    {r.method} {r.endpoint}
                  </div>
                  <div className="flex items-center gap-2 font-mono tabular-nums">
                    <span className="text-[#777267] dark:text-[#929292]">{r.responseTimeMs} ms</span>
                    <span className="px-2 py-0.5 rounded border border-[#E7E0D3] dark:border-[#252525] uppercase font-bold">
                      {r.statusCode ?? 'ERR'} · {r.severity}
                    </span>
                  </div>
                </div>
                <p className="text-[#777267] dark:text-[#929292]">{r.description}</p>
                <p className="font-mono text-[11px] text-[#777267] dark:text-[#888]">{r.evidence}</p>
                <p className="text-[#151515] dark:text-[#E5E5E5]">
                  <strong>Recommendation:</strong> {r.recommendation}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
};
