import React, { useState } from 'react';
import { AlertCircle, ShieldCheck } from 'lucide-react';
import type { ScanProfileId, ThemeMode } from '../types/audit';
import { SCAN_PROFILES } from '../lib/scanner/profiles';
import { OriginSecMark } from './OriginSecMark';
import { ParticleFieldCanvas } from './ParticleFieldCanvas';

interface LandingHomeProps {
  theme: ThemeMode;
  onStartScan: (params: {
    targetUrl: string;
    authorizedConfirmed: boolean;
    scanProfile: ScanProfileId;
    maxPages: number;
    crawlDepth: number;
  }) => void;
  isSubmitting: boolean;
  errorMessage: string | null;
  defaultProfile?: ScanProfileId;
}

const CATEGORIES = [
  {
    title: 'Cybersecurity & Hardening',
    description:
      'SSL/TLS posture, HTTP security headers, cookie flags, DNS/CAA records, and externally observable security configuration.',
  },
  {
    title: 'Front-End & UI/UX',
    description:
      'DOM structure, page metadata, responsive layout signals, WCAG accessibility checks, render-blocking scripts, and image optimization.',
  },
  {
    title: 'Back-End & Architecture',
    description:
      'Deterministic server response timing breakdown, compression, caching directives, CORS posture, and infrastructure verification.',
  },
  {
    title: 'Product & Engagement',
    description:
      'CTA clarity, heading structure, SEO meta & canonical tags, sitemap/robots validation, broken internal links, and remediation tracking.',
  },
];

export const LandingHome: React.FC<LandingHomeProps> = ({
  theme,
  onStartScan,
  isSubmitting,
  errorMessage,
  defaultProfile = 'standard',
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [authorizedConfirmed, setAuthorizedConfirmed] = useState(false);
  const [scanProfile, setScanProfile] = useState<ScanProfileId>(defaultProfile);
  const [localValidationError, setLocalValidationError] = useState<string | null>(null);

  const selectedProfileDef = SCAN_PROFILES[scanProfile] || SCAN_PROFILES.standard;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalValidationError(null);

    const trimmed = urlInput.trim();
    if (!trimmed) {
      setLocalValidationError('Please enter a website URL (e.g. https://example.com).');
      return;
    }

    let candidate = trimmed;
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
      candidate = `https://${candidate}`;
    }

    try {
      const parsed = new URL(candidate);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setLocalValidationError(`Unsupported protocol "${parsed.protocol}". Only http:// and https:// are allowed.`);
        return;
      }
      if (!parsed.hostname || !parsed.hostname.includes('.')) {
        setLocalValidationError('Please enter a valid public domain name (e.g. https://example.com).');
        return;
      }
    } catch {
      setLocalValidationError('Invalid URL format. Example: https://example.com');
      return;
    }

    if (!authorizedConfirmed) {
      setLocalValidationError('Please confirm that you own this website or have permission to assess it.');
      return;
    }

    onStartScan({
      targetUrl: candidate,
      authorizedConfirmed: true,
      scanProfile,
      maxPages: selectedProfileDef.maxPages,
      crawlDepth: selectedProfileDef.crawlDepth,
    });
  };

  const displayError = localValidationError || errorMessage;

  return (
    <main className="relative flex-1 flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-9 sm:py-12 overflow-hidden">
      <ParticleFieldCanvas theme={theme} variant="hero" />

      <div className="relative z-10 max-w-4xl w-full mx-auto text-center space-y-6 animate-fade-up">
        <div className="inline-flex items-center justify-center gap-2.5 text-base sm:text-lg font-medium text-[#0A0A0C] dark:text-white">
          <OriginSecMark theme={theme} className="w-7 h-7" />
          <span>OriginSec</span>
        </div>

        <h1 className="text-[44px] sm:text-[62px] lg:text-[74px] font-medium tracking-[-0.03em] leading-[1.04] text-[#0A0A0C] dark:text-white text-balance">
          Find every weakness before anyone else does.
        </h1>

        <p className="max-w-2xl mx-auto text-[18px] sm:text-[21px] text-[#5A606E] dark:text-[#9499A6] leading-[1.5]">
          Paste any URL.{' '}
          <span className="text-[#0A0A0C] dark:text-white font-medium">OriginSec</span>{' '}
          probes live endpoints and scores security, front-end, back-end, and engagement with deterministic evidence.
        </p>

        {/* Responsive Pill URL Input Bar (button always stays neatly inside box on mobile & desktop) */}
        <form onSubmit={handleSubmit} className="pt-2 max-w-3xl mx-auto w-full space-y-3.5" noValidate>
          <div className="w-full overflow-hidden rounded-2xl sm:rounded-full border border-[#E5E7EB] dark:border-white/[0.12] bg-white/95 dark:bg-[#101115]/95 backdrop-blur-md p-2 sm:p-2.5 flex flex-col sm:flex-row items-stretch sm:items-center gap-2 focus-within:border-[#2F75C3] dark:focus-within:border-[#2F71E3] transition-all duration-200 shadow-[0_14px_42px_rgba(10,10,12,0.06)] dark:shadow-[0_18px_50px_rgba(0,0,0,0.45)]">
            <label htmlFor="target-url-input" className="sr-only">
              Website URL to analyze
            </label>
            <input
              id="target-url-input"
              type="url"
              inputMode="url"
              autoComplete="url"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (localValidationError) setLocalValidationError(null);
              }}
              placeholder="https://example.com"
              className="w-full min-w-0 flex-1 bg-transparent px-4 sm:px-5 py-2.5 sm:py-3 text-base sm:text-[18px] text-[#0A0A0C] dark:text-white placeholder:text-[#8A919E] dark:placeholder:text-[#6B7280] focus:outline-none"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full sm:w-auto px-6 sm:px-7 py-3 sm:py-3.5 rounded-xl sm:rounded-full font-medium text-[15px] bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-95 active:scale-[0.99] transition-all duration-150 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? 'Auditing live...' : 'Analyze target'}
            </button>
          </div>

          {/* Authorization Statement & Scan Profile */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 px-2 text-left">
            <label className="inline-flex items-start sm:items-center gap-2.5 text-[14px] text-[#5A606E] dark:text-[#9499A6] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={authorizedConfirmed}
                onChange={(e) => {
                  setAuthorizedConfirmed(e.target.checked);
                  if (localValidationError) setLocalValidationError(null);
                }}
                className="mt-0.5 sm:mt-0 w-4 h-4 shrink-0 rounded border-[#D1D5DB] dark:border-white/[0.2] accent-[#2F75C3] dark:accent-[#2F71E3] cursor-pointer"
              />
              <span>I confirm I own this website or have explicit permission to assess it.</span>
            </label>

            <div className="inline-flex items-center gap-1.5 text-[14px] text-[#5A606E] dark:text-[#9499A6] shrink-0">
              <ShieldCheck className="w-4 h-4 text-[#2F75C3] dark:text-[#2F71E3]" />
              <label htmlFor="scan-profile-select" className="sr-only">
                Scan Profile
              </label>
              <select
                id="scan-profile-select"
                value={scanProfile}
                onChange={(e) => setScanProfile(e.target.value as ScanProfileId)}
                className="bg-transparent text-[14px] font-medium text-[#0A0A0C] dark:text-white focus:outline-none cursor-pointer"
              >
                {Object.values(SCAN_PROFILES).map((prof) => (
                  <option key={prof.id} value={prof.id} className="bg-white dark:bg-[#101115]">
                    {prof.shortLabel}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <p className="text-[13px] text-[#5A606E] dark:text-[#9499A6] text-left px-2">
            {selectedProfileDef.label}: {selectedProfileDef.description}
          </p>

          {displayError && (
            <div
              role="alert"
              className="flex items-center gap-2.5 px-4 py-3.5 rounded-2xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm text-left"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{displayError}</span>
            </div>
          )}
        </form>
      </div>

      {/* Four Primary Category Cards */}
      <section
        aria-label="Audit Categories"
        className="relative z-10 max-w-7xl w-full mx-auto mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-up"
      >
        {CATEGORIES.map((cat) => (
          <div
            key={cat.title}
            className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white/92 dark:bg-[#101115]/92 backdrop-blur-sm p-6 text-left hover:-translate-y-1 hover:border-[#2F75C3]/50 dark:hover:border-[#2F71E3]/50 transition-all duration-200 ease-out"
          >
            <h2 className="text-[18px] font-semibold text-[#0A0A0C] dark:text-white mb-2.5 leading-snug">
              {cat.title}
            </h2>
            <p className="text-[15px] leading-[1.6] text-[#5A606E] dark:text-[#9499A6]">
              {cat.description}
            </p>
          </div>
        ))}
      </section>
    </main>
  );
};
