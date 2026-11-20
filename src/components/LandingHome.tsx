import React, { useState } from 'react';
import { AlertCircle, ShieldCheck } from 'lucide-react';

interface LandingHomeProps {
  onStartScan: (params: { targetUrl: string; authorizedConfirmed: boolean; maxPages: number; crawlDepth: number }) => void;
  isSubmitting: boolean;
  errorMessage: string | null;
}

const CATEGORIES = [
  {
    title: 'Cybersecurity & Hardening',
    description:
      'SSL/TLS posture, HTTP security headers, cookie flags, DNS security signals, and externally observable security configuration.',
  },
  {
    title: 'Front-End & UI/UX',
    description:
      'DOM structure, page metadata, responsive layout signals, accessibility, render-blocking resources, and frontend performance.',
  },
  {
    title: 'Back-End & Architecture',
    description:
      'Observable server response time, API health, caching directives, HTTP behaviour, and connected infrastructure configuration.',
  },
  {
    title: 'Product & Engagement',
    description:
      'CTA clarity, navigation structure, content quality, usability, accessibility, and improvement recommendations.',
  },
];

export const LandingHome: React.FC<LandingHomeProps> = ({
  onStartScan,
  isSubmitting,
  errorMessage,
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [authorizedConfirmed, setAuthorizedConfirmed] = useState(false);
  const [crawlDepthMode, setCrawlDepthMode] = useState<'standard' | 'deep'>('standard');
  const [localValidationError, setLocalValidationError] = useState<string | null>(null);

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
      maxPages: crawlDepthMode === 'deep' ? 20 : 8,
      crawlDepth: crawlDepthMode === 'deep' ? 2 : 1,
    });
  };

  const displayError = localValidationError || errorMessage;

  return (
    <main className="flex-1 flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-14 sm:py-20">
      <div className="max-w-4xl w-full mx-auto text-center space-y-6 animate-fade-up">
        <p className="text-xs sm:text-[13px] font-semibold tracking-[0.24em] uppercase text-[#777267] dark:text-[#929292]">
          AUTONOMOUS FULL-SPECTRUM WEBSITE AUDIT
        </p>

        <h1 className="text-[38px] sm:text-6xl md:text-[64px] font-extrabold tracking-[-0.03em] leading-[1.06] text-[#151515] dark:text-white text-balance">
          Find every weakness before anyone else does.
        </h1>

        <p className="max-w-2xl mx-auto text-[17px] sm:text-[20px] text-[#777267] dark:text-[#929292] leading-[1.6]">
          Paste any URL.{' '}
          <span className="text-[#151515] dark:text-white font-medium">OriginSec</span>{' '}
          probes the live site and scores it across security, front-end, back-end, and engagement — with exact fixes
          for every issue it finds.
        </p>

        {/* Rounded URL Input Bar */}
        <form onSubmit={handleSubmit} className="pt-4 max-w-3xl mx-auto w-full space-y-3.5" noValidate>
          <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-2.5 sm:p-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 focus-within:border-[#008C55] dark:focus-within:border-[#00E69A] transition-all duration-200 shadow-[0_12px_40px_rgba(0,0,0,0.06)] dark:shadow-none">
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
              className="flex-1 bg-transparent px-4 sm:px-5 py-3.5 text-base sm:text-[18px] text-[#151515] dark:text-white placeholder:text-[#929292] dark:placeholder:text-[#666] focus:outline-none"
            />
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-7 py-3.5 rounded-xl font-semibold text-[15px] bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 active:scale-[0.99] transition-all duration-150 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? 'Starting audit...' : 'Analyze target'}
            </button>
          </div>

          {/* Authorization Statement & Crawl Budget */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5 px-1 text-left">
            <label className="inline-flex items-start sm:items-center gap-2.5 text-[13px] text-[#777267] dark:text-[#929292] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={authorizedConfirmed}
                onChange={(e) => {
                  setAuthorizedConfirmed(e.target.checked);
                  if (localValidationError) setLocalValidationError(null);
                }}
                className="mt-0.5 sm:mt-0 w-4 h-4 shrink-0 rounded border-[#E7E0D3] dark:border-[#333] accent-[#008C55] dark:accent-[#00E69A] cursor-pointer"
              />
              <span>I confirm I own this website or have explicit permission to assess it.</span>
            </label>

            <div className="inline-flex items-center gap-1.5 text-[13px] text-[#777267] dark:text-[#929292] shrink-0">
              <ShieldCheck className="w-4 h-4 text-[#008C55] dark:text-[#00E69A]" />
              <label htmlFor="crawl-budget-select" className="sr-only">
                Crawl depth
              </label>
              <select
                id="crawl-budget-select"
                value={crawlDepthMode}
                onChange={(e) => setCrawlDepthMode(e.target.value as 'standard' | 'deep')}
                className="bg-transparent text-[13px] font-medium text-[#151515] dark:text-white focus:outline-none cursor-pointer"
              >
                <option value="standard" className="bg-white dark:bg-[#0B0B0B]">
                  Standard (max 8 pages)
                </option>
                <option value="deep" className="bg-white dark:bg-[#0B0B0B]">
                  Extended (max 20 pages)
                </option>
              </select>
            </div>
          </div>

          {displayError && (
            <div
              role="alert"
              className="flex items-center gap-2.5 px-4 py-3.5 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm text-left"
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
        className="max-w-7xl w-full mx-auto mt-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 animate-fade-up"
      >
        {CATEGORIES.map((cat) => (
          <div
            key={cat.title}
            className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-7 text-left hover:-translate-y-1 hover:border-[#C7BDA9] dark:hover:border-[#3A3A3A] transition-all duration-200 ease-out"
          >
            <h2 className="text-[17px] font-bold text-[#151515] dark:text-white mb-3 leading-snug">
              {cat.title}
            </h2>
            <p className="text-[15px] leading-[1.6] text-[#777267] dark:text-[#929292]">
              {cat.description}
            </p>
          </div>
        ))}
      </section>
    </main>
  );
};
