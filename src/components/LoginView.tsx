import React, { useState } from 'react';
import { ArrowLeft, ChevronDown, ChevronUp, Loader2 } from 'lucide-react';
import type { ThemeMode } from '../types/audit';
import { OriginSecMark } from './OriginSecMark';
import { ParticleFieldCanvas } from './ParticleFieldCanvas';

interface LoginViewProps {
  theme: ThemeMode;
  authLoading: boolean;
  authNotice: string | null;
  onGoogleSignIn: () => Promise<void>;
  onContinueAsGuest: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  theme,
  authLoading,
  authNotice,
  onGoogleSignIn,
  onContinueAsGuest,
}) => {
  const [showHelp, setShowHelp] = useState(false);

  return (
    <main className="relative flex-1 flex flex-col items-center justify-center px-4 py-16 min-h-[calc(100vh-140px)] overflow-hidden">
      <ParticleFieldCanvas theme={theme} variant="wave" />

      <div className="relative z-10 w-full max-w-[390px] flex flex-col items-center text-center space-y-6 animate-fade-up">
        <div className="w-12 h-12 flex items-center justify-center text-[#0A0A0C] dark:text-white">
          <OriginSecMark className="w-10 h-10" />
        </div>

        <div className="space-y-2">
          <h1 className="text-[28px] sm:text-[32px] font-medium tracking-[-0.025em] text-[#0A0A0C] dark:text-white">
            Welcome to OriginSec
          </h1>
          <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">
            Sign in once to persist scan reports, verify domains, and monitor uptime across devices.
          </p>
        </div>

        <div className="w-full rounded-2xl border border-[#E5E7EB] dark:border-white/[0.09] bg-white/90 dark:bg-[#101115]/90 backdrop-blur-md p-4 space-y-2.5 shadow-[0_18px_50px_rgba(10,10,12,0.08)] dark:shadow-[0_24px_60px_rgba(0,0,0,0.6)]">
          <button
            type="button"
            onClick={() => void onGoogleSignIn()}
            disabled={authLoading}
            className="w-full h-11 rounded-full bg-[#2F75C3] dark:bg-[#2F71E3] hover:opacity-95 active:scale-[0.99] text-white text-sm font-medium inline-flex items-center justify-center gap-2.5 transition-all cursor-pointer disabled:opacity-60"
          >
            {authLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current" aria-hidden="true">
                <path d="M21.8 10.23h-9.7v3.87h5.6c-.25 1.44-1.05 2.66-2.24 3.47v2.88h3.62c2.12-1.95 3.34-4.83 3.34-8.22 0-.67-.06-1.34-.18-2h-.44z" />
                <path d="M12.1 22c3.04 0 5.59-1 7.45-2.72l-3.62-2.88c-1.01.68-2.3 1.08-3.83 1.08-2.94 0-5.44-1.99-6.33-4.66H2.03v2.96C3.93 19.55 7.77 22 12.1 22z" />
                <path d="M5.77 12.82A5.95 5.95 0 0 1 5.45 11c0-.63.11-1.24.32-1.82V6.22H2.03A9.96 9.96 0 0 0 1 11c0 1.61.39 3.13 1.03 4.78l3.74-2.96z" />
                <path d="M12.1 4.52c1.65 0 3.14.57 4.31 1.68l3.23-3.23C17.68 1.15 15.13 0 12.1 0 7.77 0 3.93 2.45 2.03 6.22l3.74 2.96c.89-2.67 3.39-4.66 6.33-4.66z" />
              </svg>
            )}
            <span>{authLoading ? 'Signing in...' : 'Continue with Google'}</span>
          </button>

          <button
            type="button"
            onClick={onContinueAsGuest}
            className="w-full h-11 rounded-full bg-[#F1F3F6] dark:bg-[#1B1D23] hover:bg-[#E5E8EE] dark:hover:bg-[#242730] text-[#0A0A0C] dark:text-white text-sm font-medium transition-colors cursor-pointer"
          >
            Continue to Scanner without signing in
          </button>
        </div>

        {authNotice && (
          <div
            role="alert"
            className="w-full rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-xs text-amber-800 dark:text-amber-300 text-left"
          >
            {authNotice}
          </div>
        )}

        <div className="space-y-2 w-full">
          <button
            type="button"
            onClick={() => setShowHelp((v) => !v)}
            aria-expanded={showHelp}
            className="inline-flex items-center gap-1 text-xs text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white transition-colors cursor-pointer"
          >
            <span>Having trouble signing in?</span>
            {showHelp ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showHelp && (
            <div className="rounded-xl border border-[#E5E7EB] dark:border-white/[0.08] bg-white/95 dark:bg-[#101115]/95 p-4 text-left text-xs text-[#5A606E] dark:text-[#9499A6] space-y-1.5">
              <p className="font-semibold text-[#0A0A0C] dark:text-white">Troubleshooting Sign-In</p>
              <p>1. Allow pop-ups for this site or wait for redirect completion if blocked by your browser.</p>
              <p>2. Ensure your current hostname is listed in Firebase Console → Authentication → Authorized Domains.</p>
              <p>3. Your session stays persisted locally once verified—you will not be prompted repeatedly.</p>
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={onContinueAsGuest}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-[#2F75C3] dark:text-[#2F71E3] hover:underline cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Landing Page
        </button>
      </div>
    </main>
  );
};
