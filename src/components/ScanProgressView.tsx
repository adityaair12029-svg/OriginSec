import React from 'react';
import { CheckCircle2, Circle, Loader2, XCircle, Ban } from 'lucide-react';
import type { ScanStatus } from '../types/audit';
import { ORDERED_PROGRESS_STAGES } from '../lib/scanner/profiles';

export interface ActiveScanProgress {
  scanId: string;
  targetUrl: string;
  normalizedDomain: string;
  status: ScanStatus;
  currentStage: string;
  progressPercent: number;
  stagesLog: Array<{ stage: string; status: 'completed' | 'skipped' | 'failed'; detail: string; timestamp: string }>;
  error?: string;
}

interface ScanProgressViewProps {
  progress: ActiveScanProgress;
  onCancel: () => void;
  onBackHome: () => void;
}

export const ScanProgressView: React.FC<ScanProgressViewProps> = ({
  progress,
  onCancel,
  onBackHome,
}) => {
  const isTerminalFailure = progress.status === 'failed' || progress.status === 'cancelled';

  const completedNames = new Set(progress.stagesLog.filter((s) => s.status === 'completed').map((s) => s.stage));
  const failedNames = new Set(progress.stagesLog.filter((s) => s.status === 'failed').map((s) => s.stage));

  return (
    <main className="flex-1 max-w-3xl w-full mx-auto px-4 sm:px-6 py-12">
      <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-6 sm:p-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E7E0D3] dark:border-[#1E1E1E] pb-5">
          <div className="space-y-1">
            <p className="text-xs font-semibold uppercase tracking-widest text-[#008C55] dark:text-[#00E69A]">
              {progress.status.replace('_', ' ')}
            </p>
            <h1 className="text-xl sm:text-2xl font-bold text-[#151515] dark:text-white">
              Auditing {progress.normalizedDomain}
            </h1>
            <p className="text-xs font-mono text-[#777267] dark:text-[#929292] break-all">
              {progress.targetUrl} · ID: {progress.scanId}
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <span className="text-2xl font-bold tabular-nums text-[#151515] dark:text-white">
              {progress.progressPercent}%
            </span>
            {!isTerminalFailure && progress.status !== 'completed' && (
              <button
                type="button"
                onClick={onCancel}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium border border-[#E7E0D3] dark:border-[#252525] text-[#777267] dark:text-[#929292] hover:text-red-600 dark:hover:text-red-400 cursor-pointer"
              >
                <Ban className="w-3.5 h-3.5" />
                Cancel
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div
          className="w-full h-2 rounded-full bg-[#EFECE4] dark:bg-[#1B1B1B] overflow-hidden"
          role="progressbar"
          aria-valuenow={progress.progressPercent}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            className={`h-full transition-all duration-300 ${
              isTerminalFailure ? 'bg-red-500' : 'bg-[#008C55] dark:bg-[#00E69A]'
            }`}
            style={{ width: `${progress.progressPercent}%` }}
          />
        </div>

        {/* Error Box if failed/cancelled */}
        {isTerminalFailure && (
          <div
            role="alert"
            className="rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 p-4 space-y-3"
          >
            <div className="flex items-center gap-2 text-red-700 dark:text-red-300 font-semibold text-sm">
              <XCircle className="w-4 h-4 shrink-0" />
              <span>{progress.status === 'cancelled' ? 'Scan cancelled' : 'Scan could not be completed'}</span>
            </div>
            <p className="text-sm text-red-700/90 dark:text-red-300/90">
              {progress.error || 'The scan was stopped before generating a report.'}
            </p>
            <button
              type="button"
              onClick={onBackHome}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] cursor-pointer"
            >
              Return to Scanner
            </button>
          </div>
        )}

        {/* Stage Checklist */}
        <div className="space-y-2.5">
          {ORDERED_PROGRESS_STAGES.map((stageName) => {
            const isCompleted = completedNames.has(stageName);
            const isFailed = failedNames.has(stageName);
            const isActive = !isTerminalFailure && progress.currentStage === stageName && !isCompleted;
            const logEntry = progress.stagesLog.find((s) => s.stage === stageName);

            return (
              <div
                key={stageName}
                className="flex items-start justify-between gap-4 py-2 border-b border-[#EFECE4] dark:border-[#161616] last:border-b-0"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {isFailed ? (
                    <XCircle className="w-4 h-4 text-red-500 shrink-0" />
                  ) : isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-[#008C55] dark:text-[#00E69A] shrink-0" />
                  ) : isActive ? (
                    <Loader2 className="w-4 h-4 text-[#008C55] dark:text-[#00E69A] animate-spin shrink-0" />
                  ) : (
                    <Circle className="w-4 h-4 text-[#C5BFA8] dark:text-[#333] shrink-0" />
                  )}
                  <div className="min-w-0">
                    <p
                      className={`text-sm font-medium ${
                        isCompleted || isActive
                          ? 'text-[#151515] dark:text-white'
                          : 'text-[#777267] dark:text-[#666]'
                      }`}
                    >
                      {stageName}
                    </p>
                    {logEntry && (
                      <p className="text-xs text-[#777267] dark:text-[#929292] truncate">
                        {logEntry.detail}
                      </p>
                    )}
                  </div>
                </div>
                <span className="text-[11px] font-mono text-[#777267] dark:text-[#666] shrink-0">
                  {isFailed ? 'Failed' : isCompleted ? 'Done' : isActive ? 'Running' : 'Pending'}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </main>
  );
};
