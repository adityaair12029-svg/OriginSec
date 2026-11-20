import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: Error): State {
    let display = error.message || 'An unexpected rendering error occurred.';
    try {
      const parsed = JSON.parse(error.message);
      if (parsed && parsed.error && parsed.operationType) {
        display = `Database permission error during ${parsed.operationType} (${parsed.path || 'unknown path'}): ${parsed.error}`;
      }
    } catch {
      // Standard error message
    }
    return { hasError: true, message: display };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-6 bg-[#F7F5EF] dark:bg-[#050505] text-[#151515] dark:text-white">
          <div className="max-w-lg w-full rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-8 space-y-4">
            <div className="flex items-center gap-3 text-red-600 dark:text-red-400">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h2 className="text-lg font-semibold">Application Error</h2>
            </div>
            <p className="text-sm text-[#777267] dark:text-[#929292] leading-relaxed">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => {
                this.setState({ hasError: false, message: '' });
                window.location.reload();
              }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 transition-opacity"
            >
              <RefreshCw className="w-4 h-4" />
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
