import React from 'react';
import {
  Activity,
  Database,
  FileSearch,
  HardDrive,
  History,
  LayoutDashboard,
  Plug,
  PlusCircle,
  Server,
  Settings,
  ShieldCheck,
  Webhook,
  Info,
} from 'lucide-react';
import type { AppRoute } from './Header';

interface DashboardShellProps {
  activeRoute: AppRoute;
  onNavigate: (route: AppRoute) => void;
  children: React.ReactNode;
}

const SIDEBAR_ITEMS: Array<{ route: AppRoute; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { route: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { route: 'home', label: 'New Website Scan', icon: PlusCircle },
  { route: 'history', label: 'Scan History', icon: History },
  { route: 'security-reports', label: 'Security Reports', icon: ShieldCheck },
  { route: 'api-audits', label: 'API Audits', icon: Webhook },
  { route: 'database-audits', label: 'Database Audits', icon: Database },
  { route: 'infrastructure', label: 'Infrastructure', icon: Server },
  { route: 'backups', label: 'Backup & Recovery', icon: HardDrive },
  { route: 'monitoring', label: 'Monitoring', icon: Activity },
  { route: 'integrations', label: 'Integrations', icon: Plug },
  { route: 'settings', label: 'Settings', icon: Settings },
  { route: 'about', label: 'About OriginSec', icon: Info },
];

export const DashboardShell: React.FC<DashboardShellProps> = ({
  activeRoute,
  onNavigate,
  children,
}) => {
  return (
    <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col lg:flex-row gap-8">
      {/* Sidebar Navigation */}
      <aside className="lg:w-60 shrink-0" aria-label="Workspace Sections">
        <nav className="flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible pb-2 lg:pb-0">
          {SIDEBAR_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeRoute === item.route;
            return (
              <button
                key={item.route}
                type="button"
                onClick={() => onNavigate(item.route)}
                className={`inline-flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer text-left ${
                  active
                    ? 'bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white border border-[#E7E0D3] dark:border-[#252525]'
                    : 'text-[#777267] dark:text-[#929292] hover:text-[#151515] dark:hover:text-white hover:bg-white/50 dark:hover:bg-[#0B0B0B]/50 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-[#008C55] dark:text-[#00E69A]' : ''}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      {/* Main Workspace Content */}
      <main className="flex-1 min-w-0">{children}</main>
    </div>
  );
};

export const EmptyWorkspaceState: React.FC<{
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}> = ({ title, description, actionLabel, onAction }) => (
  <div className="rounded-2xl border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] p-10 text-center space-y-4">
    <div className="w-10 h-10 rounded-full border border-[#E7E0D3] dark:border-[#252525] mx-auto flex items-center justify-center text-[#777267] dark:text-[#929292]">
      <FileSearch className="w-5 h-5" />
    </div>
    <div className="space-y-1.5 max-w-md mx-auto">
      <h3 className="text-base font-semibold text-[#151515] dark:text-white">{title}</h3>
      <p className="text-sm text-[#777267] dark:text-[#929292]">{description}</p>
    </div>
    {actionLabel && onAction && (
      <button
        type="button"
        onClick={onAction}
        className="px-5 py-2.5 rounded-xl text-xs font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505] hover:opacity-90 cursor-pointer"
      >
        {actionLabel}
      </button>
    )}
  </div>
);
