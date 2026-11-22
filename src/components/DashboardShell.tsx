import React from 'react';
import {
  Accessibility,
  Activity,
  Bell,
  Database,
  FileSearch,
  Gauge,
  Globe,
  HardDrive,
  History,
  Info,
  Layers,
  LayoutDashboard,
  Plug,
  PlusCircle,
  Search,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Sparkles,
  Webhook,
  Wrench,
} from 'lucide-react';
import type { AppRoute } from './Header';

interface DashboardShellProps {
  activeRoute: AppRoute;
  onNavigate: (route: AppRoute) => void;
  isAdmin?: boolean;
  unreadNotificationsCount?: number;
  openRemediationCount?: number;
  onOpenSearch?: () => void;
  children: React.ReactNode;
}

type NavGroup = {
  heading: string;
  items: Array<{
    route: AppRoute;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
  }>;
};

export const DashboardShell: React.FC<DashboardShellProps> = ({
  activeRoute,
  onNavigate,
  isAdmin = false,
  unreadNotificationsCount = 0,
  openRemediationCount = 0,
  onOpenSearch,
  children,
}) => {
  const groups: NavGroup[] = [
    {
      heading: 'Workspace',
      items: [
        { route: 'dashboard', label: 'Overview', icon: LayoutDashboard },
        { route: 'home', label: 'New Website Scan', icon: PlusCircle },
        { route: 'websites', label: 'My Websites', icon: Globe },
        { route: 'history', label: 'Scan History', icon: History },
        { route: 'remediation', label: 'Remediation', icon: Wrench, badge: openRemediationCount },
      ],
    },
    {
      heading: 'Audit Intelligence',
      items: [
        { route: 'security-reports', label: 'Security Reports', icon: ShieldCheck },
        { route: 'frontend-intel', label: 'Frontend Intel', icon: Layers },
        { route: 'seo-quality', label: 'SEO & Content', icon: Sparkles },
        { route: 'performance-lab', label: 'Performance Lab', icon: Gauge },
        { route: 'accessibility', label: 'Accessibility', icon: Accessibility },
        { route: 'api-audits', label: 'API Audits', icon: Webhook },
        { route: 'backend-assessment', label: 'Backend Scope', icon: Server },
      ],
    },
    {
      heading: 'Infrastructure & Ops',
      items: [
        { route: 'database-audits', label: 'Database Audits', icon: Database },
        { route: 'infrastructure', label: 'Infrastructure', icon: Server },
        { route: 'backups', label: 'Backup & Recovery', icon: HardDrive },
        { route: 'monitoring', label: 'Monitoring', icon: Activity },
        { route: 'notifications', label: 'Notifications', icon: Bell, badge: unreadNotificationsCount },
        { route: 'integrations', label: 'Integrations', icon: Plug },
      ],
    },
    {
      heading: 'Platform',
      items: [
        { route: 'settings', label: 'Settings', icon: Settings },
        { route: 'about', label: 'About OriginSec', icon: Info },
        ...(isAdmin ? [{ route: 'admin' as AppRoute, label: 'Founder Admin', icon: Shield }] : []),
      ],
    },
  ];

  return (
    <div className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col lg:flex-row gap-8">
      {/* Sidebar Navigation */}
      <aside className="lg:w-64 shrink-0 space-y-5" aria-label="Workspace Sections">
        {onOpenSearch && (
          <button
            type="button"
            onClick={onOpenSearch}
            className="w-full flex items-center justify-between gap-2 px-3.5 py-2.5 rounded-xl text-xs border border-[#E5E7EB] dark:border-white/[0.08] bg-[#F7F8FA] dark:bg-[#101115] text-[#5A606E] dark:text-[#9499A6] hover:border-[#2F75C3] dark:hover:border-[#2F71E3] cursor-pointer transition-colors"
          >
            <span className="inline-flex items-center gap-2">
              <Search className="w-3.5 h-3.5" />
              Search workspace...
            </span>
            <kbd className="px-1.5 py-0.5 rounded bg-[#E5E7EB] dark:bg-white/[0.08] text-[10px] font-mono">⌘K</kbd>
          </button>
        )}

        <nav className="flex lg:flex-col gap-5 overflow-x-auto lg:overflow-visible pb-2 lg:pb-0">
          {groups.map((group) => (
            <div key={group.heading} className="flex lg:flex-col gap-1 shrink-0">
              <p className="hidden lg:block px-3.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#5A606E] dark:text-[#6B7280]">
                {group.heading}
              </p>
              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activeRoute === item.route;
                return (
                  <button
                    key={item.route}
                    type="button"
                    onClick={() => onNavigate(item.route)}
                    className={`inline-flex items-center justify-between gap-2.5 px-3.5 py-2 rounded-xl text-[13px] font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer text-left ${
                      active
                        ? 'bg-[#F1F5FB] dark:bg-[#14171F] text-[#0A0A0C] dark:text-white border border-[#2F75C3]/35 dark:border-[#2F71E3]/40'
                        : 'text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white hover:bg-[#F7F8FA] dark:hover:bg-[#101115] border border-transparent'
                    }`}
                  >
                    <span className="inline-flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-[#2F75C3] dark:text-[#2F71E3]' : ''}`} />
                      <span>{item.label}</span>
                    </span>
                    {item.badge !== undefined && item.badge > 0 && (
                      <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-[#2F75C3]/15 text-[#2F75C3] dark:bg-[#2F71E3]/20 dark:text-[#60A5FA] tabular-nums">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
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
  <div className="rounded-2xl border border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#101115] p-10 text-center space-y-4">
    <div className="w-10 h-10 rounded-full border border-[#E5E7EB] dark:border-white/[0.1] mx-auto flex items-center justify-center text-[#5A606E] dark:text-[#9499A6]">
      <FileSearch className="w-5 h-5" />
    </div>
    <div className="space-y-1.5 max-w-md mx-auto">
      <h3 className="text-base font-semibold text-[#0A0A0C] dark:text-white">{title}</h3>
      <p className="text-sm text-[#5A606E] dark:text-[#9499A6]">{description}</p>
    </div>
    {actionLabel && onAction && (
      <button
        type="button"
        onClick={onAction}
        className="px-5 py-2.5 rounded-full text-xs font-medium bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-90 cursor-pointer"
      >
        {actionLabel}
      </button>
    )}
  </div>
);
