import React, { useState } from 'react';
import { Bell, LogOut, Menu, Search, Shield, User as UserIcon, X } from 'lucide-react';
import type { User } from 'firebase/auth';
import type { ThemeMode } from '../types/audit';
import { OriginSecMark } from './OriginSecMark';

export type AppRoute =
  | 'home'
  | 'login'
  | 'dashboard'
  | 'websites'
  | 'scan'
  | 'history'
  | 'security-reports'
  | 'frontend-intel'
  | 'api-audits'
  | 'backend-assessment'
  | 'database-audits'
  | 'seo-quality'
  | 'performance-lab'
  | 'accessibility'
  | 'infrastructure'
  | 'backups'
  | 'monitoring'
  | 'integrations'
  | 'remediation'
  | 'notifications'
  | 'settings'
  | 'about'
  | 'admin'
  | 'report';

interface HeaderProps {
  theme: ThemeMode;
  onToggleTheme: () => void;
  user: User | null;
  onSignIn: () => void;
  onSignOut: () => void;
  activeRoute: AppRoute;
  onNavigate: (route: AppRoute) => void;
  authLoading?: boolean;
  authReady?: boolean;
  unreadNotificationsCount?: number;
  onOpenSearch?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  theme,
  onToggleTheme,
  user,
  onSignOut,
  activeRoute,
  onNavigate,
  authLoading,
  authReady = true,
  unreadNotificationsCount = 0,
  onOpenSearch,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: Array<{ route: AppRoute; label: string }> = user
    ? [
        { route: 'dashboard', label: 'Workspace' },
        { route: 'websites', label: 'Websites' },
        { route: 'history', label: 'Scan history' },
        { route: 'remediation', label: 'Remediation' },
      ]
    : [];

  const handleNav = (route: AppRoute) => {
    onNavigate(route);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF]/90 dark:bg-[#070708]/90 backdrop-blur-md transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-[72px] flex items-center justify-between gap-4">
        {/* Zone 1: Brand Lockup */}
        <button
          type="button"
          onClick={() => handleNav(user ? 'home' : 'login')}
          className="inline-flex items-center gap-2.5 text-lg sm:text-xl font-semibold tracking-tight text-[#0A0A0C] dark:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#2F75C3] dark:focus-visible:outline-[#2F71E3]"
          aria-label="OriginSec Home"
        >
          <OriginSecMark theme={theme} className="w-7 h-7" />
          <span>OriginSec</span>
        </button>

        {/* Zone 2: Desktop Navigation */}
        {navItems.length > 0 && (
          <nav className="hidden md:flex items-center gap-7" aria-label="Primary Navigation">
            {navItems.map((item) => {
              const isActive = activeRoute === item.route;
              return (
                <button
                  key={item.route}
                  type="button"
                  onClick={() => handleNav(item.route)}
                  className={`text-[15px] font-medium transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                    isActive
                      ? 'text-[#0A0A0C] dark:text-white underline underline-offset-8 decoration-[#2F75C3] dark:decoration-[#2F71E3] decoration-2'
                      : 'text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>
        )}

        {/* Zone 3: Search, Notifications, Auth & Theme Toggle */}
        <div className="flex items-center gap-2.5 shrink-0">
          {user && onOpenSearch && (
            <button
              type="button"
              onClick={onOpenSearch}
              aria-label="Search scans, websites and findings"
              title="Universal Search (Ctrl+K)"
              className="hidden sm:inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#101115] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white transition-colors cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">Search</span>
            </button>
          )}

          {user ? (
            <div className="hidden sm:flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleNav('notifications')}
                aria-label="Notifications"
                title="Notification Centre"
                className="relative p-2 rounded-full border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#101115] text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white cursor-pointer"
              >
                <Bell className="w-4 h-4" />
                {unreadNotificationsCount > 0 && (
                  <span className="absolute -top-1 -right-1 min-w-[17px] h-[17px] px-1 rounded-full bg-[#2F75C3] dark:bg-[#2F71E3] text-white text-[10px] font-bold flex items-center justify-center tabular-nums">
                    {unreadNotificationsCount > 9 ? '9+' : unreadNotificationsCount}
                  </span>
                )}
              </button>

              {user.email?.toLowerCase() === 'adityaair1.2029@gmail.com' && (
                <button
                  type="button"
                  onClick={() => handleNav('admin')}
                  aria-label="Admin Overview"
                  title="Founder Admin Overview"
                  className="p-2 rounded-full border border-[#E5E7EB] dark:border-white/[0.1] bg-[#F7F8FA] dark:bg-[#101115] text-[#2F75C3] dark:text-[#2F71E3] hover:border-[#2F75C3] dark:hover:border-[#2F71E3] cursor-pointer"
                >
                  <Shield className="w-4 h-4" />
                </button>
              )}

              <button
                type="button"
                onClick={() => handleNav('settings')}
                className="inline-flex items-center gap-2 text-sm font-medium text-[#0A0A0C] dark:text-white hover:opacity-80 cursor-pointer transition-opacity pl-1"
                title={user.email || 'Account'}
              >
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'Profile'}
                    referrerPolicy="no-referrer"
                    className="w-8 h-8 rounded-full border border-[#E5E7EB] dark:border-white/[0.12] object-cover"
                  />
                ) : (
                  <span className="w-8 h-8 rounded-full bg-[#F1F3F6] dark:bg-[#1A1C23] flex items-center justify-center">
                    <UserIcon className="w-4 h-4" />
                  </span>
                )}
                <span className="hidden xl:inline max-w-[120px] truncate">{user.displayName?.split(' ')[0] || 'Account'}</span>
              </button>
              <button
                type="button"
                onClick={onSignOut}
                aria-label="Sign out"
                title="Sign out"
                className="p-2 rounded-full text-[#5A606E] dark:text-[#9499A6] hover:text-[#0A0A0C] dark:hover:text-white transition-colors cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : !authReady ? (
            <span className="hidden sm:inline-flex items-center px-3 py-2 text-[12px] font-medium text-[#5A606E] dark:text-[#9499A6] whitespace-nowrap shrink-0">
              Checking session...
            </span>
          ) : (
            <button
              type="button"
              onClick={() => handleNav('login')}
              disabled={authLoading}
              className="btn-lighting inline-flex items-center gap-2 px-4 py-2 rounded-full text-[13px] font-medium bg-[#2F75C3] dark:bg-[#2F71E3] text-white hover:opacity-90 transition-opacity whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              Sign in
            </button>
          )}

          <button
            type="button"
            onClick={onToggleTheme}
            className="px-4 py-2 rounded-full text-xs font-medium tracking-wide border border-[#E5E7EB] dark:border-white/[0.12] bg-[#F7F8FA] dark:bg-[#101115] text-[#0A0A0C] dark:text-white hover:border-[#2F75C3] dark:hover:border-[#2F71E3] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>

          {user && (
            <button
              type="button"
              onClick={() => setMobileMenuOpen((v) => !v)}
              aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
              className="md:hidden p-2 rounded-lg border border-[#E5E7EB] dark:border-white/[0.12] text-[#0A0A0C] dark:text-white cursor-pointer"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          )}
        </div>
      </div>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && user && (
        <div className="md:hidden border-t border-[#E5E7EB] dark:border-white/[0.08] bg-[#FFFFFF] dark:bg-[#070708] px-4 py-4 space-y-2">
          {onOpenSearch && (
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onOpenSearch();
              }}
              className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6]"
            >
              <Search className="w-4 h-4" />
              Search scans &amp; findings
            </button>
          )}
          {navItems.map((item) => (
            <button
              key={item.route}
              type="button"
              onClick={() => handleNav(item.route)}
              className={`block w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium ${
                activeRoute === item.route
                  ? 'bg-[#F7F8FA] dark:bg-[#101115] text-[#0A0A0C] dark:text-white border border-[#E5E7EB] dark:border-white/[0.1]'
                  : 'text-[#5A606E] dark:text-[#9499A6]'
              }`}
            >
              {item.label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => handleNav('notifications')}
            className="block w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium text-[#5A606E] dark:text-[#9499A6]"
          >
            Notifications {unreadNotificationsCount > 0 ? `(${unreadNotificationsCount})` : ''}
          </button>
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              onSignOut();
            }}
            className="w-full mt-2 px-4 py-2.5 rounded-lg text-sm font-medium border border-[#E5E7EB] dark:border-white/[0.1] text-[#5A606E] dark:text-[#9499A6]"
          >
            Sign out ({user.email})
          </button>
        </div>
      )}
    </header>
  );
};
