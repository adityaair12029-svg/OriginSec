import React, { useState } from 'react';
import { Menu, X, LogOut, User as UserIcon } from 'lucide-react';
import type { ThemeMode } from '../types/audit';
import type { User } from 'firebase/auth';

export type AppRoute =
  | 'home'
  | 'dashboard'
  | 'scan'
  | 'history'
  | 'security-reports'
  | 'api-audits'
  | 'database-audits'
  | 'infrastructure'
  | 'backups'
  | 'monitoring'
  | 'integrations'
  | 'settings'
  | 'about'
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
}

export const Header: React.FC<HeaderProps> = ({
  theme,
  onToggleTheme,
  user,
  onSignIn,
  onSignOut,
  activeRoute,
  onNavigate,
  authLoading,
  authReady = true,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: Array<{ route: AppRoute; label: string; requireAuth?: boolean }> = user
    ? [
        { route: 'dashboard', label: 'Dashboard' },
        { route: 'history', label: 'Scan history' },
        { route: 'integrations', label: 'Integrations' },
        { route: 'settings', label: 'Profile' },
      ]
    : [
        { route: 'history', label: 'Scan history' },
        { route: 'api-audits', label: 'API Audit' },
        { route: 'about', label: 'About' },
      ];

  const handleNav = (route: AppRoute) => {
    onNavigate(route);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[#E7E0D3] dark:border-[#1E1E1E] bg-[#F7F5EF]/95 dark:bg-[#050505]/95 backdrop-blur-md transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-[72px] flex items-center justify-between gap-4">
        {/* Zone 1: Brand Wordmark */}
        <button
          type="button"
          onClick={() => handleNav('home')}
          className="inline-flex items-center gap-1.5 text-xl font-extrabold tracking-tight text-[#151515] dark:text-white whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#008C55] dark:focus-visible:outline-[#00E69A]"
          aria-label="OriginSec Home"
        >
          <span>ORIGIN</span>
          <span className="text-[#008C55] dark:text-[#00E69A]">SEC</span>
          <span
            className="inline-block w-2 h-2 rounded-full bg-[#008C55] dark:bg-[#00E69A] ml-0.5"
            aria-hidden="true"
          />
        </button>

        {/* Zone 2: Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-8" aria-label="Primary Navigation">
          {navItems.map((item) => {
            const isActive = activeRoute === item.route;
            return (
              <button
                key={item.route}
                type="button"
                onClick={() => handleNav(item.route)}
                className={`text-[15px] font-medium transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                  isActive
                    ? 'text-[#151515] dark:text-white underline underline-offset-8 decoration-[#008C55] dark:decoration-[#00E69A] decoration-2'
                    : 'text-[#777267] dark:text-[#929292] hover:text-[#151515] dark:hover:text-white'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Actions & Theme Toggle */}
        <div className="flex items-center gap-3 shrink-0">
          {user ? (
            <div className="hidden sm:flex items-center gap-2.5">
              <button
                type="button"
                onClick={() => handleNav('settings')}
                className="inline-flex items-center gap-2 text-sm font-medium text-[#151515] dark:text-white hover:opacity-80 cursor-pointer transition-opacity"
                title={user.email || 'Account'}
              >
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'Profile'}
                    referrerPolicy="no-referrer"
                    className="w-8 h-8 rounded-full border border-[#E7E0D3] dark:border-[#252525] object-cover"
                  />
                ) : (
                  <span className="w-8 h-8 rounded-full bg-[#E7E0D3] dark:bg-[#252525] flex items-center justify-center">
                    <UserIcon className="w-4 h-4" />
                  </span>
                )}
                <span className="hidden lg:inline max-w-[130px] truncate">{user.displayName?.split(' ')[0] || 'Account'}</span>
              </button>
              <button
                type="button"
                onClick={onSignOut}
                aria-label="Sign out"
                title="Sign out"
                className="p-2 rounded-full text-[#777267] dark:text-[#929292] hover:text-[#151515] dark:hover:text-white transition-colors cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : !authReady ? (
            <span className="hidden sm:inline-flex items-center px-3 py-2 text-[12px] font-medium text-[#777267] dark:text-[#929292] whitespace-nowrap shrink-0">
              Checking session...
            </span>
          ) : (
            <button
              type="button"
              onClick={onSignIn}
              disabled={authLoading}
              className="hidden sm:inline-flex items-center gap-2 px-4 py-2 rounded-full text-[13px] font-medium border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#008C55] dark:hover:border-[#00E69A] transition-all duration-150 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              Sign in with Google
            </button>
          )}

          <button
            type="button"
            onClick={onToggleTheme}
            className="px-5 py-2.5 rounded-full text-xs font-semibold tracking-wider uppercase border border-[#E7E0D3] dark:border-[#252525] bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white hover:border-[#929292] dark:hover:border-[#555] transition-all duration-150 whitespace-nowrap shrink-0 cursor-pointer"
          >
            {theme === 'dark' ? 'LIGHT MODE' : 'DARK MODE'}
          </button>

          <button
            type="button"
            onClick={() => setMobileMenuOpen((v) => !v)}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="md:hidden p-2 rounded-lg border border-[#E7E0D3] dark:border-[#252525] text-[#151515] dark:text-white cursor-pointer"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-[#E7E0D3] dark:border-[#1E1E1E] bg-[#F7F5EF] dark:bg-[#050505] px-4 py-4 space-y-2">
          {navItems.map((item) => (
            <button
              key={item.route}
              type="button"
              onClick={() => handleNav(item.route)}
              className={`block w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium ${
                activeRoute === item.route
                  ? 'bg-white dark:bg-[#0B0B0B] text-[#151515] dark:text-white border border-[#E7E0D3] dark:border-[#252525]'
                  : 'text-[#777267] dark:text-[#929292]'
              }`}
            >
              {item.label}
            </button>
          ))}
          {!user ? (
            authReady ? (
              <button
                type="button"
                onClick={() => {
                  setMobileMenuOpen(false);
                  onSignIn();
                }}
                className="w-full mt-2 px-4 py-2.5 rounded-lg text-sm font-semibold bg-[#151515] text-white dark:bg-white dark:text-[#050505]"
              >
                Sign in with Google
              </button>
            ) : null
          ) : (
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onSignOut();
              }}
              className="w-full mt-2 px-4 py-2.5 rounded-lg text-sm font-medium border border-[#E7E0D3] dark:border-[#252525] text-[#777267] dark:text-[#929292]"
            >
              Sign out ({user.email})
            </button>
          )}
        </div>
      )}
    </header>
  );
};
