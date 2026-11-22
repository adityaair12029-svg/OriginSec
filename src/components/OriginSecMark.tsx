import React from 'react';
import type { ThemeMode } from '../types/audit';

interface OriginSecMarkProps {
  theme?: ThemeMode;
  className?: string;
}

const LIGHT_LOGO_SRC = '/assets/aistudio/Screenshot_20260821-152942_2b0f49ae.jpg';
const DARK_LOGO_SRC = '/assets/aistudio/Screenshot_20260809-103828_3b3c6268.jpg';

export const OriginSecMark: React.FC<OriginSecMarkProps> = ({ theme, className = 'w-7 h-7' }) => {
  const isDark =
    theme !== undefined
      ? theme === 'dark'
      : typeof document !== 'undefined' && document.documentElement.classList.contains('dark');

  return (
    <span
      className={`inline-flex items-center justify-center overflow-hidden shrink-0 select-none ${className}`}
      aria-hidden="true"
    >
      {isDark ? (
        <img
          src={DARK_LOGO_SRC}
          alt=""
          className="w-full h-full object-cover object-[50%_52%] scale-[1.58] mix-blend-screen contrast-125 brightness-110 [mask-image:radial-gradient(circle,black_55%,transparent_82%)] pointer-events-none"
        />
      ) : (
        <img
          src={LIGHT_LOGO_SRC}
          alt=""
          className="w-full h-full object-contain scale-[1.08] mix-blend-multiply pointer-events-none"
        />
      )}
    </span>
  );
};
