import React from 'react';
import type { AppRoute } from './Header';
import { OriginSecMark } from './OriginSecMark';

export const Footer: React.FC<{ onNavigate: (route: AppRoute) => void }> = ({ onNavigate }) => {
  return (
    <footer className="relative z-10 w-full border-t border-[#E5E7EB] dark:border-white/[0.08] py-9 px-4 sm:px-6 mt-auto bg-[#FFFFFF]/80 dark:bg-[#070708]/80 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto flex flex-col items-center justify-center gap-2.5 text-center">
        <div className="flex items-center gap-2 text-[15px]">
          <OriginSecMark className="w-5 h-5 text-[#0A0A0C] dark:text-white" />
          <span className="font-semibold tracking-tight text-[#0A0A0C] dark:text-white">
            OriginSec
          </span>
          <span className="text-[#5A606E] dark:text-[#9499A6]">— real-time diagnostics, no fluff.</span>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[13px] text-[#5A606E] dark:text-[#9499A6]">
          <span>Founded by Aditya Choudhary | A DopTails Company</span>
          <span aria-hidden="true">·</span>
          <button
            type="button"
            onClick={() => onNavigate('about')}
            className="hover:text-[#0A0A0C] dark:hover:text-white underline underline-offset-4 cursor-pointer transition-colors"
          >
            Methodology &amp; About
          </button>
        </div>
      </div>
    </footer>
  );
};
