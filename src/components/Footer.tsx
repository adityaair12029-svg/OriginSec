import React from 'react';
import type { AppRoute } from './Header';

export const Footer: React.FC<{ onNavigate: (route: AppRoute) => void }> = ({ onNavigate }) => {
  return (
    <footer className="w-full border-t border-[#E7E0D3] dark:border-[#1E1E1E] py-9 px-4 sm:px-6 mt-auto">
      <div className="max-w-7xl mx-auto flex flex-col items-center justify-center gap-2.5 text-center">
        <div className="flex items-center gap-1.5 text-[15px]">
          <span className="font-extrabold tracking-tight text-[#151515] dark:text-white">
            ORIGIN <span className="text-[#008C55] dark:text-[#00E69A]">SEC</span>
          </span>
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#008C55] dark:bg-[#00E69A]" aria-hidden="true" />
          <span className="text-[#777267] dark:text-[#929292]">— real-time diagnostics, no fluff.</span>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[13px] text-[#777267] dark:text-[#929292]">
          <span>Founded by Aditya Choudhary | A DopTails Company</span>
          <span aria-hidden="true">·</span>
          <button
            type="button"
            onClick={() => onNavigate('about')}
            className="hover:text-[#151515] dark:hover:text-white underline underline-offset-4 cursor-pointer transition-colors"
          >
            Methodology &amp; About
          </button>
        </div>
      </div>
    </footer>
  );
};
